package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleDeviceGroupCRUD: the write-boundary guards (invalid JSON, a member with no MAC/IP, a bad
// MAC, an empty id → 400) + the happy 200/persist; confirms a RoutingList's scope flows through the
// existing upsert unchanged; and delete (unknown 409, existing 200 + the list's scope pruned to all).
func TestHandleDeviceGroupCRUD(t *testing.T) {
	s, _ := sharehandlers_server(t)
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleUpsertDeviceGroup(w, httptest.NewRequest(http.MethodPost, "/api/device-groups", strings.NewReader(body)))
		return w
	}
	if w := post("{bad"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON = %d, want 400", w.Code)
	}
	if w := post(`{"id":"g","name":"G","members":[{}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("member with no mac/ip = %d, want 400", w.Code)
	}
	if w := post(`{"id":"g","name":"G","members":[{"mac":"zz:zz"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mac = %d, want 400", w.Code)
	}
	if w := post(`{"name":"noid","members":[{"ip":"192.168.1.5"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty id = %d, want 400", w.Code)
	}
	if w := post(`{"id":"kids","name":"Kids","members":[{"mac":"aa:bb:cc:dd:ee:ff"},{"ip":"192.168.1.50"}]}`); w.Code != http.StatusOK {
		t.Fatalf("valid = %d (%s)", w.Code, w.Body)
	}
	if n := len(s.store.Profile().DeviceGroups); n != 1 {
		t.Fatalf("device group not persisted: %d", n)
	}

	// A routing list scoped to the group flows through the existing upsert unchanged.
	rl := httptest.NewRecorder()
	s.handleUpsertRoutingList(rl, httptest.NewRequest(http.MethodPost, "/api/routing", strings.NewReader(`{"id":"yt","name":"YT","manual":["youtube.com"],"outbound":"block","enabled":true,"scope_mode":"only","scope_groups":["kids"]}`)))
	if rl.Code != http.StatusOK {
		t.Fatalf("scoped list upsert = %d (%s)", rl.Code, rl.Body)
	}
	got := s.store.Profile().RoutingLists
	if len(got) != 1 || got[0].ScopeMode != "only" || len(got[0].ScopeGroups) != 1 || got[0].ScopeGroups[0] != "kids" {
		t.Fatalf("list scope did not persist through upsert: %+v", got)
	}

	// Delete: unknown → 409; existing → 200 + the list's now-empty scope reset to all-clients.
	un := httptest.NewRecorder()
	s.handleDeleteDeviceGroup(un, routingReq(http.MethodDelete, "/api/device-groups/nope", "", "nope"))
	if un.Code != http.StatusConflict {
		t.Fatalf("delete unknown = %d, want 409", un.Code)
	}
	del := httptest.NewRecorder()
	s.handleDeleteDeviceGroup(del, routingReq(http.MethodDelete, "/api/device-groups/kids", "", "kids"))
	if del.Code != http.StatusOK {
		t.Fatalf("delete existing = %d, want 200", del.Code)
	}
	p := s.store.Profile()
	if len(p.DeviceGroups) != 0 {
		t.Fatalf("group not deleted: %+v", p.DeviceGroups)
	}
	if p.RoutingLists[0].ScopeMode != "" || len(p.RoutingLists[0].ScopeGroups) != 0 {
		t.Fatalf("list scope should reset after its only group deleted: %+v", p.RoutingLists[0])
	}
}
