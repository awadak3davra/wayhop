package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func routingReq(method, path, body string, id string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if id != "" {
		req.SetPathValue("id", id)
	}
	return req
}

// TestHandleUpsertRoutingList_Validation covers the write-boundary guards: invalid JSON, the
// refresh_hours flash-protection reject (a cidr_source list below the min cadence), the empty-id store
// reject, and the happy 200 + persistence.
func TestHandleUpsertRoutingList_Validation(t *testing.T) {
	s, _ := sharehandlers_server(t)
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleUpsertRoutingList(w, httptest.NewRequest(http.MethodPost, "/api/routing", strings.NewReader(body)))
		return w
	}
	if w := post("{bad json"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON = %d, want 400", w.Code)
	}
	// cidr_source list with refresh_hours=3 (< MinCIDRRefreshHours) → 400 flash protection.
	if w := post(`{"id":"r1","cidr_source":"https://x/feed","refresh_hours":3,"outbound":"direct"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad refresh_hours = %d, want 400", w.Code)
	}
	// missing id → store rejects → 400.
	if w := post(`{"name":"x","outbound":"direct"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty id = %d, want 400", w.Code)
	}
	// valid → 200 + persisted.
	if w := post(`{"id":"r1","name":"OK","outbound":"direct","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("valid upsert = %d (%s)", w.Code, w.Body)
	}
	if n := len(s.store.Profile().RoutingLists); n != 1 {
		t.Fatalf("list not persisted: %d", n)
	}
}

// TestHandleDeleteRoutingList: unknown id → 409, existing → 200 + removed.
func TestHandleDeleteRoutingList(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "r1", Outbound: "direct"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleDeleteRoutingList(w, routingReq(http.MethodDelete, "/api/routing/nope", "", "nope"))
	if w.Code != http.StatusConflict {
		t.Fatalf("delete unknown = %d, want 409", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleDeleteRoutingList(w, routingReq(http.MethodDelete, "/api/routing/r1", "", "r1"))
	if w.Code != http.StatusOK {
		t.Fatalf("delete existing = %d (%s)", w.Code, w.Body)
	}
	if n := len(s.store.Profile().RoutingLists); n != 0 {
		t.Fatalf("list not deleted: %d", n)
	}
}

// TestHandleRoutingStatus_ManualList: a manual (no-source) list short-circuits to ok=true with NO
// network fetch — exercising the handler + the short-circuit branch offline.
func TestHandleRoutingStatus_ManualList(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "m1", Name: "Manual", Manual: []string{"1.2.3.0/24"}, Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleRoutingStatus(w, httptest.NewRequest(http.MethodGet, "/api/routing/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body)
	}
	var res []struct {
		ID string `json:"id"`
		OK bool   `json:"ok"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].ID != "m1" || !res[0].OK {
		t.Fatalf("manual list should be ok=true with no fetch: %+v", res)
	}
}
