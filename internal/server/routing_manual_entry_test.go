package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// SEC-07: a manual entry with a line break is refused when it is saved, not stored to block the next
// Apply (or, before model.ValidateManualEntries, to land in dnsmasq's configuration on KeeneticOS).
func TestUpsertRoutingListRefusesALineBreakInAManualEntry(t *testing.T) {
	s, _ := sharehandlers_server(t)
	w := httptest.NewRecorder()
	body := `{"id":"l","name":"L","manual":["a.a","b.b\nserver=203.0.113.9"],"outbound":"direct","enabled":true}`
	s.handleUpsertRoutingList(w, httptest.NewRequest(http.MethodPost, "/api/routing", strings.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("entry with a line break = %d (%s), want 400", w.Code, w.Body)
	}
	if n := len(s.store.Profile().RoutingLists); n != 0 {
		t.Fatalf("the refused list was stored (%d lists)", n)
	}
}

// An entry with a "/" that is not an IP prefix was saved and then emitted to the core as a
// domain suffix, which no name matches: the network the operator meant was routed nowhere and
// nothing said so. It is refused where it is typed.
func TestUpsertRoutingListRefusesASlashEntryThatIsNoPrefix(t *testing.T) {
	post := func(s *Server, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleUpsertRoutingList(w, httptest.NewRequest(http.MethodPost, "/api/routing", strings.NewReader(body)))
		return w
	}
	for _, bad := range []string{"10.0.0.0/99", "example.com/path", "https://example.com"} {
		s, _ := sharehandlers_server(t)
		w := post(s, `{"id":"l","name":"L","manual":["a.a","`+bad+`"],"outbound":"direct","enabled":true}`)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), bad) {
			t.Errorf("%q = %d (%s), want 400 naming the entry", bad, w.Code, w.Body)
		}
		if n := len(s.store.Profile().RoutingLists); n != 0 {
			t.Errorf("%q: the refused list was stored", bad)
		}
	}

	s, _ := sharehandlers_server(t)
	if w := post(s, `{"id":"l","name":"L","manual":["a.a","192.0.2.0/24","2001:db8::/32","# see https://example.com/x"],"outbound":"direct","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("prefixes and a comment = %d (%s), want 200", w.Code, w.Body)
	}

	// A list saved before this check keeps its entry, inert as it always was, and can still be edited:
	// only an entry the save adds is refused.
	old := model.RoutingList{ID: "old", Name: "Old", Enabled: true, Outbound: "direct", Manual: []string{"a.a", "10.0.0.0/99"}}
	if err := s.store.UpsertRoutingList(old); err != nil {
		t.Fatal(err)
	}
	if w := post(s, `{"id":"old","name":"Renamed","manual":["a.a","10.0.0.0/99"],"outbound":"direct","enabled":true}`); w.Code != http.StatusOK {
		t.Errorf("an edit that keeps a stored entry = %d (%s), want 200", w.Code, w.Body)
	}
	if w := post(s, `{"id":"old","name":"Renamed","manual":["a.a","10.0.0.0/99","10.0.0.0/88"],"outbound":"direct","enabled":true}`); w.Code != http.StatusBadRequest {
		t.Errorf("an edit that adds another = %d, want 400", w.Code)
	}
}
