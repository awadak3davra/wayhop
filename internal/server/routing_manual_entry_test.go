package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
