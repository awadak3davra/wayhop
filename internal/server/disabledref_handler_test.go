package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"wayhop/internal/model"
)

// The panel is where this was invisible: switching an exit off is one click, it answered 200, and the
// next Apply — any Apply — failed with a message about a rule the operator was not editing.
func TestDisabledRefHandler_SwitchingOffAnExitInUseIsRefusedAtTheClick(t *testing.T) {
	s := dnsSeed(t)
	ep := profilehandlers_endpoint("x1", "x1")
	if err := s.store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "r", Outbound: "x1", Domain: []string{"a.example"}}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ep.Enabled = false
	body, err := json.Marshal(ep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := profilehandlers_post(s.handleUpsertEndpoint, string(body))
	if w.Code == http.StatusOK {
		t.Fatal("the panel answered 200 and broke every later Apply")
	}
	// The refusal is not the end of the answer. Deleting an exit in use has long replied 409 with the
	// dependents and the outbounds they could move to, so the panel can offer a way through instead of
	// a dead end; switching one off asks the same question of the same objects and now replies the
	// same way. A bare 400 here is what left the operator clicking a switch that would not move.
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409 (%s)", w.Code, w.Body.String())
	}
	var refusal struct {
		Code         string              `json:"code"`
		Error        string              `json:"error"`
		Dependents   []map[string]string `json:"dependents"`
		Replacements []string            `json:"replacements"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("invalid refusal JSON: %v (%s)", err, w.Body.String())
	}
	if refusal.Code != "ENDPOINT_IN_USE" || refusal.Error == "" {
		t.Errorf("refusal does not name itself: %s", w.Body.String())
	}
	if len(refusal.Dependents) == 0 {
		t.Errorf("refusal names no dependent, so the panel has nothing to show: %s", w.Body.String())
	}
	if len(refusal.Replacements) == 0 {
		t.Errorf("refusal offers nowhere to move them, which is the dead end it exists to remove: %s", w.Body.String())
	}
	for _, e := range s.store.Profile().Endpoints {
		if e.ID == "x1" && !e.Enabled {
			t.Error("the exit was switched off despite the refusal")
		}
	}
}
