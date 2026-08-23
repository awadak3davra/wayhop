package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestApply_NoCoreDoesNotFakeSuccess pins the "applied with no engine" bug from the other side:
// in NON-demo mode with no sing-box binary present, a configuration that needs the core is refused
// as BLOCKED with the core.unavailable finding — never accepted and reported as applied over a
// config nothing runs. pbrApplyServer builds exactly this world (Demo=false, sing-box unavailable);
// "mixed" mode keeps it off the native-only path so the core is required.
func TestApply_NoCoreDoesNotFakeSuccess(t *testing.T) {
	s, _ := pbrApplyServer(t)
	s.cfg.RoutingMode = "mixed" // non-hybrid + sing-box endpoint => the core is required
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("apply: got %d, want 422 BLOCKED (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Code     string    `json:"code"`
		Error    string    `json:"error"`
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Code != applyCodeBlocked {
		t.Errorf("code = %q, want %q", resp.Code, applyCodeBlocked)
	}
	found := false
	for _, f := range resp.Findings {
		if f.ID == "core.unavailable" && f.Blocks == "apply" {
			found = true
		}
	}
	if !found {
		t.Errorf("findings = %+v, want core.unavailable as a hard blocker", resp.Findings)
	}
	if resp.Error == "" {
		t.Error("a refusal must say why")
	}
	// Nothing was applied: the record stays empty.
	if s.appliedBaseline() != nil {
		t.Error("a refused Apply must not advance the record")
	}
}
