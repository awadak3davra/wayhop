package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestApply_NoCoreDoesNotFakeSuccess pins the fix for the "applied_ok=true with no engine" bug:
// in NON-demo, non-native-only mode with no sing-box binary present, Apply writes the config but
// nothing runs it, so the response must report applied_ok=false (not a fake success) and surface a
// reload_error — otherwise the UI toasts "Applied" and clears "pending" for a config no engine
// reflects. pbrApplyServer already builds exactly this world (Demo=false, sing-box unavailable);
// "mixed" mode keeps it off the native-only path so the sing-box reload chain is exercised.
func TestApply_NoCoreDoesNotFakeSuccess(t *testing.T) {
	s, _ := pbrApplyServer(t)
	s.cfg.RoutingMode = "mixed" // non-hybrid + sing-box endpoint => not native-only
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("apply: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}

	if resp["applied_ok"] != false {
		t.Errorf("applied_ok = %v, want false — no sing-box core to run the written config", resp["applied_ok"])
	}
	if resp["reloaded"] != false {
		t.Errorf("reloaded = %v, want false (nothing was reloaded/started)", resp["reloaded"])
	}
	if resp["checked"] != false {
		t.Errorf("checked = %v, want false (no core to CheckConfig)", resp["checked"])
	}
	if re, _ := resp["reload_error"].(string); re == "" {
		t.Errorf("reload_error should be present (core missing), got %v", resp["reload_error"])
	}
}
