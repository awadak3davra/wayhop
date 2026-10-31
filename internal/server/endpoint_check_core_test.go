package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A Hysteria2 realm on a core older than 1.14 is rendered without it, so the config checks clean
// while the connection can never come up. The Check button said "configuration is valid" (QA-059);
// it now says why it cannot work, and a 1.14 core is not held against it.
func TestEndpointCheckRefusesARealmTheCoreCannotCarry(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.13.21\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	hy := model.Endpoint{ID: "hy", Name: "Cabin", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "cabin.example.com"},
		Params: map[string]any{"password": "pw", "realm": "realm://tok@rendezvous.example.com/my-cabin-1f3a8c2e9b"}}
	if err := s.store.UpsertEndpoint(hy); err != nil {
		t.Fatal(err)
	}
	check := func() map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints/hy/check", nil)
		r.SetPathValue("id", "hy")
		w := httptest.NewRecorder()
		s.handleEndpointCheck(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if out := check(); out["ok"] != false || !strings.Contains(out["error"].(string), "sing-box 1.14") {
		t.Fatalf("1.13 core: check = %v, want a refusal naming the version it needs", out)
	}
	// A new binary is a new probe (the cache keys on size and mtime).
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.14.4\n"
	if out := check(); out["error"] != nil && strings.Contains(out["error"].(string), "sing-box 1.14") {
		t.Errorf("1.14 core: check still refuses the realm: %v", out)
	}
}
