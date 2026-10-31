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
	"wayhop/internal/platform"
)

// QUIC tuning on a pre-1.14 core is left out of the shared config (1.13 refuses the keys at decode),
// so the connection comes up untuned: the review names it as degraded and blocking nothing, and the
// connection check says so. A 1.14 core has nothing to say, and neither has a connection without it.
func TestEndpointFindings_QUICTuningOnAnOlderCore(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.13.21\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	tuned := model.Endpoint{ID: "tu", Name: "Tuned TUIC", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
		Server: "192.0.2.6", Port: 8443, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "tuic.example.com"},
		Params: map[string]any{"uuid": "2dd61d93-75d8-4da4-ac0e-6aece7eac365", "password": "pw",
			model.ParamQUICInitialPacketSize: 1232, model.ParamQUICDisablePMTUD: true}}
	plain := model.Endpoint{ID: "hy", Name: "Plain", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		Server: "192.0.2.7", Port: 8443, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"},
		Params: map[string]any{"password": "pw"}}
	prof := model.Profile{Endpoints: []model.Endpoint{tuned, plain}}

	findings := func() []PlanFinding {
		var out []PlanFinding
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if f.ID == "endpoint.quic.tuning" {
				out = append(out, f)
			}
		}
		return out
	}
	fs := findings()
	if len(fs) != 1 || fs[0].Severity != platform.SeverityDegraded || fs[0].Blocks != platform.BlocksNothing ||
		fs[0].Reason != platform.ReasonBinaryTooOld || fs[0].Item != "Tuned TUIC" {
		t.Fatalf("1.13 core: findings = %+v, want one degraded finding blocking nothing, naming the tuned connection", fs)
	}

	if err := s.store.UpsertEndpoint(tuned); err != nil {
		t.Fatal(err)
	}
	check := func() map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints/tu/check", nil)
		r.SetPathValue("id", "tu")
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
	if fs := findings(); len(fs) != 0 {
		t.Fatalf("1.14 core: unexpected findings %+v", fs)
	}
	if out := check(); out["error"] != nil && strings.Contains(out["error"].(string), "QUIC") {
		t.Errorf("1.14 core: check still refuses the QUIC tuning: %v", out)
	}
}
