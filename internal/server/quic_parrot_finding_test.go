package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// On a 1.14 core a Hysteria2 that parrots Chrome's QUIC handshake starts at Chrome's size whatever it
// sets. The form says so beside the field; a size that came from the API or an import is named in the
// review instead - degraded, blocking nothing - and not once the parrot is off, on TUIC, or on a 1.13
// core (which gets no size, and says so under endpoint.quic.tuning).
func TestEndpointFindings_QUICSizeReplacedByChrome(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.14.4\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	tls := &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"}
	parrot := model.Endpoint{ID: "hp", Name: "Parroting", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		Server: "192.0.2.7", Port: 8443, TLS: tls, Params: map[string]any{"password": "pw", model.ParamQUICInitialPacketSize: 1232}}
	noParrot := model.Endpoint{ID: "hn", Name: "No parrot", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		Server: "192.0.2.8", Port: 8443, TLS: tls, Params: map[string]any{"password": "pw", "disable_chrome_parrot": true,
			model.ParamQUICInitialPacketSize: 1232}}
	tuic := model.Endpoint{ID: "tu", Name: "TUIC", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
		Server: "192.0.2.9", Port: 8443, TLS: tls, Params: map[string]any{"uuid": "2dd61d93-75d8-4da4-ac0e-6aece7eac365",
			"password": "pw", model.ParamQUICInitialPacketSize: 1232}}
	prof := model.Profile{Endpoints: []model.Endpoint{parrot, noParrot, tuic}}

	findings := func() []PlanFinding {
		var out []PlanFinding
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if f.ID == "endpoint.hysteria2.quic_size_parrot" {
				out = append(out, f)
			}
		}
		return out
	}
	fs := findings()
	if len(fs) != 1 || fs[0].Item != "Parroting" || fs[0].Severity != platform.SeverityDegraded || fs[0].Blocks != platform.BlocksNothing {
		t.Fatalf("1.14 core: findings = %+v, want one degraded finding blocking nothing, naming the parroting connection", fs)
	}
	if code, title, detail, _ := findingTemplate(fs[0]); code != "QUIC_SIZE_REPLACED_BY_CHROME" || title == "" || detail == "" {
		t.Errorf("template = %q %q %q", code, title, detail)
	}
	// A new binary is a new probe (the cache keys on size and mtime).
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.13.21\n"
	if fs := findings(); len(fs) != 0 {
		t.Fatalf("1.13 core: unexpected findings %+v", fs)
	}
}
