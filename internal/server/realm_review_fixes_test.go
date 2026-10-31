package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// A Hysteria2 pin an older WayHop kept in the legacy parameter as the link held it: one that is not a
// SHA-256 hash can be checked by no core, so it is ignored, and the review says so in its own finding
// whatever the core, certificate checks on or off. Nothing is blocked, and nothing is said without a
// pin. (pin_finding_test.go covers the pins a core leaves out by version.)
func TestEndpointFindings_UnenforceablePin(t *testing.T) {
	s, _ := sharehandlers_server(t)
	hy := func(id string, insecure bool, pin string) model.Endpoint {
		p := map[string]any{"password": "pw"}
		if pin != "" {
			p[model.ParamLegacyPin] = pin
		}
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "192.0.2.4", Port: 443, TLS: &model.TLS{Enabled: true, Type: "tls", Insecure: insecure}, Params: p}
	}
	prof := model.Profile{Endpoints: []model.Endpoint{hy("pinned", true, "deadbeef"), hy("checked", false, "deadbeef"), hy("nopin", true, "")}}
	got := map[string]PlanFinding{}
	for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
		if strings.HasPrefix(f.ID, "endpoint.tls.pin") {
			got[f.Item] = f
		}
	}
	if f, ok := got["pinned"]; !ok || f.ID != "endpoint.tls.pin.invalid" || f.Blocks != platform.BlocksNothing || f.Severity != platform.SeverityDegraded {
		t.Errorf("pinned + insecure: finding = %+v (present %v), want a degraded, non-blocking one", f, ok)
	}
	if f, ok := got["checked"]; !ok || f.ID != "endpoint.tls.pin.invalid" || f.Blocks != platform.BlocksNothing {
		t.Errorf("pinned, checks on: finding = %+v (present %v)", f, ok)
	}
	if len(got) != 2 {
		t.Errorf("findings for %v, want only the two pinned connections", got)
	}
}

// A Server left over beside a realm is not where the connection goes: the exit-IP view must not report
// it (the health check and the bypass list read the same ServerAddress).
func TestRealmConnectionHasNoServerAddress(t *testing.T) {
	e := model.Endpoint{Protocol: model.ProtoHysteria2, Server: "192.0.2.4", Port: 8443,
		Params: map[string]any{"realm": "realm://tok@rendezvous.example.com/my-cabin-1f3a8c2e9b"}}
	if got := e.ServerAddress(); got != "" {
		t.Errorf("ServerAddress = %q, want none for a realm connection", got)
	}
	if got := endpointServerIP(&e); got != "" {
		t.Errorf("endpointServerIP = %q, want none for a realm connection", got)
	}
	plain := model.Endpoint{Protocol: model.ProtoHysteria2, Server: "192.0.2.4", Port: 8443}
	if got := plain.ServerAddress(); got != "192.0.2.4" {
		t.Errorf("plain ServerAddress = %q", got)
	}
}
