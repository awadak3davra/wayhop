package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func TestExitName(t *testing.T) {
	if got := exitName(&model.Endpoint{Name: "NL", ID: "nl-1"}); got != "NL" {
		t.Errorf("exitName = %q, want NL", got)
	}
	if got := exitName(&model.Endpoint{ID: "nl-1"}); got != "nl-1" {
		t.Errorf("exitName fallback = %q, want nl-1 (the id)", got)
	}
}

func TestEndpointServerIP(t *testing.T) {
	if got := endpointServerIP(&model.Endpoint{Server: "1.2.3.4"}); got != "1.2.3.4" {
		t.Errorf("server = %q, want 1.2.3.4", got)
	}
	// An EngineExternal tunnel binds an iface and records the peer endpoint_ip instead of a Server.
	ext := &model.Endpoint{Engine: model.EngineExternal, Params: map[string]any{"endpoint_ip": "203.0.113.7"}}
	if got := endpointServerIP(ext); got != "203.0.113.7" {
		t.Errorf("external server = %q, want the endpoint_ip 203.0.113.7", got)
	}
	if got := endpointServerIP(&model.Endpoint{}); got != "" {
		t.Errorf("no server/endpoint_ip must yield \"\", got %q", got)
	}
}

func TestKernelIfaceOf(t *testing.T) {
	ext := &model.Endpoint{Engine: model.EngineExternal, Params: map[string]any{"interface": "awg1"}}
	if got := kernelIfaceOf(ext); got != "awg1" {
		t.Errorf("iface = %q, want awg1", got)
	}
	// A sing-box VLESS outbound has no kernel interface — the grid falls back to its server IP.
	if got := kernelIfaceOf(&model.Endpoint{Engine: model.EngineSingBox, Server: "1.2.3.4"}); got != "" {
		t.Errorf("sing-box endpoint must have no kernel iface, got %q", got)
	}
}

func TestValidExitIP(t *testing.T) {
	if validExitIP("  203.0.113.10\n") != "203.0.113.10" {
		t.Error("a trimmed valid IP must pass")
	}
	if validExitIP("not-an-ip") != "" {
		t.Error("garbage must be rejected")
	}
}

// TestResolveExitIP_FallsBackToServer: off Linux (the dev build's stub probe returns "") the exit
// grid must fall back to the endpoint's server IP with probed=false.
func TestResolveExitIP_FallsBackToServer(t *testing.T) {
	s := opshandlers_server(t)
	e := &model.Endpoint{ID: "nl", Name: "NL", Engine: model.EngineExternal, Server: "1.2.3.4", Params: map[string]any{"interface": "awg1"}}
	ip, probed := s.resolveExitIP(context.TODO(), e)
	if ip != "1.2.3.4" || probed {
		t.Errorf("resolveExitIP = (%q, %v), want (1.2.3.4, false) on the non-linux stub", ip, probed)
	}
}

// TestExitIPs_DemoSynthetic: in demo the exit grid serves a synthetic set of tiles (so the dashboard
// renders off-router) whose IPs are all RFC-5737 documentation addresses — never real exit data.
func TestExitIPs_DemoSynthetic(t *testing.T) {
	s := opshandlers_server(t)
	s.cfg.Demo = true
	req := httptest.NewRequest(http.MethodGet, "/api/exit-ips", nil)
	w := httptest.NewRecorder()
	s.handleExitIPs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var resp struct {
		Available bool `json:"available"`
		Exits     []struct {
			ID string `json:"id"`
			IP string `json:"ip"`
		} `json:"exits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Available || len(resp.Exits) == 0 {
		t.Fatalf("demo exit grid = {available:%v, %d exits}, want available with synthetic tiles", resp.Available, len(resp.Exits))
	}
	// Every synthetic IP must be a documentation address (TEST-NET-2/3) — a real-looking IP here would
	// mean the demo path leaked into a screenshot-facing endpoint.
	for _, e := range resp.Exits {
		if !strings.HasPrefix(e.IP, "203.0.113.") && !strings.HasPrefix(e.IP, "198.51.100.") {
			t.Errorf("exit %q ip %q is not an RFC-5737 documentation address", e.ID, e.IP)
		}
	}
}
