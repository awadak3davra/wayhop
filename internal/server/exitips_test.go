package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/util"
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
	ip, probed := s.resolveExitIP(context.TODO(), e, &exitFacts{})
	if ip != "1.2.3.4" || probed {
		t.Errorf("resolveExitIP = (%q, %v), want (1.2.3.4, false) on the non-linux stub", ip, probed)
	}
}

// TestResolveExitIP_FallsBackToLivePeer: an external tunnel adopted by hand carries neither a
// Server nor an endpoint_ip, so before the peer fallback its tile had no address and was dropped
// from the grid entirely (which is how a wrong probe result went unnoticed — the WAN IP was the
// only thing the tile ever showed). The live wg/awg peer stands in.
func TestResolveExitIP_FallsBackToLivePeer(t *testing.T) {
	s := opshandlers_server(t)
	e := &model.Endpoint{ID: "external-awg0", Name: "awg0 (native)", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}}
	f := &exitFacts{peersDone: true, peers: map[string]string{"awg0": "198.51.100.20"}}
	ip, probed := s.resolveExitIP(context.TODO(), e, f)
	if ip != "198.51.100.20" || probed {
		t.Errorf("resolveExitIP = (%q, %v), want (198.51.100.20, false) from the live peer", ip, probed)
	}
}

// fakeProbe swaps the per-egress probe for the duration of a test and records the (iface, mark)
// pairs it was called with, so the ordering and the discard rule can be asserted off-router.
func fakeProbe(t *testing.T, answer func(iface string, mark int) string) *[]string {
	t.Helper()
	var calls []string
	prev := probeIface
	probeIface = func(_ context.Context, iface string, mark int) string {
		calls = append(calls, fmt.Sprintf("%s/%#x", iface, mark))
		return answer(iface, mark)
	}
	t.Cleanup(func() { probeIface = prev })
	return &calls
}

// TestProbeEgressIP_BypassMarkFirst: the engine's transparent redirect is the normal state on a
// gateway router, so the marked attempt must come first — an unmarked probe there is answered by
// the engine, not by the tunnel.
func TestProbeEgressIP_BypassMarkFirst(t *testing.T) {
	calls := fakeProbe(t, func(_ string, mark int) string {
		if mark == engineBypassMark {
			return "198.51.100.20"
		}
		return "203.0.113.9"
	})
	if ip := probeEgressIP(context.TODO(), "awg0", "203.0.113.1"); ip != "198.51.100.20" {
		t.Errorf("probeEgressIP = %q, want the marked answer 198.51.100.20", ip)
	}
	if len(*calls) != 1 || (*calls)[0] != fmt.Sprintf("awg0/%#x", engineBypassMark) {
		t.Errorf("calls = %v, want a single awg0 probe carrying the bypass mark", *calls)
	}
}

// TestProbeEgressIP_RetriesUnmarked: where nothing redirects local traffic the mark can only hit
// some other rule, so a marked probe that yields nothing must be retried plain.
func TestProbeEgressIP_RetriesUnmarked(t *testing.T) {
	calls := fakeProbe(t, func(_ string, mark int) string {
		if mark == 0 {
			return "198.51.100.31"
		}
		return ""
	})
	if ip := probeEgressIP(context.TODO(), "awg1", "203.0.113.1"); ip != "198.51.100.31" {
		t.Errorf("probeEgressIP = %q, want the unmarked retry 198.51.100.31", ip)
	}
	if len(*calls) != 2 {
		t.Errorf("calls = %v, want the marked attempt then the plain one", *calls)
	}
}

// TestProbeEgressIP_DiscardsWANAnswer is the defect this guard exists for: a probe swallowed by
// the engine's redirect comes back with the ROUTER'S OWN exit, and presenting that as the
// tunnel's exit tells the user their traffic leaves through the address the tunnel exists to
// replace. No answer at all is the honest result — the caller then shows the server address.
func TestProbeEgressIP_DiscardsWANAnswer(t *testing.T) {
	calls := fakeProbe(t, func(string, int) string { return "203.0.113.1" })
	if ip := probeEgressIP(context.TODO(), "awg0", "203.0.113.1"); ip != "" {
		t.Errorf("probeEgressIP = %q, want \"\" — the WAN exit is not awg0's exit", ip)
	}
	if len(*calls) != 2 {
		t.Errorf("calls = %v, want both attempts tried before giving up", *calls)
	}
}

// TestProbeEgressIP_NoBaseline: an unmeasurable WAN baseline disables the guard rather than the
// probe — the grid keeps reporting measured exits, it just cannot cross-check them.
func TestProbeEgressIP_NoBaseline(t *testing.T) {
	fakeProbe(t, func(string, int) string { return "203.0.113.1" })
	if ip := probeEgressIP(context.TODO(), "awg0", ""); ip != "203.0.113.1" {
		t.Errorf("probeEgressIP = %q, want the probed answer when there is no baseline to reject it", ip)
	}
}

// exitips_coreUp points the Clash controller at a stub that answers /version, so coreUp reads a live
// core and resolveExitIP goes on to the per-egress probe.
func exitips_coreUp(t *testing.T, s *Server) {
	t.Helper()
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"sing-box"}`))
	}))
	t.Cleanup(ctrl.Close)
	s.cfg.Clash.Controller = ctrl.Listener.Addr().String()
	if !s.coreUp() {
		t.Fatal("test setup broken: the stub controller does not read as a live core")
	}
}

// exitips_facts is one refresh's facts as the handler builds them, with the router's own exit already
// measured and no live peers, so the only probes left are the ones bound to a tunnel and nothing
// asks this host's wg/awg for its tunnels.
func exitips_facts(s *Server) *exitFacts {
	f := s.newExitFacts()
	f.wanIP, f.wanDone = "203.0.113.1", true
	f.peers, f.peersDone = map[string]string{}, true
	return f
}

// With no native plan applied a tunnel's device comes from the profile, as the health monitor reads
// it: the interface an adopted tunnel records, and for an AmneziaWG endpoint WayHop manages (imported
// from a .conf) the name derived from its id. The grid read only the recorded interface, so the
// managed tunnel was never probed and its tile showed the server address. A sing-box proxy has no
// device, and its server address stands, unprobed.
func TestResolveExitIP_ProfileDeviceWithoutAPlan(t *testing.T) {
	s, _ := applytest_server(t)
	exitips_coreUp(t, s)
	derived := util.AWGIface("imported")
	exits := map[string]string{derived: "198.51.100.41", "awg0": "198.51.100.42"}
	var devices []string
	fakeProbe(t, func(iface string, _ int) string {
		devices = append(devices, iface)
		return exits[iface]
	})
	f := exitips_facts(s)
	for _, c := range []struct {
		e        model.Endpoint
		link, ip string
	}{
		{model.Endpoint{ID: "imported", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "192.0.2.10"}, derived, "198.51.100.41"},
		{model.Endpoint{ID: "adopted", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}}, "awg0", "198.51.100.42"},
		{model.Endpoint{ID: "proxy", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "192.0.2.30"}, "", "192.0.2.30"},
	} {
		devices = nil
		ip, probed := s.resolveExitIP(context.TODO(), &c.e, f)
		if got := strings.Join(devices, ","); ip != c.ip || probed != (c.link != "") || got != c.link {
			t.Errorf("%s: (%q, %v) after probing %q, want %s through %q", c.e.ID, ip, probed, got, c.ip, c.link)
		}
	}
}

// An applied native plan names the device, not the editable profile. An adopted tunnel whose
// interface was edited and not yet applied is probed through the one the plan bound, and on a
// Keenetic a created tunnel is probed through the kernel link of its NDM name (Wireguard2 -> nwg2),
// where the profile would have derived a wr_* name the router does not have.
func TestResolveExitIP_AppliedBindingWins(t *testing.T) {
	s, _ := applytest_server(t)
	exitips_coreUp(t, s)
	m := applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)
	m.Native.Delta.Reconcile.Platform = platform.Keenetic
	m.Native.Delta.Reconcile.Target.Platform = platform.Keenetic
	m.Native.Delta.Reconcile.Target.Decisions = []nativeplan.EndpointDecision{
		{EndpointID: "adopted", Path: nativeplan.PathNativeAdopt, Interface: "nwg0"},
		{EndpointID: "managed", Path: nativeplan.PathNativeCreate, Interface: "Wireguard2"},
	}
	s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: *m})
	exits := map[string]string{"nwg0": "198.51.100.43", "nwg2": "198.51.100.44"}
	var devices []string
	fakeProbe(t, func(iface string, _ int) string {
		devices = append(devices, iface)
		return exits[iface]
	})
	f := exitips_facts(s)
	for _, c := range []struct {
		e        model.Endpoint
		link, ip string
	}{
		{model.Endpoint{ID: "adopted", Engine: model.EngineExternal, Params: map[string]any{"interface": "nwg5"}}, "nwg0", "198.51.100.43"},
		{model.Endpoint{ID: "managed", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "192.0.2.20"}, "nwg2", "198.51.100.44"},
	} {
		devices = nil
		ip, probed := s.resolveExitIP(context.TODO(), &c.e, f)
		if got := strings.Join(devices, ","); ip != c.ip || !probed || got != c.link {
			t.Errorf("%s: (%q, %v) after probing %q, want %s through %q", c.e.ID, ip, probed, got, c.ip, c.link)
		}
	}
}

// An empty applied binding is an answer, not a gap for the profile to fill. An endpoint the applied
// plan gives no device (the core carries it, or, as here, it was enabled after the last Apply) is not
// probed through the interface an adopted tunnel records or the name derived for an AmneziaWG
// endpoint, since the plan brought neither up. Its tile shows the server address.
func TestResolveExitIP_EmptyBindingProbesNothing(t *testing.T) {
	s, _ := applytest_server(t)
	exitips_coreUp(t, s)
	m := applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)
	m.Native.Delta.Reconcile.Target.Decisions = []nativeplan.EndpointDecision{
		{EndpointID: "proxy", Path: nativeplan.PathCompatibility},
	}
	s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: *m})
	var devices []string
	fakeProbe(t, func(iface string, _ int) string {
		devices = append(devices, iface)
		return "198.51.100.45"
	})
	f := exitips_facts(s)
	for _, c := range []struct {
		e  model.Endpoint
		ip string
	}{
		{model.Endpoint{ID: "imported", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "192.0.2.21"}, "192.0.2.21"},
		{model.Endpoint{ID: "adopted", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg3", "endpoint_ip": "192.0.2.22"}}, "192.0.2.22"},
	} {
		devices = nil
		ip, probed := s.resolveExitIP(context.TODO(), &c.e, f)
		if ip != c.ip || probed || len(devices) != 0 {
			t.Errorf("%s: (%q, %v) after probing %q, want the server address %s and no probe", c.e.ID, ip, probed, devices, c.ip)
		}
	}

	// An adopted tunnel that records no server address falls back to its live peer, read by the
	// device the profile names: the empty binding stops the probe, not the lookup, or the tile would
	// drop from the grid.
	f.peers = map[string]string{"awg4": "192.0.2.23"}
	devices = nil
	bare := model.Endpoint{ID: "bare", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg4"}}
	if ip, probed := s.resolveExitIP(context.TODO(), &bare, f); ip != "192.0.2.23" || probed || len(devices) != 0 {
		t.Errorf("bare: (%q, %v) after probing %q, want the live peer 192.0.2.23 and no probe", ip, probed, devices)
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
