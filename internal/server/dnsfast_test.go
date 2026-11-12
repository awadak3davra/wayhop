package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"wayhop/internal/dnscheck"
	"wayhop/internal/model"
)

func newDNSFastTestServer(t *testing.T, prof model.Profile) *Server {
	t.Helper()
	s := bindTestServer(t, prof, "")
	s.dnsPlatformOf = func() string { return "keenetic" }
	s.dnsCheckWANOf = func() (string, error) { return "eth3", nil }
	s.dnsCheckIfaceExistsOf = func(iface string) bool { return true }
	return s
}

func getDNSFastState(t *testing.T, s *Server, via string) (int, dnscheck.FastState) {
	t.Helper()
	url := "/api/dns/fast"
	if via != "" {
		url += "?via=" + via
	}
	w := httptest.NewRecorder()
	s.handleDNSFastState(w, httptest.NewRequest(http.MethodGet, url, nil))
	var state dnscheck.FastState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode fast state: %v, body %s", err, w.Body.String())
	}
	return w.Code, state
}

// 9. Job: 202 then a report under that via, 409 while running, 400 for an unknown via,
// and a report for one via not shown under another. go test -race clean.
func TestDNSFastJobLifecycle(t *testing.T) {
	prof := model.Profile{
		Endpoints: []model.Endpoint{adopted("vpn1", "nwg1", true)},
	}
	s := newDNSFastTestServer(t, prof)

	// 1. POST with an unknown via -> 400
	reqBad := dnscheck.FastRequest{Via: "nonexistent-via"}
	wBad := postJSON(t, s.handleDNSFastStart, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("POST unknown via status = %d, want 400; body: %s", wBad.Code, wBad.Body.String())
	}

	// Channel to control fake measurement execution:
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	s.dnsFastMeasureOf = func(ctx context.Context, _ dnscheck.FastNet, path dnscheck.Path,
		entries []dnscheck.FastEntry, opts dnscheck.FastOptions) []dnscheck.FastResult {
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		if opts.OnProgress != nil {
			opts.OnProgress(len(entries), len(entries))
		}
		return []dnscheck.FastResult{
			{ID: "cloudflare", Alive: true, Best: "doh", Ms: 25},
		}
	}

	// 2. POST with valid via ("direct") -> 202 Accepted
	reqValid := dnscheck.FastRequest{Via: model.OutboundDirect}
	wStart := postJSON(t, s.handleDNSFastStart, reqValid)
	if wStart.Code != http.StatusAccepted {
		t.Fatalf("POST valid status = %d, want 202; body: %s", wStart.Code, wStart.Body.String())
	}

	// Wait until goroutine is running:
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dns fast measurement did not start")
	}

	// 3. Second POST while already running -> 409 Conflict
	wConflict := postJSON(t, s.handleDNSFastStart, reqValid)
	if wConflict.Code != http.StatusConflict {
		t.Fatalf("POST while running status = %d, want 409; body: %s", wConflict.Code, wConflict.Body.String())
	}

	// 4. Verify running state reported
	codeRunning, stateRunning := getDNSFastState(t, s, model.OutboundDirect)
	if codeRunning != http.StatusOK || !stateRunning.Running {
		t.Fatalf("expected Running=true, got code %d, state: %#v", codeRunning, stateRunning)
	}

	// Release measurement so it completes:
	close(release)

	// Wait for report to appear under "direct":
	deadline := time.Now().Add(2 * time.Second)
	var directReport *dnscheck.FastReport
	for time.Now().Before(deadline) {
		_, state := getDNSFastState(t, s, model.OutboundDirect)
		if !state.Running && state.Report != nil {
			directReport = state.Report
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if directReport == nil {
		t.Fatal("expected report under 'direct' within timeout, got none")
	}
	if directReport.Via != model.OutboundDirect {
		t.Errorf("report via = %q, want %q", directReport.Via, model.OutboundDirect)
	}
	if len(directReport.Results) != 1 || directReport.Results[0].ID != "cloudflare" {
		t.Errorf("unexpected report results: %#v", directReport.Results)
	}

	// 5. Report for "direct" is NOT shown under another via ("vpn1"):
	_, stateOther := getDNSFastState(t, s, "vpn1")
	if stateOther.Report != nil {
		t.Errorf("report for 'direct' leaked into 'vpn1': %#v", stateOther.Report)
	}
}

// 10. Vias and Default from a profile with a group, an endpoint, a proxy and a missing interface;
// Default never direct while a tunnel exists.
func TestDNSFastViasAndDefault(t *testing.T) {
	prof := model.Profile{
		Groups: []model.Group{
			{ID: "grp1", Name: "Failover Group", Members: []string{"ep-live"}},
		},
		Endpoints: []model.Endpoint{
			adopted("ep-live", "nwg1", true),
			adopted("ep-missing", "nwg-missing", true),
			{
				ID:       "proxy-vless",
				Engine:   model.EngineSingBox,
				Protocol: model.ProtoVLESS,
				Server:   "192.0.2.100",
				Port:     443,
				Enabled:  true,
			},
		},
	}

	s := newDNSFastTestServer(t, prof)
	s.dnsCheckWANOf = func() (string, error) { return "eth3", nil }
	s.dnsFastGroupIfaceOf = func(p *model.Profile, g *model.Group) (string, error) {
		return "nwg1", nil
	}
	s.dnsCheckIfaceExistsOf = func(iface string) bool {
		switch iface {
		case "eth3", "nwg1":
			return true
		case "nwg-missing":
			return false
		default:
			return false
		}
	}

	vias := s.dnsFastVias(&prof)

	// Verify vias:
	// - "direct" is first (Kind: WAN, Iface: "eth3")
	// - group "grp1" is present (Kind: Tunnel, Iface: "nwg1")
	// - "ep-live" is present (Kind: Tunnel, Iface: "nwg1")
	// - "ep-missing" is absent (missing interface)
	// - "proxy-vless" is absent (no kernel interface)
	if len(vias) != 3 {
		t.Fatalf("vias count = %d, want 3; vias: %#v", len(vias), vias)
	}
	if vias[0].ID != model.OutboundDirect || vias[0].Kind != dnscheck.PathWAN || vias[0].Iface != "eth3" {
		t.Errorf("vias[0] = %#v, want direct on eth3", vias[0])
	}
	if vias[1].ID != "grp1" || vias[1].Kind != dnscheck.PathTunnel || vias[1].Iface != "nwg1" {
		t.Errorf("vias[1] = %#v, want grp1 on nwg1", vias[1])
	}
	if vias[2].ID != "ep-live" || vias[2].Kind != dnscheck.PathTunnel || vias[2].Iface != "nwg1" {
		t.Errorf("vias[2] = %#v, want ep-live on nwg1", vias[2])
	}

	// Verify Default: never direct while a tunnel exists:
	// Case A: No DNS detour configured: Default must be the first tunnel ("grp1"), not direct.
	profNoDetour := prof
	defA := dnsFastDefault(&profNoDetour, vias)
	if defA != "grp1" {
		t.Errorf("default with no detour = %q, want first tunnel 'grp1'", defA)
	}

	// Case B: DNS detour explicitly set to "direct": Default must still be first tunnel ("grp1").
	profDirectDetour := prof
	profDirectDetour.DNS = &model.DNSSettings{
		Enabled: true,
		Final:   "server-direct",
		Servers: []model.DNSServer{
			{Tag: "server-direct", Type: "https", Server: "1.1.1.1", Detour: model.OutboundDirect, Enabled: true},
		},
	}
	defB := dnsFastDefault(&profDirectDetour, vias)
	if defB != "grp1" {
		t.Errorf("default with direct detour = %q, want first tunnel 'grp1'", defB)
	}

	// Case C: Default rule set to "ep-live": Default must be "ep-live".
	profTunnelDetour := prof
	profTunnelDetour.Rules = []model.Rule{
		{ID: "default", Default: true, Outbound: "ep-live"},
	}
	defC := dnsFastDefault(&profTunnelDetour, vias)
	if defC != "ep-live" {
		t.Errorf("default with tunnel detour = %q, want 'ep-live'", defC)
	}

	// Case D: Profile with only direct (no tunnels): Default is "direct".
	viasDirectOnly := []dnscheck.FastVia{
		{ID: model.OutboundDirect, Label: "Provider", Kind: dnscheck.PathWAN, Iface: "eth3"},
	}
	defD := dnsFastDefault(&prof, viasDirectOnly)
	if defD != model.OutboundDirect {
		t.Errorf("default with only direct = %q, want direct", defD)
	}
}

// Off a router (dnsPlatform() empty): Vias is empty and POST answers 409
// with a message saying this host cannot measure.
func TestDNSFastOffRouterRefuses(t *testing.T) {
	prof := model.Profile{
		Endpoints: []model.Endpoint{adopted("vpn1", "nwg1", true)},
	}
	s := bindTestServer(t, prof, "")
	s.dnsPlatformOf = func() string { return "" } // off router

	vias := s.dnsFastVias(&prof)
	if len(vias) != 0 {
		t.Errorf("off router vias = %#v, want empty", vias)
	}

	w := postJSON(t, s.handleDNSFastStart, dnscheck.FastRequest{Via: model.OutboundDirect})
	if w.Code != http.StatusConflict {
		t.Fatalf("POST off router status = %d, want 409", w.Code)
	}
	var errResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "this host cannot measure encrypted resolvers; run WayHop on a router" {
		t.Errorf("unexpected error message: %v", errResp)
	}
}
