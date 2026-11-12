package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/dnscheck"
	"wayhop/internal/model"
	"wayhop/internal/nativedns"
)

const dnsCheckCanaryFlow = "ipv4 2 udp 17 29 src=192.0.2.2 dst=1.1.1.1 sport=51742 dport=53 packets=1 bytes=68 src=1.1.1.1 dst=192.0.2.2 sport=53 dport=51742 packets=1 bytes=84 mark=0 use=2\n"

type dnsCheckFakeRouter struct {
	mu         sync.Mutex
	snapshots  []string
	reads      int
	unreadable bool
}

func (f *dnsCheckFakeRouter) run(name string, args ...string) (string, error) {
	joined := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "/proc/net/nf_conntrack"):
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.unreadable {
			return "", errors.New("no conntrack")
		}
		i := f.reads
		if i >= len(f.snapshots) {
			i = len(f.snapshots) - 1
		}
		f.reads++
		if i < 0 {
			return "", nil
		}
		return f.snapshots[i], nil
	case name == "conntrack":
		return "", errors.New("no conntrack")
	case name == "sh" && strings.Contains(joined, "ps 2>/dev/null"):
		return "", nil
	case name == "sh":
		return "no-resolv\nstrict-order\nserver=1.1.1.1@nwg1\nserver=1.0.0.1\n", nil
	case name == "netstat":
		return "udp 0 0 0.0.0.0:53 0.0.0.0:* 951/dnsmasq\n", nil
	case name == "cat" && len(args) == 1 && args[0] == "/etc/resolv.conf":
		return "nameserver 203.0.113.53\n", nil
	case name == "ip" && strings.Contains(joined, "-o addr"):
		return "1: lo inet 127.0.0.1/8\n2: eth3 inet 203.0.113.10/24\n5: nwg1 inet 192.0.2.2/32\n", nil
	default:
		return "", nil
	}
}

type dnsCheckFakeNet struct{ calls atomic.Int64 }

func (n *dnsCheckFakeNet) UDP(context.Context, dnscheck.Path, string, []byte, time.Duration) ([]dnscheck.Reply, error) {
	n.calls.Add(1)
	return nil, nil
}
func (n *dnsCheckFakeNet) DoT(context.Context, dnscheck.Path, string, string, []byte) ([]byte, string, error) {
	n.calls.Add(1)
	return nil, "", nil
}
func (n *dnsCheckFakeNet) DoH(context.Context, dnscheck.Path, string, []byte) ([]byte, string, error) {
	n.calls.Add(1)
	return nil, "", nil
}
func (n *dnsCheckFakeNet) Cert(context.Context, dnscheck.Path, string, string) dnscheck.CertResult {
	n.calls.Add(1)
	return dnscheck.CertNoConn
}

func newDNSCheckTestServer(t *testing.T) (*Server, *dnsCheckFakeRouter) {
	t.Helper()
	profile := model.Profile{
		Endpoints: []model.Endpoint{adopted("vpn2", "nwg2", true), adopted("vpn1", "nwg1", true)},
		Groups:    []model.Group{{ID: "main", Name: "Main", Members: []string{"vpn1", "vpn2"}}},
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "main"}},
	}
	s := bindTestServer(t, profile, "")
	runner := &dnsCheckFakeRouter{snapshots: []string{"", dnsCheckCanaryFlow}}
	s.dnsPlatformOf = func() string { return "keenetic" }
	s.dnsRunnerOf = runner.run
	s.dnsCheckProbeOf = func(context.Context, string, []byte) error { return nil }
	s.dnsCheckWaitOf = func(context.Context, time.Duration) error { return nil }
	s.dnsCheckRandomOf = func() string { return "0123456789abcdef" }
	s.dnsCheckWANOf = func() (string, error) { return "eth3", nil }
	s.dnsCheckIfaceExistsOf = func(string) bool { return true }
	return s, runner
}

func getDNSCheckState(t *testing.T, s *Server) (int, dnscheck.State) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleDNSCheckState(w, httptest.NewRequest(http.MethodGet, "/api/dns/check", nil))
	var state dnscheck.State
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return w.Code, state
}

func waitForDNSCheckReport(t *testing.T, s *Server) dnscheck.Report {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, state := getDNSCheckState(t, s)
		if !state.Running && state.Report != nil {
			return *state.Report
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("DNS check did not finish")
	return dnscheck.Report{}
}

func TestDNSCheckJobAcceptedConflictAndReport(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	net := &dnsCheckFakeNet{}
	var factoryCalls atomic.Int64
	s.dnsCheckNetOf = func() dnscheck.Net { factoryCalls.Add(1); return net }
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.dnsCheckWaitOf = func(ctx context.Context, _ time.Duration) error {
		once.Do(func() {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		return nil
	}

	w := postJSON(t, s.handleDNSCheckStart, dnscheck.Request{Full: false})
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d, body %s", w.Code, w.Body.String())
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}
	if conflict := postJSON(t, s.handleDNSCheckStart, dnscheck.Request{}); conflict.Code != http.StatusConflict {
		t.Fatalf("second POST status = %d, want 409", conflict.Code)
	}
	_, running := getDNSCheckState(t, s)
	if !running.Running || running.Progress.Stage != "path" || running.Progress.Total != 1 {
		t.Fatalf("running state = %#v", running)
	}
	close(release)
	report := waitForDNSCheckReport(t, s)
	if !report.Path.Measured || report.Path.SampleSec != 10 || report.Level != dnscheck.LevelTunnelPlain ||
		report.Path.Exposure != dnscheck.ExposureExit {
		t.Fatalf("report path = %#v, level %s", report.Path, report.Level)
	}
	if len(report.Path.Upstreams) != 2 || !report.Path.Upstreams[1].LastResort {
		t.Fatalf("upstreams = %#v", report.Path.Upstreams)
	}
	if len(report.Path.Flows) != 1 || !report.Path.Flows[0].FromCanary || report.Path.Flows[0].Kind != dnscheck.PathTunnel {
		t.Fatalf("flows = %#v", report.Path.Flows)
	}
	if factoryCalls.Load() != 0 || net.calls.Load() != 0 {
		t.Fatalf("path-only check created or used Net: factory %d, calls %d", factoryCalls.Load(), net.calls.Load())
	}
}

func TestDNSCheckCancelledContextEnds(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	started := make(chan struct{})
	var once sync.Once
	s.dnsCheckWaitOf = func(ctx context.Context, _ time.Duration) error {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runDNSCheck(ctx, dnscheck.Request{})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("check did not reach its wait")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled check is still running")
	}
	_, state := getDNSCheckState(t, s)
	if state.Running || state.Report == nil {
		t.Fatalf("state after cancellation = %#v", state)
	}
}

func TestDNSCheckExtraNamesValidation(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	tests := []struct {
		name string
		req  dnscheck.Request
	}{
		{name: "too many", req: dnscheck.Request{ExtraNames: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}}},
		{name: "option injection", req: dnscheck.Request{ExtraNames: []string{"-f"}}},
		{name: "space", req: dnscheck.Request{ExtraNames: []string{"bad name"}}},
		{name: "empty", req: dnscheck.Request{ExtraNames: []string{""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if w := postJSON(t, s.handleDNSCheckStart, tt.req); w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	s.handleDNSCheckStart(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", w.Code)
	}
}

func TestDNSCheckUnreadableConntrackFallsBackToConfig(t *testing.T) {
	s, runner := newDNSCheckTestServer(t)
	runner.unreadable = true
	s.runDNSCheck(context.Background(), dnscheck.Request{})
	_, state := getDNSCheckState(t, s)
	if state.Report == nil || state.Report.Path.Measured {
		t.Fatalf("unreadable table produced a measured report: %#v", state.Report)
	}
	if state.Report.Level != dnscheck.LevelTunnelPlain || len(state.Report.Path.Flows) != 0 {
		t.Fatalf("configuration fallback = %#v", state.Report)
	}
	if len(state.Report.Warnings) == 0 {
		t.Fatal("unreadable table was presented as a clean result")
	}
}

func TestDNSCheckOffRouterIsUnknownWithoutNet(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	s.dnsPlatformOf = func() string { return "" }
	var calls atomic.Int64
	s.dnsCheckNetOf = func() dnscheck.Net { calls.Add(1); return &dnsCheckFakeNet{} }
	s.runDNSCheck(context.Background(), dnscheck.Request{Full: true})
	_, state := getDNSCheckState(t, s)
	if state.Report.Level != dnscheck.LevelUnknown || len(state.Report.Warnings) != 1 ||
		state.Report.Warnings[0].ID != dnscheck.WarnNotMeasured || calls.Load() != 0 {
		t.Fatalf("off-router report = %#v, Net factories %d", state.Report, calls.Load())
	}
}

func TestDNSCheckPathsAndTargets(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	prof := s.store.Profile()
	paths := s.dnsCheckPaths(&prof)
	if len(paths) != 3 || paths[0].Kind != dnscheck.PathWAN || paths[1].Iface != "nwg1" || paths[2].Iface != "nwg2" {
		t.Fatalf("paths = %#v", paths)
	}
	for i := 3; i <= 6; i++ {
		id := "vpn" + strconv.Itoa(i)
		prof.Endpoints = append(prof.Endpoints, adopted(id, "nwg"+strconv.Itoa(i), true))
	}
	if limited := s.dnsCheckPaths(&prof); len(limited) != 5 || limited[4].Iface != "nwg4" {
		t.Fatalf("paths exceeded five or lost primary order: %#v", limited)
	}
	nd := nativedns.NativeDNS{Resolvers: []nativedns.NativeResolver{
		{Address: "9.9.9.9", Kind: nativedns.KindPlain, Iface: "nwg1"},
		{Address: "1.0.0.1", Kind: nativedns.KindPlain},
		{Address: "127.0.0.1#5353", Kind: nativedns.KindLocal},
	}}
	targets := dnsCheckTargets(nd, paths[:2], "127.0.0.1:53")
	seen := map[string]bool{}
	router := 0
	for _, target := range targets {
		key := target.Address + "/" + target.Path.Iface + "/" + string(target.Path.Kind)
		if seen[key] {
			t.Errorf("duplicate target %#v", target)
		}
		seen[key] = true
		if target.Path.Kind == dnscheck.PathRouter {
			router++
		}
	}
	if router != 1 || len(targets) != 8 {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestDNSCheckProofPathAndRouterHidden(t *testing.T) {
	wan := dnscheck.Path{Kind: dnscheck.PathWAN, Iface: "eth3"}
	first := dnscheck.Path{Kind: dnscheck.PathTunnel, Iface: "nwg1"}
	second := dnscheck.Path{Kind: dnscheck.PathTunnel, Iface: "nwg2"}
	proof := dnsCheckProofPath([]dnscheck.Interception{
		{Path: wan, Status: dnscheck.StatusPass},
		{Path: first, Status: dnscheck.StatusFail, Intercepted: true},
		{Path: second, Status: dnscheck.StatusNoData},
	})
	if proof == nil || proof.Iface != "nwg2" {
		t.Fatalf("proof path = %#v", proof)
	}
	path := dnscheck.PathReport{Measured: true}
	if !dnsCheckRouterHidden(dnscheck.LevelTunnelEncrypted, path) {
		t.Fatal("measured encrypted tunnel is not hidden")
	}
	path.Upstreams = []dnscheck.Upstream{{Address: "1.0.0.1", LastResort: true}}
	if dnsCheckRouterHidden(dnscheck.LevelTunnelPlain, path) {
		t.Fatal("last-resort row was treated as hidden")
	}
}

func TestDNSCheckCanaryNameAndQuery(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	var query []byte
	s.dnsCheckProbeOf = func(_ context.Context, addr string, q []byte) error {
		if addr != "127.0.0.1:53" {
			t.Errorf("listener address = %q", addr)
		}
		query = append([]byte(nil), q...)
		return nil
	}
	s.runDNSCheck(context.Background(), dnscheck.Request{})
	if !bytes.Contains(query, []byte("wh-0123456789abcdef-nx")) || !bytes.Contains(query, []byte("\x03com\x00")) {
		t.Fatalf("canary query does not contain unique wire-format name: %q", query)
	}
}

func TestDNSCheckDemoBranchStillServesCannedReports(t *testing.T) {
	s := &Server{cfg: &config.Config{Demo: true}}
	w := httptest.NewRecorder()
	s.handleDNSCheckState(w, httptest.NewRequest(http.MethodGet, "/?scenario=forged", nil))
	var state dnscheck.State
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Report == nil || !state.Report.Demo || state.Report.Scenario != "forged" || len(state.Scenarios) == 0 {
		t.Fatalf("demo GET = %#v", state)
	}
	post := postJSON(t, s.handleDNSCheckStart, dnscheck.Request{Full: true})
	if post.Code != http.StatusAccepted {
		t.Fatalf("demo POST status = %d", post.Code)
	}
	if err := json.Unmarshal(post.Body.Bytes(), &state); err != nil || len(state.Scenarios) == 0 {
		t.Fatalf("demo POST = %#v, %v", state, err)
	}
}

func TestDNSCheckAdviseInput_RulesUnknown(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	prof := model.Profile{}
	eff := nativedns.EffectivePath{
		RulesUnknown:     true,
		Hijack53:         false,
		DoTBypassBlocked: false,
		DoHBypassBlocked: false,
		Hijack53Gaps:     []string{"br1"},
	}
	in := dnsCheckAdviseInput(s, &prof, eff)
	if !in.InterceptOn {
		t.Errorf("RulesUnknown must set InterceptOn=true, got %v", in.InterceptOn)
	}
	if in.EncryptedEscape {
		t.Errorf("RulesUnknown must set EncryptedEscape=false, got %v", in.EncryptedEscape)
	}
	if len(in.BypassGaps) != 1 || in.BypassGaps[0] != "br1" {
		t.Errorf("BypassGaps = %v, want [br1]", in.BypassGaps)
	}
}

func TestMeasureDNSCheckPath_DropsLoopbackFromOwnResolvConf(t *testing.T) {
	s, runner := newDNSCheckTestServer(t)
	prof := model.Profile{}
	eff := nativedns.EffectivePath{
		Upstreams: []string{"127.0.0.1", "1.1.1.1", "::1", "8.8.8.8"},
	}
	path := s.measureDNSCheckPath(context.Background(), runner.run, eff, nativedns.NativeDNS{}, nil, &prof)
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(path.OwnResolvConf, want) {
		t.Fatalf("OwnResolvConf = %v, want %v", path.OwnResolvConf, want)
	}
}

func TestRunDNSCheck_PreservesPreviousFullFields(t *testing.T) {
	s, _ := newDNSCheckTestServer(t)
	// Seed previous report
	fullTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.dnsCheckMu.Lock()
	s.dnsCheckReport = &dnscheck.Report{
		Full:         true,
		FullAt:       &fullTime,
		Interception: []dnscheck.Interception{{Status: dnscheck.StatusPass}},
		Resolvers:    []dnscheck.ResolverResult{{Address: "1.1.1.1", Verdict: dnscheck.VerdictGenuine}},
		Encrypted:    []dnscheck.EncryptedResult{{Address: "1.1.1.1"}},
	}
	s.dnsCheckMu.Unlock()
	// Run shallow check (!Full)
	s.runDNSCheck(context.Background(), dnscheck.Request{Full: false})
	rep := s.dnsCheckState().Report
	if rep == nil {
		t.Fatal("expected report")
	}
	if rep.FullAt == nil || !rep.FullAt.Equal(fullTime) {
		t.Errorf("FullAt = %v, want %v", rep.FullAt, fullTime)
	}
	if len(rep.Interception) != 1 || rep.Interception[0].Status != dnscheck.StatusPass {
		t.Errorf("Interception was not preserved: %+v", rep.Interception)
	}
	if len(rep.Resolvers) != 1 || rep.Resolvers[0].Address != "1.1.1.1" {
		t.Errorf("Resolvers was not preserved: %+v", rep.Resolvers)
	}
	if len(rep.Encrypted) != 1 || rep.Encrypted[0].Address != "1.1.1.1" {
		t.Errorf("Encrypted was not preserved: %+v", rep.Encrypted)
	}
}
