package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"velinx/internal/config"
	"velinx/internal/core"
	"velinx/internal/failsafe"
	"velinx/internal/health"
	"velinx/internal/model"
	"velinx/internal/store"
	"velinx/internal/traffic"
	"velinx/internal/version"
)

// applyhealth_server builds a *Server with exactly the deps the apply/health/
// traffic handlers touch, all rooted in t.TempDir() so the suite stays offline
// and deterministic. It deliberately reuses the construction style of the
// existing share/ops helpers (build the struct's fields directly) rather than
// the full New() wiring. The sing-box binary path points at a file that does
// NOT exist, so core.SingBox.Available()/Running() are both false and Commit()
// is a no-op (its config file does not exist yet).
func applyhealth_server(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.SingBox.Bin = filepath.Join(dir, "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "out", "singbox.json")
	cfg.Demo = true

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}

	return &Server{
		cfg:      cfg,
		store:    st,
		singbox:  sb,
		hub:      traffic.NewHub(8),
		failsafe: failsafe.New(failsafe.DefaultDurations()),
		// monitor stays nil here; tests that need it set it explicitly so the
		// nil-monitor branches can also be exercised.
	}
}

// applyhealth_endpoint is an enabled endpoint the demo monitor will synthesize a
// health view for. The protocol/engine are irrelevant to monitor.targets(),
// which keys only off ID/Name/Enabled.
func applyhealth_endpoint(id, name string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "203.0.113.10", Port: 443, Enabled: true,
	}
}

// applyhealth_failsafeStatus decodes a failsafe.Status from a JSON body.
type applyhealth_failsafeStatus struct {
	Pending     bool   `json:"pending"`
	Phase       string `json:"phase"`
	SecondsLeft int    `json:"seconds_left"`
	LastCheckOk bool   `json:"last_check_ok"`
	LastCheckAt int64  `json:"last_check_at"`
}

// --- handleApplyStatus ------------------------------------------------------

func TestApplyHealth_ApplyStatusFreshManagerIsIdle(t *testing.T) {
	s := applyhealth_server(t)

	req := httptest.NewRequest(http.MethodGet, "/api/apply/status", nil)
	w := httptest.NewRecorder()
	s.handleApplyStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var st applyhealth_failsafeStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	// A freshly-built Manager (failsafe.New) starts idle and not pending.
	if st.Pending {
		t.Errorf("pending = true, want false for a fresh manager")
	}
	if st.Phase != "idle" {
		t.Errorf("phase = %q, want idle", st.Phase)
	}
	if st.SecondsLeft != 0 {
		t.Errorf("seconds_left = %d, want 0 when not pending", st.SecondsLeft)
	}
	if st.LastCheckAt != 0 {
		t.Errorf("last_check_at = %d, want 0 before any check", st.LastCheckAt)
	}
}

func TestApplyHealth_ApplyStatusReflectsArmedWindow(t *testing.T) {
	s := applyhealth_server(t)
	// Arm the window with inert stubs. Arm spins a goroutine that sleeps Grace
	// (20s) before doing anything, so it cannot interfere within this test.
	s.failsafe.Arm(
		func() bool { return true },
		func() error { return nil },
		func() {},
		false,
	)

	req := httptest.NewRequest(http.MethodGet, "/api/apply/status", nil)
	w := httptest.NewRecorder()
	s.handleApplyStatus(w, req)

	var st applyhealth_failsafeStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !st.Pending {
		t.Errorf("pending = false, want true while armed")
	}
	if st.Phase != "armed" {
		t.Errorf("phase = %q, want armed", st.Phase)
	}
	// KeepWindow is 3m, so seconds_left should be a positive countdown.
	if st.SecondsLeft <= 0 {
		t.Errorf("seconds_left = %d, want > 0 while armed", st.SecondsLeft)
	}
}

// --- handleApplyConfirm -----------------------------------------------------

func TestApplyHealth_ApplyConfirmCommitsAndCancelsWindow(t *testing.T) {
	s := applyhealth_server(t)
	// Put the manager into a pending/armed state first, so we can observe the
	// transition to "committed".
	s.failsafe.Arm(
		func() bool { return true },
		func() error { return nil },
		func() {},
		false,
	)

	req := httptest.NewRequest(http.MethodPost, "/api/apply/confirm", nil)
	w := httptest.NewRecorder()
	s.handleApplyConfirm(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("confirm: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Committed bool                       `json:"committed"`
		Failsafe  applyhealth_failsafeStatus `json:"failsafe"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !resp.Committed {
		t.Errorf("committed = false, want true")
	}
	// Confirm() cancels the window and marks the phase committed.
	if resp.Failsafe.Pending {
		t.Errorf("failsafe.pending = true, want false after confirm")
	}
	if resp.Failsafe.Phase != "committed" {
		t.Errorf("failsafe.phase = %q, want committed", resp.Failsafe.Phase)
	}

	// The live state queried separately must agree.
	if got := s.failsafe.Status(); got.Phase != "committed" || got.Pending {
		t.Errorf("post-confirm Status() = %+v, want committed/not-pending", got)
	}
}

// --- handleApplyRollback ----------------------------------------------------

func TestApplyHealth_ApplyRollbackTransitionsToRolledBack(t *testing.T) {
	s := applyhealth_server(t)

	req := httptest.NewRequest(http.MethodPost, "/api/apply/rollback", nil)
	w := httptest.NewRecorder()
	s.handleApplyRollback(w, req)

	// RollbackNow with no armed rollback func is a no-op that returns nil, so the
	// handler must succeed (200) rather than 500.
	if w.Code != http.StatusOK {
		t.Fatalf("rollback: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		RolledBack bool                       `json:"rolled_back"`
		Failsafe   applyhealth_failsafeStatus `json:"failsafe"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !resp.RolledBack {
		t.Errorf("rolled_back = false, want true")
	}
	if resp.Failsafe.Phase != "rolled_back" {
		t.Errorf("failsafe.phase = %q, want rolled_back", resp.Failsafe.Phase)
	}
	if resp.Failsafe.Pending {
		t.Errorf("failsafe.pending = true, want false after rollback")
	}
}

func TestApplyHealth_ApplyRollbackInvokesArmedRollbackFunc(t *testing.T) {
	s := applyhealth_server(t)
	called := false
	s.failsafe.Arm(
		func() bool { return true },
		func() error { called = true; return nil },
		func() {},
		false,
	)

	req := httptest.NewRequest(http.MethodPost, "/api/apply/rollback", nil)
	w := httptest.NewRecorder()
	s.handleApplyRollback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("rollback: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	// RollbackNow() must invoke the rollback func registered by Arm().
	if !called {
		t.Errorf("armed rollback func was not invoked by RollbackNow")
	}
	if got := s.failsafe.Status(); got.Phase != "rolled_back" || got.Pending {
		t.Errorf("post-rollback Status() = %+v, want rolled_back/not-pending", got)
	}
}

// --- handleHealth -----------------------------------------------------------

func TestApplyHealth_HealthShape(t *testing.T) {
	s := applyhealth_server(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Demo    bool   `json:"demo"`
		SingBox struct {
			Available bool `json:"available"`
			Running   bool `json:"running"`
		} `json:"singbox"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.Version != version.Version {
		t.Errorf("version = %q, want %q", resp.Version, version.Version)
	}
	if !resp.Demo {
		t.Errorf("demo = false, want true (cfg.Demo set in helper)")
	}
	// The bin path does not exist, so the core reports neither available nor running.
	if resp.SingBox.Available {
		t.Errorf("singbox.available = true, want false (binary missing)")
	}
	if resp.SingBox.Running {
		t.Errorf("singbox.running = true, want false (never started)")
	}
}

func TestApplyHealth_HealthNilSingboxStillOK(t *testing.T) {
	// handleHealth must tolerate a nil singbox (it guards with a nil check).
	s := applyhealth_server(t)
	s.singbox = nil

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health (nil singbox): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Status  string `json:"status"`
		SingBox struct {
			Available bool `json:"available"`
			Running   bool `json:"running"`
		} `json:"singbox"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.SingBox.Available || resp.SingBox.Running {
		t.Errorf("singbox flags = %+v, want both false with nil core", resp.SingBox)
	}
}

// --- handleHealthEndpoints --------------------------------------------------

func TestApplyHealth_HealthEndpointsNilMonitorReturnsEmptyArray(t *testing.T) {
	s := applyhealth_server(t) // monitor is nil

	req := httptest.NewRequest(http.MethodGet, "/api/health/endpoints", nil)
	w := httptest.NewRecorder()
	s.handleHealthEndpoints(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("endpoints (nil monitor): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var arr []any
	if err := json.Unmarshal(w.Body.Bytes(), &arr); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array with nil monitor, got %d entries: %s", len(arr), w.Body.String())
	}
}

func TestApplyHealth_HealthEndpointsDemoMonitorSynthesizesPerEndpoint(t *testing.T) {
	s := applyhealth_server(t)

	// Two enabled endpoints become two monitor targets.
	for _, e := range []model.Endpoint{
		applyhealth_endpoint("e1", "Reality"),
		applyhealth_endpoint("e2", "Reserve"),
	} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatalf("UpsertEndpoint %s: %v", e.ID, err)
		}
	}

	// Wire a demo monitor over the same store (no clash client, no log source).
	mon := health.NewMonitor(nil, s.store, nil, true)
	s.monitor = mon
	// Run a single deterministic demo tick: Run() ticks once before consulting
	// the (already-cancelled) context, then returns immediately. The demo tick
	// synthesizes alive/down stats so the snapshot has populated rows.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mon.Run(ctx)

	req := httptest.NewRequest(http.MethodGet, "/api/health/endpoints", nil)
	w := httptest.NewRecorder()
	s.handleHealthEndpoints(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("endpoints: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var views []health.View
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	// One view per enabled endpoint target, in profile order.
	if len(views) != 2 {
		t.Fatalf("expected 2 endpoint views, got %d: %s", len(views), w.Body.String())
	}
	byID := map[string]health.View{}
	for _, v := range views {
		byID[v.ID] = v
	}
	for _, want := range []struct{ id, name string }{{"e1", "Reality"}, {"e2", "Reserve"}} {
		v, ok := byID[want.id]
		if !ok {
			t.Fatalf("missing view for %q in %s", want.id, w.Body.String())
		}
		if v.Name != want.name {
			t.Errorf("view %s name = %q, want %q", want.id, v.Name, want.name)
		}
		if v.Kind != "endpoint" {
			t.Errorf("view %s kind = %q, want endpoint", want.id, v.Kind)
		}
		// The demo tick records at least one probe per target.
		if v.Probes < 1 {
			t.Errorf("view %s probes = %d, want >= 1 after a demo tick", want.id, v.Probes)
		}
		// Handshake mirrors state and is always one of the three known values.
		switch v.Handshake {
		case "ok", "failed", "unknown":
		default:
			t.Errorf("view %s handshake = %q, want one of ok|failed|unknown", want.id, v.Handshake)
		}
	}

	// The demo monitor forces the last endpoint target "down" to demonstrate the
	// failure-cause row; that view must carry a non-empty cause + fix.
	if down := byID["e2"]; down.State == "down" {
		if down.Cause == "" || down.CauseFix == "" {
			t.Errorf("down view e2 missing cause/fix: %+v", down)
		}
	}
}

// --- handleTrafficRecent ----------------------------------------------------

func TestApplyHealth_TrafficRecentEmptyBuffer(t *testing.T) {
	s := applyhealth_server(t)

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/recent", nil)
	w := httptest.NewRecorder()
	s.handleTrafficRecent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("recent: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var samples []traffic.Sample
	if err := json.Unmarshal(w.Body.Bytes(), &samples); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(samples) != 0 {
		t.Errorf("expected no samples from a fresh hub, got %d", len(samples))
	}
}

func TestApplyHealth_TrafficRecentReturnsPushedSamplesInOrder(t *testing.T) {
	s := applyhealth_server(t)

	pushed := []traffic.Sample{
		{T: 1000, Up: 10, Down: 100},
		{T: 2000, Up: 20, Down: 200},
		{T: 3000, Up: 30, Down: 300},
	}
	for _, sm := range pushed {
		s.hub.Push(sm)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/recent", nil)
	w := httptest.NewRecorder()
	s.handleTrafficRecent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("recent: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var samples []traffic.Sample
	if err := json.Unmarshal(w.Body.Bytes(), &samples); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(samples) != len(pushed) {
		t.Fatalf("got %d samples, want %d: %s", len(samples), len(pushed), w.Body.String())
	}
	// Recent() returns the retained samples oldest-first, unmodified.
	for i, sm := range pushed {
		if samples[i] != sm {
			t.Errorf("sample[%d] = %+v, want %+v", i, samples[i], sm)
		}
	}
}

func TestApplyHealth_TrafficRecentRespectsRingCapacity(t *testing.T) {
	// The helper builds an 8-slot hub; pushing more than that evicts the oldest,
	// so Recent() reflects the ring's capacity (current behavior of traffic.Hub).
	s := applyhealth_server(t)
	for i := int64(0); i < 12; i++ {
		s.hub.Push(traffic.Sample{T: i, Up: i, Down: i})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/recent", nil)
	w := httptest.NewRecorder()
	s.handleTrafficRecent(w, req)

	var samples []traffic.Sample
	if err := json.Unmarshal(w.Body.Bytes(), &samples); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(samples) != 8 {
		t.Fatalf("got %d samples, want 8 (ring capacity)", len(samples))
	}
	// Oldest retained sample is T=4 (0..3 evicted), newest is T=11.
	if samples[0].T != 4 {
		t.Errorf("oldest retained T = %d, want 4", samples[0].T)
	}
	if samples[len(samples)-1].T != 11 {
		t.Errorf("newest retained T = %d, want 11", samples[len(samples)-1].T)
	}
}

// TestRoutingBrainUp pins the fail-safe gate: a connectivity ping only counts
// when the routing brain is actually up. sing-box installed-but-down must read as
// a failure (so a config that crashed the core is rolled back, even though the
// ping target 1.1.1.1 is routed via awg0 outside sing-box). Demo/no-core keeps
// the ping-only behavior.
func TestRoutingBrainUp(t *testing.T) {
	cases := []struct {
		name               string
		available, running bool
		want               bool
	}{
		{"no-core-demo", false, false, true},
		{"no-core-but-running-flag", false, true, true},
		{"core-up", true, true, true},
		{"core-installed-but-down", true, false, false},
	}
	for _, c := range cases {
		if got := routingBrainUp(c.available, c.running); got != c.want {
			t.Errorf("%s: routingBrainUp(%v,%v)=%v, want %v", c.name, c.available, c.running, got, c.want)
		}
	}
}
