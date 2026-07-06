package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// pbrApplyServer builds a non-demo Server with an injected RecordRunner so the kernel
// PBR plane is exercised WITHOUT executing real nft/ip. sing-box stays unavailable (the
// builder points at a missing binary), so handleApply runs the no-binary path (no check,
// no reload) while still driving applyPBR. RoutingMode defaults to "hybrid".
func pbrApplyServer(t *testing.T) (*Server, *pbr.RecordRunner) {
	t.Helper()
	s := opshandlers_server(t)
	s.cfg.Demo = false
	s.cfg.RoutingMode = "hybrid"
	rr := &pbr.RecordRunner{}
	s.pbrRunner = rr
	return s, rr
}

// pbr_extEndpoint is an EngineExternal kernel endpoint (UCI-managed interface). It emits
// NO generator Plugin, so syncPluginsFor is a no-op — safe to drive with Demo=false
// without spawning real awg-quick.
func pbr_extEndpoint(id, iface, server string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineExternal, Server: server,
		Enabled: true, Params: map[string]any{"interface": iface},
	}
}

func pbr_list(id, cidr, outbound string) model.RoutingList {
	return model.RoutingList{ID: id, Name: id, Manual: []string{cidr}, Outbound: outbound, Enabled: true}
}

// seedVoWiFi seeds the canonical carve-out: an awg1 kernel exit + a manual IP list to it.
func seedVoWiFi(t *testing.T, s *Server) {
	t.Helper()
	if err := s.store.UpsertEndpoint(pbr_extEndpoint("ru-awg1", "awg1", "198.51.100.20")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(pbr_list("carrier-carveout", "198.51.100.0/24", "ru-awg1")); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
}

func rrHasFrom(rr *pbr.RecordRunner, from int, substr string) bool {
	for _, c := range rr.Calls[from:] {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func rrStdinHasFrom(rr *pbr.RecordRunner, from int, substr string) bool {
	for _, s := range rr.Stdin[from:] {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// TestPass4_HybridApplyInstallsPlan: a hybrid apply installs the nft table + the ip
// rule/route for the carve-out, records pbrPlan, and returns 200 with no pbr_error.
func TestPass4_HybridApplyInstallsPlan(t *testing.T) {
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("handleApply: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !rrStdinHasFrom(rr, 0, "198.51.100.0/24") || !rrStdinHasFrom(rr, 0, "delete table inet wayhop_pbr") {
		t.Errorf("nft stdin missing zone CIDR / self-flush:\n%v", rr.Stdin)
	}
	if !rrHasFrom(rr, 0, "ip route replace default dev awg1 table 151") {
		t.Errorf("ip route for the kernel egress not installed: %v", rr.Calls)
	}
	if s.pbrPlan == nil {
		t.Error("s.pbrPlan is nil after a successful hybrid apply")
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, has := resp["pbr_error"]; has {
		t.Errorf("unexpected pbr_error on success: %v", resp["pbr_error"])
	}
}

// TestPass4_NonHybridApplyNoPBR: a "tun" apply (Demo=false, runner injected) installs NO
// kernel plane and the response carries no pbr_error key (byte-identical to pre-Pass-4).
func TestPass4_NonHybridApplyNoPBR(t *testing.T) {
	s, rr := pbrApplyServer(t)
	s.cfg.RoutingMode = "tun"
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("handleApply: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if len(rr.Calls) != 0 {
		t.Errorf("non-hybrid apply must not touch the kernel plane, got calls: %v", rr.Calls)
	}
	if s.pbrPlan != nil {
		t.Error("s.pbrPlan must stay nil in non-hybrid mode")
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, has := resp["pbr_error"]; has {
		t.Error("non-hybrid response must not carry a pbr_error key")
	}
}

// TestPass4_DemoApplyNoPBR: demo mode never touches nft/ip even with RoutingMode=hybrid
// and even with a nil pbrRunner (the demo guard fires first). Proves existing demo apply
// behavior is preserved.
func TestPass4_DemoApplyNoPBR(t *testing.T) {
	s := opshandlers_server(t) // Demo=true, pbrRunner nil
	s.cfg.RoutingMode = "hybrid"
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("demo hybrid apply: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if s.pbrPlan != nil {
		t.Error("demo must not install a kernel plan")
	}
}

// TestPass4_ApplyErrorAbortsToBaselineNonSave: when the kernel install fails on a NON-save
// apply, the handler aborts (500) instead of committing green (the ping target lies
// outside the carve-out, so the fail-safe would otherwise miss it).
func TestPass4_ApplyErrorAbortsToBaselineNonSave(t *testing.T) {
	s, rr := pbrApplyServer(t)
	rr.Fail = map[string]error{"ip route replace default dev": errBoom{}}
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hybrid PBR apply failed") {
		t.Errorf("missing abort error message: %s", w.Body.String())
	}
	// This harness has no prior config, so no .bak exists — the abort must take the
	// "no rollback target" branch (stop sing-box / plain WAN) rather than silently
	// leaving the half-hybrid config live (finding 1).
	if !strings.Contains(w.Body.String(), "no rollback target") {
		t.Errorf("first-apply abort must report no rollback target, got: %s", w.Body.String())
	}
	if s.pbrPlan != nil {
		t.Error("s.pbrPlan must be nil (indeterminate) after an aborted apply")
	}
}

// TestPass4_ApplyErrorSaveSurfacesNotAbort: the same failure under save:true is surfaced
// in the response (pbr_error) but NOT aborted — the user explicitly committed.
func TestPass4_ApplyErrorSaveSurfacesNotAbort(t *testing.T) {
	s, rr := pbrApplyServer(t)
	rr.Fail = map[string]error{"ip route replace default dev": errBoom{}}
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save apply with PBR error: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, has := resp["pbr_error"]; !has {
		t.Error("save apply with a PBR failure must surface pbr_error")
	}
}

// TestPass4_RollbackRestoresBaseline: a manual rollback after a hybrid apply tears the
// installed plan down to the (nil) baseline.
func TestPass4_RollbackRestoresBaseline(t *testing.T) {
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("apply: got %d (%s)", w.Code, w.Body.String())
	}
	mark := len(rr.Calls)
	_ = s.failsafe.RollbackNow() // returns sing-box Restore error in this harness; PBR teardown still runs

	if !rrHasFrom(rr, mark, "nft delete table inet wayhop_pbr") {
		t.Errorf("rollback did not tear down the nft table: %v", rr.Calls[mark:])
	}
	if s.pbrPlan != nil {
		t.Error("after rollback to a nil baseline, s.pbrPlan must be nil")
	}
}

// TestPass4_PlanShrinkRemovesStaleTable: shrinking from two kernel egresses to one must
// flush the orphaned higher table (Teardown(old) is load-bearing — Apply(new) only
// touches the new plan's own tables).
func TestPass4_PlanShrinkRemovesStaleTable(t *testing.T) {
	s, rr := pbrApplyServer(t)
	if err := s.store.UpsertEndpoint(pbr_extEndpoint("awg1", "awg1", "198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEndpoint(pbr_extEndpoint("awg2", "awg2", "203.0.113.15")); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertRoutingList(pbr_list("l1", "10.1.0.0/16", "awg1")); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertRoutingList(pbr_list("l2", "10.2.0.0/16", "awg2")); err != nil {
		t.Fatal(err)
	}
	// A1: two egresses → tables 151 (awg1) + 152 (awg2).
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`); w.Code != http.StatusOK {
		t.Fatalf("A1: %d (%s)", w.Code, w.Body.String())
	}
	if !rrHasFrom(rr, 0, "ip route replace default dev awg2 table 152") {
		t.Fatalf("A1 should install table 152: %v", rr.Calls)
	}
	// Shrink: disable the second list+endpoint so only awg1 remains.
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "l2", Name: "l2", Manual: []string{"10.2.0.0/16"}, Outbound: "awg2", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	mark := len(rr.Calls)
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`); w.Code != http.StatusOK {
		t.Fatalf("A2: %d (%s)", w.Code, w.Body.String())
	}
	if !rrHasFrom(rr, mark, "ip route flush table 152") {
		t.Errorf("A2 must flush the orphaned table 152 via Teardown(old): %v", rr.Calls[mark:])
	}
}

// TestPass4_ModeChangeTeardown: flipping hybrid→tun tears the kernel plane down and the
// generated config drops route_exclude_address.
func TestPass4_ModeChangeTeardown(t *testing.T) {
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`); w.Code != http.StatusOK {
		t.Fatalf("hybrid apply: %d (%s)", w.Code, w.Body.String())
	}
	if s.pbrPlan == nil {
		t.Fatal("expected a plan installed after the hybrid apply")
	}
	s.cfg.RoutingMode = "tun"
	mark := len(rr.Calls)
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`); w.Code != http.StatusOK {
		t.Fatalf("tun apply: %d (%s)", w.Code, w.Body.String())
	}
	if !rrHasFrom(rr, mark, "nft delete table inet wayhop_pbr") {
		t.Errorf("mode change must tear down the kernel plane: %v", rr.Calls[mark:])
	}
	if s.pbrPlan != nil {
		t.Error("s.pbrPlan must be nil after switching away from hybrid")
	}
	data, err := os.ReadFile(s.cfg.SingBox.Config)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if strings.Contains(string(data), "route_exclude_address") {
		t.Error("non-hybrid config must not carry route_exclude_address")
	}
}

// TestPass4_BootSyncInstallsHybrid: SyncPlugins (the boot path) installs the kernel plane
// AFTER plugins, in one goroutine.
func TestPass4_BootSyncInstallsHybrid(t *testing.T) {
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)
	s.SyncPlugins()
	if !rrHasFrom(rr, 0, "ip route replace default dev awg1 table 151") {
		t.Errorf("boot sync did not install the hybrid kernel plane: %v", rr.Calls)
	}
	if s.pbrPlan == nil {
		t.Error("boot sync should record the installed plan")
	}
}

// TestPass4_BootSyncOrphanTeardown: SyncPlugins in a non-hybrid mode clears any stale
// wayhop_pbr table left by a prior hybrid era (the user switched mode + rebooted).
func TestPass4_BootSyncOrphanTeardown(t *testing.T) {
	s, rr := pbrApplyServer(t)
	s.cfg.RoutingMode = "tun"
	seedVoWiFi(t, s)
	s.SyncPlugins()
	if !rrHasFrom(rr, 0, "nft delete table inet wayhop_pbr") {
		t.Errorf("non-hybrid boot sync must clear a stale table: %v", rr.Calls)
	}
	if rrHasFrom(rr, 0, "ip route replace default dev") {
		t.Errorf("non-hybrid boot sync must NOT install routes: %v", rr.Calls)
	}
}

// TestPass4_RoutingModePersists guards the pre-existing blocker: handlePutConfig must
// copy routing_mode, else the whole hybrid path is unreachable from the panel/API.
func TestPass4_RoutingModePersists(t *testing.T) {
	s := opshandlers_server(t)
	// Give the live config a file path so Save() works (Default() has none).
	path := t.TempDir() + "/config.json"
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded

	cfg := s.config()
	cfg.RoutingMode = "hybrid"
	body, _ := json.Marshal(cfg)
	w := httptest.NewRecorder()
	s.handlePutConfig(w, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}
	if s.config().RoutingMode != "hybrid" {
		t.Errorf("RoutingMode = %q, want hybrid (handlePutConfig dropped it)", s.config().RoutingMode)
	}
}

// TestPass4_RollbackResyncsPlugins: a fail-safe rollback must re-Sync the engine plugins
// to the pre-window set, so a restored sing-box config's bind_interface (awg) targets are
// up — not left at the failed apply's plugin set (which would run a dead tunnel).
func TestPass4_RollbackResyncsPlugins(t *testing.T) {
	s := opshandlers_server(t) // Demo=true; real plugin.Manager, no engine binaries → needs_binary, specs tracked
	syncFromStore := func() {
		p := s.store.Profile()
		res, err := generator.Generate(&p, s.genOptions(&p))
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		s.syncPluginsFor(res)
	}
	specIDs := func() []string {
		out := []string{}
		for _, sp := range s.plugins.Specs() {
			out = append(out, sp.ID)
		}
		return out
	}

	// Pre-window plugin set = {awgA}.
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgA")); err != nil {
		t.Fatal(err)
	}
	syncFromStore()
	if ids := specIDs(); len(ids) != 1 || ids[0] != "awgA" {
		t.Fatalf("baseline plugins = %v, want [awgA]", ids)
	}
	s.snapshotPluginBaseline() // as handleApply does at the first apply of a window

	// The (failed) apply switches the plugin set to {awgB}: remove awgA, add awgB.
	if err := s.store.DeleteEndpoint("awgA"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgB")); err != nil {
		t.Fatal(err)
	}
	syncFromStore()
	if ids := specIDs(); len(ids) != 1 || ids[0] != "awgB" {
		t.Fatalf("post-apply plugins = %v, want [awgB]", ids)
	}

	// Rollback must restore the plugin set to the baseline {awgA}.
	s.restorePluginBaseline()
	if ids := specIDs(); len(ids) != 1 || ids[0] != "awgA" {
		t.Errorf("after rollback plugins = %v, want [awgA] (baseline re-synced)", ids)
	}
}

// TestPass4_ConcurrentApplyRollbackNoDeadlock guards the failsafe-rollback-applyMu fix:
// the rollback closure now takes applyMu to serialize its sing-box file ops with
// handleApply (else a rollback firing mid-apply tears the live config). A concurrent
// handleApply + manual RollbackNow must BOTH complete — a lock-ordering cycle would
// hang here (caught by the deadline), and -race catches any data race on shared state.
func TestPass4_ConcurrentApplyRollbackNoDeadlock(t *testing.T) {
	s := opshandlers_server(t)
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgA")); err != nil {
		t.Fatal(err)
	}
	// First apply arms the fail-safe window (stores the rollback closure).
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`); w.Code != http.StatusOK {
		t.Fatalf("arming apply: %d (%s)", w.Code, w.Body.String())
	}
	// Race a second apply against a manual rollback. With the fix they serialize on
	// applyMu; without a correct lock order this deadlocks.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`) }()
	go func() { defer wg.Done(); _ = s.failsafe.RollbackNow() }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: concurrent handleApply + RollbackNow did not complete within 20s")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
