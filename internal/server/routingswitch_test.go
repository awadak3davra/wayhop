package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/failsafe"
	"wayhop/internal/health"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// routingtest_server is applytest_server with the routing switch's own ops recorded too, and a
// committed revision that runs every plane: core, kernel plane, engine plugins and a native target.
func routingtest_server(t *testing.T) (*Server, *applytest_ops, *routingtest_native) {
	t.Helper()
	s, fake := applytest_server(t)
	native := &routingtest_native{changed: true}
	ops := fake.ops()
	ops.nativeRoutingOff = func(_ context.Context, target nativeplan.Plan) (bool, error) {
		fake.record("nativeRoutingOff")
		return native.changed, native.offErr
	}
	ops.nativeRoutingSave = func(context.Context, nativeplan.Plan) error {
		fake.record("nativeRoutingSave")
		return nil
	}
	ops.resolverReload = func(context.Context, executionKernelArtifactV1) error {
		fake.record("resolverReload")
		return nil
	}
	s.execOps = &ops
	committed := &appliedRevision{Rev: "committed-rev", At: 1,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsurePresent, true)}
	s.recordApplied(true, committed)
	fake.reset()
	return s, fake, native
}

type routingtest_native struct {
	changed bool
	offErr  error
}

func routingtest_has(calls []string, name string) bool { return slices.Contains(calls, name) }

// Switching off removes the capture and the routing, keeps the tunnels, and is recorded first.
func TestRoutingOffRemovesRoutingAndKeepsTheTunnels(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	view, err := s.setRouting(context.Background(), false, routingByPanel)
	if err != nil {
		t.Fatalf("switch off: %v", err)
	}
	if view.Enabled || view.By != routingByPanel || view.Since == 0 || !view.Restorable {
		t.Fatalf("view after off = %+v", view)
	}
	calls := fake.snapshot()
	for _, want := range []string{"core:ensure_absent", "kernelTeardown", "resolverReload", "nativeRoutingOff", "nativeRoutingSave"} {
		if !routingtest_has(calls, want) {
			t.Fatalf("switching off did not run %s: %v", want, calls)
		}
	}
	for _, never := range []string{"plugins", "abortNative", "prepareNative", "commitNative", "core:ensure_present", "kernel:ensure_present"} {
		if routingtest_has(calls, never) {
			t.Fatalf("switching off ran %s — the tunnels must stay up and nothing may be installed: %v", never, calls)
		}
	}
	if !s.routingIsOff() {
		t.Fatal("the switch is not recorded")
	}
	// The committed configuration is untouched: switching on restores exactly it.
	if c := s.committedRevision(); c == nil || c.Rev != "committed-rev" {
		t.Fatalf("committed revision after off = %+v", c)
	}
}

// The off state survives a daemon restart (it is in apply-state.json), and switching on removes it
// from the file without leaving a key behind.
func TestRoutingSwitchPersists(t *testing.T) {
	s, _, _ := routingtest_server(t)
	if _, err := s.setRouting(context.Background(), false, routingByTelegram); err != nil {
		t.Fatal(err)
	}
	fresh := &Server{cfg: s.cfg, applyStateDir: s.applyStateDir}
	if !fresh.routingIsOff() || fresh.routingSwitchView().By != routingByTelegram {
		t.Fatalf("a restarted daemon does not see the off state: %+v", fresh.routingSwitchView())
	}
	if _, err := s.setRouting(context.Background(), true, routingByPanel); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.applyStateDir, applyStateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "routing_off") {
		t.Fatalf("switched on, the record still carries the switch: %s", raw)
	}
	if again := (&Server{cfg: s.cfg, applyStateDir: s.applyStateDir}); again.routingIsOff() {
		t.Fatal("a restarted daemon still sees routing off after it was switched on")
	}
}

// Switching on re-executes the committed materialization (converge) and saves the native state.
func TestRoutingOnRestoresTheCommittedConfiguration(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}
	fake.reset()
	view, err := s.setRouting(context.Background(), true, routingByPanel)
	if err != nil {
		t.Fatalf("switch on: %v", err)
	}
	if !view.Enabled || s.routingIsOff() {
		t.Fatalf("view after on = %+v", view)
	}
	calls := fake.snapshot()
	for _, want := range []string{"prepareNative", "core:ensure_present", "kernel:ensure_present", "commitNative", "nativeRoutingSave"} {
		if !routingtest_has(calls, want) {
			t.Fatalf("switching on did not run %s: %v", want, calls)
		}
	}
	// Already on: nothing runs.
	fake.reset()
	if _, err := s.setRouting(context.Background(), true, routingByPanel); err != nil || len(fake.snapshot()) != 0 {
		t.Fatalf("switching on what is on ran %v (%v)", fake.snapshot(), err)
	}
}

// Off works whatever state the parts are in: a failing kernel teardown does not keep the core or
// the native routing in place; the failure is reported and kept, and a retry clears it.
func TestRoutingOffReportsAPartialFailureAndRetries(t *testing.T) {
	s, fake, native := routingtest_server(t)
	ops := *s.execOps
	failKernel := true
	ops.kernelTeardown = func(context.Context, executionKernelArtifactV1) error {
		fake.record("kernelTeardown")
		if failKernel {
			return errors.New("nft: table busy")
		}
		return nil
	}
	s.execOps = &ops
	native.changed = true
	_, err := s.setRouting(context.Background(), false, routingByPanel)
	if err == nil || err.Code != routingCodeIncomplete || err.Status != http.StatusInternalServerError ||
		!strings.Contains(err.Detail, "table busy") {
		t.Fatalf("partial failure = %+v", err)
	}
	calls := fake.snapshot()
	if !routingtest_has(calls, "core:ensure_absent") || !routingtest_has(calls, "nativeRoutingOff") {
		t.Fatalf("one failing part kept the others in place: %v", calls)
	}
	if v := s.routingSwitchView(); v.Enabled || !strings.Contains(v.Error, "table busy") {
		t.Fatalf("the failure is not kept for the banner: %+v", v)
	}
	failKernel = false
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if v := s.routingSwitchView(); v.Enabled || v.Error != "" {
		t.Fatalf("a successful retry must clear the failure: %+v", v)
	}
}

// Switching on that fails removes what it restored and stays off with the reason.
func TestRoutingOnFailureLeavesTheRouterOff(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}
	fake.reset()
	fake.kernelErr = errors.New("ip rule add failed")
	_, err := s.setRouting(context.Background(), true, routingByPanel)
	if err == nil || err.Status != http.StatusInternalServerError {
		t.Fatalf("a failed restore must be reported, got %+v", err)
	}
	if !s.routingIsOff() || !strings.Contains(s.routingSwitchView().Error, "removed again") {
		t.Fatalf("a failed restore must leave routing off with the reason: %+v", s.routingSwitchView())
	}
	calls := fake.snapshot()
	last := calls[len(calls)-1]
	if !routingtest_has(calls[1:], "core:ensure_absent") || last == "core:ensure_present" {
		t.Fatalf("what the failed restore put in place was not removed again: %v", calls)
	}
}

// A Test window open when routing goes off is closed without a rollback (which would put routing
// back), and switching on reconciles its leftovers away from the committed configuration.
func TestRoutingOffClosesTheFailSafeWindow(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	s.failsafe = failsafe.New(failsafe.Durations{Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour})
	live := &appliedRevision{Rev: "test-rev", At: 2,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsurePresent, false)}
	s.recordApplied(false, live)
	var rolledBack atomic.Int32
	s.failsafe.Arm(func() bool { return false }, func() error { rolledBack.Add(1); return nil }, func() {}, false)

	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}
	if s.failsafe.Status().Pending {
		t.Fatal("the fail-safe window outlived routing off")
	}
	if rolledBack.Load() != 0 {
		t.Fatal("switching off rolled the Test state back (that would re-install routing)")
	}
	if s.liveRevision() != nil {
		t.Fatal("the Test state is still recorded as running")
	}
	if off := s.routingOffRecord(); off == nil || off.Leftover == nil || off.Leftover.Rev != "test-rev" {
		t.Fatalf("the Test state is not kept for switching on to retire: %+v", off)
	}
	fake.reset()
	if _, err := s.setRouting(context.Background(), true, routingByPanel); err != nil {
		t.Fatal(err)
	}
	if off := s.routingOffRecord(); off != nil {
		t.Fatalf("switched on, the leftover is still recorded: %+v", off)
	}
	if !routingtest_has(fake.snapshot(), "core:ensure_present") {
		t.Fatalf("switching on did not restore the committed configuration: %v", fake.snapshot())
	}
}

// Nothing in the background puts routing back while it is off.
func TestNothingRepairsRoutingWhileItIsOff(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}

	fake.reset()
	s.markKernelPlane(kernelPlaneMissing)
	s.reconcileKernelPlane(context.Background())
	if calls := fake.snapshot(); len(calls) != 0 {
		t.Fatalf("the reconcile loop touched the router while routing is off: %v", calls)
	}

	if ok, err := s.convergeAfterInstall(context.Background()); ok || err != nil || len(fake.snapshot()) != 0 {
		t.Fatalf("an engine install converged while routing is off: %v %v %v", ok, err, fake.snapshot())
	}

	_, applyErr := s.runApply(context.Background(), applyRequest{Save: true})
	if applyErr == nil || applyErr.Code != routingCodeOff || applyErr.Status != http.StatusConflict {
		t.Fatalf("Apply while routing is off = %+v", applyErr)
	}

	// Boot re-asserts the off state instead of converging.
	fake.reset()
	s.convergeOnBoot(context.Background())
	calls := fake.snapshot()
	if !routingtest_has(calls, "core:ensure_absent") || routingtest_has(calls, "core:ensure_present") ||
		routingtest_has(calls, "kernel:ensure_present") || routingtest_has(calls, "prepareNative") {
		t.Fatalf("boot with routing off: %v", calls)
	}

	// A fail-safe rollback that slipped past the disarm (armed by a path that forgot it) skips too.
	live := &appliedRevision{Rev: "test-rev", At: 3,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)}
	s.armFailSafe(live)
	fake.reset()
	if err := s.failsafe.RollbackNow(); err != nil {
		t.Fatal(err)
	}
	if calls := fake.snapshot(); len(calls) != 0 {
		t.Fatalf("a fail-safe rollback ran while routing is off: %v", calls)
	}
	if !s.routingIsOff() {
		t.Fatal("the rollback switched routing back on")
	}
}

// The list failover writes nothing while routing is off, and resumes when it is back on.
func TestListFailoverStandsAsideWhileRoutingIsOff(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	tables := &fakeTables{up: map[string]bool{"wr_u": true}}
	s := restoreServer(t, restorePlan(false), tables)
	s.store = st
	s.monitor = health.NewMonitor(nil, st, nil, true)
	s.applyState.rec.RoutingOff = &routingOffRecord{At: 1, By: routingByPanel}
	s.listFailoverTick(context.Background())
	if len(tables.writes) != 0 {
		t.Fatalf("the list failover wrote a table while routing is off: %v", tables.writes)
	}
	s.applyState.rec.RoutingOff = nil
	s.listFailoverTick(context.Background())
	if !reflect.DeepEqual(tables.writes, []string{"v4 wr_u 1001"}) {
		t.Fatalf("with routing back on the lost route was not restored: %v", tables.writes)
	}
}

// The demo flips the switch and runs nothing on the host.
func TestRoutingSwitchInTheDemoTouchesNothing(t *testing.T) {
	s, fake, _ := routingtest_server(t)
	s.cfg.Demo = true
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}
	if !s.routingIsOff() || len(fake.snapshot()) != 0 {
		t.Fatalf("demo off: off=%v calls=%v", s.routingIsOff(), fake.snapshot())
	}
	if _, err := s.setRouting(context.Background(), true, routingByPanel); err != nil {
		t.Fatal(err)
	}
	if s.routingIsOff() || len(fake.snapshot()) != 0 {
		t.Fatalf("demo on: off=%v calls=%v", s.routingIsOff(), fake.snapshot())
	}
}

// /api/state carries the switch, so the panel's 10-second poll keeps the banner right.
func TestStateReportsTheRoutingSwitch(t *testing.T) {
	s, _, _ := routingtest_server(t)
	if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
		t.Fatal(err)
	}
	w := tgDo(t, s, http.MethodGet, "/api/state", "")
	var body struct {
		Routing         routingSwitchView `json:"routing"`
		Effective       string            `json:"effective"`
		EffectiveReason string            `json:"effective_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET /api/state = %d %s", w.Code, w.Body)
	}
	if body.Routing.Enabled || body.Effective != effectiveUnknown || !strings.Contains(body.EffectiveReason, "switched off") {
		t.Fatalf("/api/state with routing off: %+v", body)
	}
}

// The endpoint takes a session AND the CSRF token, like every other mutation, and a well-formed body.
func TestRoutingSwitchEndpointAuth(t *testing.T) {
	s, handler, _ := authTestServer(t)
	cookie, csrf := setupAuth(t, handler, false, nil)
	body := `{"enabled":false}`
	if r := authRequest(t, handler, http.MethodPost, "/api/routing/switch", body, nil, "", false); r.Code != http.StatusUnauthorized {
		t.Fatalf("no session = %d %s", r.Code, r.Body)
	}
	if r := authRequest(t, handler, http.MethodPost, "/api/routing/switch", body, cookie, "", false); r.Code != http.StatusForbidden ||
		authResponse(t, r)["code"] != AuthCodeCSRFRequired {
		t.Fatalf("no CSRF = %d %s", r.Code, r.Body)
	}
	if r := authRequest(t, handler, http.MethodGet, "/api/routing/switch", "", nil, "", false); r.Code != http.StatusUnauthorized {
		t.Fatalf("GET without a session = %d", r.Code)
	}
	if s.routingIsOff() {
		t.Fatal("a refused request switched routing")
	}
	if r := authRequest(t, handler, http.MethodPost, "/api/routing/switch", `{"on":false}`, cookie, csrf, false); r.Code != http.StatusBadRequest {
		t.Fatalf("a body without enabled = %d %s", r.Code, r.Body)
	}
	r := authRequest(t, handler, http.MethodPost, "/api/routing/switch", body, cookie, csrf, false)
	if r.Code != http.StatusOK {
		t.Fatalf("switch off = %d %s", r.Code, r.Body)
	}
	got := authResponse(t, r)["routing"].(map[string]any)
	if got["enabled"] != false || got["by"] != routingByPanel || !s.routingIsOff() {
		t.Fatalf("switch off answered %v", got)
	}
	r = authRequest(t, handler, http.MethodGet, "/api/routing/switch", "", cookie, "", false)
	if got := authResponse(t, r)["routing"].(map[string]any); r.Code != http.StatusOK || got["enabled"] != false {
		t.Fatalf("GET = %d %v", r.Code, got)
	}
	r = authRequest(t, handler, http.MethodPost, "/api/routing/switch", `{"enabled":true}`, cookie, csrf, false)
	if r.Code != http.StatusOK || s.routingIsOff() {
		t.Fatalf("switch on = %d %s", r.Code, r.Body)
	}
}

// --- KeeneticOS: routes and ladder go, interfaces stay -------------------------------------------

func routingtest_keeneticTarget() nativeplan.Plan {
	target := exactKeeneticTestTarget()
	plan := cloneKeeneticPlanForTest(target.Keenetic)
	plan.Singbox = nil // the clone helper allocates one; a plan with no compatibility endpoint has none
	plan.GlobalPriority = map[string]int{"Wireguard10": 55634}
	plan.GlobalPriorityWas = map[string]int{"Wireguard10": 1000}
	target.Keenetic = plan
	return target
}

const routingtest_keeneticOn = "interface GigabitEthernet1\n    ip global 54610\n!\n" +
	"interface Wireguard10\n    description wayhop\n    ip global 55634\n    up\n!\n" +
	"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto\n"

const routingtest_keeneticOff = "interface GigabitEthernet1\n    ip global 54610\n!\n" +
	"interface Wireguard10\n    description wayhop\n    ip global 1000\n    up\n!\n"

func TestKeeneticRoutingOffLowersTheLadderAndRemovesRoutesOnly(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	adapter.readConfig = exactKeeneticConfigReader(routingtest_keeneticOn, routingtest_keeneticOff)
	changed, err := adapter.routingOff(context.Background(), routingtest_keeneticTarget())
	if err != nil || !changed {
		t.Fatalf("routingOff = %v, %v", changed, err)
	}
	want := [][]string{
		{"interface Wireguard10", "ip global 1000"},
		{"no ip route 203.0.113.0 255.255.255.0 Wireguard10"},
	}
	if !reflect.DeepEqual(runner.batches, want) {
		t.Fatalf("batches = %v, want %v", runner.batches, want)
	}
	for _, batch := range runner.batches {
		for _, command := range batch {
			if strings.HasPrefix(command, "no interface") {
				t.Fatalf("routing off removed an interface: %v", runner.batches)
			}
		}
	}
}

// Already off (a boot re-assertion): nothing is submitted and nothing needs saving.
func TestKeeneticRoutingOffIsIdempotent(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	adapter.readConfig = exactKeeneticConfigReader(routingtest_keeneticOff)
	changed, err := adapter.routingOff(context.Background(), routingtest_keeneticTarget())
	if err != nil || changed || len(runner.batches) != 0 {
		t.Fatalf("routingOff on an off router = %v, %v, %v", changed, err, runner.batches)
	}
}

// An accepted-but-ignored command is not reported as routing removed.
func TestKeeneticRoutingOffVerifiesTheRunningConfig(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	adapter.readConfig = exactKeeneticConfigReader(routingtest_keeneticOn, routingtest_keeneticOn)
	changed, err := adapter.routingOff(context.Background(), routingtest_keeneticTarget())
	if err == nil || !changed || !errors.Is(err, errExactKeeneticApply) {
		t.Fatalf("routingOff over an NDM that ignored it = %v, %v", changed, err)
	}
}

func TestNativeRoutingOffOnOpenWrtChangesNothing(t *testing.T) {
	adapter := &exactNativePlatformAdapter{}
	changed, err := adapter.routingOff(context.Background(), nativeplan.Plan{Platform: platform.OpenWrt})
	if err != nil || changed {
		t.Fatalf("OpenWrt routingOff = %v, %v", changed, err)
	}
	if err := adapter.routingSave(context.Background(), nativeplan.Plan{Platform: platform.OpenWrt}); err != nil {
		t.Fatalf("OpenWrt routingSave = %v", err)
	}
}

// A Test left from before routing went off is rolled back when it goes on. Since a native abort that
// fails is a rollback failure (QA-144), one that kept failing kept routing off for good: switching on
// removed routing again, and an Apply is refused while routing is off. The committed configuration is
// back by then, so routing goes on and the leftover stays on record as an outstanding rollback, which
// Roll back retries.
func TestRoutingOn_ALeftoverWhoseTunnelsCannotBeRemovedStillSwitchesOn(t *testing.T) {
	for _, committed := range []bool{true, false} {
		t.Run(map[bool]string{true: "over the committed configuration", false: "with nothing committed"}[committed], func(t *testing.T) {
			s, fake := applytest_server(t)
			aborts := 0
			ops := fake.ops()
			ops.nativeRoutingOff = func(context.Context, nativeplan.Plan) (bool, error) { return false, nil }
			ops.resolverReload = func(context.Context, executionKernelArtifactV1) error { return nil }
			ops.abortNative = func(context.Context, nativeplan.Plan) error {
				if aborts++; aborts == 1 {
					return errors.New("ndmc: timed out")
				}
				return nil
			}
			s.execOps = &ops
			if committed {
				s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1,
					Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)})
			}
			s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2,
				Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)})
			if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
				t.Fatalf("off: %v", err.body())
			}

			view, aerr := s.setRouting(context.Background(), true, routingByPanel)
			if aerr != nil || !view.Enabled || s.routingIsOff() {
				t.Fatalf("on = %+v, %v: want routing on", view, aerr)
			}
			mark := s.liveRollbackFailed()
			if l := s.liveRevision(); l == nil || l.Rev != "tested" || mark == nil || mark.KernelPlane != rollbackPlaneCommitted ||
				!strings.Contains(mark.Error, "ndmc: timed out") {
				t.Fatalf("live %+v, mark %+v: want the leftover kept with its rollback outstanding", l, mark)
			}
			if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusOK || resp["rolled_back"] != true || aborts != 2 {
				t.Fatalf("Roll back = %d %v after %d aborts, want the removal retried and finished", code, resp, aborts)
			}
			if s.liveRevision() != nil || s.liveRollbackFailed() != nil {
				t.Fatalf("after Roll back: live %+v, mark %+v", s.liveRevision(), s.liveRollbackFailed())
			}
		})
	}
}

// Only a rollback whose every failure is the native leftover lets routing go on.
func TestOnlyNativeLeftover(t *testing.T) {
	leftover := &nativeLeftoverError{errors.New("ndmc: timed out")}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("stop core: sing-box will not stop"), false},
		{leftover, true},
		{errors.Join(leftover), true},
		{errors.Join(errors.New("stop core: sing-box will not stop"), leftover), false},
	} {
		if got := onlyNativeLeftover(c.err); got != c.want {
			t.Errorf("onlyNativeLeftover(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
