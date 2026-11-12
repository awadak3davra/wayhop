package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// The Apply pipeline end to end, with the router adapters faked: what it refuses and why, what it
// mutates, what it records, and what it restores when a plane fails half-way.

// apply_seedVLESS gives the server one sing-box connection — the shape that needs the core.
func apply_seedVLESS(t *testing.T, s *Server) {
	t.Helper()
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestRunApply_SaveCommitsTheRecord(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)

	res, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if !res.Applied || !res.OK || !res.Saved {
		t.Errorf("result = %+v, want applied/ok/saved", res)
	}
	if res.Summary.Core != "running" {
		t.Errorf("summary.core = %q, want running", res.Summary.Core)
	}
	// The core config is validated before anything is touched, then written and started.
	want := []string{"checkCore", "core:ensure_present", "kernel:ensure_absent"}
	if got := fake.snapshot(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ops = %v, want %v", got, want)
	}
	committed := s.committedRevision()
	if committed == nil || committed.Rev != res.Rev || s.liveRevision() != nil {
		t.Fatalf("a saving Apply must commit and close the window: committed=%+v live=%+v", committed, s.liveRevision())
	}
	if !committed.Materialization.known() || committed.Materialization.Core.Action != ExecutionEnsurePresent {
		t.Errorf("the committed record must carry what was installed: %+v", committed.Materialization.Core)
	}
	if committed.Desired == nil || len(committed.Desired.Profile.Endpoints) != 1 {
		t.Errorf("the committed record must carry the desired snapshot for the change review")
	}
	if rec, _ := s.applyStateSnapshot(); rec.InFlight != nil || !rec.Last.OK || rec.Last.Rev != res.Rev {
		t.Errorf("record after a successful save = %+v", rec)
	}
	if st := s.failsafe.Status(); st.Pending {
		t.Errorf("a saving Apply must not arm the fail-safe: %+v", st)
	}
	if s.currentStage() != "" || s.applyInProgress.Load() {
		t.Error("the stage must be cleared when Apply returns")
	}
}

func TestRunApply_TestArmsTheFailSafeAndRecordsLive(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)

	res, aerr := s.runApply(context.Background(), applyRequest{})
	if aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if res.Saved {
		t.Error("saved = true for an unsaved Apply")
	}
	if s.liveRevision() == nil || s.committedRevision() != nil {
		t.Fatalf("a Test apply must record live only: live=%+v committed=%+v", s.liveRevision(), s.committedRevision())
	}
	if !res.Failsafe.Pending || res.Failsafe.Phase != "armed" {
		t.Errorf("failsafe = %+v, want an armed window", res.Failsafe)
	}
}

func TestRunApply_RevStaleReturnsThePlanAndChangesNothing(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)

	_, aerr := s.runApply(context.Background(), applyRequest{Rev: "a-revision-that-moved"})
	if aerr == nil {
		t.Fatal("a stale rev must be refused")
	}
	if aerr.Status != http.StatusConflict || aerr.Code != applyCodeRevStale {
		t.Fatalf("got %d %s, want 409 REV_STALE", aerr.Status, aerr.Code)
	}
	if aerr.Plan == nil || aerr.Plan.Rev == "" {
		t.Fatal("REV_STALE must carry the current plan so the panel can re-render in place")
	}
	if aerr.Plan.Rev == "a-revision-that-moved" {
		t.Error("the plan must carry the CURRENT revision")
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("a refused Apply touched the router: %v", got)
	}
	if s.appliedBaseline() != nil {
		t.Error("a refused Apply advanced the record")
	}
}

func TestRunApply_BlockedCarriesTheBlockingFindings(t *testing.T) {
	s, fake := applytest_server(t)
	s.caps.set = applytest_caps([]string{platform.CapProtocolPrefix + "vless"})
	apply_seedVLESS(t, s)

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil {
		t.Fatal("a protocol this router cannot carry must be refused")
	}
	if aerr.Status != http.StatusUnprocessableEntity || aerr.Code != applyCodeBlocked {
		t.Fatalf("got %d %s, want 422 BLOCKED", aerr.Status, aerr.Code)
	}
	if len(aerr.Findings) == 0 || aerr.Findings[0].ID != "endpoint.protocol.vless" {
		t.Fatalf("findings = %+v, want the blocking protocol finding", aerr.Findings)
	}
	if aerr.Findings[0].AckRequired {
		t.Error("a hard blocker must never be acknowledgeable")
	}
	if !strings.Contains(aerr.Message, aerr.Findings[0].Title) {
		t.Errorf("the message must name the blocker: %q", aerr.Message)
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("a blocked Apply touched the router: %v", got)
	}
}

func TestRunApply_AckRequiredThenAppliesWithTheAckInTheSameRequest(t *testing.T) {
	s, fake := applytest_server(t)
	s.caps.set = applytest_caps([]string{platform.CapEngineAmneziaWG})
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgA")); err != nil {
		t.Fatal(err)
	}
	// The finding this test is about exists only while the engine binary is absent, and the real
	// lookup ends in exec.LookPath — on a developer machine that has `awg` installed the test would
	// silently prove nothing. Pin the answer instead of skipping.
	s.binaryPresentOf = func(string) bool { return false }
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.unacked()) == 0 {
		t.Fatalf("the plan raises no acknowledgeable finding: %+v", plan.Findings)
	}

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Status != http.StatusConflict || aerr.Code != applyCodeAckRequired {
		t.Fatalf("got %+v, want 409 ACK_REQUIRED", aerr)
	}
	if len(aerr.Findings) == 0 || aerr.Findings[0].ID != "endpoint.engine.amneziawg" {
		t.Fatalf("findings = %+v, want the engine finding", aerr.Findings)
	}
	if len(fake.snapshot()) != 0 {
		t.Error("an unacknowledged Apply must not touch the router")
	}

	// Acknowledging and applying is ONE round trip: the ack is merged before the plan is judged.
	res, aerr := s.runApply(context.Background(), applyRequest{Save: true, Ack: []string{"endpoint.engine.amneziawg"}})
	if aerr != nil {
		t.Fatalf("apply with the ack: %v", aerr.body())
	}
	if !res.Applied {
		t.Error("applied = false")
	}
	if !s.isAcked("endpoint.engine.amneziawg") {
		t.Error("the acknowledgement must be persisted for the next review")
	}
}

func TestRunApply_InvalidConfigFromTheCoreCheckTouchesNothing(t *testing.T) {
	s, fake := applytest_server(t)
	fake.checkErr = errors.New("sing-box check failed: exit status 1: FATAL[0000] decode config at /tmp/x: rule_set[3] invalid")
	apply_seedVLESS(t, s)

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Status != http.StatusBadRequest || aerr.Code != applyCodeInvalidConfig {
		t.Fatalf("got %+v, want 400 INVALID_CONFIG", aerr)
	}
	if aerr.Stage != "check" {
		t.Errorf("stage = %q, want check", aerr.Stage)
	}
	if !strings.Contains(aerr.Detail, "rule_set[3] invalid") {
		t.Errorf("the tool output must reach the operator: %q", aerr.Detail)
	}
	if got := fake.snapshot(); strings.Join(got, ",") != "checkCore" {
		t.Errorf("a rejected config must not be installed, ops = %v", got)
	}
	if s.appliedBaseline() != nil {
		t.Error("a rejected config advanced the record")
	}
	if rec, _ := s.applyStateSnapshot(); rec.InFlight != nil {
		t.Error("nothing was mutated, so no in-flight marker should be left")
	}
}

func TestRunApply_ExecutionFailureRollsBackToTheBaseline(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("baseline apply: %v", aerr.body())
	}
	baseline := s.committedRevision()
	fake.reset()

	// A second Apply whose kernel step fails once. failOnce lets the baseline re-execution through
	// the same adapter succeed, which is what a real rollback does.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatal(err)
	}
	fake.failOnce = true
	fake.kernelErr = errors.New("nft: table wayhop_pbr busy")

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Status != http.StatusInternalServerError || aerr.Code != applyCodeApplyFailed {
		t.Fatalf("got %+v, want 500 APPLY_FAILED", aerr)
	}
	if aerr.Stage != stepKernel {
		t.Errorf("stage = %q, want %q", aerr.Stage, stepKernel)
	}
	if aerr.RolledBack == nil || !*aerr.RolledBack {
		t.Fatalf("rolled_back = %v, want true (the baseline was restored)", aerr.RolledBack)
	}
	if !strings.Contains(aerr.Detail, "table wayhop_pbr busy") {
		t.Errorf("the adapter's cause must reach the operator: %q", aerr.Detail)
	}
	if !strings.Contains(aerr.Message, "previous configuration was restored") {
		t.Errorf("the message must state the consequence: %q", aerr.Message)
	}
	// The failed step, then the baseline re-executed through the same adapters.
	got := strings.Join(fake.snapshot(), ",")
	if !strings.Contains(got, "kernel:ensure_absent,core:ensure_present") {
		t.Errorf("ops = %v, want the failed step followed by the baseline re-execution", fake.snapshot())
	}
	// The record still describes the baseline, and the failure is recorded as such.
	if got := s.committedRevision(); got == nil || got.Rev != baseline.Rev {
		t.Errorf("committed = %+v, want the untouched baseline %s", got, baseline.Rev)
	}
	if s.liveRevision() != nil {
		t.Error("a failed Apply must not leave a live revision")
	}
	rec, _ := s.applyStateSnapshot()
	if rec.InFlight != nil || rec.Last.OK || rec.Last.Error == "" {
		t.Errorf("record after a failed Apply = %+v", rec)
	}
}

func TestRunApply_ExecutionFailureWithNoBaselineTearsDown(t *testing.T) {
	t.Run("teardown succeeds", func(t *testing.T) {
		s, fake := applytest_server(t)
		apply_seedVLESS(t, s)
		fake.failOnce = true
		fake.coreErr = errors.New("sing-box exited right after (re)start")

		_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
		if aerr == nil || aerr.Code != applyCodeApplyFailed || aerr.Stage != stepCore {
			t.Fatalf("got %+v, want a core-stage APPLY_FAILED", aerr)
		}
		if aerr.RolledBack == nil || !*aerr.RolledBack {
			t.Fatalf("rolled_back = %v, want true (everything installed was removed)", aerr.RolledBack)
		}
		// With nothing to return to, the teardown stops the core and retires the plugins.
		got := strings.Join(fake.snapshot(), ",")
		if !strings.Contains(got, "core:ensure_present,core:ensure_absent") || !strings.Contains(got, "plugins") {
			t.Errorf("ops = %v, want the teardown path", fake.snapshot())
		}
		if s.appliedBaseline() != nil {
			t.Error("a failed first Apply must leave the record empty")
		}
	})

	t.Run("teardown fails, and says so", func(t *testing.T) {
		s, fake := applytest_server(t)
		apply_seedVLESS(t, s)
		fake.coreErr = errors.New("sing-box will not stop") // never cleared: the teardown fails too

		_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
		if aerr == nil || aerr.Code != applyCodeApplyFailed {
			t.Fatalf("got %+v, want APPLY_FAILED", aerr)
		}
		if aerr.RolledBack == nil || *aerr.RolledBack {
			t.Fatalf("rolled_back = %v, want false — the router was NOT restored", aerr.RolledBack)
		}
		if !strings.Contains(aerr.Message, "could NOT be fully restored") {
			t.Errorf("the message must not claim a restore that did not happen: %q", aerr.Message)
		}
	})
}

func TestRunApply_DemoAdvancesTheRecordWithoutTouchingTheRouter(t *testing.T) {
	s, fake := applytest_server(t)
	s.cfg.Demo = true
	apply_seedVLESS(t, s)

	res, aerr := s.runApply(context.Background(), applyRequest{})
	if aerr != nil {
		t.Fatalf("demo apply: %v", aerr.body())
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("demo must call no adapter, got %v", got)
	}
	live := s.liveRevision()
	if live == nil || !materializationIsDemo(&live.Materialization) {
		t.Fatalf("the record must advance with a demo materialization: %+v", live)
	}
	if res.Summary.Core != "demo" || res.Summary.Kernel != "demo" {
		t.Errorf("summary = %+v, want demo planes", res.Summary)
	}
	// The fail-safe still arms so the UI flow can be exercised, but never reboots in demo.
	if !res.Failsafe.Pending {
		t.Error("demo must still arm the fail-safe window")
	}
}

func TestRunApply_PluginThatDidNotStartIsAProblemNotARefusal(t *testing.T) {
	s, fake := applytest_server(t)
	fake.problems = []map[string]any{{"id": "awgA", "engine": "amneziawg", "needs_binary": true,
		"reason": "awg: executable file not found"}}
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgA")); err != nil {
		t.Fatal(err)
	}

	res, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr != nil {
		t.Fatalf("a plugin that did not start must not refuse the Apply: %v", aerr.body())
	}
	if !res.Applied || res.OK {
		t.Errorf("applied=%v ok=%v, want applied with ok=false", res.Applied, res.OK)
	}
	if len(res.Problems) != 1 || res.Problems[0]["id"] != "awgA" {
		t.Fatalf("problems = %+v, want the engine named", res.Problems)
	}
	if !strings.Contains(res.Summary.Plugins, "0 of 1") {
		t.Errorf("summary.plugins = %q, want it to count the ones that came up", res.Summary.Plugins)
	}
	// Make-before-break: the union is synced first, the target set after the consumer planes switched.
	if len(fake.pluginSyncs) != 2 {
		t.Fatalf("plugin syncs = %v, want prepare + retire", fake.pluginSyncs)
	}
	if s.committedRevision() == nil {
		t.Error("a soft problem still records what was applied")
	}
}

func TestRunApply_NativePersistFailureKeepsTheWindowOpen(t *testing.T) {
	s, fake := applytest_server(t)
	applytest_keenetic(s)
	if err := s.store.UpsertEndpoint(applytest_wireguardEndpoint("wg1")); err != nil {
		t.Fatal(err)
	}
	fake.persistNativeErr = errors.New("ndmc: system configuration save timed out")

	res, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if res.Saved {
		t.Error("saved = true although the router-native configuration was not persisted")
	}
	if res.OK || len(res.Problems) != 1 || res.Problems[0]["id"] != "native_persist" {
		t.Fatalf("problems = %+v, want the persist failure named", res.Problems)
	}
	if s.liveRevision() == nil || s.committedRevision() != nil {
		t.Fatalf("the configuration must stay an unsaved window: live=%+v committed=%+v",
			s.liveRevision(), s.committedRevision())
	}
	if !res.Failsafe.Pending {
		t.Error("an unsaved window must be protected by the fail-safe")
	}
	// The native plane really was driven (prepare → commit → persist).
	if got := strings.Join(fake.snapshot(), ","); !strings.Contains(got, "prepareNative") ||
		!strings.Contains(got, "commitNative") || !strings.Contains(got, "persistNative") {
		t.Errorf("ops = %v", fake.snapshot())
	}
}

func TestRunApply_BusyWhenTheLockIsHeld(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller gave up rather than waiting out the lock budget

	_, aerr := s.runApply(ctx, applyRequest{})
	if aerr == nil || aerr.Status != http.StatusServiceUnavailable || aerr.Code != applyCodeBusy {
		t.Fatalf("got %+v, want 503 BUSY", aerr)
	}
	if aerr.Remedy == "" {
		t.Error("BUSY must tell the client what to do")
	}
}

func TestDecodeApplyRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
		want applyRequest
		err  bool
	}{
		{name: "empty body means a Test apply", body: ""},
		{name: "whitespace only", body: "  \n"},
		{name: "empty object", body: `{}`},
		{name: "save", body: `{"save":true}`, want: applyRequest{Save: true}},
		{name: "every field", body: `{"save":true,"rev":"abc","ack":["a","b"],"detail":true}`,
			want: applyRequest{Save: true, Rev: "abc", Ack: []string{"a", "b"}, Detail: true}},
		{name: "unknown fields are ignored", body: `{"save":true,"principal":"x","plan_rev":"y"}`,
			want: applyRequest{Save: true}},
		{name: "malformed", body: `{"save":`, err: true},
		{name: "not an object", body: `[1,2]`, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeApplyRequest(strings.NewReader(tc.body))
			if tc.err {
				if err == nil {
					t.Fatalf("decode(%q) = %+v, want an error", tc.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode(%q): %v", tc.body, err)
			}
			if got.Save != tc.want.Save || got.Rev != tc.want.Rev || got.Detail != tc.want.Detail ||
				strings.Join(got.Ack, ",") != strings.Join(tc.want.Ack, ",") {
				t.Errorf("decode(%q) = %+v, want %+v", tc.body, got, tc.want)
			}
		})
	}
	// A nil body is the same as an empty one: the handler must not depend on the client sending one.
	if got, err := decodeApplyRequest(nil); err != nil || got.Save {
		t.Errorf("decode(nil) = %+v, %v", got, err)
	}
}

// A profile the model itself refuses is answered with the validation message, not with a router
// capability the user cannot act on.
func TestRunApply_InvalidProfileIsNamed(t *testing.T) {
	s, fake := applytest_server(t)
	if err := s.store.UpsertRule(model.Rule{ID: "r1", Outbound: "does-not-exist"}); err != nil {
		t.Fatal(err)
	}
	_, aerr := s.runApply(context.Background(), applyRequest{})
	if aerr == nil || aerr.Code != applyCodeInvalidConfig || aerr.Stage != "profile" {
		t.Fatalf("got %+v, want a profile-stage INVALID_CONFIG", aerr)
	}
	if !strings.Contains(aerr.Detail, `rule "r1"`) {
		t.Errorf("detail = %q, want the offending object named", aerr.Detail)
	}
	if len(fake.snapshot()) != 0 {
		t.Error("an invalid profile must not reach the router")
	}
}

// apply_failRollbackCore fails the core step of the rollback that follows a failed Apply: the core
// calls are counted from now, and the forward run makes the first.
func apply_failRollbackCore(s *Server, fake *applytest_ops) {
	ops := fake.ops()
	inner := ops.core
	n := 0
	ops.core = func(ctx context.Context, artifact executionCoreArtifactV1) error {
		if n++; n == 2 {
			return errors.New("sing-box did not restart")
		}
		return inner(ctx, artifact)
	}
	s.execOps = &ops
}

// QA-140: a failed Apply whose rollback also failed was recorded only while an earlier rollback was
// outstanding. Otherwise the record went on naming the committed revision as running over the Apply's
// leftovers: Roll back answered "the committed configuration is running", and the reconcile loop put
// the committed plane back under the failed Apply's core. The Apply is now the live state with its
// rollback outstanding, which Keep refuses and Roll back finishes.
func TestRunApply_FailedRollbackOfAFailedApplyIsRecorded(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("baseline apply: %v", aerr.body())
	}
	committed := s.committedRevision()
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatal(err)
	}
	apply_failRollbackCore(s, fake)
	fake.failOnce = true
	fake.kernelErr = errors.New("nft: table wayhop_pbr busy")

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Stage != stepKernel || aerr.RolledBack == nil || *aerr.RolledBack {
		t.Fatalf("got %+v, want a kernel-stage failure that was not rolled back", aerr)
	}
	live, mark := s.liveRevision(), s.liveRollbackFailed()
	if live == nil || live.Rev == committed.Rev || mark == nil || !strings.Contains(mark.Error, "did not restart") {
		t.Fatalf("live %+v, mark %+v: want the failed Apply on record with its rollback outstanding", live, mark)
	}
	// The forward run failed at its kernel step and the rollback stopped before its own: neither
	// revision's plane can be vouched for, so the reconcile loop puts none back.
	if mark.KernelPlane != rollbackPlaneUnknown || s.supervisedBaseline() != nil {
		t.Fatalf("mark plane %q, supervised %+v", mark.KernelPlane, s.supervisedBaseline())
	}
	if c := s.committedRevision(); c != committed {
		t.Fatalf("committed = %+v, want the untouched %s", c, committed.Rev)
	}
	if code, resp := s.applyConfirm(context.Background(), ""); code != http.StatusConflict || resp["code"] != applyCodeRollbackOutstanding {
		t.Fatalf("Keep = %d %v, want the outstanding rollback refused", code, resp)
	}
	if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusOK || resp["rolled_back"] != true {
		t.Fatalf("Roll back = %d %v, want it to finish the rollback", code, resp)
	}
	if s.liveRevision() != nil || s.liveRollbackFailed() != nil || s.committedRevision() != committed {
		t.Fatalf("after Roll back: live %+v, mark %+v", s.liveRevision(), s.liveRollbackFailed())
	}
}

// With a Test window open the failed Apply rolls back to the Test. When that fails too, the Test no
// longer runs as tested, and Keep must not commit it.
func TestRunApply_FailedRollbackToTheTestMarksIt(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("baseline apply: %v", aerr.body())
	}
	committed := s.committedRevision()
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatal(err)
	}
	if _, aerr := s.runApply(context.Background(), applyRequest{}); aerr != nil {
		t.Fatalf("test apply: %v", aerr.body())
	}
	tested := s.liveRevision()
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v3", "FR")); err != nil {
		t.Fatal(err)
	}
	apply_failRollbackCore(s, fake)
	fake.failOnce = true
	fake.kernelErr = errors.New("nft: table wayhop_pbr busy")

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.RolledBack == nil || *aerr.RolledBack {
		t.Fatalf("got %+v, want a failure that was not rolled back", aerr)
	}
	mark := s.liveRollbackFailed()
	if l := s.liveRevision(); !sameRevision(l, tested) || mark == nil || mark.KernelPlane != rollbackPlaneUnknown {
		t.Fatalf("live %+v, mark %+v: want the Test marked with a plane nobody can vouch for", l, mark)
	}
	if code, resp := s.applyConfirm(context.Background(), ""); code != http.StatusConflict || resp["code"] != applyCodeRollbackOutstanding {
		t.Fatalf("Keep = %d %v, want the half-restored Test refused", code, resp)
	}
	if c := s.committedRevision(); c != committed {
		t.Fatalf("committed = %+v, want the untouched %s", c, committed.Rev)
	}
}

// The failed Apply recorded as live is the next Apply's ownership baseline, and alone it left out what
// the committed configuration created and the failed Apply never retired: it stopped before its native
// commit, so the committed tunnel stayed on the router, outside every later Apply's ownership. The next
// Apply retires what either of them left that its capture still finds; what is gone is not retired.
func TestRunApply_OverAFailedApplyRetiresWhatTheCommittedOneLeft(t *testing.T) {
	for _, present := range []bool{true, false} {
		t.Run(map[bool]string{true: "still on the router", false: "already gone"}[present], func(t *testing.T) {
			s, fake := applytest_server(t)
			applytest_keenetic(s)
			for _, id := range []string{"wg1", "wg2"} {
				if err := s.store.UpsertEndpoint(applytest_wireguardEndpoint(id)); err != nil {
					t.Fatal(err)
				}
			}
			if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
				t.Fatalf("committed apply: %v", aerr.body())
			}
			committed := s.committedRevision().Materialization.nativeTarget()
			retired := "no interface " + committed.Keenetic.IfaceFor["wg2"]
			// The router runs the committed configuration, minus wg2's tunnel when it is gone.
			running := *committed
			running.Keenetic = &keenetic.Plan{Interfaces: committed.Keenetic.Interfaces, Routes: committed.Keenetic.Routes}
			if !present {
				running.Keenetic.Interfaces, running.Keenetic.Routes = nil, nil
				for _, block := range committed.Keenetic.Interfaces {
					if "no "+block[0] != retired {
						running.Keenetic.Interfaces = append(running.Keenetic.Interfaces, block)
					}
				}
			}
			config := exactKeeneticBaselineConfig + "\n" + exactKeeneticTargetRunningConfig(running)
			s.keeneticConfigReader = func(context.Context) (string, error) { return config, nil }
			if err := s.store.DeleteEndpoint("wg2"); err != nil {
				t.Fatal(err)
			}

			// The Apply that drops wg2 fails at its kernel step, before its native commit, and its
			// rollback fails at native prepare: it becomes the live state with its rollback outstanding.
			ops := fake.ops()
			prepare, commit := ops.prepareNative, ops.commitNative
			prepares := 0
			ops.prepareNative = func(ctx context.Context, target nativeplan.Plan) error {
				if prepares++; prepares == 2 {
					return errors.New("ndmc: NDM not answering")
				}
				return prepare(ctx, target)
			}
			var teardown []string
			ops.commitNative = func(ctx context.Context, reconcile nativeplan.Reconciliation) error {
				teardown = append(teardown, reconcile.KeeneticTeardown...)
				return commit(ctx, reconcile)
			}
			s.execOps = &ops
			fake.failOnce = true
			fake.kernelErr = errors.New("nft: table wayhop_pbr busy")
			if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr == nil || s.liveRollbackFailed() == nil {
				t.Fatalf("setup: got %+v, mark %+v; want a failed Apply whose rollback failed", aerr, s.liveRollbackFailed())
			}
			if len(teardown) != 0 {
				t.Fatalf("setup: the failed Apply reached its native commit: %v", teardown)
			}

			if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
				t.Fatalf("next apply: %v", aerr.body())
			}
			if got := slices.Contains(teardown, retired); got != present {
				t.Fatalf("teardown %v: %q retired = %v, want %v", teardown, retired, got, present)
			}
		})
	}
}

// SRV-03: the forward run used the HTTP request context. An Apply that reloads the core or re-creates
// the tunnel the operator's own session rides on drops that connection; net/http then cancels the
// context, the next step refused to start and the whole Apply was rolled back, on every retry. Once
// the router may change, the run is detached from the request and finishes on its own bound.
func TestRunApply_ALostClientDoesNotAbortTheRunMidWay(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops := *s.execOps
	core, kernel := ops.core, ops.kernel
	ops.core = func(c context.Context, artifact executionCoreArtifactV1) error {
		err := core(c, artifact)
		cancel() // the core reload took the panel's connection with it
		return err
	}
	var kernelCtxErr error
	kernelBounded := false
	ops.kernel = func(c context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
		kernelCtxErr = context.Cause(c)
		_, kernelBounded = c.Deadline()
		return kernel(c, target, previous)
	}
	s.execOps = &ops

	res, aerr := s.runApply(ctx, applyRequest{Save: true})
	if aerr != nil {
		t.Fatalf("the Apply was aborted when its client went away: %v (ops %v)", aerr.body(), fake.snapshot())
	}
	if kernelCtxErr != nil {
		t.Errorf("the step after the disconnect ran on a cancelled context: %v", kernelCtxErr)
	}
	if !kernelBounded {
		t.Error("the detached run must still be bounded by a deadline")
	}
	if committed := s.committedRevision(); committed == nil || committed.Rev != res.Rev {
		t.Fatalf("the Apply must be committed: %+v", committed)
	}
	if rec, _ := s.applyStateSnapshot(); rec.InFlight != nil || !rec.Last.OK {
		t.Errorf("record = %+v, want a finished, successful Apply", rec)
	}
}

// Before anything is changed a cancelled request still stops the Apply: cancelling there is free.
func TestRunApply_ARequestCancelledBeforeAnyChangeTouchesNothing(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops := *s.execOps
	check := ops.checkCore
	ops.checkCore = func(c context.Context, config []byte) error {
		err := check(c, config)
		cancel()
		return err
	}
	s.execOps = &ops

	if _, aerr := s.runApply(ctx, applyRequest{Save: true}); aerr == nil {
		t.Fatal("an Apply whose request ended before the first change went ahead")
	} else if aerr.RolledBack == nil || !*aerr.RolledBack {
		t.Errorf("the refusal must say nothing was changed: %+v", aerr.body())
	}
	if got := strings.Join(fake.snapshot(), ","); got != "checkCore" {
		t.Errorf("ops = %v, want only the config check", got)
	}
	if rec, _ := s.applyStateSnapshot(); rec.InFlight != nil || s.committedRevision() != nil {
		t.Errorf("nothing may be recorded: %+v", rec)
	}
}
