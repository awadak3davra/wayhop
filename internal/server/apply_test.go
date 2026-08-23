package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"wayhop/internal/model"
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
