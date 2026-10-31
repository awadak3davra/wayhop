package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/failsafe"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netdiag"
)

// A rollback that fails leaves the tested configuration (or part of it) on the router. The record
// used to drop the live revision anyway, so the retry had nothing to undo: with no committed
// revision it tore down nil and reported success — cancelling the reboot fallback — while the Test
// kept running; once the window had closed, Roll back answered that the committed configuration was
// running.

// failsafe_retryServer is a router whose first Apply was a Test (no committed revision) and whose
// first kernel teardown fails.
func failsafe_retryServer(t *testing.T) (*Server, *appliedRevision, *atomic.Int32) {
	t.Helper()
	s, fake := applytest_server(t)
	live := &appliedRevision{Rev: "tested", At: 2,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)}
	s.recordApplied(false, live)
	var teardowns atomic.Int32
	ops := fake.ops()
	ops.kernelTeardown = func(context.Context, executionKernelArtifactV1) error {
		if teardowns.Add(1) == 1 {
			return errors.New("nft: table busy")
		}
		return nil
	}
	s.execOps = &ops
	return s, live, &teardowns
}

func TestFailSafeRollback_FailureKeepsTheLiveRecordForTheRetry(t *testing.T) {
	s, live, teardowns := failsafe_retryServer(t)
	s.applyMu.Lock()
	s.armFailSafe(live)
	s.applyMu.Unlock()

	if err := s.failsafe.RollbackNow(); err == nil {
		t.Fatal("setup: the first rollback should fail")
	}
	if s.liveRevision() == nil {
		t.Fatal("a failed rollback must leave the tested revision on record: it is what the retry undoes")
	}
	if err := s.failsafe.RollbackNow(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := teardowns.Load(); n != 2 {
		t.Fatalf("the retry must tear the tested configuration down again; kernel teardowns = %d, want 2", n)
	}
	if s.liveRevision() != nil {
		t.Error("a rollback that worked must end the live state")
	}
	if st := s.failsafe.Status(); st.Pending || st.Phase != "rolled_back" {
		t.Errorf("after a successful retry: %+v", st)
	}
}

// The same through Roll back once no window is pending (it closed at RebootAfter, or the daemon was
// restarted): the manual path must not drop the record on failure either.
func TestApplyRollback_FailureKeepsTheLiveRecordForTheRetry(t *testing.T) {
	s, _, teardowns := failsafe_retryServer(t)

	code, resp := s.applyRollback(context.Background(), "")
	if code != http.StatusInternalServerError {
		t.Fatalf("setup: the first rollback should fail: %d %v", code, resp)
	}
	code, resp = s.applyRollback(context.Background(), "")
	if code != http.StatusOK || resp["rolled_back"] != true {
		t.Fatalf("retry = %d %v, want a rollback that ran", code, resp)
	}
	if n := teardowns.Load(); n != 2 {
		t.Fatalf("kernel teardowns = %d, want 2", n)
	}
	if s.liveRevision() != nil {
		t.Error("a rollback that worked must end the live state")
	}
}

// A rollback can fail AFTER it installed the committed kernel plane: sing-box will not stop (the
// committed configuration does not use it), the native commit or the postcheck fails. The record keeps
// the Test for the retry, and the reconcile loop read it as the baseline: within 30 s it found the
// Test's plane missing and put it back: the plane that had broken connectivity, for good with
// auto-reboot off (the default). Keep, meanwhile, saved a Test the router no longer ran as tested.

// rollbackOutstanding_server is a router whose committed configuration has a kernel plane, and whose
// Test ran sing-box with another plane. The fake kernel holds one plane at a time and its postcheck
// proves only that one; sing-box fails whatever it is asked. With committedCore absent (native-only, no
// sing-box) a rollback installs the committed plane and then fails to stop sing-box; with it present
// the core step comes first, so the rollback fails before it reaches the kernel plane.
func rollbackOutstanding_server(t *testing.T, committedCore ExecutionActionV1) (*Server, *applytest_ops, *appliedRevision, func() string) {
	t.Helper()
	s, fake := applytest_server(t)
	committed := applytest_materialization(committedCore, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)
	committed.Kernel.Nft = []byte("committed plane")
	tested := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)
	tested.Kernel.Nft = []byte("tested plane")
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: *committed})
	live := &appliedRevision{Rev: "tested", At: 2, Materialization: *tested}
	s.recordApplied(false, live)

	var mu sync.Mutex
	plane := "tested plane"
	ops := fake.ops()
	ops.kernel = func(_ context.Context, target executionKernelArtifactV1, _ *executionKernelArtifactV1) error {
		mu.Lock()
		defer mu.Unlock()
		plane = string(target.Nft)
		return nil
	}
	ops.kernelPostcheck = func(_ context.Context, target executionKernelArtifactV1) error {
		mu.Lock()
		defer mu.Unlock()
		if plane != string(target.Nft) {
			return fmt.Errorf("nft: %s is not installed", target.Nft)
		}
		return nil
	}
	s.execOps = &ops
	fake.coreRunning = true
	fake.coreErr = errors.New("sing-box did not stop")
	if committedCore == ExecutionEnsurePresent {
		fake.coreErr = errors.New("sing-box did not restart")
	}
	installed := func() string {
		mu.Lock()
		defer mu.Unlock()
		return plane
	}
	return s, fake, live, installed
}

// rollbackPaths are the three places a rollback of the Test runs and, when it fails, marks it outstanding.
var rollbackPaths = []struct {
	name     string
	rollback func(s *Server, live *appliedRevision) error
}{
	{"fail-safe rollback", func(s *Server, live *appliedRevision) error {
		s.applyMu.Lock()
		s.armFailSafe(live)
		s.applyMu.Unlock()
		return s.failsafe.RollbackNow()
	}},
	{"Roll back after the window closed", func(s *Server, _ *appliedRevision) error {
		if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusOK {
			return fmt.Errorf("%d %v", code, resp)
		}
		return nil
	}},
	{"boot rollback", func(s *Server, _ *appliedRevision) error {
		_, err := s.rollbackLiveOnBootOnce(context.Background(), s.liveRevision())
		return err
	}},
}

func TestRollbackFailure_ReconcileKeepsTheCommittedPlane(t *testing.T) {
	for _, tc := range rollbackPaths {
		t.Run(tc.name, func(t *testing.T) {
			s, fake, live, installed := rollbackOutstanding_server(t, ExecutionEnsureAbsent)
			if err := tc.rollback(s, live); err == nil {
				t.Fatal("setup: the rollback should fail at the core step")
			}
			if got := installed(); got != "committed plane" {
				t.Fatalf("setup: the rollback should have installed the committed plane before it failed; %q is installed", got)
			}

			s.reconcileKernelPlane(context.Background())
			if got := installed(); got != "committed plane" {
				t.Fatalf("the reconcile loop put the %q back over the rollback's committed plane", got)
			}

			code, resp := s.applyConfirm(context.Background(), "")
			if code != http.StatusConflict || resp["code"] != applyCodeRollbackOutstanding {
				t.Fatalf("Keep after a failed rollback = %d %v, want a refusal", code, resp)
			}
			if c := s.committedRevision(); c == nil || c.Rev != "committed" {
				t.Fatalf("a refused Keep moved the committed revision: %+v", c)
			}

			// A restart reads the same record: the mark is persisted with it.
			again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
			if again.liveRollbackFailed() == nil {
				t.Fatal("the outstanding rollback must survive a restart")
			}
			if b := again.supervisedBaseline(); b == nil || b.Rev != "committed" {
				t.Fatalf("after a restart the reconcile baseline = %+v, want the committed revision", b)
			}

			// A retry that works ends it.
			fake.mu.Lock()
			fake.coreErr = nil
			fake.mu.Unlock()
			if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusOK || resp["rolled_back"] != true {
				t.Fatalf("retry = %d %v", code, resp)
			}
			if s.liveRollbackFailed() != nil || s.liveRevision() != nil {
				t.Error("a rollback that worked must end the live state and its mark")
			}
		})
	}
}

// A rollback runs native prepare, plugins, core, then the kernel plane. One that fails before the kernel
// step (here sing-box will not restart on the committed configuration) leaves the Test's plane, core and
// interfaces as they were, yet the mark sent the reconcile loop to the committed revision: one tick
// later the committed plane sat under the Test's core. After a Roll back past the window or a boot
// rollback, no window is left to catch that.
func TestRollbackFailure_BeforeTheKernelStepKeepsTheTestedPlane(t *testing.T) {
	for _, tc := range rollbackPaths {
		t.Run(tc.name, func(t *testing.T) {
			s, _, live, installed := rollbackOutstanding_server(t, ExecutionEnsurePresent)
			if err := tc.rollback(s, live); err == nil {
				t.Fatal("setup: the rollback should fail at the core step")
			}
			if got := installed(); got != "tested plane" {
				t.Fatalf("setup: the rollback should have stopped before the kernel plane; %q is installed", got)
			}
			if s.liveRollbackFailed() == nil {
				t.Fatal("setup: the failed rollback must be marked outstanding")
			}

			s.reconcileKernelPlane(context.Background())
			if got := installed(); got != "tested plane" {
				t.Fatalf("the reconcile loop installed the %q under the Test's core", got)
			}
			if b := s.supervisedBaseline(); b == nil || b.Rev != "tested" {
				t.Fatalf("supervised baseline = %+v, want the Test the router still runs", b)
			}
			// The core step may have changed sing-box all the same: Keep stays refused.
			if code, resp := s.applyConfirm(context.Background(), ""); code != http.StatusConflict || resp["code"] != applyCodeRollbackOutstanding {
				t.Fatalf("Keep = %d %v, want a refusal", code, resp)
			}
		})
	}
}

// A kernel step that itself fails leaves neither plane for certain. Reinstalling either one, once the
// router drops what is there, could put it under a core it does not pair with: nothing is put back
// until the rollback is finished.
func TestRollbackFailure_InTheKernelStepPutsNoPlaneBack(t *testing.T) {
	s, fake, _, installed := rollbackOutstanding_server(t, ExecutionEnsureAbsent)
	fake.mu.Lock()
	fake.coreErr = nil
	fake.mu.Unlock()
	ops := *s.execOps
	install := ops.kernel
	var broken atomic.Bool
	broken.Store(true)
	ops.kernel = func(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
		if broken.Load() {
			return errors.New("nft: netlink busy")
		}
		return install(ctx, target, previous)
	}
	s.execOps = &ops

	if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusInternalServerError {
		t.Fatalf("setup: the rollback should fail at the kernel step: %d %v", code, resp)
	}
	if b := s.supervisedBaseline(); b != nil {
		t.Fatalf("supervised baseline = %+v, want none", b)
	}
	// A firewall reload drops whatever plane there was.
	broken.Store(false)
	if err := install(context.Background(), executionKernelArtifactV1{}, nil); err != nil {
		t.Fatal(err)
	}
	s.reconcileKernelPlane(context.Background())
	if got := installed(); got != "" {
		t.Fatalf("the reconcile loop installed the %q over a rollback that failed in its kernel step", got)
	}
}

// A retry that stops before the kernel step leaves the plane the earlier attempt left. Recording "not
// reached" over it would send the reconcile loop back to the Test's plane, over the committed one.
func TestNoteRollbackFailed_ARetryThatStopsEarlierKeepsThePlane(t *testing.T) {
	s, _ := applytest_server(t)
	m := applyboot_kernelMaterialization()
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: m})
	live := &appliedRevision{Rev: "tested", At: 2, Materialization: m}
	s.recordApplied(false, live)

	s.noteRollbackFailed(live, rollbackPlaneCommitted, errors.New("sing-box did not stop"))
	s.noteRollbackFailed(live, rollbackPlaneTested, errors.New("uci: preflight refused"))
	mark := s.liveRollbackFailed()
	if mark == nil || mark.KernelPlane != rollbackPlaneCommitted || mark.Error != "uci: preflight refused" {
		t.Fatalf("mark = %+v, want the latest error over the plane the first attempt installed", mark)
	}
	if b := s.supervisedBaseline(); b == nil || b.Rev != "committed" {
		t.Fatalf("supervised baseline = %+v, want committed", b)
	}
	// One that did reach the kernel plane says what it left.
	s.noteRollbackFailed(live, rollbackPlaneUnknown, errors.New("nft: netlink busy"))
	if b := s.supervisedBaseline(); b != nil {
		t.Fatalf("supervised baseline = %+v, want none after a failed kernel step", b)
	}
}

// failsafeRetry_vless is a sing-box endpoint on a documentation address.
func failsafeRetry_vless(id string) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.40", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}}
}

// failsafeRetry_outstanding is a router with a committed configuration and a Test whose Roll back,
// pressed during its window, failed at the core step: the window holds on rollback_failed and the
// record marks the rollback outstanding. lastCore is the sing-box configuration last started.
func failsafeRetry_outstanding(t *testing.T) (s *Server, fake *applytest_ops, committed, tested *appliedRevision, lastCore func() []byte) {
	t.Helper()
	s, fake = applytest_server(t)
	var mu sync.Mutex
	var started []byte
	ops := fake.ops()
	core := ops.core
	ops.core = func(ctx context.Context, artifact executionCoreArtifactV1) error {
		err := core(ctx, artifact)
		if err == nil && artifact.Action == ExecutionEnsurePresent {
			mu.Lock()
			started = artifact.Config
			mu.Unlock()
		}
		return err
	}
	s.execOps = &ops
	lastCore = func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return started
	}

	if err := s.store.UpsertEndpoint(failsafeRetry_vless("v1")); err != nil {
		t.Fatal(err)
	}
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("committed apply: %v", aerr.body())
	}
	committed = s.committedRevision()
	if err := s.store.UpsertEndpoint(failsafeRetry_vless("v2")); err != nil {
		t.Fatal(err)
	}
	if _, aerr := s.runApply(context.Background(), applyRequest{}); aerr != nil {
		t.Fatalf("test apply: %v", aerr.body())
	}
	tested = s.liveRevision()
	fake.mu.Lock()
	fake.coreErr = errors.New("sing-box did not restart")
	fake.mu.Unlock()
	if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusInternalServerError {
		t.Fatalf("setup: the Roll back should fail: %d %v", code, resp)
	}
	if s.liveRollbackFailed() == nil || s.failsafe.Status().Phase != "rollback_failed" {
		t.Fatalf("setup: mark %+v, window %+v", s.liveRollbackFailed(), s.failsafe.Status())
	}
	fake.mu.Lock()
	fake.coreErr = nil
	fake.mu.Unlock()
	if err := s.store.UpsertEndpoint(failsafeRetry_vless("v3")); err != nil {
		t.Fatal(err)
	}
	return s, fake, committed, tested, lastCore
}

// A failed Apply rolls back to what the router ran before it. While a rollback of the Test is
// outstanding that is not the Test: rolling back to it restarted the configuration whose own rollback
// was under way, reported "the previous configuration was restored", and left the Test and its mark in
// the record, so the reconcile loop went on mixing the committed plane with the Test's core.
func TestRunApply_FailureWhileARollbackIsOutstandingRestoresTheCommittedConfiguration(t *testing.T) {
	s, fake, committed, tested, lastCore := failsafeRetry_outstanding(t)
	fake.mu.Lock()
	fake.failOnce = true
	fake.kernelErr = errors.New("nft: table wayhop_pbr busy")
	fake.mu.Unlock()

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Code != applyCodeApplyFailed || aerr.Stage != stepKernel {
		t.Fatalf("got %+v, want a kernel-stage APPLY_FAILED", aerr)
	}
	if aerr.RolledBack == nil || !*aerr.RolledBack {
		t.Fatalf("rolled_back = %v, want true", aerr.RolledBack)
	}
	if got := lastCore(); !bytes.Equal(got, committed.Materialization.Core.Config) {
		if bytes.Equal(got, tested.Materialization.Core.Config) {
			t.Fatal("the failed Apply rolled back to the Test whose rollback was outstanding")
		}
		t.Fatalf("the failed Apply left sing-box on %s, want the committed configuration", got)
	}
	if !strings.Contains(aerr.Message, "committed configuration was restored") {
		t.Errorf("message %q", aerr.Message)
	}
	if s.liveRevision() != nil || s.liveRollbackFailed() != nil {
		t.Fatalf("the committed configuration is back: the Test and its mark must go (live %+v, mark %+v)",
			s.liveRevision(), s.liveRollbackFailed())
	}
	if c := s.committedRevision(); c == nil || c.Rev != committed.Rev {
		t.Fatalf("committed = %+v", c)
	}
	// The Test's window held on for its failed rollback; left so, it would close announcing that
	// failure (or reboot) for a router running the committed configuration.
	if st := s.failsafe.Status(); st.Pending || st.Phase != "rolled_back" || st.LastError != "" {
		t.Fatalf("window after the rollback = %+v", st)
	}
}

// If that rollback fails as well, the rollback is still outstanding, now with its error.
func TestRunApply_FailureWhileARollbackIsOutstandingKeepsTheMarkIfItsRollbackFails(t *testing.T) {
	s, fake, _, tested, _ := failsafeRetry_outstanding(t)
	fake.mu.Lock()
	fake.kernelErr = errors.New("nft: table wayhop_pbr busy") // the rollback's kernel step fails too
	fake.mu.Unlock()

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.RolledBack == nil || *aerr.RolledBack || !strings.Contains(aerr.Message, "could NOT be fully restored") {
		t.Fatalf("got %+v, want a failure that says the router was not restored", aerr)
	}
	if l := s.liveRevision(); l == nil || l.Rev != tested.Rev {
		t.Fatalf("live = %+v, want the Test still on record", l)
	}
	mark := s.liveRollbackFailed()
	if mark == nil || !strings.Contains(mark.Error, "table wayhop_pbr busy") || mark.KernelPlane != rollbackPlaneUnknown {
		t.Fatalf("mark = %+v, want this rollback's error and a kernel plane nobody can vouch for", mark)
	}
	if b := s.supervisedBaseline(); b != nil {
		t.Fatalf("supervised baseline = %+v, want none", b)
	}
}

// The bot read only the window's phase, so a failed Roll back after the window closed, or a failed boot
// rollback, reached it as nothing at all. The pulse it watches and the status it shows carry the mark.
func TestTelegramPulse_CarriesAnOutstandingRollback(t *testing.T) {
	s, _, _, _ := rollbackOutstanding_server(t, ExecutionEnsurePresent)
	if p := (tgBackend{s}).Pulse(context.Background()); p.FailSafe.RollbackOutstanding {
		t.Fatal("setup: nothing has failed yet")
	}
	if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusInternalServerError {
		t.Fatalf("setup: the Roll back should fail: %d %v", code, resp)
	}
	p := (tgBackend{s}).Pulse(context.Background())
	if !p.FailSafe.RollbackOutstanding || !strings.Contains(p.FailSafe.RollbackError, "sing-box did not restart") ||
		!p.FailSafe.Live || p.FailSafe.Pending || p.FailSafe.Window == "" {
		t.Fatalf("pulse = %+v", p.FailSafe)
	}
	if st := (tgBackend{s}).Status(context.Background()); !st.FailSafe.RollbackOutstanding || st.FailSafe.Window != p.FailSafe.Window {
		t.Fatalf("status = %+v, want the mark and the Test's window", st.FailSafe)
	}
}

// The webhook said "rolled back to the previous configuration" before the rollback ran, and nothing
// corrected it when the rollback then failed.
func TestFailSafeRollback_WebhookTellsTheOutcome(t *testing.T) {
	got := make(chan string, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- body.Text
	}))
	defer ts.Close()
	next := func() string {
		t.Helper()
		select {
		case msg := <-got:
			return msg
		case <-time.After(3 * time.Second):
			t.Fatal("no webhook")
		}
		return ""
	}

	s, live, _ := failsafe_retryServer(t)
	s.allowInternalFetch = true // the webhook goes to a loopback httptest server
	s.cfgMu.Lock()
	s.cfg.Watchdog.NotifyURL = ts.URL
	s.cfgMu.Unlock()
	s.applyMu.Lock()
	s.armFailSafe(live)
	s.applyMu.Unlock()

	if err := s.failsafe.RollbackNow(); err == nil {
		t.Fatal("setup: the first rollback should fail")
	}
	if msg := next(); !strings.Contains(msg, "FAILED") || !strings.Contains(msg, "table busy") || strings.Contains(msg, "— rolled back") {
		t.Fatalf("webhook after a failed rollback: %q", msg)
	}
	select {
	case msg := <-got:
		t.Fatalf("a second webhook for one rollback: %q", msg)
	case <-time.After(300 * time.Millisecond):
	}
	if err := s.failsafe.RollbackNow(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if msg := next(); !strings.Contains(msg, "rolled back to the previous configuration") || strings.Contains(msg, "FAILED") {
		t.Fatalf("webhook after the retry: %q", msg)
	}
}

// The mark names the Test it is about, so one that some path failed to clear cannot pin a later Test
// to the committed revision; and a record without it, as every record before it existed, loads.
func TestApplyState_RollbackOutstandingNamesItsTest(t *testing.T) {
	s, _ := applytest_server(t)
	m := applyboot_kernelMaterialization()
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: m})
	first := &appliedRevision{Rev: "tested", At: 2, Materialization: m}
	s.recordApplied(false, first)

	raw, err := os.ReadFile(filepath.Join(s.applyStateDir, applyStateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("rollback_outstanding")) {
		t.Fatalf("a record without a failed rollback must not carry the field: %s", raw)
	}
	older := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if older.liveRevision() == nil || older.liveRollbackFailed() != nil {
		t.Fatal("a record without the mark must load with its Test and no mark")
	}

	s.noteRollbackFailed(first, rollbackPlaneCommitted, errors.New("sing-box did not stop"))
	if b := s.supervisedBaseline(); b == nil || b.Rev != "committed" {
		t.Fatalf("supervised baseline = %+v, want committed", b)
	}
	if b := s.appliedBaseline(); b == nil || b.Rev != "tested" {
		t.Fatalf("the record must still name the Test the retry undoes: %+v", b)
	}

	s.applyState.mu.Lock()
	stale := *s.stateLocked().RollbackOutstanding
	s.applyState.mu.Unlock()
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 3, Materialization: m})
	s.applyState.mu.Lock()
	s.stateLocked().RollbackOutstanding = &stale
	s.applyState.mu.Unlock()
	if s.liveRollbackFailed() != nil {
		t.Error("a mark about an earlier Test applies to a later one")
	}
	if b := s.supervisedBaseline(); b == nil || b.At != 3 {
		t.Errorf("supervised baseline = %+v, want the new Test", b)
	}
}

// rollbackAnswer is what one Roll back press got.
type rollbackAnswer struct {
	code int
	resp map[string]any
}

func pressRollback(s *Server) <-chan rollbackAnswer {
	out := make(chan rollbackAnswer, 1)
	go func() {
		code, resp := s.applyRollback(context.Background(), "")
		out <- rollbackAnswer{code, resp}
	}()
	return out
}

// After a failed rollback, a second Roll back pressed while the retry ran (two owners, a double tap in
// Telegram) was not refused: it waited for applyMu and ran the rollback again over what the retry had
// just restored, with a second webhook; had that run failed, a false "FAILED" and rollback_failed on
// the closed window.
func TestFailSafeRollback_SecondPressDuringARetryRunsNothing(t *testing.T) {
	s, live, _ := failsafe_retryServer(t)
	var teardowns atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	ops := *s.execOps
	ops.kernelTeardown = func(context.Context, executionKernelArtifactV1) error {
		switch teardowns.Add(1) {
		case 1:
			return errors.New("nft: table busy")
		case 2:
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	s.execOps = &ops
	s.applyMu.Lock()
	s.armFailSafe(live)
	s.applyMu.Unlock()
	if err := s.failsafe.RollbackNow(); err == nil {
		t.Fatal("setup: the first rollback should fail")
	}

	retry := pressRollback(s)
	<-entered // the retry is tearing the Test down, holding applyMu
	second := pressRollback(s)
	select {
	case got := <-second:
		if got.code == http.StatusOK || got.resp["rolled_back"] == true {
			t.Fatalf("a press during the retry reported a rollback: %d %v", got.code, got.resp)
		}
	case <-time.After(2 * time.Second):
		close(release)
		<-retry
		<-second
		t.Fatalf("a press during the retry was not refused: it queued a second rollback (teardowns=%d)", teardowns.Load())
	}
	close(release)
	if got := <-retry; got.code != http.StatusOK || got.resp["rolled_back"] != true {
		t.Fatalf("retry = %d %v", got.code, got.resp)
	}
	if n := teardowns.Load(); n != 2 {
		t.Fatalf("kernel teardowns = %d, want 2", n)
	}
	if st := s.failsafe.Status(); st.Pending || st.Phase != "rolled_back" || st.LastError != "" {
		t.Fatalf("window after the retry = %+v", st)
	}
}

// The window's rollback closure re-checks the record: a run queued behind one that already finished
// (or behind a Keep, whose Confirm comes after applyMu is released) must not re-execute anything.
func TestFailSafeRollback_NothingLeftToUndoRunsNothing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		meanwhile func(*Server)
		want      error
		phase     string
	}{
		{"already rolled back", (*Server).recordRollback, nil, "rolled_back"},
		{"kept", (*Server).recordCommit, failsafe.ErrSuperseded, "armed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := applytest_server(t)
			live := &appliedRevision{Rev: "tested", At: 2,
				Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)}
			s.recordApplied(false, live)
			s.applyMu.Lock()
			s.armFailSafe(live)
			s.applyMu.Unlock()
			tc.meanwhile(s)
			fake.reset()

			if err := s.failsafe.RollbackNow(); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("RollbackNow = %v, want %v", err, tc.want)
			}
			if calls := fake.snapshot(); len(calls) != 0 {
				t.Fatalf("a rollback with nothing left to undo ran %v", calls)
			}
			if st := s.failsafe.Status(); st.Phase != tc.phase || st.LastError != "" {
				t.Fatalf("window = %+v, want phase %q", st, tc.phase)
			}
		})
	}
}

// The rollback of a failed Apply undoes that Apply: its kernel retire list, flush and native reconcile
// come from what it was installing. With a Test's rollback outstanding, the Apply rolls back to the
// committed revision and the record lets go of the Test, so whatever only the Test had (here its second
// ip rule and its native interfaces, with an Apply that failed before its kernel step) stayed for good.
func TestRunApply_FailureWhileARollbackIsOutstandingUndoesTheTestToo(t *testing.T) {
	s, fake := applytest_server(t)
	committed := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)
	committed.Kernel.Teardown = []string{"ip rule del priority 100 lookup 100"}
	tested := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, true)
	tested.Kernel.Teardown = []string{"ip rule del priority 100 lookup 100", "ip rule del priority 101 lookup 101"}
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: *committed})
	live := &appliedRevision{Rev: "tested", At: 2, Materialization: *tested}
	s.recordApplied(false, live)
	// The rollback of the Test stopped before its kernel step.
	s.noteRollbackFailed(live, rollbackPlaneTested, errors.New("sing-box did not restart"))

	var mu sync.Mutex
	var retired []string
	ops := fake.ops()
	install := ops.kernel
	ops.kernel = func(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
		mu.Lock()
		retired = append(retired, target.Retire...)
		mu.Unlock()
		return install(ctx, target, previous)
	}
	s.execOps = &ops
	if err := s.store.UpsertEndpoint(failsafeRetry_vless("v3")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.failOnce = true
	fake.coreErr = errors.New("sing-box did not start") // before the Apply's kernel step
	fake.mu.Unlock()

	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Stage != stepCore || aerr.RolledBack == nil || !*aerr.RolledBack {
		t.Fatalf("got %+v, want a core-stage failure that was rolled back", aerr)
	}
	mu.Lock()
	gotRetired := append([]string(nil), retired...)
	mu.Unlock()
	if !slices.Contains(gotRetired, "ip rule del priority 101 lookup 101") {
		t.Errorf("the Test's own ip rule was never retired (retired %q)", gotRetired)
	}
	if !slices.Contains(fake.snapshot(), "abortNative") {
		t.Errorf("the native interfaces only the Test had were left in place: %v", fake.snapshot())
	}
	if s.liveRevision() != nil || s.liveRollbackFailed() != nil {
		t.Fatalf("live %+v, mark %+v: the Test is undone", s.liveRevision(), s.liveRollbackFailed())
	}
}

// A Roll back pressed while an Apply holds applyMu waits for it. When that Apply failed and restored the
// committed configuration, it closed the window, which superseded the press: the answer was 500 "nothing
// was rolled back" for a router that had just been rolled back.
func TestApplyRollback_DuringAFailedApplyThatRestoredTheCommittedConfiguration(t *testing.T) {
	s, _, _, _, _ := failsafeRetry_outstanding(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var kernels atomic.Int32
	ops := *s.execOps
	install := ops.kernel
	ops.kernel = func(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
		if kernels.Add(1) == 1 {
			entered <- struct{}{}
			<-release
			return errors.New("nft: table wayhop_pbr busy")
		}
		return install(ctx, target, previous)
	}
	s.execOps = &ops

	applied := make(chan *applyError, 1)
	go func() {
		_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
		applied <- aerr
	}()
	<-entered // the Apply holds applyMu in its kernel step
	pressed := pressRollback(s)
	time.Sleep(200 * time.Millisecond) // the press parks on applyMu
	close(release)
	if aerr := <-applied; aerr == nil || aerr.RolledBack == nil || !*aerr.RolledBack {
		t.Fatalf("setup: the Apply should fail and restore the committed configuration: %+v", aerr)
	}
	got := <-pressed
	if got.code != http.StatusOK {
		t.Fatalf("Roll back = %d %v, want a success: the committed configuration was restored", got.code, got.resp)
	}
	// A press that ran only after the Apply finished finds no window and says the committed
	// configuration runs; one that waited on the Apply says it was rolled back.
	if msg, _ := got.resp["message"].(string); got.resp["rolled_back"] != true && !strings.Contains(msg, "committed configuration is running") {
		t.Fatalf("Roll back = %v", got.resp)
	}
}

// QA-143: whether sing-box must run was fixed from the tested configuration when the window opened.
// After the window rolled a crashed core back to a committed configuration that runs none by design,
// every later check read the stopped core as an outage: the window never closed as recovered and, with
// auto-reboot on, rebooted the router with "no connectivity even after rollback".
func TestFailSafeCheck_JudgesTheRestoredConfigurationAfterARollback(t *testing.T) {
	s, _ := applytest_server(t)
	if err := os.WriteFile(s.cfg.SingBox.Bin, []byte("x"), 0o755); err != nil { // installed, never running
		t.Fatal(err)
	}
	s.failSafePingOf = func(context.Context, string, int) netdiag.PingResult {
		return netdiag.PingResult{Ran: true, Ok: true}
	}
	s.failsafe = failsafe.New(failsafe.Durations{Grace: 10 * time.Millisecond, Interval: 25 * time.Millisecond,
		RollbackAfter: 50 * time.Millisecond, RebootAfter: 600 * time.Millisecond, KeepWindow: 30 * time.Second})
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, // native-only: no core by design
		Materialization: *applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)})
	tested := &appliedRevision{Rev: "tested", At: 2, // runs sing-box, which crashed
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)}
	s.recordApplied(false, tested)
	s.applyMu.Lock()
	s.armFailSafe(tested)
	s.applyMu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for s.failsafe.Status().Pending && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := s.failsafe.Status()
	if st.Pending || s.liveRevision() != nil {
		t.Fatalf("window %+v, live %+v: want the Test rolled back and the window closed", st, s.liveRevision())
	}
	if st.Phase != "rolled_back" || !st.LastCheckOk {
		t.Fatalf("window = %+v, want it closed as recovered on the restored configuration", st)
	}
}

// QA-144: rolling a native Test back to a committed revision with no native plan aborts the Test's
// native target. A failed abort was only logged: Roll back answered rolled_back and the record forgot
// the tunnels, routes and ladder still on the router. It is a rollback failure, retried by Roll back.
func TestApplyRollback_FailedNativeAbortIsARollbackFailure(t *testing.T) {
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)})
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2,
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)})
	tested := s.liveRevision()
	aborts := 0
	ops := fake.ops()
	ops.abortNative = func(context.Context, nativeplan.Plan) error {
		if aborts++; aborts == 1 {
			return errors.New("ndmc: timed out")
		}
		return nil
	}
	s.execOps = &ops

	code, resp := s.applyRollback(context.Background(), "")
	if detail, _ := resp["detail"].(string); code != http.StatusInternalServerError || resp["rolled_back"] != false ||
		!strings.Contains(detail, "ndmc: timed out") {
		t.Fatalf("Roll back = %d %v, want the failed abort reported", code, resp)
	}
	// The committed core and plane are back; the Test's native objects are what is left to undo.
	mark := s.liveRollbackFailed()
	if s.liveRevision() != tested || mark == nil || mark.KernelPlane != rollbackPlaneCommitted {
		t.Fatalf("live %+v, mark %+v: want the Test kept with its rollback outstanding", s.liveRevision(), mark)
	}
	if code, resp := s.applyRollback(context.Background(), ""); code != http.StatusOK || resp["rolled_back"] != true || aborts != 2 {
		t.Fatalf("retry = %d %v after %d aborts, want the abort retried and the rollback finished", code, resp, aborts)
	}
	if s.liveRevision() != nil || s.liveRollbackFailed() != nil {
		t.Fatalf("after the retry: live %+v, mark %+v", s.liveRevision(), s.liveRollbackFailed())
	}
}

// The check judges what runs, not what is committed: a Roll back pressed in the window that stops at
// native prepare leaves the native-only Test running, core stopped by design. Judging the committed
// configuration, which runs sing-box, read that as an outage at every check while every ping answered,
// relabelled the failed rollback "rolled_back" and escalated the window to its reboot step.
func TestFailSafeCheck_JudgesWhatAFailedRollbackLeftRunning(t *testing.T) {
	s, fake := applytest_server(t)
	if err := os.WriteFile(s.cfg.SingBox.Bin, []byte("x"), 0o755); err != nil { // installed, not running
		t.Fatal(err)
	}
	s.failSafePingOf = func(context.Context, string, int) netdiag.PingResult {
		return netdiag.PingResult{Ran: true, Ok: true}
	}
	s.failsafe = failsafe.New(failsafe.Durations{Grace: 10 * time.Millisecond, Interval: 25 * time.Millisecond,
		RollbackAfter: 100 * time.Millisecond, RebootAfter: 400 * time.Millisecond, KeepWindow: 30 * time.Second})
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, // runs sing-box
		Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)})
	tested := &appliedRevision{Rev: "tested", At: 2, // native-only: no core by design
		Materialization: *applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)}
	s.recordApplied(false, tested)
	s.applyMu.Lock()
	s.armFailSafe(tested)
	s.applyMu.Unlock()

	fake.mu.Lock()
	fake.prepareNativeErr = errors.New("ndmc: NDM not answering")
	fake.mu.Unlock()
	if err := s.failsafe.RollbackNow(); err == nil {
		t.Fatal("setup: the Roll back should stop at native prepare")
	}
	if mark := s.liveRollbackFailed(); mark == nil || mark.KernelPlane != rollbackPlaneTested {
		t.Fatalf("setup: mark %+v, want the Test's plane left in place", mark)
	}
	fake.mu.Lock()
	fake.prepareNativeErr = nil
	fake.mu.Unlock()
	time.Sleep(700 * time.Millisecond) // past RebootAfter
	if st := s.failsafe.Status(); !st.Pending || !st.LastCheckOk || st.Phase == "rolled_back" {
		t.Fatalf("window = %+v, want it still open on the running Test, every check healthy", st)
	}
}
