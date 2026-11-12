package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// Boot and supervision: the router is converged to what the record says was committed, an unsaved
// window from a previous life is discarded, and the kernel plane is put back when the router drops it.

// applyboot_kernelMaterialization is a committed state that installs the core and the kernel plane.
func applyboot_kernelMaterialization() executionMaterializationV1 {
	m := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)
	m.Kernel.Retire = []string{"ip rule del fwmark 0x10000 table 100"}
	return *m
}

// A Keenetic reboot with no native revision is the case where the Test is gone with the boot: NDM
// starts from startup-config, which an ordinary Test never writes. The unsaved window is discarded.
func TestStartApply_DiscardsAnUnsavedWindowFromThePreviousLife(t *testing.T) {
	s, fake := applytest_server(t)
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	boot := "boot-before"
	s.bootIDOf = func() string { return boot }
	committed := &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()}
	s.recordApplied(true, committed)
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: applyboot_kernelMaterialization()})
	s.setInFlight(false, "tested")
	boot = "boot-after" // the router rebooted

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the converge/reconcile goroutine exits immediately; the discard is synchronous
	s.StartApply(ctx, filepath.Join(s.applyStateDir, "config.json"))

	if s.liveRevision() != nil {
		t.Error("the router booted from its saved configuration, so an unsaved window must be discarded")
	}
	rec, _ := s.applyStateSnapshot()
	if rec.InFlight != nil {
		t.Error("an Apply that did not finish must not stay marked in flight")
	}
	if rec.Committed == nil || rec.Committed.Rev != committed.Rev {
		t.Fatalf("the committed state must survive a boot: %+v", rec.Committed)
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("nothing should have been executed with a cancelled context: %v", got)
	}
	// The record now lives beside the startup config, whatever it was read from before.
	if s.applyStateFile() != filepath.Join(s.applyStateDir, applyStateFileName) {
		t.Errorf("record path = %q", s.applyStateFile())
	}
}

// QA-145: the routing switch can save a Test's native tunnels into startup-config. A reboot must not
// discard their record as though every Test had vanished; boot rolls that native state back.
func TestLiveNeedsRollbackOnBoot_KeepsNativeStateForRollback(t *testing.T) {
	s, _ := applytest_server(t)
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	s.bootIDOf = func() string { return "boot-after" }
	m := applyboot_kernelMaterialization()
	m.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
		SchemaVersion: executionNativeDeltaSchemaV1,
		Reconcile: nativeplan.Reconciliation{
			Platform: platform.Keenetic, Target: &nativeplan.Plan{Platform: platform.Keenetic},
		},
	}}
	live := &appliedRevision{Rev: "tested", BootID: "boot-before", Materialization: m}
	if !s.liveNeedsRollbackOnBoot(live) {
		t.Fatal("a native revision was discarded across a Keenetic reboot instead of being rolled back")
	}
}

func TestConvergeOnBoot_ReExecutesTheCommittedState(t *testing.T) {
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})

	s.convergeOnBoot(context.Background())

	want := []string{"core:ensure_present", "kernel:ensure_present", "kernelPostcheck"}
	if got := strings.Join(fake.snapshot(), ","); got != strings.Join(want, ",") {
		t.Errorf("converge ops = %v, want %v", fake.snapshot(), want)
	}
	if s.kernelPlaneObserved() != kernelPlanePresent {
		t.Error("a successful converge must record the plane as present")
	}
	// Converge is additive: the retire list and the native removals belong to the Apply that
	// introduced them, and replaying them on every boot would tear down what is running.
	m := applyboot_kernelMaterialization()
	m.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
		SchemaVersion: executionNativeDeltaSchemaV1,
		Reconcile: nativeplan.Reconciliation{
			Platform: platform.Keenetic, Target: &nativeplan.Plan{Platform: platform.Keenetic},
			KeeneticTeardown: []string{"no interface Wireguard11"},
		},
	}}
	target := convergeMaterialization(&m)
	if len(target.Kernel.Retire) != 0 {
		t.Errorf("converge must not retire: %v", target.Kernel.Retire)
	}
	if len(target.Native.Delta.Reconcile.KeeneticTeardown) != 0 {
		t.Errorf("converge must not remove native resources: %v", target.Native.Delta.Reconcile.KeeneticTeardown)
	}
	if m.Native.Delta.Reconcile.KeeneticTeardown == nil {
		t.Error("convergeMaterialization must not mutate the record's own materialization")
	}
}

func TestConvergeOnBoot_NothingToConverge(t *testing.T) {
	// A fresh install has no committed state, and an imported pre-ledger baseline knows what was
	// asked for but not what was installed. Neither may be executed.
	for _, tc := range []struct {
		name string
		rev  *appliedRevision
	}{
		{name: "nothing applied"},
		{name: "imported baseline with no materialization",
			rev: &appliedRevision{Rev: "legacy", At: 1, Desired: &appliedDesired{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := applytest_server(t)
			if tc.rev != nil {
				s.recordApplied(true, tc.rev)
			}
			s.convergeOnBoot(context.Background())
			if got := fake.snapshot(); len(got) != 0 {
				t.Errorf("converge executed something: %v", got)
			}
		})
	}
}

// A router that cannot be converged must still boot: the panel comes up, the failure is logged, and
// the record is left alone.
func TestConvergeOnBoot_FailureIsNeverFatal(t *testing.T) {
	s, fake := applytest_server(t)
	committed := &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()}
	s.recordApplied(true, committed)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.coreErr = errors.New("sing-box binary not found")
	// Cancelling from the failing adapter keeps the retry deterministic: the first attempt runs, the
	// wait before the second returns immediately.
	ops := fake.ops()
	inner := ops.core
	ops.core = func(c context.Context, artifact executionCoreArtifactV1) error {
		err := inner(c, artifact)
		cancel()
		return err
	}
	s.execOps = &ops

	done := make(chan struct{})
	go func() { s.convergeOnBoot(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("convergeOnBoot did not return after a failing attempt")
	}
	if got := s.committedRevision(); got == nil || got.Rev != committed.Rev {
		t.Errorf("a failed converge must leave the record alone: %+v", got)
	}
	if s.liveRevision() != nil {
		t.Error("a failed converge must not invent a live revision")
	}
}

// QA-139: boot converge read the committed revision once, and its retry re-executed it without looking
// again. Routing switched off, or an Apply & Save recorded, during the wait is what the router must run:
// the retry put the core and the kernel plane back under a switch that said off, or ran the old core
// config under a record that named the new one. Each attempt re-reads both under applyMu.
func TestConvergeOnBoot_RetryStandsDownForWhatChangedDuringTheWait(t *testing.T) {
	old := applyConvergeRetry
	applyConvergeRetry = 300 * time.Millisecond
	t.Cleanup(func() { applyConvergeRetry = old })

	// run fails the first attempt at its core step and calls during while that attempt still holds
	// applyMu, so what during does queues behind it and ahead of the retry. It returns the adapter
	// calls made after during.
	run := func(t *testing.T, s *Server, fake *applytest_ops, during func()) []string {
		t.Helper()
		failing := make(chan struct{})
		var first sync.Once
		ops := *s.execOps
		inner := ops.core
		ops.core = func(ctx context.Context, artifact executionCoreArtifactV1) error {
			failed := false
			first.Do(func() { failed = true; close(failing) })
			if failed {
				return errors.New("network not up yet")
			}
			return inner(ctx, artifact)
		}
		s.execOps = &ops
		done := make(chan struct{})
		go func() { s.convergeOnBoot(context.Background()); close(done) }()
		select {
		case <-failing:
		case <-time.After(10 * time.Second):
			t.Fatal("the first attempt never ran")
		}
		during()
		fake.reset()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("convergeOnBoot did not return")
		}
		return fake.snapshot()
	}

	t.Run("routing switched off", func(t *testing.T) {
		s, fake, _ := routingtest_server(t)
		calls := run(t, s, fake, func() {
			if _, err := s.setRouting(context.Background(), false, routingByPanel); err != nil {
				t.Errorf("routing off: %v", err.body())
			}
		})
		if !s.routingIsOff() || len(calls) != 0 {
			t.Fatalf("the retry touched the router after routing was switched off: %v", calls)
		}
	})

	t.Run("an Apply & Save recorded", func(t *testing.T) {
		s, fake := applytest_server(t)
		s.recordApplied(true, &appliedRevision{Rev: "A", At: 1, Materialization: applyboot_kernelMaterialization()})
		saved := &appliedRevision{Rev: "B", At: 2, Materialization: applyboot_kernelMaterialization()}
		calls := run(t, s, fake, func() {
			s.applyMu.Lock() // as runApply records it
			s.recordApplied(true, saved)
			s.applyMu.Unlock()
		})
		if s.committedRevision() != saved || len(calls) != 0 {
			t.Fatalf("the retry re-executed A over the committed B: %v", calls)
		}
	})
}

// noReconcileSettle makes the reconcile loop's second read immediate.
func noReconcileSettle(t *testing.T) {
	old := applyReconcileSettle
	applyReconcileSettle = 0
	t.Cleanup(func() { applyReconcileSettle = old })
}

func TestReconcileKernelPlane_ReinstallsWhenTheRouterDroppedIt(t *testing.T) {
	noReconcileSettle(t)
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})
	// The plane is gone (an fw4 reload that no hook restores): both reads before the reinstall say so,
	// the one after it proves it is back.
	ops := fake.ops()
	reinstalled := false
	innerKernel := ops.kernel
	ops.kernel = func(c context.Context, a executionKernelArtifactV1, r *executionKernelArtifactV1) error {
		reinstalled = true
		return innerKernel(c, a, r)
	}
	innerCheck := ops.kernelPostcheck
	ops.kernelPostcheck = func(c context.Context, a executionKernelArtifactV1) error {
		_ = innerCheck(c, a)
		if !reinstalled {
			return errors.New("nft: no such table")
		}
		return nil
	}
	s.execOps = &ops

	s.reconcileKernelPlane(context.Background())

	want := []string{"kernelPostcheck", "kernelPostcheck", "kernel:ensure_present", "kernelPostcheck"}
	if got := strings.Join(fake.snapshot(), ","); got != strings.Join(want, ",") {
		t.Fatalf("reconcile ops = %v, want %v", fake.snapshot(), want)
	}
	if s.kernelPlaneObserved() != kernelPlanePresent {
		t.Error("a verified reinstall must record the plane as present")
	}

	// A plane that is still in place is left alone.
	fake.reset()
	s.reconcileKernelPlane(context.Background())
	if got := strings.Join(fake.snapshot(), ","); got != "kernelPostcheck" {
		t.Errorf("a healthy plane was reinstalled: %v", fake.snapshot())
	}
}

// QA-118: KeeneticOS rebuilds its firewall every 150 s and its hook restores WayHop's rules within a
// second. A tick that reads inside that gap must not reinstall the plane on top of the hook: the
// second read, after the settle, finds it back and nothing is reinstalled.
func TestReconcileKernelPlane_RidesOutAFirmwareRebuild(t *testing.T) {
	noReconcileSettle(t)
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})
	fake.failOnce = true
	fake.kernelCheckErr = errors.New("iptables: No chain/target/match by that name.")

	s.reconcileKernelPlane(context.Background())

	if got := strings.Join(fake.snapshot(), ","); got != "kernelPostcheck,kernelPostcheck" {
		t.Fatalf("a plane the hook restored within the settle was reinstalled: %v", fake.snapshot())
	}
	if s.kernelPlaneObserved() != kernelPlanePresent {
		t.Error("a plane found on the second read must be recorded present")
	}
}

// The settle never outlives the tick: a cancelled loop returns without reinstalling.
func TestReconcileKernelPlane_SettleHonoursCancel(t *testing.T) {
	old := applyReconcileSettle
	applyReconcileSettle = time.Hour
	t.Cleanup(func() { applyReconcileSettle = old })
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})
	fake.kernelCheckErr = errors.New("nft: no such table")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	done := make(chan struct{})
	go func() { s.reconcileKernelPlane(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the settle did not return on cancel")
	}
	if got := strings.Join(fake.snapshot(), ","); got != "kernelPostcheck" {
		t.Errorf("a cancelled tick went on after the settle: %v", fake.snapshot())
	}
}

func TestReconcileKernelPlane_StepsAside(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *applytest_ops) {
		s, fake := applytest_server(t)
		s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: applyboot_kernelMaterialization()})
		return s, fake
	}
	t.Run("while an Apply is in flight", func(t *testing.T) {
		s, fake := newServer(t)
		s.applyInProgress.Store(true)
		s.reconcileKernelPlane(context.Background())
		if got := fake.snapshot(); len(got) != 0 {
			t.Errorf("the reconcile loop must not race an Apply: %v", got)
		}
	})
	t.Run("while the apply lock is held", func(t *testing.T) {
		s, fake := newServer(t)
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		s.reconcileKernelPlane(context.Background())
		if got := fake.snapshot(); len(got) != 0 {
			t.Errorf("the reconcile loop must not wait on the apply lock: %v", got)
		}
	})
	t.Run("in demo", func(t *testing.T) {
		s, fake := newServer(t)
		s.cfg.Demo = true
		s.reconcileKernelPlane(context.Background())
		if got := fake.snapshot(); len(got) != 0 {
			t.Errorf("demo has no kernel plane to reconcile: %v", got)
		}
	})
	t.Run("when no plane is applied", func(t *testing.T) {
		s, fake := applytest_server(t)
		s.recordApplied(true, &appliedRevision{Rev: "c", At: 1,
			Materialization: *applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)})
		s.reconcileKernelPlane(context.Background())
		if got := fake.snapshot(); len(got) != 0 {
			t.Errorf("there is no plane to check: %v", got)
		}
	})
}

// The health monitor attributes traffic by interface, so it must read the names the applied native
// plan actually assigned rather than guessing from the editable profile.
func TestCurrentNativeInterfaceBindings(t *testing.T) {
	s, _ := applytest_server(t)
	if _, known := s.currentNativeInterfaceBindings(); known {
		t.Error("with nothing applied there is no authoritative mapping")
	}
	m := applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)
	m.Native.Delta.Reconcile.Target.Decisions = []nativeplan.EndpointDecision{
		{EndpointID: "wg1", Path: nativeplan.PathNativeCreate, Interface: "wr_0a1b2c3d"},
		{EndpointID: "proxy", Path: nativeplan.PathCompatibility},
	}
	s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: *m})

	bindings, known := s.currentNativeInterfaceBindings()
	if !known {
		t.Fatal("an applied native plan is the authoritative mapping")
	}
	if bindings["wg1"] != "wr_0a1b2c3d" {
		t.Errorf("bindings = %v, want the interface OpenWrt runs it on", bindings)
	}
	if _, ok := bindings["proxy"]; ok {
		t.Error("a compatibility endpoint has no kernel interface of its own")
	}
}

// SRV-02: boot converge made two attempts 30 s apart and then only logged. Nothing else starts the
// core, the plugins or the native plane, so a router whose first half minute was not enough (NDM still
// settling, a tunnel device not up, no network yet) stayed without its VPN until somebody pressed
// Apply, and nobody was told. It now keeps retrying with a backoff and reports the failure and the
// recovery once each.
func TestConvergeOnBoot_KeepsRetryingAfterTheTwoBootAttempts(t *testing.T) {
	oldRetry, oldBackoff := applyConvergeRetry, applyConvergeBackoff
	applyConvergeRetry = 10 * time.Millisecond
	applyConvergeBackoff = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { applyConvergeRetry, applyConvergeBackoff = oldRetry, oldBackoff })

	alerts := make(chan string, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		alerts <- body.Text
	}))
	defer hook.Close()

	s, fake := applytest_server(t)
	s.allowInternalFetch = true // the webhook is a loopback httptest server
	s.cfg.Watchdog.NotifyURL = hook.URL
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})

	// The core cannot start for the first four attempts: both of boot's and two of the retries.
	const failing = 4
	var mu sync.Mutex
	attempts := 0
	ops := *s.execOps
	inner := ops.core
	ops.core = func(ctx context.Context, artifact executionCoreArtifactV1) error {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n <= failing {
			return errors.New("network not up yet")
		}
		return inner(ctx, artifact)
	}
	s.execOps = &ops

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.convergeOnBoot(ctx) // returns after boot's two attempts, as before

	deadline := time.Now().Add(10 * time.Second)
	for s.kernelPlaneObserved() != kernelPlanePresent {
		if time.Now().After(deadline) {
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("the router was never converged: %d attempts, ops %v", attempts, fake.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i, want := range []string{"could not be restored", "was restored"} {
		select {
		case msg := <-alerts:
			if !strings.Contains(msg, want) {
				t.Errorf("alert %d = %q, want it to say %q", i+1, msg, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("alert %d (%q) was never sent", i+1, want)
		}
	}
	// It stops once converged: no attempt after the one that worked.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if attempts != failing+1 {
		t.Errorf("attempts = %d, want %d", attempts, failing+1)
	}
}
