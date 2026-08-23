package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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

func TestStartApply_DiscardsAnUnsavedWindowFromThePreviousLife(t *testing.T) {
	s, fake := applytest_server(t)
	committed := &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()}
	s.recordApplied(true, committed)
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: applyboot_kernelMaterialization()})
	s.setInFlight(false, "tested")

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

func TestReconcileKernelPlane_ReinstallsWhenTheRouterDroppedIt(t *testing.T) {
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})
	// The first postcheck reports the plane missing (an NDM firewall rebuild, an fw4 reload); the
	// one after the reinstall proves it is back.
	fake.failOnce = true
	fake.kernelCheckErr = errors.New("nft: no such table")

	s.reconcileKernelPlane(context.Background())

	want := []string{"kernelPostcheck", "kernel:ensure_present", "kernelPostcheck"}
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
		{EndpointID: "wg1", Path: nativeplan.PathNativeCreate, Interface: "Wireguard10"},
		{EndpointID: "proxy", Path: nativeplan.PathCompatibility},
	}
	s.recordApplied(true, &appliedRevision{Rev: "c", At: 1, Materialization: *m})

	bindings, known := s.currentNativeInterfaceBindings()
	if !known {
		t.Fatal("an applied native plan is the authoritative mapping")
	}
	if bindings["wg1"] != "Wireguard10" {
		t.Errorf("bindings = %v, want the assigned NDM interface", bindings)
	}
	if _, ok := bindings["proxy"]; ok {
		t.Error("a compatibility endpoint has no kernel interface of its own")
	}
}
