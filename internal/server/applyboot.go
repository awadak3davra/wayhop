package server

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// Boot and supervision: converge to the committed record, keep the health monitor's native
// interface names current, and re-install the kernel plane when the router drops it.

// Kernel-plane observations from the last postcheck/reconcile.
const (
	kernelPlaneUnknown int32 = iota
	kernelPlanePresent
	kernelPlaneMissing
)

// applyReconcileInterval is the cadence of the kernel-plane reconcile loop.
const applyReconcileInterval = 30 * time.Second

// applyConvergeRetry is how long boot converge waits before its one retry.
const applyConvergeRetry = 30 * time.Second

func (s *Server) markKernelPlane(state int32) { s.kernelPlaneState.Store(state) }

func (s *Server) kernelPlaneObserved() int32 { return s.kernelPlaneState.Load() }

// installedKernelPlan is the kernel plan the applied baseline keeps installed (nil = none).
func (s *Server) installedKernelPlan() *pbr.Plan {
	base := s.appliedBaseline()
	if base == nil {
		return nil
	}
	return base.Materialization.kernelPlan()
}

// StartApply wires the apply subsystem after server.New: it points the record at the startup config
// directory, discards a stale unsaved state, converges the router to the committed state (in the
// background, never fatal), feeds the health monitor the applied native interface names and starts
// the kernel-plane reconcile loop.
func (s *Server) StartApply(ctx context.Context, startupConfigPath string) {
	dir := filepath.Dir(startupConfigPath)
	s.applyState.mu.Lock()
	s.applyStateDir = dir
	if s.applyState.loaded && s.applyState.path != filepath.Join(dir, applyStateFileName) {
		s.applyState.loaded = false
	}
	s.applyState.mu.Unlock()
	if s.detectedPlatform() == platform.Keenetic && !s.config().Demo && s.nativeOperations == nil {
		s.nativeOperations = keeneticProductionNativeOperations()
	}
	s.discardLiveOnBoot()
	if s.monitor != nil {
		s.monitor.SetNativeInterfaceResolver(s.currentNativeInterfaceBindings)
	}
	go func() {
		s.convergeOnBoot(ctx)
		s.reconcileLoop(ctx)
	}()
	// The routing lists' own failover. Started after boot convergence has had its turn, in its own
	// goroutine: it re-points one routing table at another member of the same group and must not be
	// serialized behind the 30-second reconcile pass, which is where a dead tunnel would otherwise
	// wait out its first minute. See listfailover.go for why nothing else does this today.
	go s.listFailoverLoop(ctx)
}

// convergeOnBoot re-executes the committed materialization: the adapters are idempotent (NDM blocks
// already present are skipped, UCI is diffed, the kernel plane reinstalled, the core started when
// the record says so). Failures are logged and retried once; they never stop the daemon.
func (s *Server) convergeOnBoot(ctx context.Context) {
	committed := s.committedRevision()
	if committed == nil {
		log.Printf("apply: nothing applied before — nothing to converge")
		return
	}
	if !committed.Materialization.known() {
		log.Printf("apply: the committed state %s predates this record — nothing to converge", committed.Rev)
		return
	}
	if s.config().Demo || materializationIsDemo(&committed.Materialization) {
		return
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if ctx.Err() != nil {
			return
		}
		err := s.converge(ctx, committed)
		if err == nil {
			log.Printf("apply: converged to the committed configuration %s", committed.Rev)
			return
		}
		log.Printf("apply: converge to %s failed (attempt %d): %v", committed.Rev, attempt, err)
		if attempt == 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(applyConvergeRetry):
			}
		}
	}
}

// converge executes one revision's materialization as the boot/reconcile baseline: retire lists
// and native removals are cleared (they were applied when the revision went in) so the run is
// purely additive and idempotent.
func (s *Server) converge(ctx context.Context, rev *appliedRevision) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.setStage("converge")
	defer s.setStage("")
	target := convergeMaterialization(&rev.Materialization)
	_, err := executeMaterialization(ctx, s.productionExecOps(), target, nil, s.setStage)
	if err == nil && target.Kernel.Action == ExecutionEnsurePresent {
		s.markKernelPlane(kernelPlanePresent)
	}
	return err
}

// convergeMaterialization is m without the parts that only make sense relative to a previous state.
func convergeMaterialization(m *executionMaterializationV1) *executionMaterializationV1 {
	target := *m
	target.Kernel.Retire = []string{}
	if target.Kernel.Action == ExecutionEnsureAbsent {
		target.Kernel.NFTTool, target.Kernel.IPTool = ExecutionToolIdentityV1{}, ExecutionToolIdentityV1{}
	}
	if m.Native != nil {
		native := *m.Native
		native.Delta.Reconcile.KeeneticTeardown = nil
		native.Delta.Reconcile.OpenWrtRemovals = nil
		target.Native = &native
	}
	return &target
}

// reconcileLoop re-runs the kernel-plane postcheck of the applied baseline every 30 s and reinstalls
// the plane when the router dropped it (an NDM firewall rebuild on Keenetic, a fw4 reload flushing
// the table on OpenWrt). It runs under applyMu and steps aside while an Apply is in flight.
func (s *Server) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(applyReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.reconcileKernelPlane(ctx)
	}
}

// reconcileKernelPlane is one tick of the reconcile loop.
func (s *Server) reconcileKernelPlane(ctx context.Context) {
	if s.applyInProgress.Load() || s.config().Demo {
		return
	}
	base := s.appliedBaseline()
	if base == nil || !base.Materialization.known() || base.Materialization.Kernel.Action != ExecutionEnsurePresent {
		return
	}
	if !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	ops := s.productionExecOps()
	if ops.kernelPostcheck == nil || ops.kernel == nil {
		return
	}
	kernel := base.Materialization.Kernel
	kernel.Retire = []string{}
	tickCtx, cancel := context.WithTimeout(ctx, applyReconcileInterval)
	defer cancel()
	if err := ops.kernelPostcheck(tickCtx, kernel); err == nil {
		s.markKernelPlane(kernelPlanePresent)
		return
	}
	s.markKernelPlane(kernelPlaneMissing)
	log.Printf("apply: the kernel routing plane is missing — reinstalling it")
	if err := ops.kernel(tickCtx, kernel, nil); err != nil {
		log.Printf("apply: kernel plane reinstall failed: %v", err)
		return
	}
	if err := ops.kernelPostcheck(tickCtx, kernel); err != nil {
		log.Printf("apply: kernel plane reinstalled but not verified: %v", err)
		return
	}
	s.markKernelPlane(kernelPlanePresent)
	log.Printf("apply: kernel routing plane reinstalled")
}

// currentNativeInterfaceBindings maps endpoint id → the router-native interface the applied plan
// gave it (wr_* on OpenWrt, WireguardN/wrtunN on Keenetic), so health and traffic attribution use
// the real names instead of guesses derived from the editable profile. known=false means no native
// plan is applied; callers then keep the profile-derived behavior.
func (s *Server) currentNativeInterfaceBindings() (map[string]string, bool) {
	base := s.appliedBaseline()
	if base == nil {
		return nil, false
	}
	plan := base.Materialization.nativeTarget()
	if plan == nil {
		return nil, false
	}
	bindings := make(map[string]string)
	seenEndpoints := make(map[string]bool, len(plan.Decisions))
	seenInterfaces := make(map[string]bool)
	for _, decision := range plan.Decisions {
		if decision.EndpointID == "" || seenEndpoints[decision.EndpointID] {
			return nil, false
		}
		seenEndpoints[decision.EndpointID] = true
		if decision.Interface == "" {
			continue
		}
		if seenInterfaces[decision.Interface] {
			return nil, false
		}
		seenInterfaces[decision.Interface] = true
		bindings[decision.EndpointID] = decision.Interface
	}
	return bindings, true
}

// convergeAfterInstall re-executes the committed materialization once an engine the plan expects has
// arrived. It answers "the binary is here now — make the router match what was applied", which is the
// same question boot convergence answers, so it is the same code path.
//
// Reports false (with no error) when there is nothing to converge to: no committed revision, a record
// that predates the materialization, a demo instance, or a committed plan that does not run a core at
// all. In that last case the install genuinely changed nothing about the datapath, and saying so is
// better than re-executing a plan for effect.
func (s *Server) convergeAfterInstall(ctx context.Context) (bool, error) {
	committed := s.committedRevision()
	if committed == nil || !committed.Materialization.known() {
		return false, nil
	}
	if s.config().Demo || materializationIsDemo(&committed.Materialization) {
		return false, nil
	}
	if committed.Materialization.Core.Action != ExecutionEnsurePresent {
		return false, nil
	}
	if err := s.converge(ctx, committed); err != nil {
		return false, err
	}
	return true, nil
}
