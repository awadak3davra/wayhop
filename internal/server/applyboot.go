package server

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/model"
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

// applyReconcileSettle is how long the reconcile loop waits before it believes a missing plane.
// KeeneticOS rebuilds its firewall every 150 s and its netfilter.d hook puts WayHop's rules back
// within a second. A tick that read the tables inside that gap took the plane for missing and
// reinstalled it while the hook was doing the same, the two interleaving: the live router logged "the
// kernel routing plane is missing" five times in twenty minutes, each at a rebuild, with the hook's
// "No chain/target/match by that name" beside them (QA-118). A second read after the settle tells a
// rebuild in progress from a plane that is really gone. A var so tests need not wait.
var applyReconcileSettle = 3 * time.Second

// applyConvergeRetry is how long boot converge waits before its one retry. A var so tests need not
// wait.
var applyConvergeRetry = 30 * time.Second

func (s *Server) markKernelPlane(state int32) { s.kernelPlaneState.Store(state) }

func (s *Server) kernelPlaneObserved() int32 { return s.kernelPlaneState.Load() }

// installedKernelPlan is the kernel plan the reconcile loop keeps installed (nil = none).
func (s *Server) installedKernelPlan() *pbr.Plan {
	base := s.supervisedBaseline()
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
	if live := s.liveRevision(); live != nil {
		// A daemon restart leaves the Test plane's flows behind. After a reboot the table holds only
		// flows the committed plane marked, which the flush judges consistent and keeps.
		s.bootDroppedPlan = live.Materialization.kernelPlan()
		if s.liveNeedsRollbackOnBoot(live) {
			s.bootLive = live
		}
	}
	s.discardLiveOnBoot(s.bootLive != nil)
	if s.monitor != nil {
		s.monitor.SetNativeInterfaceResolver(s.currentNativeInterfaceBindings)
	}
	s.removeStaleCoreTemps()
	s.reapStrayCore()
	s.reapStrayPlugins()
	go func() {
		s.convergeOnBoot(ctx)
		s.reconcileLoop(ctx)
	}()
	// The routing lists' own failover. Started after boot convergence has had its turn, in its own
	// goroutine: it re-points one routing table at another member of the same group and must not be
	// serialized behind the 30-second reconcile pass, which is where a dead tunnel would otherwise
	// wait out its first minute. See listfailover.go for why nothing else does this today.
	go s.listFailoverLoop(ctx)
	go s.coreRestartLoop(ctx)
}

// reapStrayPlugins ends a ciadpi an earlier daemon left running (a SIGKILL, a panic, the OOM killer):
// it still holds its SOCKS port, so the new daemon's ByeDPI exits at every start with "Address in use",
// and it keeps the old strategy flags nobody can change (QA-097). ByeDPI runs as a uid nothing else on
// the router uses, so only WayHop's own ciadpi matches. amneziawg-go has its own per-interface cleanup
// (awgClearStale) and sing-box its own (reapStrayCore). It runs before converge starts any plugin. The
// demo leaves the host's processes alone.
func (s *Server) reapStrayPlugins() {
	if s.plugins == nil || s.config().Demo {
		return
	}
	s.plugins.ReapStrays("ciadpi", model.ByeDPIUID)
}

// reapStrayCore ends a sing-box an earlier daemon left running on this daemon's config (QA-109). A
// core that outlives its daemon holds the cache-file lock, the Clash and mixed ports and the TUN, and
// keeps routing by the old config; the core this daemon starts then dies at every start with
// "initialize cache-file: timeout" and the watchdog restarts it in a loop. The core now dies with
// the daemon (core's dieWithDaemon), but one started by an older build, which had no such tie,
// survived an OOM kill, a kill -9 or a Go fatal error. core.SingBox.ReapStrays was written for this
// and lost its only caller with the old exact core adapter. Here it runs once, before converge, the
// watchdog and the update loop exist, so no core of this daemon is up yet and any process running
// this config is a stray. The demo leaves the host's processes alone.
func (s *Server) reapStrayCore() {
	if s.singbox == nil || s.config().Demo {
		return
	}
	s.singbox.ReapStrays()
}

// removeStaleCoreTemps deletes what a crash left beside the live core config: a half-written
// replacement of the config or of its fail-safe copies (.bak, .good), and the candidate `sing-box
// check` was validating. Each is a full config with endpoint keys that nothing else would ever remove.
// It runs before converge, the HTTP server, the watchdog and the update loop exist, so no write there
// is in flight.
func (s *Server) removeStaleCoreTemps() {
	live := s.config().SingBox.Config
	if live == "" {
		return
	}
	for _, p := range []string{live, live + ".bak", live + ".good"} {
		atomicfile.RemoveStale(p)
	}
	atomicfile.RemoveStaleMatching(filepath.Dir(live), coreCheckStagePrefix+"*")
}

// convergeOnBoot re-executes the committed materialization: the adapters are idempotent (NDM blocks
// already present are skipped, UCI is diffed, the kernel plane reinstalled, the core started when
// the record says so). Failures are logged and retried once; they never stop the daemon.
func (s *Server) convergeOnBoot(ctx context.Context) {
	// Routing switched off: boot must not put back what the operator removed. It re-asserts the off
	// state instead (a daemon that died half way through the switch finishes it here).
	if s.routingIsOff() {
		s.enforceRoutingOffOnBoot(ctx)
		return
	}
	if s.bootLive != nil {
		s.rollbackLiveOnBoot(ctx, s.bootLive)
		return
	}
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
		done, err := s.convergeOnBootOnce(ctx, committed)
		if done {
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

// convergeOnBootOnce is one attempt of convergeOnBoot. Like rollbackLiveOnBootOnce it re-reads the
// record and the routing switch under applyMu: the retry used to re-execute the revision read before
// the first attempt, so routing switched off, or an Apply recorded, during the 30 s wait was undone by
// the retry, which put the core and the kernel plane back or ran the old core config under the new
// record (QA-139).
func (s *Server) convergeOnBootOnce(ctx context.Context, committed *appliedRevision) (bool, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.routingIsOff() || s.committedRevision() != committed || s.liveRevision() != nil {
		log.Printf("apply: converge to %s skipped: the applied state changed since this process started", committed.Rev)
		return true, nil
	}
	if err := s.convergeLocked(ctx, committed); err != nil {
		return false, err
	}
	log.Printf("apply: converged to the committed configuration %s", committed.Rev)
	if s.bootDroppedPlan != nil {
		// A daemon restart, not a reboot, keeps the Test state's flows and their marks.
		s.flushStaleFlows(s.bootDroppedPlan, committed.Materialization.kernelPlan())
	}
	return true, nil
}

// liveNeedsRollbackOnBoot reports whether the Test state a previous process left is still on the
// router, so boot must undo it rather than forget it. The additive converge that follows a discard
// cannot: it re-executes the committed plan with its removals stripped. On OpenWrt every UCI write of
// the Test was committed to flash as it was made, so after a reboot the committed plan's preflight
// found the Test's values, refused at native prepare — before the core step, so no sing-box — and
// the Test's own interfaces stayed as unrecorded orphans. A daemon restart, on any platform, leaves
// all of the Test running. Only a Keenetic reboot loses it all (NDM starts from startup-config, which
// a Test never writes, and the kernel plane and core do not survive), and there a teardown would name
// interfaces that no longer exist: the discard stays right. Without both boot ids that case cannot
// be told from a restart, and it keeps the discard it always had.
func (s *Server) liveNeedsRollbackOnBoot(live *appliedRevision) bool {
	if live == nil || !live.Materialization.known() || materializationIsDemo(&live.Materialization) ||
		s.config().Demo || s.routingIsOff() {
		return false
	}
	keenetic := s.detectedPlatform() == platform.Keenetic
	if target := live.Materialization.nativeTarget(); target != nil {
		keenetic = keenetic || target.Platform == platform.Keenetic
	}
	if !keenetic {
		return true
	}
	now := s.bootID()
	return live.BootID != "" && now != "" && live.BootID == now
}

// rollbackLiveOnBoot ends the Test window the previous process left open the way the window's own
// rollback would have, retried once like converge. Only a rollback that worked drops the live state:
// after a failure the record still names what is left to undo, and Roll back retries it.
func (s *Server) rollbackLiveOnBoot(ctx context.Context, live *appliedRevision) {
	for attempt := 1; attempt <= 2; attempt++ {
		if ctx.Err() != nil {
			return
		}
		done, err := s.rollbackLiveOnBootOnce(ctx, live)
		if done {
			return
		}
		log.Printf("apply: rolling back the unsaved state %s failed (attempt %d): %v", live.Rev, attempt, err)
		if attempt == 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(applyConvergeRetry):
			}
		}
	}
}

func (s *Server) rollbackLiveOnBootOnce(ctx context.Context, live *appliedRevision) (bool, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	// Re-read under the lock: an Apply, Roll back or the routing switch that ran since this process
	// started has replaced the record, and what it did is what the router runs now.
	if s.routingIsOff() {
		return true, nil
	}
	if s.liveRevision() != live {
		if s.committedRevision() != live {
			return true, nil
		}
		// Keep made this very revision the committed one before boot got to it. Keep only records
		// and persists: returning here left a Test cut short by an OpenWrt reboot with its UCI on
		// flash but no sing-box and no kernel plane, and nothing else converges after boot. The
		// committed revision is now the one to converge to, as boot does for any other.
		if err := s.convergeLocked(ctx, live); err != nil {
			return false, err
		}
		log.Printf("apply: converged to %s, kept since this process started", live.Rev)
		return true, nil
	}
	s.setStage("converge")
	defer s.setStage("")
	if plane, err := s.rollbackTo(ctx, s.productionExecOps(), s.committedRevision(), &live.Materialization); err != nil {
		// Keep the record and mark it with how far it got: the reconcile loop must keep the plane the
		// rollback left rather than reinstall the Test's over a committed one, or the committed one
		// under the Test's core; and Keep must not save a half-undone Test.
		s.noteRollbackFailed(live, plane, err)
		return false, err
	}
	s.recordRollback()
	log.Printf("apply: rolled the unsaved state %s back to the committed configuration", live.Rev)
	return true, nil
}

// converge executes one revision's materialization as the boot/reconcile baseline: retire lists
// and native removals are cleared (they were applied when the revision went in) so the run is
// purely additive and idempotent.
func (s *Server) converge(ctx context.Context, rev *appliedRevision) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	return s.convergeLocked(ctx, rev)
}

// convergeLocked is converge for a caller that already holds applyMu (the routing switch).
func (s *Server) convergeLocked(ctx context.Context, rev *appliedRevision) error {
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
	if s.applyInProgress.Load() || s.config().Demo || s.routingIsOff() {
		return
	}
	if !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	// Re-read under the lock: the switch holds applyMu while it turns routing off, so a tick that
	// passed the check above just before it may only now get the lock.
	if s.routingIsOff() {
		return
	}
	// Also read under the lock: a rollback that failed while this tick waited marks the record before
	// it lets go of applyMu, and a baseline read before that still named the Test it was undoing.
	base := s.supervisedBaseline()
	if base == nil || !base.Materialization.known() || base.Materialization.Kernel.Action != ExecutionEnsurePresent {
		return
	}
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
	select {
	case <-tickCtx.Done():
		return
	case <-time.After(applyReconcileSettle):
	}
	if err := ops.kernelPostcheck(tickCtx, kernel); err == nil {
		s.markKernelPlane(kernelPlanePresent) // a firmware rebuild in progress; its hook restored the plane
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

// convergeAfterInstall re-executes the applied materialization once an engine the plan expects has
// arrived. It answers "the binary is here now — make the router match what was applied", which is the
// same question boot convergence answers, so it is the same code path.
//
// Reports false (with no error) when there is nothing to converge to: no applied revision, a record
// that predates the materialization, a demo instance, a Test whose rollback is outstanding, or a plan
// that does not run a core at all. In that last case the install genuinely changed nothing about the
// datapath, and saying so is better than re-executing a plan for effect.
func (s *Server) convergeAfterInstall(ctx context.Context) (bool, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	// Routing switched off: the binary is here, and it stays unused until routing is switched on.
	// Read under applyMu, which the switch holds while it turns routing off.
	if s.routingIsOff() {
		return false, nil
	}
	// What was applied is the Test while a window is open: converging the committed revision ran its
	// core and plane under a record and a panel that named the Test, and Keep then saved the Test
	// (QA-142). A Test whose rollback failed part way runs as neither; Roll back finishes it.
	base := s.appliedBaseline()
	if base == nil || !base.Materialization.known() || s.liveRollbackFailed() != nil {
		return false, nil
	}
	if s.config().Demo || materializationIsDemo(&base.Materialization) {
		return false, nil
	}
	if base.Materialization.Core.Action != ExecutionEnsurePresent {
		return false, nil
	}
	if err := s.convergeLocked(ctx, base); err != nil {
		return false, err
	}
	return true, nil
}
