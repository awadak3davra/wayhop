package server

import (
	"context"
	"log"
	"os/exec"
	"sync/atomic"
	"time"

	"wayhop/internal/failsafe"
	"wayhop/internal/netdiag"
)

// armFailSafe starts the rollback window after a Test (unsaved) Apply of live: it pings the
// configured target, restores the committed configuration if connectivity is lost, and (only when
// opted in, on-device) reboots as a last resort. Caller holds applyMu.
func (s *Server) armFailSafe(live *appliedRevision) {
	if s.failsafe == nil {
		return
	}
	c := s.config()
	// This window's epoch (set by ArmHealth below). The rollback/reboot closures capture it and
	// skip if a newer Apply has superseded this window — see the rollback closure. atomic: Arm
	// starts run() (which can reach the closures) before this Store returns.
	var myEpoch atomic.Int64
	target := c.FailSafe.Target
	if target == "" {
		target = "1.1.1.1"
	}
	// The core is only part of the connectivity picture when this materialization runs it. A
	// native-only datapath keeps sing-box intentionally stopped and the ping through the kernel
	// plane / native tunnels is the authoritative signal.
	coreExpected := live != nil && live.Materialization.Core.Action == ExecutionEnsurePresent && !c.Demo
	check := func() failsafe.Health {
		// The routing brain must be up for a bare ping to mean anything: the ping target is often
		// statically routed OUTSIDE sing-box (1.1.1.1 pinned to a kernel interface for DoH), so a ping
		// succeeds even after a new config CRASHED sing-box. Treat "installed but down" as a
		// connectivity failure so the bad config is rolled back.
		if coreExpected && s.singbox != nil && !routingBrainUp(s.singbox.Available(), s.singbox.Running()) {
			return failsafe.HealthDown
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		p := netdiag.Ping(ctx, target, 2)
		if !p.Ran {
			// The probe never produced a measurement — no ping binary on this PATH, an invalid
			// target, a timeout. Reporting that as lost connectivity would roll the configuration
			// back and then reboot a router whose internet is fine. Say nothing was learned; the
			// window holds and the user still has Keep and Roll back.
			log.Printf("fail-safe: connectivity check could not run (%s) — holding, not counting this as a failure", p.Output)
			return failsafe.HealthUnknown
		}
		if p.Ok {
			return failsafe.HealthUp
		}
		return failsafe.HealthDown
	}
	rollback := func() error {
		// Serialize against Apply/confirm/converge under applyMu. DEADLOCK-SAFE: this closure runs
		// ONLY from goroutines that do NOT hold applyMu — the failsafe run() loop and RollbackNow —
		// and Apply never waits on it (Arm just starts the goroutine).
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		// applyMu serializes this rollback against Apply's arm, so the epoch check is authoritative:
		// if a newer Apply superseded this window while we were blocked on the lock, its Arm already
		// bumped the epoch — skip, or we'd restore a config the user just replaced.
		if !s.failsafe.IsCurrent(myEpoch.Load()) {
			log.Printf("fail-safe: a newer Apply superseded this window — skipping the stale rollback")
			return nil
		}
		log.Printf("fail-safe: connectivity lost — restoring the committed configuration")
		// Notify (fire-and-forget, async) so a remote operator learns their Apply was auto-reverted.
		s.alert("⚠️ WayHop fail-safe: connectivity was lost after Apply — rolled back to the previous configuration.")
		liveNow := s.liveRevision()
		var failed *executionMaterializationV1
		if liveNow != nil {
			failed = &liveNow.Materialization
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		err := s.rollbackTo(ctx, s.productionExecOps(), s.committedRevision(), failed)
		// The router runs the committed configuration again (or nothing of WayHop's), so the record
		// must not keep claiming the tested revision is active — /api/state goes back to "pending".
		s.recordRollback()
		return err
	}
	reboot := func() {
		if !s.failsafe.IsCurrent(myEpoch.Load()) {
			return // a newer Apply superseded this window — don't reboot on its behalf
		}
		log.Printf("fail-safe: still no connectivity after rollback — rebooting router")
		s.alert("⚠️ WayHop fail-safe: no connectivity even after rollback — rebooting the router.")
		_ = exec.Command("reboot").Start()
	}
	allowReboot := !c.Demo && c.FailSafe.AutoReboot
	myEpoch.Store(s.failsafe.ArmHealth(check, rollback, reboot, allowReboot))
}

// routingBrainUp reports whether sing-box is in a state where the fail-safe's connectivity ping
// reflects the routing brain's health. It is false only when sing-box is installed (available) but
// not running — a crashed core that a ping routed outside sing-box would otherwise miss. With no
// core at all (demo, available=false) the ping alone is the signal, as before.
func routingBrainUp(available, running bool) bool {
	return !available || running
}
