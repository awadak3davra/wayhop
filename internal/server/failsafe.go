package server

import (
	"context"
	"log"
	"net/http"
	"os/exec"
	"sync/atomic"
	"time"

	"wayhop/internal/failsafe"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
)

// failSafeReachURL is what the fail-safe fetches through the default exit: the same no-content page
// groups test their members with, so it adds no new place the router talks to.
const failSafeReachURL = "http://cp.cloudflare.com/generate_204"

// armFailSafe starts the rollback window after a Test (unsaved) Apply of live: it pings the
// configured target, restores the committed configuration if connectivity is lost, and (only when
// opted in, on-device) reboots as a last resort. Caller holds applyMu.
// failSafeHealth judges one fail-safe check from the ping and, where the default route is a tunnel the
// core carries, a request sent out through it.
//
// The ping alone often leaves outside the core: ICMP is not captured, and the target may be pinned to
// the WAN. Measured on an emulated OpenWrt in hybrid mode, the default route through a WireGuard whose
// server never answered: devices had neither HTTP nor DNS, the ping answered all window long, and the
// window closed with the household offline and "live, not saved" on the banner.
func failSafeHealth(p netdiag.PingResult, coreExpected bool, exitTag string, reach func(string) (ok, ran bool)) failsafe.Health {
	if !p.Ran {
		// The probe never produced a measurement — no ping binary on this PATH, an invalid
		// target, a timeout. Reporting that as lost connectivity would roll the configuration
		// back and then reboot a router whose internet is fine. Say nothing was learned; the
		// window holds and the user still has Keep and Roll back.
		log.Printf("fail-safe: connectivity check could not run (%s) — holding, not counting this as a failure", p.Output)
		return failsafe.HealthUnknown
	}
	if !p.Ok {
		return failsafe.HealthDown
	}
	if exitTag != "" && coreExpected && reach != nil {
		// Only a request that went out and got nothing counts. One that could not be sent (no probe
		// inbound in a config applied before it existed) says nothing, as a ping that never ran.
		if ok, ran := reach(exitTag); ran && !ok {
			log.Printf("fail-safe: the ping answered, but nothing came back through the default exit %s", exitTag)
			return failsafe.HealthDown
		}
	}
	return failsafe.HealthUp
}

// failSafeDefaultExit is the exit the profile's default rule sends traffic to, when that is a tunnel or
// a group; "" for the provider's line and for a block, which a request through it cannot judge.
func failSafeDefaultExit(p model.Profile) string {
	for _, r := range p.Rules {
		if !r.Default {
			continue
		}
		switch r.Outbound {
		case "", model.OutboundDirect, model.OutboundBlock:
			return ""
		}
		return r.Outbound
	}
	return ""
}

// reachThroughExit fetches a no-content page through one exit of the running core, the way a device's
// request would leave. ran is false when the core's config has no probe inbound or no user for the exit.
func (s *Server) reachThroughExit(tag string) (ok, ran bool) {
	probe, have := runningProbeInbound(s.config().SingBox.Config)
	if !have {
		return false, false
	}
	pw, have := probe.users[generator.ProbeUser(tag)]
	if !have {
		return false, false
	}
	c, _, _, why := probeCoreClient(tag, pw, probe.port, true)
	if c == nil || why != "" {
		return false, false
	}
	resp, err := c.Get(failSafeReachURL)
	if err != nil {
		return false, true
	}
	resp.Body.Close()
	return resp.StatusCode < http.StatusInternalServerError, true
}

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
	// The core is only part of the connectivity picture when the configuration that runs now runs it.
	// A native-only datapath keeps sing-box intentionally stopped and the ping through the kernel
	// plane / native tunnels is the authoritative signal. Read at each check from the record rather
	// than fixed from the tested materialization: after this window's rollback the committed
	// configuration runs, and one that runs no core by design read as an outage at every later check,
	// so the window never closed as recovered and, with auto-reboot on, rebooted the router (QA-143).
	// A rollback that failed part way left what supervisedBaseline says: the Test while it never got
	// to its kernel step, the committed configuration once it did, and neither when that step failed,
	// where the ping alone decides. Judging the committed configuration whatever the rollback reached
	// read a native-only Test that a failed Roll back left running as a stopped core, and escalated a
	// window whose every ping answered.
	coreExpected := func() bool {
		if live == nil || c.Demo {
			return false
		}
		runs := s.supervisedBaseline()
		return runs != nil && runs.Materialization.Core.Action == ExecutionEnsurePresent
	}
	ping := netdiag.Ping
	if s.failSafePingOf != nil {
		ping = s.failSafePingOf
	}
	reach := s.reachThroughExit
	if s.failSafeReachOf != nil {
		reach = s.failSafeReachOf
	}
	// Where the household's traffic goes by default in the configuration this window tests.
	exitTag := failSafeDefaultExit(s.store.Profile())
	check := func() failsafe.Health {
		// The routing brain must be up for a bare ping to mean anything: the ping target is often
		// statically routed OUTSIDE sing-box (1.1.1.1 pinned to a kernel interface for DoH), so a ping
		// succeeds even after a new config CRASHED sing-box. Treat "installed but down" as a
		// connectivity failure so the bad config is rolled back.
		if s.singbox != nil && !routingBrainUp(s.singbox.Available(), s.singbox.Running()) && coreExpected() {
			return failsafe.HealthDown
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return failSafeHealth(ping(ctx, target, 2), coreExpected(), exitTag, reach)
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
			// Not nil: a skip is not a rollback, and a manual Roll back waiting here must not report one.
			return failsafe.ErrSuperseded
		}
		// The routing switch disarms the window before it turns routing off, which supersedes the
		// epoch above. This is the same answer read from the switch itself, so no later path that
		// forgets to disarm can make a rollback put back the routing the operator removed.
		if s.routingIsOff() {
			log.Printf("fail-safe: WayHop's routing is switched off — skipping the rollback")
			return nil
		}
		// A rollback that worked drops the Test from the record without replacing the window, so a second
		// run queued behind it on applyMu still passed the epoch check: it re-executed the committed
		// configuration over itself, sent a second webhook, and when that redundant run failed, a false
		// "FAILED" and a rollback_failed on the closed window. The record is what says whether there is
		// anything left to undo.
		if live != nil && !sameRevision(s.liveRevision(), live) {
			if sameRevision(s.committedRevision(), live) {
				// Keep made it the committed configuration (its failsafe.Confirm comes after applyMu is
				// released): nothing was rolled back, and nothing may be.
				log.Printf("fail-safe: the tested configuration was kept — skipping the rollback")
				return failsafe.ErrSuperseded
			}
			log.Printf("fail-safe: the tested configuration was already rolled back — nothing left to undo")
			return nil
		}
		// This closure is the window's automatic rollback and the Roll back pressed while it runs; the
		// last connectivity check is what tells them apart for the webhook below.
		st := s.failsafe.Status()
		lost := st.LastCheckAt > 0 && !st.LastCheckOk
		log.Printf("fail-safe: restoring the committed configuration (connectivity lost: %v)", lost)
		// What this window tested, as armed — not re-read from the record. A retry after a failed
		// rollback must undo the same configuration; reading the record made it depend on nothing
		// having cleared Live in between.
		var failed *executionMaterializationV1
		if live != nil {
			failed = &live.Materialization
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		plane, err := s.rollbackTo(ctx, s.productionExecOps(), s.committedRevision(), failed)
		// Notify (fire-and-forget, async) so a remote operator learns what happened to their Apply. Sent
		// once the outcome is known: it used to say "rolled back" before the rollback ran and stayed the
		// only word on a rollback that then failed.
		s.alert(failSafeRollbackAlert(lost, err))
		if err != nil {
			// Keep the record on the tested revision. Dropping it here made the retry (Roll back, or
			// the auto path's escalation) roll back nothing — a teardown of nil, or an additive
			// converge that keeps the Test's native interfaces — and report success over the leftovers,
			// cancelling the reboot fallback; once the window closed, Roll back answered that the
			// committed configuration was running. The mark, with how far the rollback got, keeps the
			// reconcile loop on the plane the rollback left, and stops Keep saving the Test.
			s.noteRollbackFailed(live, plane, err)
			return err
		}
		// The router runs the committed configuration again (or nothing of WayHop's), so the record
		// must not keep claiming the tested revision is active — /api/state goes back to "pending".
		s.recordRollback()
		return nil
	}
	reboot := func() {
		if !s.failsafe.IsCurrent(myEpoch.Load()) {
			return // a newer Apply superseded this window — don't reboot on its behalf
		}
		if s.routingIsOff() {
			return // nothing of WayHop's is routing: a lost connection is not WayHop's to fix
		}
		log.Printf("fail-safe: still no connectivity after rollback — rebooting router")
		s.alert("⚠️ WayHop fail-safe: no connectivity even after rollback — rebooting the router.")
		_ = exec.Command("reboot").Start()
	}
	allowReboot := !c.Demo && c.FailSafe.AutoReboot
	myEpoch.Store(s.failsafe.ArmHealth(check, rollback, reboot, allowReboot))
}

// failSafeRollbackAlert is the webhook's word on a fail-safe window's rollback: what came of it, and
// that connectivity was lost when the last check says so (a Roll back pressed during the window runs
// the same rollback with the connection fine).
func failSafeRollbackAlert(lost bool, err error) string {
	cause := ""
	if lost {
		cause = "connectivity was lost after Apply — "
	}
	if err != nil {
		return "❌ WayHop fail-safe: " + cause + "the rollback to the previous configuration FAILED: " +
			outputTail(err.Error(), 512) + ". Part of the tested configuration may still be running; roll back again to finish it."
	}
	if lost {
		return "⚠️ WayHop fail-safe: " + cause + "rolled back to the previous configuration."
	}
	return "↩️ WayHop fail-safe: the test Apply was rolled back to the previous configuration."
}

// routingBrainUp reports whether sing-box is in a state where the fail-safe's connectivity ping
// reflects the routing brain's health. It is false only when sing-box is installed (available) but
// not running — a crashed core that a ping routed outside sing-box would otherwise miss. With no
// core at all (demo, available=false) the ping alone is the signal, as before.
func routingBrainUp(available, running bool) bool {
	return !available || running
}
