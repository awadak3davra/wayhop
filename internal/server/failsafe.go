package server

import (
	"context"
	"log"
	"net/http"
	"os/exec"
	"sync/atomic"
	"time"

	"wayhop/internal/netdiag"
)

// armFailSafe starts the rollback window after a non-saved Apply: it pings the
// configured target, rolls the config back if connectivity is lost, and (only
// when opted in, on-device) reboots as a last resort.
func (s *Server) armFailSafe(nativeOnly bool) {
	c := s.config()
	// This window's epoch (set by Arm below). The rollback/reboot closures capture it
	// and skip if a newer Apply has superseded this window — see the rollback closure.
	// atomic: Arm starts run() (which can reach the closures) before this Store returns.
	var myEpoch atomic.Int64
	target := c.FailSafe.Target
	if target == "" {
		target = "1.1.1.1"
	}
	check := func() bool {
		// The routing brain must be up for a bare ping to mean anything. The ping
		// target is often statically routed OUTSIDE sing-box — on this router
		// 1.1.1.1 (the default target) is pinned to the awg0 kernel interface for
		// DoH (`ip route get 1.1.1.1` -> dev awg0), so a ping succeeds even after a
		// new config CRASHED sing-box, and the fail-safe would never roll back.
		// Treat "sing-box installed but down" as a connectivity failure so the bad
		// config is rolled back. (Demo / no core keeps the old ping-only behavior.)
		//
		// EXCEPTION — native-only datapath (P4): when the applied profile is native-only,
		// sing-box is intentionally STOPPED (Available && !Running) and the kernel PBR plane
		// is the routing brain. The ping (routed through the kernel plane) IS the authoritative
		// signal, so we must NOT treat the stopped core as a failure — otherwise every
		// native-only "Apply (until reboot)" would auto-roll-back at the rollback deadline.
		if !nativeOnly && !routingBrainUp(s.singbox.Available(), s.singbox.Running()) {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return netdiag.Ping(ctx, target, 2).Ok
	}
	rollback := func() error {
		// Serialize the rollback against handleApply under applyMu: both rewrite the live
		// singbox.json (handleApply via Backup + os.Rename, rollback via Restore) and
		// reload the core, so without a shared lock a rollback firing mid-apply could
		// interleave the file swap + reload and leave a TORN / nondeterministic live
		// config. applyMu already guards handleApply's swap, so it is the right lock.
		// DEADLOCK-SAFE: this closure runs ONLY from goroutines that do NOT hold applyMu —
		// the failsafe run() loop (tick() releases failsafe.mu before run() calls this) and
		// RollbackNow (releases failsafe.mu before invoking it). handleApply never waits on
		// this closure (Arm just starts the goroutine), and the lock order here (applyMu
		// then pbrMu via restore*Baseline, then singbox.mu via the core calls) matches
		// handleApply's, so there is no lock-ordering cycle.
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		// applyMu serializes this rollback against handleApply's apply+Arm, so the epoch
		// check is now authoritative: if a newer Apply superseded this window while we were
		// blocked on the lock, its Arm already bumped the epoch — skip, or we'd restore a
		// config the user just replaced and clobber the fresh Apply.
		if !s.failsafe.IsCurrent(myEpoch.Load()) {
			log.Printf("fail-safe: a newer Apply superseded this window — skipping the stale rollback")
			return nil
		}
		log.Printf("fail-safe: connectivity lost — rolling back to the previous config")
		// Notify (fire-and-forget, async) so a remote operator learns their Apply was
		// auto-reverted — the key event for managing the router from away.
		s.alert("⚠️ WayHop fail-safe: connectivity was lost after Apply — rolled back to the previous config.")
		var sbErr error
		if nativeOnly {
			// #7: native-only baseline — the kernel PBR plane is the routing brain and sing-box was
			// intentionally STOPPED. Do NOT resurrect a redundant TUN core on rollback: layering a
			// capture-all TUN over the restored kernel plane is the exact black-hole the native-only
			// design (and the watchdog TOCTOU fix) exists to prevent. Keep the core DOWN (Stop also
			// clears Desired so the watchdog won't fight it); restorePBRBaseline below re-establishes
			// the real datapath. (config+profile don't change across a non-saved Apply, so this
			// window's nativeOnly verdict is the baseline's too.)
			if s.singbox.Running() {
				sbErr = s.singbox.Stop()
			}
		} else if err := s.singbox.Restore(); err != nil {
			sbErr = err
		} else if s.singbox.Running() {
			sbErr = s.singbox.Reload()
		} else if s.singbox.Available() {
			// The core is down (it likely crashed on the bad config) — start it on the
			// restored config now rather than waiting out the watchdog crash backoff.
			sbErr = s.singbox.Start()
		}
		// Restore the kernel PBR plane to its pre-window baseline too. Best-effort and
		// demo/nil-guarded inside restorePBRBaseline; its error is LOGGED, not returned,
		// so a secondary nft/ip failure can't flip the window to "rollback_failed" when
		// sing-box (the primary connectivity brain) actually recovered.
		s.restorePBRBaseline()
		// Re-Sync the engine plugins (AmneziaWG/olcRTC) to the pre-window set so the
		// restored sing-box config's bind_interface/SOCKS targets are actually up — else
		// the restored config runs a dead tunnel. Best-effort.
		s.restorePluginBaseline()
		return sbErr
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
	myEpoch.Store(s.failsafe.Arm(check, rollback, reboot, allowReboot))
}

// routingBrainUp reports whether sing-box is in a state where the fail-safe's
// connectivity ping reflects the routing brain's health. It is false only when
// sing-box is installed (available) but not running — a crashed core that a ping
// routed outside sing-box would otherwise miss. With no core at all (demo,
// available=false) the ping alone is the signal, as before.
func routingBrainUp(available, running bool) bool {
	return !available || running
}

// handleApplyConfirm commits the live config (user confirmed it works).
func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	_ = s.singbox.Commit()
	s.failsafe.Confirm()
	writeJSON(w, http.StatusOK, map[string]any{"committed": true, "failsafe": s.failsafe.Status()})
}

// handleApplyRollback performs an immediate manual rollback.
func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.failsafe.RollbackNow(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true, "failsafe": s.failsafe.Status()})
}

// handleApplyStatus returns the current fail-safe state (for the countdown UI).
func (s *Server) handleApplyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.failsafe.Status())
}
