package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"wayhop/internal/nativeplan"
)

// The routing switch turns WayHop's routing off and back on without touching its configuration.
//
// Off means the router routes as if WayHop were not installed: everything WayHop CAPTURES or
// STEERS traffic with is removed, so every LAN client goes out through the router's own WAN.
//
//   - sing-box is stopped. It is the capture engine: its TUN, the auto_route rules and the
//     auto_redirect table it installs, its DNS hijack and every proxy outbound go with it (a
//     Keenetic compatibility TUN, wrtun0, is a capture device in the same sense).
//   - The kernel plane is torn down: the nftables table, the fwmark ip rules and per-egress tables
//     on OpenWrt; the ipset/iptables marks, the DNS REDIRECT and the DoT/DoH refusals, the
//     netfilter.d re-assert hook and the dnsmasq ipset= file on KeeneticOS (whose resolver is then
//     restarted). The redirect and the refusals sit in chains NDM owns, so the teardown deletes
//     them by name whatever the plane's own switches were; for a plane recorded before it did
//     (QA-114) the executor adds those deletes from the plane's own program
//     (keeneticTeardownProgram).
//   - A native plan's routing is removed and its tunnels are kept: on KeeneticOS its `ip route`s go
//     and the `ip global` ladder is lowered below the router's own connections, then saved so a
//     reboot does not bring them back from flash; OpenWrt tunnels carry no routes of their own.
//
// Kept, deliberately: the tunnels WayHop owns (native WireguardN / wr_* interfaces and the
// AmneziaWG engine plugin). They stay up and carry nothing, so switching on is a commit rather
// than a reconnect. Nothing WayHop does not own is touched — the only router-owned settings edited
// are the `ip global` numbers WayHop itself raised. The panel, the bot, health checks and the
// engine supervisor keep running.
//
// On restores exactly the COMMITTED configuration: the materialization recorded in apply-state.json,
// re-executed the way boot does (converge). Saved-but-unapplied edits stay pending, and an Apply is
// refused while routing is off (it would switch routing back on as a side effect).
//
// The state is persisted in apply-state.json (see applyStateRecord.RoutingOff) BEFORE anything is
// removed, so a daemon that dies half way boots into the off state and finishes the job, and every
// loop that would "repair" routing reads it: boot converge, the kernel-plane reconcile, the routing
// lists' failover, the post-install converge, the package manager's core restore, and the fail-safe
// (whose window is disarmed). Turning routing off works with a crashed core or a broken saved
// configuration: it never generates anything, it only removes what the record says was installed,
// and each part is removed whatever happened to the one before. Every failure is reported and kept
// in the record (the panel's banner shows it); switching on that fails removes what it restored, so
// the router is never left half way.

// Who switched routing; recorded and shown.
const (
	routingByPanel    = "panel"
	routingByTelegram = "telegram"
)

// routingSwitchTimeout bounds one switch. The switch runs detached from the request that asked for
// it: a closed browser tab must not leave the router half way through.
const routingSwitchTimeout = 2 * time.Minute

// routingBootRetry is how long the boot re-assertion waits before its one retry (NDM's CLI can be
// unreachable for a while after KeeneticOS starts).
const routingBootRetry = 30 * time.Second

// Routing switch codes.
const (
	routingCodeOff        = "ROUTING_OFF"
	routingCodeIncomplete = "ROUTING_INCOMPLETE"
)

// routingOffRecord is the persisted off state. Published values are immutable: changes replace it.
type routingOffRecord struct {
	At int64  `json:"at"`
	By string `json:"by"`
	// Rev is the committed revision switching on restores, for display; switching on always reads
	// the record's committed revision at that moment.
	Rev string `json:"rev,omitempty"`
	// Leftover is the unsaved (Test) state that ran when routing was switched off. Its routing was
	// removed with the rest and its window closed; switching on reconciles it away (as a rollback
	// would) so the tunnels only it created do not outlive it.
	Leftover *appliedRevision `json:"leftover,omitempty"`
	// Error is why the last attempt to remove or restore routing did not fully succeed; "" = clean.
	Error string `json:"error,omitempty"`
}

// routingSwitchView is the switch as the panel and the bot see it.
type routingSwitchView struct {
	Enabled bool   `json:"enabled"`
	Since   int64  `json:"since,omitempty"`
	By      string `json:"by,omitempty"`
	Error   string `json:"error,omitempty"`
	// Restorable says a committed configuration exists for switching on to restore.
	Restorable bool `json:"restorable"`
}

func (s *Server) routingOffRecord() *routingOffRecord {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	return s.stateLocked().RoutingOff
}

// routingIsOff reports whether WayHop's routing is switched off.
func (s *Server) routingIsOff() bool { return s.routingOffRecord() != nil }

func (s *Server) routingSwitchView() routingSwitchView {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	v := routingSwitchView{Enabled: rec.RoutingOff == nil,
		Restorable: rec.Committed != nil && rec.Committed.Materialization.known()}
	if off := rec.RoutingOff; off != nil {
		v.Since, v.By, v.Error = off.At, off.By, off.Error
	}
	return v
}

// publishRoutingOff records off as the switch's state. dropLive also takes the unsaved (Test) state
// out of the record — the caller has moved it into off.Leftover. Returns the persistence failure,
// "" when the record reached the disk.
func (s *Server) publishRoutingOff(off *routingOffRecord, dropLive bool) string {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	rec.RoutingOff = off
	if dropLive {
		rec.Live = nil
		rec.RollbackOutstanding = nil
		rec.InFlight = nil
	}
	s.persistLocked()
	return s.applyState.saveErr
}

// publishRoutingOn clears the switch. Returns the persistence failure, "" when it reached the disk.
func (s *Server) publishRoutingOn() string {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	s.stateLocked().RoutingOff = nil
	s.persistLocked()
	return s.applyState.saveErr
}

// withRoutingError is off with its Error replaced.
func withRoutingError(off *routingOffRecord, msg string) *routingOffRecord {
	next := *off
	next.Error = msg
	return &next
}

// setRouting switches WayHop's routing on (enabled) or off, for the panel and the bot alike. It
// answers with the switch's state afterwards, and an error the caller reports as it stands.
func (s *Server) setRouting(ctx context.Context, enabled bool, by string) (routingSwitchView, *applyError) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), routingSwitchTimeout)
	defer cancel()
	if !s.lockApply(ctx) {
		return s.routingSwitchView(), &applyError{Status: http.StatusServiceUnavailable, Code: applyCodeBusy,
			Message: "an Apply is still running", Remedy: "Wait for it to finish and try again."}
	}
	defer s.applyMu.Unlock()
	defer s.setStage("")
	var err *applyError
	if enabled {
		err = s.routingOnLocked(ctx, by)
	} else {
		err = s.routingOffLocked(ctx, by)
	}
	return s.routingSwitchView(), err
}

// routingOffLocked switches routing off. Switching off what is already off runs the removal again,
// which is how a removal that failed part way is retried. Caller holds applyMu.
func (s *Server) routingOffLocked(ctx context.Context, by string) *applyError {
	s.setStage("routing_off")
	// No fail-safe window may outlive this. Its rollback would re-install the committed configuration
	// — what is being removed — and its check, armed for a core this stops, would read the stop as
	// an outage and escalate towards a reboot. Disarm supersedes its epoch, so a rollback already
	// dispatched and waiting for applyMu skips when it gets it.
	if s.failsafe != nil && s.failsafe.Disarm() {
		log.Printf("routing: the fail-safe window was closed — routing is being switched off")
	}
	prev := s.routingOffRecord()
	live := s.liveRevision()
	committed := s.committedRevision()
	off := &routingOffRecord{At: time.Now().Unix(), By: by}
	if prev != nil {
		off.At, off.By, off.Leftover = prev.At, prev.By, prev.Leftover
	}
	if live != nil {
		off.Leftover = live
	}
	if committed != nil {
		off.Rev = committed.Rev
	}
	// The intent goes to disk before anything is removed (see the file comment).
	saveErr := s.publishRoutingOff(off, true)
	if !s.config().Demo {
		err := removeRouting(ctx, s.productionExecOps(), off.Leftover, committed)
		s.markKernelPlane(kernelPlaneUnknown)
		if err != nil {
			msg := err.Error()
			s.publishRoutingOff(withRoutingError(off, msg), false)
			log.Printf("routing: switched off by %s, but part of WayHop's routing could not be removed: %v", by, err)
			s.alert("⚠️ WayHop: routing was switched off (" + by + "), but part of it could not be removed: " + outputTail(msg, 300))
			return &applyError{Status: http.StatusInternalServerError, Code: routingCodeIncomplete,
				Message: "routing is switched off, but part of WayHop's routing could not be removed",
				Detail:  outputTail(msg, 2048),
				Remedy:  "Read the detail, then switch routing off again to retry; until it succeeds some traffic may still follow WayHop's routes."}
		}
		if prev != nil && prev.Error != "" {
			saveErr = s.publishRoutingOff(off, false)
		}
		// With the plane gone a tunnel-marked flow would leave by the WAN under its tunnel's NAT
		// binding, dead but kept alive by its own retries; drop it so it reconnects.
		was := off.Leftover
		if was == nil {
			was = committed
		}
		if was != nil {
			s.flushStaleFlows(was.Materialization.kernelPlan(), nil)
		}
	}
	log.Printf("routing: switched off by %s — the router routes on its own", by)
	if prev == nil {
		s.alert("WayHop: routing was switched off (" + by + ") — all traffic goes straight out through the WAN.")
	}
	if saveErr != "" {
		return &applyError{Status: http.StatusInternalServerError, Code: routingCodeIncomplete,
			Message: "routing is switched off, but the switch could not be recorded — a restart would switch it back on",
			Detail:  saveErr, Remedy: "Free space in the configuration directory, then switch routing off again."}
	}
	return nil
}

// routingOnLocked switches routing back on: the committed configuration is re-executed and the
// switch is cleared. On failure everything the attempt restored is removed again and the switch
// stays off with the reason. Caller holds applyMu.
func (s *Server) routingOnLocked(ctx context.Context, by string) *applyError {
	off := s.routingOffRecord()
	if off == nil {
		return nil // already on
	}
	s.setStage("routing_on")
	committed := s.committedRevision()
	ops := s.productionExecOps()
	committedRuns := committed != nil && committed.Materialization.known() &&
		!materializationIsDemo(&committed.Materialization)
	leftover := off.Leftover != nil && off.Leftover.Materialization.known() &&
		!materializationIsDemo(&off.Leftover.Materialization)
	var leftoverErr error
	if !s.config().Demo && (committedRuns || leftover) {
		var err error
		if leftover {
			// A Test state was running when routing went off: the committed configuration goes back
			// over it the way a rollback does, so the tunnels only the tested one created are retired
			// (with no committed configuration at all, that is all of them).
			if _, err = s.rollbackTo(ctx, ops, committed, &off.Leftover.Materialization); err != nil && onlyNativeLeftover(err) {
				// The committed configuration runs; only the Test's own router-native objects could not
				// be removed. Keeping routing off for that left no way out: an Apply is refused while
				// it is off, and every switch-on retried the same removal. Routing goes on and the
				// leftover stays on record as an outstanding rollback, which Roll back retries.
				leftoverErr, err = err, nil
			}
		} else if err = s.convergeLocked(ctx, committed); err == nil && committedRuns {
			s.flushStaleFlows(nil, committed.Materialization.kernelPlan())
		}
		if err != nil {
			msg := "routing could not be switched back on: " + err.Error()
			if rmErr := removeRouting(ctx, ops, off.Leftover, committed); rmErr != nil {
				msg += "; removing what was restored failed as well: " + rmErr.Error()
			} else {
				msg += " — WayHop's routing was removed again, so the router keeps routing on its own"
			}
			s.markKernelPlane(kernelPlaneUnknown)
			s.publishRoutingOff(withRoutingError(off, msg), false)
			log.Printf("routing: %s (asked by %s)", msg, by)
			return &applyError{Status: http.StatusInternalServerError, Code: applyCodeApplyFailed,
				Message: "routing could not be switched back on; it stays off",
				Detail:  outputTail(err.Error(), 2048),
				Remedy:  "Fix the cause named in the detail (a missing engine can be reinstalled from Components) and switch routing on again."}
		}
		// The native state the commit just put back becomes the startup configuration again. A failure
		// here leaves routing on and working; a reboot would only boot into the off state's native
		// config, which the next boot converge then corrects.
		var target *nativeplan.Plan
		if committedRuns {
			target = committed.Materialization.nativeTarget()
		}
		if target != nil && ops.nativeRoutingSave != nil {
			if err := ops.nativeRoutingSave(ctx, *target); err != nil {
				log.Printf("routing: switched on, but the router-native configuration could not be saved: %v", err)
			}
		}
	}
	saveErr := s.publishRoutingOn()
	note := ""
	if leftoverErr != nil {
		// Status and the bot show the mark, and Keep is refused, as after any rollback that failed part way.
		s.noteLiveRollbackOutstanding(off.Leftover, rollbackPlaneCommitted, leftoverErr)
		note = " Part of the test configuration left from before could not be removed (" +
			outputTail(leftoverErr.Error(), 300) + "); Roll back retries it."
	}
	if saveErr != "" {
		log.Printf("routing: switched on, but the switch could not be recorded (%s) — a restart would switch it off again", saveErr)
		return &applyError{Status: http.StatusInternalServerError, Code: routingCodeIncomplete,
			Message: "routing is switched on, but the switch could not be recorded — a restart would switch it off again",
			Detail:  saveErr, Remedy: "Free space in the configuration directory, then switch routing on again."}
	}
	log.Printf("routing: switched on by %s%s", by, note)
	s.alert("WayHop: routing was switched back on (" + by + ")." + note)
	return nil
}

// removeRouting takes WayHop's capture and policy routing off the router: the core (and with it
// its TUN), then, for each revision that may have left routing behind (the leftover Test state
// first, then the committed one), its kernel plane and its native routing. Plugins and native
// interfaces are left running. Every part is removed whatever happened to the one before — a
// crashed core or an unreadable plane does not keep the rest in place — and the failures are joined.
func removeRouting(ctx context.Context, ops applyExecOps, revs ...*appliedRevision) error {
	var errs []error
	if ops.core == nil {
		errs = append(errs, errors.New("stop sing-box: the core adapter is unavailable"))
	} else if err := ops.core(ctx, executionCoreArtifactV1{Action: ExecutionEnsureAbsent}); err != nil {
		errs = append(errs, fmt.Errorf("stop sing-box: %w", err))
	}
	for _, rev := range revs {
		if rev == nil {
			continue
		}
		m := &rev.Materialization
		if materializationIsDemo(m) {
			continue
		}
		if !m.known() {
			errs = append(errs, fmt.Errorf("the applied configuration %s predates WayHop's apply record, so the kernel routing it may have installed is not known and was not removed — apply once with routing on to bring the record up to date", rev.Rev))
			continue
		}
		if m.Kernel.Action == ExecutionEnsurePresent {
			if ops.kernelTeardown == nil {
				errs = append(errs, errors.New("kernel routing plane: the kernel adapter is unavailable"))
			} else if err := ops.kernelTeardown(ctx, m.Kernel); err != nil {
				errs = append(errs, fmt.Errorf("kernel routing plane: %w", err))
			} else if ops.resolverReload != nil {
				if err := ops.resolverReload(ctx, m.Kernel); err != nil {
					errs = append(errs, fmt.Errorf("restart the resolver: %w", err))
				}
			}
		}
		if target := m.nativeTarget(); target != nil {
			if ops.nativeRoutingOff == nil {
				errs = append(errs, errors.New("router-native routing: this daemon has no native (UCI/NDM) adapter"))
				continue
			}
			changed, err := ops.nativeRoutingOff(ctx, *target)
			if err != nil {
				errs = append(errs, fmt.Errorf("router-native routing: %w", err))
			}
			if changed && ops.nativeRoutingSave != nil {
				if err := ops.nativeRoutingSave(ctx, *target); err != nil {
					errs = append(errs, fmt.Errorf("save the router-native configuration: %w", err))
				}
			}
		}
	}
	if ops.coreRunning != nil && ops.coreRunning() {
		errs = append(errs, errors.New("sing-box is still running"))
	}
	return errors.Join(errs...)
}

// enforceRoutingOffOnBoot re-asserts the off state when the daemon starts with routing switched off:
// nothing is converged, and whatever of WayHop's routing the router still carries (a plane a crash
// left half removed, a native state a reboot brought back from flash) is removed. Idempotent: on a
// router already in the off state it changes nothing. Retried once; never fatal.
func (s *Server) enforceRoutingOffOnBoot(ctx context.Context) {
	if s.config().Demo {
		log.Printf("routing: switched off — not converging (demo: nothing to remove)")
		return
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if ctx.Err() != nil {
			return
		}
		err := s.reassertRoutingOff(ctx)
		if err == nil {
			log.Printf("routing: switched off — not converging; the router routes on its own")
			return
		}
		log.Printf("routing: switched off, but re-asserting it failed (attempt %d): %v", attempt, err)
		if attempt == 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(routingBootRetry):
			}
		}
	}
}

// reassertRoutingOff is one pass of enforceRoutingOffOnBoot, under applyMu.
func (s *Server) reassertRoutingOff(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	off := s.routingOffRecord()
	if off == nil {
		return nil // switched on meanwhile
	}
	tctx, cancel := context.WithTimeout(ctx, routingSwitchTimeout)
	defer cancel()
	err := removeRouting(tctx, s.productionExecOps(), off.Leftover, s.committedRevision())
	s.markKernelPlane(kernelPlaneUnknown)
	switch {
	case err != nil:
		s.publishRoutingOff(withRoutingError(off, err.Error()), false)
	case off.Error != "":
		s.publishRoutingOff(withRoutingError(off, ""), false)
	}
	return err
}

// handleRoutingSwitchGet is GET /api/routing/switch.
func (s *Server) handleRoutingSwitchGet(w http.ResponseWriter, _ *http.Request) {
	writeJSONNoStore(w, http.StatusOK, map[string]any{"routing": s.routingSwitchView()})
}

// handleRoutingSwitchSet is POST /api/routing/switch with {"enabled": true|false}. Session and CSRF
// are enforced by the route table and the middleware like every other mutation.
func (s *Server) handleRoutingSwitchSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.Enabled == nil {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"code": applyCodeInvalidRequest,
			"error": `the body must be {"enabled": true} or {"enabled": false}`})
		return
	}
	view, err := s.setRouting(r.Context(), *body.Enabled, routingByPanel)
	if err != nil {
		resp := err.body()
		resp["routing"] = view
		writeJSONNoStore(w, err.Status, resp)
		return
	}
	writeJSONNoStore(w, http.StatusOK, map[string]any{"routing": view})
}
