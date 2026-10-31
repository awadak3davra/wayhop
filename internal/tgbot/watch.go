package tgbot

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Thresholds of the alert watcher.
const (
	// coreDownAfter: a supervised core that stays down this long is an incident, not a restart.
	coreDownAfter = time.Minute
	// memHighPct for memHighSamples pulses in a row opens the RAM incident; below memOKPct closes it.
	memHighPct     = 92.0
	memOKPct       = 85.0
	memHighSamples = 3
	// diskLowBytes free for diskLowSamples pulses in a row opens the storage incident; diskOKBytes
	// closes it. The low mark is the Diagnostics battery's "critically low" (server/diskspace.go):
	// below it a settings save, an Apply and an update fail.
	diskLowBytes   = 3 << 20
	diskOKBytes    = 5 << 20
	diskLowSamples = 3
	// countdownEvery: how often the test-Apply message's countdown is refreshed.
	countdownEvery = 30 * time.Second
)

// Apply-window states the watcher tracks.
const (
	applyNone    = "none"
	applyTesting = "testing" // the fail-safe window is running
	applyUnsaved = "unsaved" // the window passed; the tested configuration runs but is not saved
)

func applyState(f FailSafePulse) string {
	switch {
	case f.Pending:
		return applyTesting
	case f.Live:
		return applyUnsaved
	}
	return applyNone
}

// watcher turns successive pulses and the failover log into alerts. It is pure apart from the
// status callback: each step returns what changed since the previous one.
type watcher struct {
	primed bool
	prev   Pulse
	// seen holds the log's events already handled, by key. The log is read whole every step and an
	// event is new when its key is not here: its time is no guide to that, since the monitor stamps a
	// probe round's changes with the round's start but appends them after the probes, while "Test
	// now" and the list failover append theirs stamped on the spot. A time mark skipped the round's.
	seen   map[string]bool
	downAt map[string]time.Time
	// swallowed holds the exits whose failure went untold because the uplink was out; their
	// recoveries are part of the same story and go untold too.
	swallowed map[string]bool

	uplinkAt    time.Time // when the current uplink incident began (zero: none)
	coreDownAt  time.Time
	coreAlerted bool
	memHigh     int
	memAlerted  bool
	diskLow     int
	diskAlerted bool
	countdownAt time.Time
	// window is the test Apply the open apply message is about (its Keep / Roll back name it), "" when
	// none is open or its name is not known yet. A second Test inside a running window supersedes it
	// without the window ever closing, and only the name tells the two apart (QA-100).
	window string
	// autoRollback: the running window's fail-safe rolled back by itself. Its window stays pending until
	// the next healthy tick, so by the close the phase no longer tells the fail-safe's rollback from a
	// pressed one: the last check passed and the phase before the close is rolled_back (QA-098).
	autoRollback bool
	// announce: the running window replaced another one at a step whose read still showed the old
	// window's phase and time left, so its own message waits for the next step.
	announce bool
}

func newWatcher() *watcher {
	return &watcher{seen: map[string]bool{}, downAt: map[string]time.Time{}, swallowed: map[string]bool{}}
}

func eventKey(e Event) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s", e.At.UnixMilli(), e.Kind, e.ID, e.From, e.To)
}

// lazyStatus reads the full status at most once per step, and only when an alert needs detail.
type lazyStatus struct {
	get  func() Status
	done bool
	s    Status
}

func (l *lazyStatus) status() Status {
	if !l.done {
		l.done = true
		if l.get != nil {
			l.s = l.get()
		}
	}
	return l.s
}

// step compares p and log with the previous step. The first step only records a baseline: nothing
// that was already true when the bot started is announced as if it had just happened, except an
// outstanding failed rollback (see below).
func (w *watcher) step(now time.Time, p Pulse, log EventLog, status func() Status) []Alert {
	if !w.primed {
		w.primed, w.prev = true, p
		w.markEvents(log.Events)
		if p.LocalFault {
			w.uplinkAt = now
		}
		if p.FailSafe.Pending {
			w.countdownAt = now
			w.window, w.autoRollback = p.FailSafe.Window, p.FailSafe.Phase == "rolled_back"
		}
		// The one exception: a failed rollback the record still waits on is told at the next step. The
		// daemon retries boot's rollback as it starts, so its failure can land before the bot's first
		// look and would never be told; and a restart lost any memory of having told an older one.
		w.prev.FailSafe.RollbackOutstanding = false
		return nil
	}
	snap := &lazyStatus{get: status}
	var out []Alert

	// The uplink first: while every exit is down at once, the exits are not the news.
	switch {
	case !w.prev.LocalFault && p.LocalFault:
		w.uplinkAt = now
		out = append(out, uplinkLost(now))
	case w.prev.LocalFault && !p.LocalFault:
		out = append(out, uplinkBack(now, now.Sub(w.uplinkAt)))
		w.uplinkAt = time.Time{}
	}
	// While every exit is down at once, the exits are not the news. Once the uplink is back, an exit
	// failing is news again straight away: the monitor holds exits' failures back for the whole
	// outage, so one that stays dead is marked down a probe round or two after the internet
	// returned, and a quiet window after the outage used to swallow exactly that tunnel.
	quiet := p.LocalFault || w.prev.LocalFault

	// The routing switch. Switched off, the core is stopped on purpose and every exit it carried fails
	// with it: that is what the operator asked for, not news, so exits stay quiet until the step after
	// routing is back (the monitor needs a probe round to see them up again).
	switch {
	case !w.prev.RoutingOff && p.RoutingOff:
		out = append(out, routingSwitched(now, true))
	case w.prev.RoutingOff && !p.RoutingOff:
		out = append(out, routingSwitched(now, false))
	}
	quiet = quiet || p.RoutingOff || w.prev.RoutingOff

	// A step's failures are told first, then the switches they caused, then the recoveries; several
	// failures or recoveries in one step are one message each (see coalesceMin).
	var downs []Event
	var switchAlerts []Alert
	var ups []upEvent
	for _, e := range w.newEvents(log.Events) {
		switch e.Kind {
		case "down":
			w.downAt[e.ID] = e.At
			if quiet {
				w.swallowed[e.ID] = true
			} else {
				delete(w.swallowed, e.ID)
				downs = append(downs, e)
			}
		case "up":
			var was time.Duration
			if at, ok := w.downAt[e.ID]; ok {
				was = e.At.Sub(at)
				delete(w.downAt, e.ID)
			}
			// A recovery is told when its failure was: one that went untold with the uplink stays
			// untold, whenever it comes back.
			if w.swallowed[e.ID] || quiet {
				delete(w.swallowed, e.ID)
			} else {
				ups = append(ups, upEvent{e, was})
			}
		case "switch":
			switchAlerts = append(switchAlerts, groupSwitch(e, snap.status()))
		}
	}
	out = append(out, exitsDown(downs, snap)...)
	out = append(out, switchAlerts...)
	out = append(out, exitsUp(ups)...)

	out = append(out, w.core(now, p)...)
	out = append(out, w.apply(now, p)...)
	out = append(out, w.memory(now, p)...)
	out = append(out, w.disk(now, p)...)
	w.prev = p
	return out
}

// markEvents records evs, the whole log as read this step, as handled. Keys of events that have
// left the log are forgotten, so the set never outgrows the log.
func (w *watcher) markEvents(evs []Event) {
	seen := make(map[string]bool, len(evs))
	for _, e := range evs {
		seen[eventKey(e)] = true
	}
	w.seen = seen
}

// newEvents returns the log's events not handled yet, oldest first, and marks the log handled.
func (w *watcher) newEvents(evs []Event) []Event {
	var fresh []Event
	for _, e := range evs {
		if !w.seen[eventKey(e)] {
			fresh = append(fresh, e)
		}
	}
	// The log arrives newest first: reversed, it is in append order, which a stable sort by stamp
	// keeps for events stamped alike while putting a late-appended early stamp in its place.
	for i, j := 0, len(fresh)-1; i < j; i, j = i+1, j-1 {
		fresh[i], fresh[j] = fresh[j], fresh[i]
	}
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].At.Before(fresh[j].At) })
	w.markEvents(evs)
	return fresh
}

func (w *watcher) core(now time.Time, p Pulse) []Alert {
	var out []Alert
	if p.Core.Restarts > w.prev.Core.Restarts {
		out = append(out, coreRestarted(now, p.Core, w.prev.Core))
	}
	down := p.Core.Supervised && !p.Core.Alive
	switch {
	case down && w.coreDownAt.IsZero():
		w.coreDownAt = now
	case down && !w.coreAlerted && now.Sub(w.coreDownAt) >= coreDownAfter:
		w.coreAlerted = true
		out = append(out, coreDown(now, now.Sub(w.coreDownAt), p.Core.LastError))
	case !down:
		if w.coreAlerted {
			out = append(out, coreUp(now, now.Sub(w.coreDownAt)))
		}
		w.coreDownAt, w.coreAlerted = time.Time{}, false
	}
	return out
}

func (w *watcher) apply(now time.Time, p Pulse) []Alert {
	from, to := applyState(w.prev.FailSafe), applyState(p.FailSafe)
	f := p.FailSafe
	var out []Alert
	// A failed rollback outside a running window: Roll back pressed after the window closed, or boot's
	// rollback of a Test a restart left. Inside a window its phase tells it (rollback_failed below);
	// these two set nothing else the bot reads, so they went untold, and the "unsaved" message kept
	// offering a Keep the daemon refuses. Told once, when the record first shows it.
	outstanding := to == applyUnsaved && f.RollbackOutstanding && !w.prev.FailSafe.RollbackOutstanding
	// The fail-safe's own rollback, as the window last showed it before this step.
	autoRollback := w.autoRollback
	if to != applyTesting {
		w.window, w.autoRollback, w.announce = "", false, false
	}
	if from == to {
		if to == applyTesting {
			if f.Window != "" && w.window != "" && f.Window != w.window {
				// Another Test was applied inside this one's window, which supersedes it: pending never
				// drops, so this is no open or close, and the countdown re-rendered the old message with the
				// new window's Keep. An owner deciding about the first Test then kept the second, which
				// nobody had asked about (QA-100). The old message is closed without buttons, and the new
				// Test is announced in its own message. A window whose rollback has finished has no name
				// until then (nothing is live), so that is not taken for a new one.
				//
				// The pulse reads the fail-safe before the record, so a Test applied in between is seen
				// once with the old window's phase under the new one's name. rolled_back there is the old
				// window's own rollback, and the old message closes as that; it is not the new window's.
				// Carried over, it made the new Test's later Roll back close as "Connectivity was lost", and
				// the new message was drawn from the old window's time left, 0:00, until the countdown 30 s
				// later. The new Test is announced from the next step's read instead, which is its own.
				out = append(out, w.replacedOutcome(now, f, autoRollback || f.Phase == "rolled_back"))
				w.window, w.autoRollback = f.Window, false
				if f.Phase == "rolled_back" {
					w.announce = true
					return out
				}
				// Any other phase under a new name is the new window's to start with ("armed"): an old
				// window's rollback_failed must not open the new one's message as a failed rollback.
				armed := f
				armed.Phase = "armed"
				w.countdownAt = now
				return append(out, applyArmed(now, armed))
			}
			if w.announce {
				w.announce, w.countdownAt = false, now
				out = append(out, applyArmed(now, f))
			}
			if w.window == "" {
				w.window = f.Window
			}
			if f.Phase == "rolled_back" {
				// Only the fail-safe's own rollback leaves the window pending on rolled_back: a pressed
				// one (RollbackNow, MarkRolledBack) closes it in the same step. The countdown stops (below)
				// but its last edit kept Keep / Roll back until the window closed, and a Roll back pressed
				// meanwhile read "Did not work: a rollback is already in progress" right before the
				// critical alert. The message is redrawn once, without them.
				if !w.autoRollback {
					out = append(out, applyRollingBack(now))
				}
				w.autoRollback = true
			}
			// After a failed Roll back the next tick relabels the phase "degraded": that is not news.
			if f.Phase == "degraded" && w.prev.FailSafe.Phase != "degraded" && !rollbackFailed(f) {
				out = append(out, applyDegraded(now))
			}
			// Phase or record, whichever the bot sees first, and once: the record is marked a moment
			// before the phase, and the phase can be relabelled before the bot looks.
			if rollbackFailed(f) && !rollbackFailed(w.prev.FailSafe) {
				out = append(out, applyRollbackFailed(now, rollbackErrorText(f)))
			}
			// Once the fail-safe has rolled back nothing counts down any more: the countdown said "rolls
			// back by itself in 0:00 unless you keep it" with Keep / Roll back until the window closed.
			if f.Phase != "rolled_back" && now.Sub(w.countdownAt) >= countdownEvery {
				w.countdownAt = now
				out = append(out, applyCountdown(now, f))
			}
		}
		if outstanding {
			out = append(out, applyRollbackOutstanding(now, f.RollbackError, f.Window))
		}
		return out
	}
	// Close what was open. The phase is the window's verdict and is read first: a rollback that failed
	// keeps the tested revision on record (it is what a retry undoes), so such a window closes into the
	// "unsaved" state too, and reading that first told a failed rollback as "the test window passed
	// with the internet up" followed by "runs unsaved, a reboot brings the previous one back". The
	// record's mark counts as much as the phase: after a Roll back that failed inside the window the
	// next connectivity tick relabels the phase (degraded, armed, even an optimistic rolled_back for a
	// rollback the window can no longer dispatch), while the mark stays until the rollback is finished.
	passed, told := false, false
	switch from {
	case applyTesting:
		switch {
		case f.Phase == "reboot":
			// Read before the failed rollback: with auto-reboot on, that is how a failed rollback's window
			// ends, and its mark sent "closed, but the rollback failed, roll back again" instead, never the
			// reboot: the owners were asked to retry on a router going down (on Keenetic the next process
			// drops Live, so that message was never closed). The reboot answers the failed rollback too,
			// so it is not told again below as an outstanding one.
			told = true
			out = append(out, applyClosed(now, "al.apply.reboot", SevCritical, false))
		case rollbackFailed(f):
			told = true
			out = append(out, applyClosedRollbackFailed(now, rollbackErrorText(f), f.Window))
		case f.Phase == "committed":
			out = append(out, applyClosed(now, "al.apply.kept", SevInfo, true))
		case f.Phase == "rolled_back" && (autoRollback || w.prev.FailSafe.Phase == "degraded" || (f.Checked && !f.CheckOK)):
			// The fail-safe rolled back because the connection was lost: loud. Its window usually closes a
			// tick after the rollback, on the check that passed with the previous configuration back, so the
			// phase and the check at the close are a pressed Roll back's; what the window showed before it
			// is the fail-safe's (QA-098).
			out = append(out, applyClosed(now, "al.apply.rolledback", SevCritical, false))
		case f.Phase == "rolled_back":
			// Somebody pressed Roll back (here or in the panel): the outcome, quietly.
			out = append(out, applyClosed(now, "al.apply.reverted", SevInfo, true))
		case to == applyUnsaved:
			passed = true
			out = append(out, applyClosed(now, "al.apply.passed", SevInfo, true))
		default:
			out = append(out, applyClosed(now, "al.apply.ended", SevInfo, true))
		}
	case applyUnsaved:
		if f.Phase == "committed" {
			out = append(out, applyClosed(now, "al.apply.kept", SevInfo, true))
		} else {
			out = append(out, applyClosed(now, "al.apply.reverted", SevInfo, false))
		}
	}
	// Open what began.
	switch to {
	case applyTesting:
		w.countdownAt = now
		w.window, w.autoRollback = f.Window, f.Phase == "rolled_back"
		out = append(out, applyArmed(now, f))
	case applyUnsaved:
		// Only a window that passed leaves the tested configuration running as tested. One that closed
		// on a rollback is not "unsaved, undone by a reboot", and its Keep would be refused.
		switch {
		case outstanding:
			if !told {
				out = append(out, applyRollbackOutstanding(now, f.RollbackError, f.Window))
			}
		case f.RollbackOutstanding:
			// Told when it first showed; Keep would be refused.
		case from != applyTesting || passed:
			out = append(out, applyUnsavedAlert(now, f.Window))
		}
	}
	return out
}

// rollbackErrorText is why the rollback failed: the record's word when it holds one (it outlives the
// window, and a retry outside it updates only the record), else the window's.
func rollbackErrorText(f FailSafePulse) string {
	if f.RollbackOutstanding && f.RollbackError != "" {
		return f.RollbackError
	}
	return f.LastError
}

func (w *watcher) memory(now time.Time, p Pulse) []Alert {
	if !p.Mem.Known {
		return nil
	}
	pct := int(p.Mem.UsedPct + 0.5)
	switch {
	case p.Mem.UsedPct >= memHighPct:
		w.memHigh++
		if w.memHigh >= memHighSamples && !w.memAlerted {
			w.memAlerted = true
			a := simpleAlert(KindSystem, SevWarning, now, func(lang string) string { return T(lang, "al.mem", pct) })
			a.Incident = "mem"
			return []Alert{a}
		}
	case p.Mem.UsedPct < memOKPct:
		w.memHigh = 0
		if w.memAlerted {
			w.memAlerted = false
			a := simpleAlert(KindSystem, SevInfo, now, func(lang string) string { return T(lang, "al.mem.ok", pct) })
			a.Incident, a.Resolves = "mem", true
			return []Alert{a}
		}
	default:
		w.memHigh = 0
	}
	return nil
}

// disk is the storage incident, in the memory's way: a few low pulses in a row open it, and it closes
// only once there is clearly room again, so a log rotating around the mark does not flap.
func (w *watcher) disk(now time.Time, p Pulse) []Alert {
	if !p.Disk.Known {
		return nil
	}
	free := int64(p.Disk.FreeBytes)
	switch {
	case p.Disk.FreeBytes < diskLowBytes:
		w.diskLow++
		if w.diskLow >= diskLowSamples && !w.diskAlerted {
			w.diskAlerted = true
			a := simpleAlert(KindSystem, SevWarning, now, func(lang string) string { return T(lang, "al.disk", Bytes(lang, free)) })
			a.Incident = "disk"
			return []Alert{a}
		}
	case p.Disk.FreeBytes >= diskOKBytes:
		w.diskLow = 0
		if w.diskAlerted {
			w.diskAlerted = false
			a := simpleAlert(KindSystem, SevInfo, now, func(lang string) string { return T(lang, "al.disk.ok", Bytes(lang, free)) })
			a.Incident, a.Resolves = "disk", true
			return []Alert{a}
		}
	default:
		w.diskLow = 0
	}
	return nil
}

func uplinkLost(now time.Time) Alert {
	a := simpleAlert(KindUplink, SevCritical, now, func(lang string) string { return T(lang, "al.uplink") })
	a.Incident = "uplink"
	return a
}

func uplinkBack(now time.Time, was time.Duration) Alert {
	a := simpleAlert(KindUplink, SevInfo, now, func(lang string) string { return T(lang, "al.uplink.back", Duration(lang, was)) })
	a.Incident, a.Resolves = "uplink", true
	return a
}

// coalesceMin: this many exits failing, or coming back, in one step are one message. On a router
// with a subscription a provider's hiccup takes a dozen exits down at once, and a dozen messages
// bury the one that matters. Two are still told apart: each says more than a list line would.
const coalesceMin = 3

// manyLines caps the exits one merged message lists; the rest are counted.
const manyLines = 10

// via is where a group's traffic goes now: through the exit named in now, or nowhere ("").
type via struct{ group, now string }

// groupMoves says, for each group with a member among down, where its traffic goes now, or that
// nothing is left. Only what is known is said: an unknown election with members still up says
// nothing at all.
func groupMoves(s Status, down map[string]bool) []via {
	var moves []via
	for _, g := range s.Groups {
		member, othersUp := false, 0
		for _, m := range g.Members {
			if down[m] {
				member = true
			} else if x, ok := s.ExitByID(m); ok && x.State == StateAlive {
				othersUp++
			}
		}
		switch {
		case !member:
		case g.Elected != "" && !down[g.Elected]:
			moves = append(moves, via{g.Name, exitLabel(s, g.Elected)})
		case othersUp == 0:
			moves = append(moves, via{g.Name, ""})
		}
	}
	return moves
}

func writeMoves(b *strings.Builder, lang string, moves []via) {
	for _, m := range moves {
		if m.now != "" {
			b.WriteString("\n" + T(lang, "al.down.via", esc(m.group), esc(m.now)))
		} else {
			b.WriteString("\n" + T(lang, "al.down.none", esc(m.group)))
		}
	}
}

func eventName(e Event) string {
	if e.Name == "" {
		return e.ID
	}
	return e.Name
}

// exitsDown tells the exits that failed in one step: each on its own, or one message for a burst.
func exitsDown(evs []Event, snap *lazyStatus) []Alert {
	if len(evs) >= coalesceMin {
		return []Alert{manyDown(evs, snap.status())}
	}
	out := make([]Alert, 0, len(evs))
	for _, e := range evs {
		out = append(out, exitDown(e, snap.status()))
	}
	return out
}

// exitDown says which exit fell, why (the monitor's diagnosis), and where the traffic went.
func exitDown(e Event, s Status) Alert {
	name := eventName(e)
	ex, _ := s.ExitByID(e.ID)
	moves := groupMoves(s, map[string]bool{e.ID: true})
	text := func(lang string) string {
		var b strings.Builder
		b.WriteString(T(lang, "al.down", esc(name)))
		cause, fix := causeIn(lang, ex)
		if cause != "" {
			b.WriteString("\n" + T(lang, "ex.cause", esc(cause)))
		}
		if fix != "" {
			b.WriteString("\n" + T(lang, "ex.fix", esc(fix)))
		}
		writeMoves(&b, lang, moves)
		return b.String()
	}
	a := simpleAlert(KindExits, SevWarning, e.At, text)
	a.Incident = "exit:" + e.ID
	return a
}

// manyDown is a burst of failures in one message: the exits with their causes, and what the burst
// left each group with. It opens every exit's incident, so each recovery replies to it.
func manyDown(evs []Event, s Status) Alert {
	type item struct{ name, cause string }
	down := map[string]bool{}
	var items []item
	var incidents []string
	for _, e := range evs {
		if down[e.ID] {
			continue
		}
		down[e.ID] = true
		ex, _ := s.ExitByID(e.ID)
		items = append(items, item{eventName(e), ex.Cause})
		incidents = append(incidents, "exit:"+e.ID)
	}
	moves := groupMoves(s, down)
	text := func(lang string) string {
		var b strings.Builder
		b.WriteString(T(lang, "al.down.many", len(items)))
		for i, it := range items {
			if i == manyLines {
				b.WriteString("\n" + T(lang, "digest.more", len(items)-manyLines))
				break
			}
			b.WriteString("\n• <b>" + esc(it.name) + "</b>")
			if it.cause != "" {
				b.WriteString(" · <i>" + esc(truncate(it.cause, 60)) + "</i>")
			}
		}
		writeMoves(&b, lang, moves)
		return b.String()
	}
	a := simpleAlert(KindExits, SevWarning, evs[0].At, text)
	a.Incidents = incidents
	return a
}

// upEvent is a recovery with how long the exit was down (0: unknown).
type upEvent struct {
	e   Event
	was time.Duration
}

// exitsUp tells the exits that came back in one step: each on its own, or one message for a burst.
func exitsUp(ups []upEvent) []Alert {
	if len(ups) >= coalesceMin {
		return []Alert{manyUp(ups)}
	}
	out := make([]Alert, 0, len(ups))
	for _, u := range ups {
		out = append(out, exitUp(u.e, u.was))
	}
	return out
}

// manyUp is a burst of recoveries in one message; it resolves every exit's incident.
func manyUp(ups []upEvent) Alert {
	incidents := make([]string, 0, len(ups))
	for _, u := range ups {
		incidents = append(incidents, "exit:"+u.e.ID)
	}
	a := simpleAlert(KindExits, SevInfo, ups[0].e.At, func(lang string) string {
		var b strings.Builder
		b.WriteString(T(lang, "al.up.many", len(ups)))
		for i, u := range ups {
			if i == manyLines {
				b.WriteString("\n" + T(lang, "digest.more", len(ups)-manyLines))
				break
			}
			b.WriteString("\n• <b>" + esc(eventName(u.e)) + "</b>")
			if u.was > 0 {
				b.WriteString(T(lang, "al.up.after", Duration(lang, u.was)))
			}
		}
		return b.String()
	})
	a.Incidents, a.Resolves = incidents, true
	return a
}

func exitUp(e Event, was time.Duration) Alert {
	name := e.Name
	if name == "" {
		name = e.ID
	}
	a := simpleAlert(KindExits, SevInfo, e.At, func(lang string) string {
		s := T(lang, "al.up", esc(name))
		if was > 0 {
			s += T(lang, "al.up.after", Duration(lang, was))
		}
		if e.LatencyMs > 0 {
			s += " · " + T(lang, "ex.latency", e.LatencyMs)
		}
		return s
	})
	a.Incident, a.Resolves = "exit:"+e.ID, true
	return a
}

func groupSwitch(e Event, s Status) Alert {
	name := e.Name
	if name == "" {
		name = e.ID
	}
	from, to := e.From, e.To
	if from != "" {
		from = exitLabel(s, from)
	}
	if to != "" {
		to = exitLabel(s, to)
	}
	return simpleAlert(KindSwitches, SevInfo, e.At, func(lang string) string {
		f, t := from, to
		if f == "" {
			f = "—"
		}
		if t == "" {
			t = "—"
		}
		return T(lang, "al.switch", esc(name), esc(f), esc(t))
	})
}

func coreRestarted(now time.Time, c, prev CorePulse) Alert {
	failed := c.Failed > prev.Failed
	return simpleAlert(KindCore, SevWarning, now, func(lang string) string {
		s := T(lang, "al.core.restart", c.Restarts)
		if failed && c.LastError != "" {
			s += "\n" + T(lang, "al.core.lasterr", esc(c.LastError))
		}
		return s
	})
}

func coreDown(now time.Time, was time.Duration, lastErr string) Alert {
	a := simpleAlert(KindCore, SevCritical, now, func(lang string) string {
		s := T(lang, "al.core.down", Duration(lang, was))
		if lastErr != "" {
			s += "\n" + T(lang, "al.core.lasterr", esc(lastErr))
		}
		return s
	})
	a.Incident = "core"
	return a
}

// routingSwitched tells every chat that WayHop's routing was switched off, or back on. Filed under
// the Apply news: it changes what the router runs, like a Keep or a rollback does.
func routingSwitched(now time.Time, off bool) Alert {
	if off {
		a := simpleAlert(KindApply, SevWarning, now, func(lang string) string { return T(lang, "al.routing.off") })
		a.Incident = "routing"
		return a
	}
	a := simpleAlert(KindApply, SevInfo, now, func(lang string) string { return T(lang, "al.routing.on") })
	a.Incident, a.Resolves = "routing", true
	return a
}

func coreUp(now time.Time, was time.Duration) Alert {
	a := simpleAlert(KindCore, SevInfo, now, func(lang string) string { return T(lang, "al.core.up", Duration(lang, was)) })
	a.Incident, a.Resolves = "core", true
	return a
}

// applyArmed asks the owners to keep or roll back a test Apply. The same incident's countdown edits
// this message; the outcome closes it.
func applyArmed(now time.Time, f FailSafePulse) Alert {
	left := time.Duration(f.SecondsLeft) * time.Second
	text := func(lang string) string { return T(lang, "al.apply.armed", Countdown(left)) }
	keyboard := applyKeyboard
	if rollbackFailed(f) {
		// The window holds on for its reboot fallback, but nothing rolls back by itself any more and
		// Keep is refused: the message says what happened and offers the retry.
		errText := rollbackErrorText(f)
		text = func(lang string) string { return T(lang, "al.apply.rbfailed", esc(errText)) }
		keyboard = applyRetryKeyboard
	}
	return Alert{Kind: KindApply, Sev: SevAction, At: now, Incident: "apply",
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), keyboard(lang, role, f.Window) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
	}
}

// rollbackFailed reports a window whose rollback failed and is not finished: by its phase, or by the
// daemon's record, which keeps saying so after the next connectivity tick has relabelled the phase.
func rollbackFailed(f FailSafePulse) bool {
	return f.Phase == "rollback_failed" || f.RollbackOutstanding
}

func applyCountdown(now time.Time, f FailSafePulse) Alert {
	a := applyArmed(now, f)
	if f.Phase == "degraded" && !rollbackFailed(f) {
		left := time.Duration(f.SecondsLeft) * time.Second
		a.Render = func(lang, role string) (string, *Keyboard) {
			return T(lang, "al.apply.armed", Countdown(left)) + "\n" + T(lang, "al.apply.failing"), applyKeyboard(lang, role, f.Window)
		}
	}
	a.Edit = true
	return a
}

func applyDegraded(now time.Time) Alert {
	a := simpleAlert(KindApply, SevWarning, now, func(lang string) string { return T(lang, "al.apply.degraded") })
	a.Incident = "apply"
	return a
}

func applyRollbackFailed(now time.Time, errText string) Alert {
	a := simpleAlert(KindApply, SevCritical, now, func(lang string) string { return T(lang, "al.apply.rbfailed", esc(errText)) })
	a.Incident = "apply"
	return a
}

// applyClosed ends the apply incident. quiet outcomes (kept, window passed) only rewrite the opening
// message; loud ones (rolled back, rebooting) also arrive as a reply with a sound.
func applyClosed(now time.Time, key string, sev Severity, quiet bool) Alert {
	text := func(lang string) string { return T(lang, key) }
	a := simpleAlert(KindApply, sev, now, text)
	a.Incident, a.Resolves = "apply", true
	a.Closed = func(lang string) string { return T(lang, key) }
	if quiet {
		a.Edit = true
		a.Render = func(lang, _ string) (string, *Keyboard) { return text(lang), nil }
	}
	return a
}

// applyReplaced ends the message of a test window that a newer Test superseded: quietly, without its
// buttons, unless the fail-safe had already rolled the old Test back, which is told as that rollback.
func applyReplaced(now time.Time, autoRollback bool) Alert {
	if autoRollback {
		return applyClosed(now, "al.apply.rolledback", SevCritical, false)
	}
	return applyClosed(now, "al.apply.replaced", SevInfo, true)
}

// replacedOutcome closes the window w names when f shows another one. A Keep in the panel followed by
// a new Test within one pulse looks the same as the new Test superseding the old one, and was told as
// "replaced"; a kept Test is the committed revision now, under its own name. A Roll back pressed
// before the new Test still reads as replaced: the committed revision is the same either way.
func (w *watcher) replacedOutcome(now time.Time, f FailSafePulse, autoRollback bool) Alert {
	if f.Committed != "" && f.Committed == w.window {
		return applyClosed(now, "al.apply.kept", SevInfo, true)
	}
	return applyReplaced(now, autoRollback)
}

// applyRollingBack redraws a test window's message once its fail-safe has rolled back by itself: the
// window stays pending until the next healthy tick, and the countdown's Keep / Roll back are no use
// any more. Its close follows, loud. The text is plain: it is also the toast of a Keep or Roll back
// pressed before this edit lands (decideApply).
func applyRollingBack(now time.Time) Alert {
	text := func(lang string) string { return T(lang, "al.apply.rolling") }
	return Alert{Kind: KindApply, Sev: SevAction, At: now, Incident: "apply", Edit: true,
		Render: func(lang, _ string) (string, *Keyboard) { return text(lang), nil },
		Line:   func(lang string) string { return firstLine(text(lang)) },
	}
}

// applyClosedRollbackFailed ends a test window whose rollback failed (it closes at the reboot
// threshold with auto-reboot off): loud, since part of the tested configuration may still run, and
// with Roll back for the owners to retry: the tested revision stays on record for exactly that.
func applyClosedRollbackFailed(now time.Time, errText, window string) Alert {
	text := func(lang string) string { return T(lang, "al.apply.rbclosed", esc(errText)) }
	return Alert{Kind: KindApply, Sev: SevCritical, At: now, Incident: "apply", Resolves: true,
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), applyRetryKeyboard(lang, role, window) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
		Closed: text,
	}
}

// applyRollbackOutstanding tells a failed rollback outside a running window: loud, with Roll back alone
// for the owners. It closes the apply incident so the earlier "unsaved" message loses its Keep, which the
// daemon now refuses; the retry's outcome (rolled back, or the Test replaced) arrives on its own.
func applyRollbackOutstanding(now time.Time, errText, window string) Alert {
	text := func(lang string) string { return T(lang, "al.apply.rbopen", esc(errText)) }
	return Alert{Kind: KindApply, Sev: SevCritical, At: now, Incident: "apply", Resolves: true,
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), applyRetryKeyboard(lang, role, window) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
		Closed: text,
	}
}

func applyUnsavedAlert(now time.Time, window string) Alert {
	text := func(lang string) string { return T(lang, "al.apply.unsaved") }
	return Alert{Kind: KindApply, Sev: SevAction, At: now, Incident: "apply",
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), applyKeyboard(lang, role, window) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
	}
}

// bootAlert says the router or the daemon is back, and for how long it was gone when that is known.
func bootAlert(b BootInfo, now time.Time) Alert {
	rebooted := b.RouterUp > 0 && b.RouterUp < 10*time.Minute
	started := b.DaemonStart
	if started.IsZero() {
		started = now
	}
	bootAt := started.Add(-b.RouterUp)
	lastSeen := b.LastSeen
	if !lastSeen.IsZero() && (lastSeen.After(started) || started.Sub(lastSeen) > 7*24*time.Hour) {
		lastSeen = time.Time{} // a clock jump or a stale file says nothing about this outage
	}
	sev := SevInfo
	var text func(lang string) string
	switch {
	case rebooted && !lastSeen.IsZero():
		off := bootAt.Sub(lastSeen)
		if off < 0 {
			off = 0
		}
		if off > 15*time.Minute {
			sev = SevWarning
		}
		text = func(lang string) string {
			v := view{lang: lang, now: now}
			return T(lang, "al.boot.back", v.clock(bootAt), v.clock(lastSeen), Duration(lang, off))
		}
	case rebooted:
		text = func(lang string) string { return T(lang, "al.boot.reboot", view{lang: lang, now: now}.clock(bootAt)) }
	default:
		text = func(lang string) string { return T(lang, "al.boot.restart", esc(b.Version)) }
	}
	if b.UpdateNote != "" {
		// The restart was the update supervisor putting the previous build back: say so with it.
		sev = SevWarning
		inner := text
		text = func(lang string) string { return inner(lang) + "\n" + T(lang, "up.lastnote", esc(b.UpdateNote)) }
	}
	return simpleAlert(KindBoot, sev, now, text)
}
