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
	countdownAt time.Time
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
// that was already true when the bot started is announced as if it had just happened.
func (w *watcher) step(now time.Time, p Pulse, log EventLog, status func() Status) []Alert {
	if !w.primed {
		w.primed, w.prev = true, p
		w.markEvents(log.Events)
		if p.LocalFault {
			w.uplinkAt = now
		}
		if p.FailSafe.Pending {
			w.countdownAt = now
		}
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
	if from == to {
		if to == applyTesting {
			if f.Phase == "degraded" && w.prev.FailSafe.Phase != "degraded" {
				out = append(out, applyDegraded(now))
			}
			if f.Phase == "rollback_failed" && w.prev.FailSafe.Phase != "rollback_failed" {
				out = append(out, applyRollbackFailed(now, f.LastError))
			}
			if now.Sub(w.countdownAt) >= countdownEvery {
				w.countdownAt = now
				out = append(out, applyCountdown(now, f))
			}
		}
		return out
	}
	// Close what was open.
	switch from {
	case applyTesting:
		switch {
		case to == applyUnsaved:
			out = append(out, applyClosed(now, "al.apply.passed", SevInfo, true))
		case f.Phase == "committed":
			out = append(out, applyClosed(now, "al.apply.kept", SevInfo, true))
		case f.Phase == "rolled_back" && (w.prev.FailSafe.Phase == "degraded" || (f.Checked && !f.CheckOK)):
			// The fail-safe rolled back because the connection was lost: loud.
			out = append(out, applyClosed(now, "al.apply.rolledback", SevCritical, false))
		case f.Phase == "rolled_back":
			// Somebody pressed Roll back (here or in the panel): the outcome, quietly.
			out = append(out, applyClosed(now, "al.apply.reverted", SevInfo, true))
		case f.Phase == "reboot":
			out = append(out, applyClosed(now, "al.apply.reboot", SevCritical, false))
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
		out = append(out, applyArmed(now, f))
	case applyUnsaved:
		out = append(out, applyUnsavedAlert(now))
	}
	return out
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
	return Alert{Kind: KindApply, Sev: SevAction, At: now, Incident: "apply",
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), applyKeyboard(lang, role) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
	}
}

func applyCountdown(now time.Time, f FailSafePulse) Alert {
	a := applyArmed(now, f)
	if f.Phase == "degraded" {
		left := time.Duration(f.SecondsLeft) * time.Second
		a.Render = func(lang, role string) (string, *Keyboard) {
			return T(lang, "al.apply.armed", Countdown(left)) + "\n" + T(lang, "al.apply.failing"), applyKeyboard(lang, role)
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

func applyUnsavedAlert(now time.Time) Alert {
	text := func(lang string) string { return T(lang, "al.apply.unsaved") }
	return Alert{Kind: KindApply, Sev: SevAction, At: now, Incident: "apply",
		Render: func(lang, role string) (string, *Keyboard) { return text(lang), applyKeyboard(lang, role) },
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
	return simpleAlert(KindBoot, sev, now, text)
}
