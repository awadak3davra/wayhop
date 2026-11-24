package failover

import "sort"

// listunit.go is the routing-list producer's side of the elector: a list in "fastest" mode owns a
// table of its own, judged against its own destinations, and adds to a group's unit an operator pin,
// exclusions, a choice of what happens when every candidate is down, a dead verdict only after
// several failed cycles, and flap calming. The decision itself is the same Runner as a group's.

// List switch reasons beyond a group's.
const (
	ReasonPinned   = "pinned"   // the operator's pin took the table
	ReasonUnpinned = "unpinned" // the pin ended (expired or removed); the choice is automatic again
	ReasonAllDown  = "all_down" // no candidate works; the table was emptied (wan/block) or kept
	ReasonManual   = "manual"   // the incumbent was excluded by the operator
	ReasonFlapping = "flapping" // too many switches in an hour; the list calms down
	// ReasonTargetsDown: the list's targets answered through no candidate and not by the router's own
	// path either. That is the targets' problem, not the tunnels': the table is kept as it is.
	ReasonTargetsDown = "targets_down"
)

// ReferenceIface is the Iface of a reference measurement: the router's own socket, bound to no
// device, which leaves by the main table. A target that answers there but through no candidate is
// evidence that the candidates are dead; one that answers nowhere says nothing about them.
const ReferenceIface = ""

// ListPolicy is a list unit's settings, as the producer resolved them from the applied profile.
type ListPolicy struct {
	List      string   // the routing list id
	Pinned    string   // candidate the operator pinned while the pin is active, "" otherwise
	PinUntil  int64    // unix ms the pin ends; 0 = until removed
	Excluded  []string // candidates never chosen
	OnAllDown string   // "wan" | "block" | "keep"
	// DeadAfter is how many measurement cycles in a row without one successful handshake make a
	// candidate dead. 0 = 2.
	DeadAfter int
	// Fresh is true on the tick a new measurement cycle arrived (or the operator asked for one):
	// decisions are made only then, so dead-after and dwell count the list's own cycles.
	Fresh bool
	// FlapLimit is the number of switches in an hour after which dwell and hold are multiplied by
	// four. 0 = 6.
	FlapLimit int
	// RefTargets are what the reference measurement (ReferenceIface) asks when the list's targets
	// answered through no candidate; nil = the list's own Targets. A kill-switched list gets neutral
	// addresses outside every kill-switched list: the reference socket leaves by the main table, the
	// WAN, and must never dial the list's own destinations there.
	RefTargets []string
	// TargetsOnTrial: the targets were picked automatically, none of them has answered through a
	// candidate since, and the producer has others to try. A cycle in which none answers then judges
	// no candidate and counts toward no dead verdict: two cycles of unproven targets (a prefix's
	// first hosts with nothing listening) used to empty the table as "all down" while targets that
	// do answer were still waiting their turn. The producer must clear it once its pool
	// is used up, or the list would never judge its tunnels by silence.
	TargetsOnTrial bool
}

// ReferenceTargets is what the reference measurement of u asks.
func ReferenceTargets(u TableUnit) []string {
	if u.List != nil && u.List.RefTargets != nil {
		return u.List.RefTargets
	}
	return u.Targets
}

// ReferenceAnswered reports whether one of u's reference targets answered by the router's own path.
func ReferenceAnswered(u TableUnit, probes map[ProbeKey]ProbeResult) bool {
	return referenceAnswered(u, probes)
}

func (p *ListPolicy) deadAfter() int {
	if p.DeadAfter > 0 {
		return p.DeadAfter
	}
	return 2
}

func (p *ListPolicy) flapLimit() int {
	if p.FlapLimit > 0 {
		return p.FlapLimit
	}
	return 6
}

// ProbeCell is one (candidate, target) measurement, for the list panel's matrix.
type ProbeCell struct {
	MedianMs int   `json:"median_ms"`
	LossPct  int   `json:"loss_pct"`
	OK       bool  `json:"ok"`
	At       int64 `json:"at"`
}

// ListState is what a list unit shows beyond a group's state.
type ListState struct {
	List      string                          `json:"list"`
	Pinned    string                          `json:"pinned,omitempty"`
	PinUntil  int64                           `json:"pin_until,omitempty"`
	PinDead   bool                            `json:"pin_dead,omitempty"` // pinned candidate unavailable: automatic meanwhile
	Excluded  []string                        `json:"excluded,omitempty"`
	OnAllDown string                          `json:"on_all_down"`
	AllDown   bool                            `json:"all_down,omitempty"`
	Calm      bool                            `json:"calm,omitempty"` // flapping: dwell x4
	Fails     map[string]int                  `json:"fails,omitempty"`
	Matrix    map[string]map[string]ProbeCell `json:"matrix,omitempty"` // candidate -> target -> cell
	// DeadTargets answered through no candidate in the last cycle: measuring them says nothing.
	DeadTargets []string `json:"dead_targets,omitempty"`
	// TargetsDown: no target answered through any candidate, nor by the router's own path. The
	// candidates were not judged and the table was kept.
	TargetsDown bool  `json:"targets_down,omitempty"`
	LastCycle   int64 `json:"last_cycle,omitempty"`
	// Mode is what the table is doing: "auto", "pinned", "fallback" (pin dead / chosen by order),
	// "all_down", "targets_down".
	Mode string `json:"mode"`
}

func (l *ListState) clone() *ListState {
	if l == nil {
		return nil
	}
	c := *l
	c.Excluded = append([]string(nil), l.Excluded...)
	c.DeadTargets = append([]string(nil), l.DeadTargets...)
	c.Fails = make(map[string]int, len(l.Fails))
	for k, v := range l.Fails {
		c.Fails[k] = v
	}
	c.Matrix = make(map[string]map[string]ProbeCell, len(l.Matrix))
	for k, row := range l.Matrix {
		r := make(map[string]ProbeCell, len(row))
		for t, cell := range row {
			r[t] = cell
		}
		c.Matrix[k] = r
	}
	return &c
}

// listEventCap bounds a list unit's journal in memory, and so on flash: 32 lists x 50 events.
const listEventCap = 50

func (u TableUnit) eventCap() int {
	if u.List != nil {
		return listEventCap
	}
	return unitEventCap
}

func trimEvents(evs []UnitEvent, max int) []UnitEvent {
	if over := len(evs) - max; over > 0 {
		return append([]UnitEvent(nil), evs[over:]...)
	}
	return evs
}

// TableClearer is the optional write a list unit needs for on_all_down "wan" and "block": remove the
// table's device default, so the lookup falls through to the main table or to the plane's blackhole.
type TableClearer interface {
	Clear(table int) error
}

// TableLeftover is the optional read beside it: whether the table still holds a device default that
// Current does not show (the other address family's). An emptied table is emptied in both; one that
// kept its IPv6 default after the IPv4 one went (a delete that failed, a route only one family lost)
// sent the list's IPv6 on through the tunnel the list had left, with nothing asking again.
type TableLeftover interface {
	Leftover(table int) bool
}

// tableHolds reports whether a list's table has anything for an all-down list to remove.
func tableHolds(routes TableRoutes, table int, current string) bool {
	if current != "" {
		return true
	}
	l, ok := routes.(TableLeftover)
	return ok && l.Leftover(table)
}

// SeedEvents hands the elector the journal a previous run persisted for a unit owner, so the list
// panel keeps its history across a restart. Applied when the unit first appears; a later call for an
// owner already running is ignored.
func (e *TableElector) SeedEvents(owner string, evs []UnitEvent) {
	if e == nil || len(evs) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.state {
		if k.Owner == owner {
			return
		}
	}
	e.seeded[owner] = trimEvents(append([]UnitEvent(nil), evs...), listEventCap)
}

// JournalVersion changes whenever a list unit's journal does, so a persister can skip a write.
func (e *TableElector) JournalVersion() uint64 {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.changed
}

// Journals is every list unit's events by owner, for persisting.
func (e *TableElector) Journals() map[string][]UnitEvent {
	out := map[string][]UnitEvent{}
	if e == nil {
		return out
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, st := range e.state {
		if st.List != nil && len(st.Events) > 0 {
			out[k.Owner] = append([]UnitEvent(nil), st.Events...)
		}
	}
	// Seeds of lists not (yet) running are kept: a restart before the first Apply loses nothing.
	for owner, evs := range e.seeded {
		if _, ok := out[owner]; !ok {
			out[owner] = append([]UnitEvent(nil), evs...)
		}
	}
	return out
}

func (e *TableElector) recordLocked(u TableUnit, st *UnitState, ev UnitEvent) {
	ev.Key = u.Key
	st.Events = trimEvents(append(st.Events, ev), u.eventCap())
	e.changed++
}

// switchesWithin counts the table writes in the journal since `since`.
func switchesWithin(evs []UnitEvent, since int64) int {
	n := 0
	for _, ev := range evs {
		if ev.At >= since && ev.Wrote && ev.To != "" {
			n++
		}
	}
	return n
}

// tickListLocked decides one list unit. Caller holds e.mu.
func (e *TableElector) tickListLocked(u TableUnit, st *UnitState, probes map[ProbeKey]ProbeResult, fallback HealthSource, routes TableRoutes, now int64) []UnitEvent {
	lp := u.List
	ls := st.List
	if ls == nil {
		ls = &ListState{Fails: map[string]int{}}
		st.List = ls
	}
	prevPinned := ls.Pinned
	ls.List, ls.Pinned, ls.PinUntil, ls.OnAllDown = lp.List, lp.Pinned, lp.PinUntil, lp.OnAllDown
	ls.Excluded = append([]string(nil), lp.Excluded...)
	current, known := routes.Current(u.Key.Table)
	defer func() {
		now2, _ := routes.Current(u.Key.Table)
		st.CurrentIface, st.Current = now2, u.CandidateFor(now2)
		ls.Mode = listMode(ls, st.Current)
	}()
	if !known {
		return nil
	}
	if prevPinned != "" && lp.Pinned == "" {
		e.recordLocked(u, st, UnitEvent{At: now, From: prevPinned, To: u.CandidateFor(current), ToIface: current, Reason: ReasonUnpinned})
	}
	if !lp.Fresh && st.Measurements != nil {
		return nil // between the list's own cycles nothing new is known
	}
	ls.LastCycle = now
	ls.Matrix = probeMatrix(u, probes, now)
	ls.DeadTargets = deadTargets(u, probes)
	// A target that answered through no candidate says nothing about any of them (review F2): the
	// candidates are judged by the targets that answered somewhere. When none did, only a reference
	// measurement by the router's own path can tell dead tunnels from dead targets.
	judge := u
	if live := answeredTargets(u, probes); len(live) > 0 {
		judge.Targets = live
	} else if TargetsUnanswered(u, probes) && (lp.TargetsOnTrial || !referenceAnswered(u, probes)) {
		// Targets on trial are the same case without asking the reference: nothing has shown yet that
		// they answer through a tunnel at all, so their silence is not the tunnels' failure, and the
		// producer is about to replace them.
		if !ls.TargetsDown {
			ls.TargetsDown = true
			detail := "no target answered through any tunnel or the router's own path: kept"
			if lp.TargetsOnTrial {
				detail = "no target has answered through a tunnel yet and others remain to try: kept"
			}
			e.recordLocked(u, st, UnitEvent{At: now, From: u.CandidateFor(current), To: u.CandidateFor(current), FromIface: current,
				ToIface: current, Reason: ReasonTargetsDown, Detail: detail})
		}
		return nil
	}
	ls.TargetsDown = false
	health, measurements := HealthFor(judge, probes, fallback, now)
	// A candidate is dead only after DeadAfter cycles in a row without one success: one lost cycle
	// keeps it alive at a 100 % loss penalty, so it is not chosen but nothing hard-cuts off it yet.
	for i := range health {
		c := health[i].ID
		m := measurements[c]
		if m.Source != "probe" {
			continue
		}
		if m.Alive {
			ls.Fails[c] = 0
			continue
		}
		ls.Fails[c]++
		if ls.Fails[c] < lp.deadAfter() {
			// Also on a unit's first cycle (review F4): at boot the tunnels may still be handshaking,
			// and one lost cycle must not empty the table the plane seeded. Without an earlier score
			// the candidate stands at the full loss penalty: kept, never preferred.
			prev, ok := st.Measurements[c]
			if !ok || prev.Alive {
				health[i].Alive = true
				health[i].LatencyMs = prev.ScoreMs + lossPenaltyMs*100
				m.Alive, m.ScoreMs = true, health[i].LatencyMs
				measurements[c] = m
			}
		}
	}
	excluded := map[string]bool{}
	for _, x := range lp.Excluded {
		excluded[x] = true
	}
	for i := range health {
		if excluded[health[i].ID] {
			health[i].Alive = false
		}
	}
	st.Measurements = measurements
	from := u.CandidateFor(current)
	alive := map[string]bool{}
	anyAlive := false
	for _, h := range health {
		alive[h.ID] = h.Alive
		anyAlive = anyAlive || h.Alive
	}
	// A candidate works again. With "keep" (or a pin) the table may already hold it, so no switch
	// follows that would clear the flag: the list stayed "all down" forever and a second outage went
	// unrecorded (review F9). wasAllDown still names a switch made now a recovery.
	wasAllDown := ls.AllDown
	if anyAlive && wasAllDown {
		ls.AllDown = false
		if alive[from] {
			e.recordLocked(u, st, UnitEvent{At: now, From: from, To: from, FromIface: current, ToIface: current,
				Reason: ReasonRecovered, Detail: "the tunnel the table kept works again"})
		}
	}
	r := e.runners[u.Key]
	if r == nil {
		r = NewRunner()
		e.runners[u.Key] = r
	}
	commit := func(to, reason, detail string, emergency bool) []UnitEvent {
		iface := u.Iface[to]
		wrote := false
		if iface != current {
			if err := routes.Replace(u.Key.Table, iface); err != nil {
				return nil
			}
			wrote = true
		}
		ev := UnitEvent{At: now, From: from, To: to, FromIface: current, ToIface: iface, Reason: reason, Detail: detail,
			Emergency: emergency, RTTFrom: measurements[from].MedianMs, RTTTo: measurements[to].MedianMs, Wrote: wrote}
		e.committed[u.Key] = to
		r.lastSwitch[u.Key.String()] = now
		delete(r.pending, u.Key.String())
		st.Since, st.Reason = now, reason
		ls.AllDown = false
		e.recordLocked(u, st, ev)
		ev.Key = u.Key
		return []UnitEvent{ev}
	}

	// The operator's pin wins while its candidate works, at once and with no hold.
	ls.PinDead = false
	if lp.Pinned != "" {
		if alive[lp.Pinned] {
			if e.committed[u.Key] == lp.Pinned && current == u.Iface[lp.Pinned] {
				return nil
			}
			return commit(lp.Pinned, ReasonPinned, "pinned by the operator", false)
		}
		ls.PinDead = true // automatic meanwhile
	}

	if !anyAlive {
		if ls.AllDown {
			// The plane's install script seeds `default dev <first>` into an empty table (`add ||
			// true`), and the netfilter.d hook re-runs it on every firewall rebuild, which comes with
			// the interface events of a dead tunnel (review F5). For wan/block the table is emptied
			// again; no new event, the outage is the one already in the journal. The same retry takes
			// what an earlier clear left behind in the other family.
			if lp.OnAllDown != "keep" && tableHolds(routes, u.Key.Table, current) {
				if clr, ok := routes.(TableClearer); ok {
					_ = clr.Clear(u.Key.Table)
				}
			}
			return nil
		}
		if lp.OnAllDown == "keep" {
			ls.AllDown = true
			e.recordLocked(u, st, UnitEvent{At: now, From: from, To: from, FromIface: current, ToIface: current, Reason: ReasonAllDown, Detail: "kept on the last tunnel"})
			return nil
		}
		clr, ok := routes.(TableClearer)
		if !ok || !tableHolds(routes, u.Key.Table, current) {
			ls.AllDown = true
			e.recordLocked(u, st, UnitEvent{At: now, From: from, FromIface: current, Reason: ReasonAllDown, Detail: lp.OnAllDown})
			return nil
		}
		if err := clr.Clear(u.Key.Table); err != nil {
			return nil
		}
		ls.AllDown = true
		delete(e.committed, u.Key)
		st.Since, st.Reason = now, ReasonAllDown
		ev := UnitEvent{At: now, From: from, FromIface: current, Reason: ReasonAllDown, Detail: lp.OnAllDown, Emergency: true,
			RTTFrom: measurements[from].MedianMs, Wrote: true}
		e.recordLocked(u, st, ev)
		ev.Key = u.Key
		return []UnitEvent{ev}
	}

	// The incumbent was excluded: leave it now, without the failback hold. The replacement follows
	// the list's actual policy, including throughput freshness and mixed latency eligibility.
	if from != "" && excluded[from] {
		best := bestAlive(health, u.Policy, u.Cfg, now)
		return commit(best, ReasonManual, "excluded by the operator", false)
	}

	cfg := u.Cfg
	ls.Calm = switchesWithin(st.Events, now-3600_000) > lp.flapLimit()
	if ls.Calm {
		cfg.MinDwellMS = cfg.minDwell() * 4
		cfg.FailbackHoldMS = cfg.failbackHold() * 4
		if n := len(st.Events); n == 0 || st.Events[n-1].Reason != ReasonFlapping {
			e.recordLocked(u, st, UnitEvent{At: now, From: from, To: from, FromIface: current, ToIface: current, Reason: ReasonFlapping,
				Detail: "more than the hourly switch limit: dwell and hold x4"})
		}
	}
	incumbent := ""
	if c := e.committed[u.Key]; c != "" && u.Iface[c] == current {
		incumbent = c
	}
	sel := &tableSelector{key: u.Key, unit: u, current: current, incumbent: incumbent, routes: routes}
	spec := GroupSpec{ID: u.Key.String(), Policy: u.Policy, Members: u.Candidates, Cfg: cfg}
	var out []UnitEvent
	for _, sw := range r.Tick([]GroupSpec{spec}, staticHealth(health), sel, now) {
		reason := switchReason(u.Policy, incumbent, from, measurements)
		if wasAllDown || (reason == ReasonElected && from == "" && st.Reason == ReasonAllDown) {
			reason = ReasonRecovered
		}
		ev := UnitEvent{Key: u.Key, At: now, From: from, To: sw.To, FromIface: current, ToIface: u.Iface[sw.To],
			Reason: reason, Detail: sw.Reason, Emergency: sw.Emergency,
			RTTFrom: measurements[from].MedianMs, RTTTo: measurements[sw.To].MedianMs, Wrote: sel.wrote}
		e.committed[u.Key] = sw.To
		st.Since, st.Reason = now, reason
		ls.AllDown = false
		e.recordLocked(u, st, ev)
		out = append(out, ev)
	}
	return out
}

func bestAlive(h []MemberHealth, policy Policy, cfg Config, now int64) string {
	best, _ := ideal(DecideInput{Policy: policy, Members: h, Cfg: cfg, Now: now})
	return best
}

func listMode(ls *ListState, current string) string {
	switch {
	case ls.AllDown:
		return "all_down"
	case ls.TargetsDown:
		return "targets_down"
	case ls.Pinned != "" && current == ls.Pinned:
		return "pinned"
	case ls.PinDead:
		return "fallback"
	}
	return "auto"
}

// probeMatrix is the per-(candidate, target) view of this cycle's probes.
func probeMatrix(u TableUnit, probes map[ProbeKey]ProbeResult, now int64) map[string]map[string]ProbeCell {
	out := make(map[string]map[string]ProbeCell, len(u.Candidates))
	for _, c := range u.Candidates {
		iface := u.Iface[c]
		if iface == "" {
			continue
		}
		row := map[string]ProbeCell{}
		for _, t := range u.Targets {
			r, ok := probes[ProbeKey{Iface: iface, Target: t}]
			if !ok || !r.Ran || r.Attempts == 0 {
				continue
			}
			row[t] = ProbeCell{MedianMs: r.MedianMs, LossPct: 100 * (r.Attempts - r.Successes) / r.Attempts, OK: r.Successes > 0, At: now}
		}
		out[c] = row
	}
	return out
}

// answeredTargets are the targets that answered through at least one candidate this cycle.
func answeredTargets(u TableUnit, probes map[ProbeKey]ProbeResult) []string {
	var out []string
	for _, t := range u.Targets {
		for _, c := range u.Candidates {
			if r, ok := probes[ProbeKey{Iface: u.Iface[c], Target: t}]; ok && u.Iface[c] != "" && r.Ran && r.Successes > 0 {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// TargetsUnanswered reports a list cycle in which targets were measured through candidates and none
// answered through any: the cycle that needs a reference measurement (ReferenceIface) before the
// candidates may be called dead.
func TargetsUnanswered(u TableUnit, probes map[ProbeKey]ProbeResult) bool {
	return len(deadTargets(u, probes)) > 0 && len(answeredTargets(u, probes)) == 0
}

// referenceAnswered: one of the unit's reference targets answered by the router's own path this cycle.
func referenceAnswered(u TableUnit, probes map[ProbeKey]ProbeResult) bool {
	for _, t := range ReferenceTargets(u) {
		if r, ok := probes[ProbeKey{Iface: ReferenceIface, Target: t}]; ok && r.Ran && r.Successes > 0 {
			return true
		}
	}
	return false
}

// deadTargets are the targets that were measured through at least one candidate and answered
// through none.
func deadTargets(u TableUnit, probes map[ProbeKey]ProbeResult) []string {
	var out []string
	for _, t := range u.Targets {
		measured, ok := false, false
		for _, c := range u.Candidates {
			if u.Iface[c] == "" {
				continue // no link: and its key would be the reference path's
			}
			r, has := probes[ProbeKey{Iface: u.Iface[c], Target: t}]
			if !has || !r.Ran {
				continue
			}
			measured = true
			ok = ok || r.Successes > 0
		}
		if measured && !ok {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
