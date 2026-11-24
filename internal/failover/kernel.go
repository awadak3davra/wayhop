package failover

import (
	"fmt"
	"sort"
	"sync"
)

// kernel.go runs the decision brain against the KERNEL routing plane instead of a proxy core.
//
// On the kernel plane a failover group is not a device. A routing list's packets are marked, an
// `ip rule` sends the mark to a table, and the table holds one `default dev <iface>`. Electing a
// member is re-pointing that one route. Nothing here touches the router: the caller reads the tables,
// runs the probes and hands both in, and TableRoutes is the one write this file asks for.
//
// The runtime unit is a TABLE with its candidate set and its probe targets (TableUnit), not a group.
// A group whose routing lists share one table is one producer of units; a routing list with its own
// table and its own targets (the list's destinations) is another, and plugs in here unchanged.

// UnitKey names one unit: the owner that produced it ("group:<id>", later "list:<id>") and the
// routing table it elects into.
type UnitKey struct {
	Owner string
	Table int
}

func (k UnitKey) String() string { return fmt.Sprintf("%s@%d", k.Owner, k.Table) }

// TableUnit is one table to elect for.
type TableUnit struct {
	Key        UnitKey
	Name       string // display name, for logs and the API
	Group      string // the group the unit came from, "" when its producer is not a group
	Policy     Policy
	Candidates []string                    // in the operator's order
	Iface      map[string]string           // candidate → kernel link; one without a link is never elected
	Throughput map[string]ThroughputSample // candidate → last successful throughput sample
	// Targets are what a candidate is judged against for THIS unit ("host:port", resolved by the
	// caller): the destinations probed through the candidate's link. The producer decides them — a
	// group's test URL today, a list's own destinations later. A candidate that reaches its own
	// health target but none of these is not a working exit for this table.
	Targets []string
	Pick    string // selector only: the operator's pick (see DecideInput.Pick)
	Cfg     Config
	// List makes this a routing list's own unit ("fastest" mode): pin, exclusions, what to do when
	// every candidate is down, and decisions only on the list's own measurement cycle. nil = a
	// group's unit, decided every tick exactly as before.
	List *ListPolicy
}

// Accepts reports whether iface is a legitimate value for this unit's table: the link of one of its
// candidates. This is the kernel-plane verification rule for an elected table — the plan fixes the
// TABLE and the candidate SET, never the member, so any candidate is correct and anything else is not.
func (u TableUnit) Accepts(iface string) bool { return u.CandidateFor(iface) != "" }

// CandidateFor is the candidate whose link is iface, "" if none.
func (u TableUnit) CandidateFor(iface string) string {
	if iface == "" {
		return ""
	}
	for _, c := range u.Candidates {
		if u.Iface[c] == iface {
			return c
		}
	}
	return ""
}

// ProbeKey is one measurement subject: Target through link Iface. Units that share a target and a
// link share the measurement within a cycle.
type ProbeKey struct {
	Iface  string
	Target string
}

// ProbeResult is what one cycle measured for a ProbeKey. Ran is false when nothing was measured (the
// probe could not be started); the election then falls back to the endpoint's monitored state rather
// than calling the candidate dead.
type ProbeResult struct {
	Ran       bool
	Attempts  int
	Successes int
	MedianMs  int // median handshake time over the successful attempts
}

// ProbeKeys lists the measurements units need, each once, in a stable order.
func ProbeKeys(units []TableUnit) []ProbeKey {
	seen := map[ProbeKey]bool{}
	var out []ProbeKey
	for _, u := range units {
		for _, c := range u.Candidates {
			iface := u.Iface[c]
			if iface == "" {
				continue
			}
			for _, t := range u.Targets {
				k := ProbeKey{Iface: iface, Target: t}
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Iface < out[j].Iface
	})
	return out
}

// Measurement is a candidate's standing in one unit after a cycle.
type Measurement struct {
	Alive          bool   `json:"alive"`
	ScoreMs        int    `json:"score_ms"`  // what the latency policy compares: median + loss penalty
	MedianMs       int    `json:"median_ms"` // median handshake over the unit's targets
	LossPct        int    `json:"loss_pct"`
	Source         string `json:"source"` // "probe" | "monitor" | "none" (no kernel link)
	At             int64  `json:"at"`
	ThroughputKbps int64  `json:"throughput_kbps,omitempty"`
	ThroughputAt   int64  `json:"throughput_at,omitempty"`
}

// lossPenaltyMs is what one percent of lost attempts adds to a candidate's score.
const lossPenaltyMs = 10

// measure folds a candidate's per-target results into one Measurement. Dead = not one attempt to
// any target succeeded this cycle; a lossy candidate stays alive and pays for the loss in its score.
func measure(u TableUnit, cand string, probes map[ProbeKey]ProbeResult, now int64) (Measurement, bool) {
	iface := u.Iface[cand]
	if iface == "" {
		return Measurement{Source: "none", At: now}, true
	}
	attempts, successes := 0, 0
	var medians []int
	for _, t := range u.Targets {
		r, ok := probes[ProbeKey{Iface: iface, Target: t}]
		if !ok || !r.Ran {
			continue
		}
		attempts += r.Attempts
		successes += r.Successes
		if r.Successes > 0 {
			medians = append(medians, r.MedianMs)
		}
	}
	if attempts == 0 {
		return Measurement{}, false // nothing measured: the caller asks the monitor
	}
	m := Measurement{Source: "probe", At: now, LossPct: 100 * (attempts - successes) / attempts}
	if successes > 0 {
		m.Alive = true
		m.MedianMs = Median(medians)
		m.ScoreMs = m.MedianMs + lossPenaltyMs*m.LossPct
	}
	return m, true
}

// Median of xs (the lower middle for an even count); 0 for none.
func Median(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[(len(s)-1)/2]
}

// TableRoutes is the kernel side of an election.
type TableRoutes interface {
	// Current is the link table's default route goes through now. known=false: the table could not
	// be read, and an unread table is not an empty one, so the unit is skipped this cycle.
	Current(table int) (iface string, known bool)
	// Replace re-points table at iface (`ip route replace default dev <iface> table <N>`).
	Replace(table int, iface string) error
}

// Switch reasons a unit's event log carries.
const (
	ReasonElected   = "elected"   // the table held nothing of ours: first choice, after a restart or an Apply
	ReasonDead      = "dead"      // the incumbent failed its probe
	ReasonFaster    = "faster"    // a candidate beat the incumbent beyond the deadband, held long enough
	ReasonRecovered = "recovered" // a preferred candidate (order or pick) is back
)

// UnitEvent is one committed choice.
type UnitEvent struct {
	Key       UnitKey `json:"-"`
	At        int64   `json:"at"`
	From      string  `json:"from,omitempty"`
	To        string  `json:"to"`
	FromIface string  `json:"from_iface,omitempty"`
	ToIface   string  `json:"to_iface"`
	Reason    string  `json:"reason"`
	Detail    string  `json:"detail,omitempty"`
	Emergency bool    `json:"emergency,omitempty"`
	RTTFrom   int     `json:"rtt_from,omitempty"`
	RTTTo     int     `json:"rtt_to,omitempty"`
	// Wrote is false when the table already held ToIface: the elector adopted it as its choice and
	// wrote nothing.
	Wrote bool `json:"wrote"`
}

// UnitState is what the elector knows about one unit, for an API to read.
type UnitState struct {
	Key          UnitKey                `json:"-"`
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Group        string                 `json:"group,omitempty"`
	Table        int                    `json:"table"`
	Policy       Policy                 `json:"policy"`
	Targets      []string               `json:"targets"`
	Current      string                 `json:"current,omitempty"` // candidate the table holds now, "" if none of them
	CurrentIface string                 `json:"current_iface,omitempty"`
	Since        int64                  `json:"since,omitempty"` // when the elector committed Current
	Reason       string                 `json:"reason,omitempty"`
	Measurements map[string]Measurement `json:"measurements"`
	Events       []UnitEvent            `json:"events"` // oldest first
	// List is set for a routing list's unit: what the list panel shows beyond a group's state.
	List *ListState `json:"list,omitempty"`
}

// unitEventCap bounds each unit's in-memory log.
const unitEventCap = 200

// TableElector keeps the decision state (last switch, failback hold, flap damping) of every unit
// across cycles, plus what an API shows about it. One Runner per unit: a candidate's flap history
// against one set of targets says nothing about another. Tick from one goroutine; State/States may be
// called concurrently.
type TableElector struct {
	mu        sync.Mutex
	runners   map[UnitKey]*Runner
	committed map[UnitKey]string // candidate the elector itself last put into the table
	state     map[UnitKey]*UnitState
	// seeded holds events restored from flash by owner, handed to a unit's state when it first
	// appears (its table may be numbered differently after an Apply, its owner is not).
	seeded map[string][]UnitEvent
	// changed counts list-journal changes, so a persister writes only when there is something new.
	changed uint64
	// snap is what States serves: a copy taken at the end of each Tick, so a reader never waits on
	// a tick that holds mu across `ip` calls on a wedged router (review F14). Guarded by smu.
	smu  sync.Mutex
	snap []UnitState
}

// NewTableElector returns an elector that has chosen nothing yet.
func NewTableElector() *TableElector {
	return &TableElector{runners: map[UnitKey]*Runner{}, committed: map[UnitKey]string{}, state: map[UnitKey]*UnitState{},
		seeded: map[string][]UnitEvent{}}
}

// Committed is the candidate the elector last put into key's table, "" if none.
func (e *TableElector) Committed(key UnitKey) string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.committed[key]
}

// States is every unit's state as the last Tick left it, ordered by key. It never waits for a running
// Tick. The slices and maps inside are shared between callers: read them, do not change them.
func (e *TableElector) States() []UnitState {
	if e == nil {
		return nil
	}
	e.smu.Lock()
	defer e.smu.Unlock()
	return append([]UnitState(nil), e.snap...)
}

// publishLocked takes the snapshot States serves. Caller holds e.mu.
func (e *TableElector) publishLocked() {
	snap := e.statesLocked()
	e.smu.Lock()
	e.snap = snap
	e.smu.Unlock()
}

func (e *TableElector) statesLocked() []UnitState {
	out := make([]UnitState, 0, len(e.state))
	for _, s := range e.state {
		c := *s
		c.Targets = append([]string(nil), s.Targets...)
		c.Events = append([]UnitEvent(nil), s.Events...)
		c.Measurements = make(map[string]Measurement, len(s.Measurements))
		for k, v := range s.Measurements {
			c.Measurements[k] = v
		}
		c.List = s.List.clone()
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// HealthFor is the health a unit decides over, per candidate in order, with the measurement behind
// each. A candidate with no link is dead; one whose probes did not run defers to fallback (the
// endpoint monitor, may be nil).
func HealthFor(u TableUnit, probes map[ProbeKey]ProbeResult, fallback HealthSource, now int64) ([]MemberHealth, map[string]Measurement) {
	out := make([]MemberHealth, 0, len(u.Candidates))
	ms := make(map[string]Measurement, len(u.Candidates))
	var monitored map[string]MemberHealth
	for _, c := range u.Candidates {
		if m, ok := measure(u, c, probes, now); ok {
			ms[c] = m
			out = append(out, MemberHealth{ID: c, Alive: m.Alive, LatencyMs: m.ScoreMs})
			continue
		}
		if monitored == nil {
			monitored = map[string]MemberHealth{}
			if fallback != nil {
				for _, h := range fallback.MemberHealth(u.Candidates) {
					monitored[h.ID] = h
				}
			}
		}
		h := monitored[c]
		h.ID = c
		ms[c] = Measurement{Alive: h.Alive, ScoreMs: h.LatencyMs, MedianMs: h.LatencyMs, Source: "monitor", At: now}
		out = append(out, h)
	}
	// The monitor's latency is a ping to the endpoint's own target, not a handshake to this unit's
	// targets: compared against probe scores it let an unmeasured tunnel that answers ping but drops
	// traffic win as "fastest" (review F6). When any candidate was measured, an unmeasured one keeps
	// its alive verdict but is never preferred.
	probed := false
	for _, m := range ms {
		probed = probed || m.Source == "probe"
	}
	if probed {
		for i := range out {
			if m := ms[out[i].ID]; m.Source == "monitor" && out[i].Alive {
				out[i].LatencyMs = unmeasuredScoreMs
				m.ScoreMs = unmeasuredScoreMs
				ms[out[i].ID] = m
			}
		}
	}
	// Throughput is independent of this cycle's latency measurement: its own timestamp controls
	// freshness. Attach it without changing Alive, the latency score, or the monitor fallback above.
	for i := range out {
		s := u.Throughput[out[i].ID]
		out[i].ThroughputKbps, out[i].ThroughputAt = s.ThroughputKbps, s.ThroughputAt
		m := ms[out[i].ID]
		m.ThroughputKbps, m.ThroughputAt = s.ThroughputKbps, s.ThroughputAt
		ms[out[i].ID] = m
	}
	return out, ms
}

// unmeasuredScoreMs is the score of a candidate this cycle did not measure while others were: worse
// than any measured one (a 3 s timeout plus the full loss penalty stays below it), so it is kept as a
// working fallback and never chosen over a measured tunnel.
const unmeasuredScoreMs = 1 << 20

// Tick decides every unit once and re-points the tables that should move, returning the events it
// committed. Units absent from units are forgotten, so a table an Apply retired or renumbered starts
// clean if it comes back.
func (e *TableElector) Tick(units []TableUnit, probes map[ProbeKey]ProbeResult, fallback HealthSource, routes TableRoutes, now int64) []UnitEvent {
	if e == nil || routes == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishLocked()
	live := map[UnitKey]bool{}
	var out []UnitEvent
	for _, u := range units {
		live[u.Key] = true
		st := e.state[u.Key]
		if st == nil && u.List != nil {
			st = e.renumberedLocked(u.Key)
		}
		if st == nil {
			st = &UnitState{Key: u.Key, ID: u.Key.String()}
			if seed := e.seeded[u.Key.Owner]; len(seed) > 0 {
				st.Events = trimEvents(append([]UnitEvent(nil), seed...), u.eventCap())
				delete(e.seeded, u.Key.Owner)
			}
			e.state[u.Key] = st
		}
		st.Name, st.Group, st.Table, st.Policy = u.Name, u.Group, u.Key.Table, u.Policy
		st.Targets = append([]string(nil), u.Targets...)
		if u.List != nil {
			out = append(out, e.tickListLocked(u, st, probes, fallback, routes, now)...)
			continue
		}
		current, known := routes.Current(u.Key.Table)
		if !known {
			continue
		}
		health, measurements := HealthFor(u, probes, fallback, now)
		st.Measurements = measurements
		r := e.runners[u.Key]
		if r == nil {
			r = NewRunner()
			e.runners[u.Key] = r
		}
		// The elector defers to an incumbent only if it put it there itself. A table holding anything
		// else — the member Apply pinned, a route left from before a restart, a link that is not a
		// candidate — has no incumbent to protect, so the policy's choice commits now instead of
		// after a failback hold spent on the compile-time pin. That pin is the operator's FIRST
		// member, which for a latency group is exactly the choice this elector exists to replace.
		incumbent := ""
		if c := e.committed[u.Key]; c != "" && u.Iface[c] == current {
			incumbent = c
		}
		sel := &tableSelector{key: u.Key, unit: u, current: current, incumbent: incumbent, routes: routes}
		spec := GroupSpec{ID: u.Key.String(), Policy: u.Policy, Members: u.Candidates, Cfg: u.Cfg, Pick: u.Pick}
		for _, sw := range r.Tick([]GroupSpec{spec}, staticHealth(health), sel, now) {
			from := u.CandidateFor(current)
			ev := UnitEvent{
				Key: u.Key, At: now, From: from, To: sw.To, FromIface: current, ToIface: u.Iface[sw.To],
				Reason: switchReason(u.Policy, incumbent, from, measurements), Detail: sw.Reason,
				Emergency: sw.Emergency, RTTFrom: measurements[from].MedianMs, RTTTo: measurements[sw.To].MedianMs,
				Wrote: sel.wrote,
			}
			e.committed[u.Key] = sw.To
			st.Since, st.Reason = now, ev.Reason
			st.Events = trimEvents(append(st.Events, ev), unitEventCap)
			out = append(out, ev)
		}
		now2, _ := routes.Current(u.Key.Table)
		st.CurrentIface, st.Current = now2, u.CandidateFor(now2)
	}
	for k := range e.state {
		if !live[k] {
			delete(e.runners, k)
			delete(e.committed, k)
			delete(e.state, k)
		}
	}
	return out
}

// renumberedLocked moves a list unit's state to its new table when an Apply renumbered it (review
// F12): list tables are numbered after every other egress, so one new egress shifts them all. The list
// is the same list; its journal, failure counts, dwell and hold carry over instead of starting empty
// (which also made its first cycle on the new table a first cycle again). A list has one table, so any
// other key of the same owner is the old one. nil when there is none. Caller holds e.mu.
func (e *TableElector) renumberedLocked(key UnitKey) *UnitState {
	for old, st := range e.state {
		if old.Owner != key.Owner || old == key || st.List == nil {
			continue
		}
		st.Key, st.ID = key, key.String()
		e.state[key] = st
		if r := e.runners[old]; r != nil {
			// The runner keys its timers by the unit's string; carry them under the new one.
			if v, ok := r.lastSwitch[old.String()]; ok {
				r.lastSwitch[key.String()] = v
				delete(r.lastSwitch, old.String())
			}
			if v, ok := r.pending[old.String()]; ok {
				r.pending[key.String()] = v
				delete(r.pending, old.String())
			}
			e.runners[key] = r
		}
		if c, ok := e.committed[old]; ok {
			e.committed[key] = c
		}
		delete(e.state, old)
		delete(e.runners, old)
		delete(e.committed, old)
		for i := range st.Events {
			st.Events[i].Key = key
		}
		return st
	}
	return nil
}

func switchReason(p Policy, incumbent, from string, ms map[string]Measurement) string {
	switch {
	case incumbent == "" && (from == "" || ms[from].Alive):
		return ReasonElected
	case from != "" && !ms[from].Alive:
		return ReasonDead
	case p == PolicyLatency || p == PolicyThroughput || p == PolicyMixed:
		return ReasonFaster
	default:
		return ReasonRecovered
	}
}

// staticHealth hands Runner.Tick health that was measured before the tick.
type staticHealth []MemberHealth

func (h staticHealth) MemberHealth(ids []string) []MemberHealth {
	by := make(map[string]MemberHealth, len(h))
	for _, m := range h {
		by[m.ID] = m
	}
	out := make([]MemberHealth, 0, len(ids))
	for _, id := range ids {
		m := by[id]
		m.ID = id
		out = append(out, m)
	}
	return out
}

// tableSelector is the Runner's Selector over one routing table.
type tableSelector struct {
	key       UnitKey
	unit      TableUnit
	current   string
	incumbent string
	routes    TableRoutes
	wrote     bool
}

func (s *tableSelector) Selections() map[string]string {
	return map[string]string{s.key.String(): s.incumbent}
}

func (s *tableSelector) Select(_ string, member string) error {
	iface := s.unit.Iface[member]
	if iface == "" {
		return fmt.Errorf("candidate %q has no kernel link", member)
	}
	if iface == s.current {
		return nil // already there: adopt it, write nothing
	}
	if err := s.routes.Replace(s.key.Table, iface); err != nil {
		return err
	}
	s.wrote = true
	return nil
}

// Interrupt does nothing on the kernel plane. The route is looked up per packet, so an existing flow's
// next packet already leaves by the new link; one the old link's NAT rewrote breaks there and the
// client reconnects. Keeping such flows on the old link is a later stage's job (two tables per unit).
func (s *tableSelector) Interrupt(string) error { return nil }
