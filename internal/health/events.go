package health

import (
	"context"
	"time"
)

// A record of what actually changed, so the Failover page can answer "why is traffic here now?"
// with history rather than with the current instant.
//
// The monitor is the only honest place to keep this. Deriving it in the browser would mean the log
// only contains what happened while someone had the page open — a partial record presented as a
// complete one, which is the failure this codebase keeps having to correct. The monitor ticks every
// 10s whether or not anything is watching, so what it misses is bounded and stated: transitions
// faster than one tick, and anything before the daemon started.
//
// The buffer is deliberately small and in-memory. Persisting it would mean writing to the router's
// overlay every time an exit flaps, and a flapping exit is exactly when you least want extra writes.

// EventKind values. Kept as plain strings because they cross the API boundary into the UI.
const (
	// EventDown / EventUp: an exit's committed health state changed. "Committed" matters — these
	// fire after the flap hysteresis in record(), so one dropped probe does not enter the log.
	EventDown = "down"
	EventUp   = "up"
	// EventSwitch: a failover group's elected member changed — the actual switch, read from the
	// proxy core rather than guessed from latency.
	EventSwitch = "switch"
)

// eventCap bounds the ring. At one event per exit per tick — far beyond any real flap rate — this
// still covers several minutes of total chaos, and in normal operation it is days.
const eventCap = 256

// Event is one entry in the failover log.
type Event struct {
	At        int64  `json:"at"`                   // unix milliseconds
	Kind      string `json:"kind"`                 // down | up | switch
	ID        string `json:"id"`                   // endpoint id, or group id for a switch
	Name      string `json:"name"`                 // display name at the time it happened
	From      string `json:"from,omitempty"`       // previous state, or previous elected member
	To        string `json:"to,omitempty"`         // new state, or new elected member
	LatencyMS int    `json:"latency_ms,omitempty"` // latency at the moment of the change, when known
}

// pushEvent appends to the ring. The caller must hold m.mu — record() already does, and keeping the
// lock shared means an event can never describe a transition that was not also committed.
func (m *Monitor) pushEvent(e Event) {
	if len(m.events) < eventCap {
		m.events = append(m.events, e)
		return
	}
	// Full: overwrite the oldest slot and advance the head.
	m.events[m.evHead] = e
	m.evHead = (m.evHead + 1) % eventCap
}

// Events returns up to limit entries, newest first. limit <= 0 means all of them.
func (m *Monitor) Events(limit int) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.events)
	if n == 0 {
		return []Event{}
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	// Walk backwards from the newest. When the ring has wrapped, the newest sits just before
	// evHead; otherwise it is the last appended element.
	for i := 0; i < limit; i++ {
		idx := (m.evHead + n - 1 - i) % n
		out = append(out, m.events[idx])
	}
	return out
}

// RecentWindow is one target's rolling probe window, oldest sample first.
//
// It is deliberately NOT a time series. The monitor keeps outcomes, not timestamps, so the only
// honest statement is "these are the last N probes at a nominal interval" — a caller that renders it
// against a wall clock would be inventing precision. IntervalS is that nominal cadence; if the
// daemon was descheduled or the box slept, the real span is longer and nothing here can tell.
type RecentWindow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Samples   []bool `json:"samples"`    // true = the probe answered
	IntervalS int    `json:"interval_s"` // nominal seconds between probes
	Full      bool   `json:"full"`       // the window has wrapped at least once
}

// RecentWindows returns the probe window for every target the monitor is tracking.
func (m *Monitor) RecentWindows() []RecentWindow {
	m.mu.Lock()
	defer m.mu.Unlock()
	interval := int(m.interval / time.Second)
	if interval < 1 {
		interval = 1
	}
	out := make([]RecentWindow, 0, len(m.stats))
	for id, s := range m.stats {
		if s == nil || s.recentN == 0 {
			continue
		}
		w := RecentWindow{ID: id, Name: s.name, IntervalS: interval, Full: s.recentN == healthWindow}
		w.Samples = make([]bool, 0, s.recentN)
		// Walk oldest to newest. Before the ring wraps, slot 0 is the oldest; after, the oldest sits
		// at recentPos. Reading it the wrong way round would show a recovery as an outage.
		start := 0
		if s.recentN == healthWindow {
			start = s.recentPos
		}
		for i := 0; i < s.recentN; i++ {
			w.Samples = append(w.Samples, s.recent[(start+i)%healthWindow].ok)
		}
		out = append(out, w)
	}
	return out
}

// EventCount reports how many entries the ring currently holds, so a caller that asked for fewer
// can tell whether it saw all of them. Without it a limited read reports "truncated" whenever the
// limit is below the ring capacity, which is a guess dressed as a fact.
func (m *Monitor) EventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// OldestEventAt returns the timestamp of the earliest entry still held, or 0 when the log is empty.
// The API pairs it with the daemon start time so the stated coverage window actually contains every
// event shown — the monitor begins ticking before the HTTP server is constructed, so a window that
// began at server start would exclude entries it is displaying.
func (m *Monitor) OldestEventAt() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return 0
	}
	return m.events[m.evHead%len(m.events)].At
}

// sampleElection records which member each failover group is actually routing through, and logs a
// switch whenever that changes.
//
// This reads the proxy core, not the latency table: "the exit WayHop would pick" and "the exit
// sing-box is using" are different claims, and only the second one is a switch that happened. A
// core that cannot be reached yields no events at all rather than a fabricated one — an unreadable
// election is not evidence that nothing switched.
func (m *Monitor) sampleElection(ctx context.Context) {
	if m.clash == nil || m.store == nil {
		return
	}
	proxies, err := m.clash.Proxies(ctx)
	if err != nil {
		return
	}
	now := nowMS()
	groups := m.store.Profile().Groups
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.elected == nil {
		m.elected = map[string]string{}
	}
	seen := map[string]bool{}
	for _, g := range groups {
		p, ok := proxies[g.ID]
		if !ok || p.Now == "" {
			continue
		}
		seen[g.ID] = true
		prev, had := m.elected[g.ID]
		m.elected[g.ID] = p.Now
		// The first reading establishes a baseline. Logging it as a switch would report the daemon
		// starting up as a failover event every time it restarts.
		if !had || prev == p.Now {
			continue
		}
		m.pushEvent(Event{
			At: now, Kind: EventSwitch, ID: g.ID, Name: g.Name,
			From: m.nameForLocked(prev), To: m.nameForLocked(p.Now),
		})
	}
	// Forget groups that no longer exist, so a deleted-and-recreated group does not inherit a stale
	// baseline and report a switch that never happened.
	for id := range m.elected {
		if !seen[id] {
			delete(m.elected, id)
		}
	}
}

// nameForLocked resolves a target id to the display name the monitor last saw. Caller holds m.mu.
func (m *Monitor) nameForLocked(id string) string {
	if s := m.stats[id]; s != nil && s.name != "" {
		return s.name
	}
	return id
}

// SampleElectionForTest drives one election sample with an explicit deadline. Exported for tests in
// other packages that wire a fake proxy core.
func (m *Monitor) SampleElectionForTest(ctx context.Context, timeout time.Duration) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	m.sampleElection(c)
}

// RecordSwitch logs an election the DAEMON made — as opposed to one the proxy core reported. The
// kernel plane's routing-list failover is the first such writer: it re-points a list's routing table
// at another member of the group, which is a switch by every meaning the log already has, and
// without this entry it would happen invisibly.
func (m *Monitor) RecordSwitch(groupID, name, from, to string) {
	if m == nil || groupID == "" || to == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushEvent(Event{
		At: time.Now().UnixMilli(), Kind: "switch",
		ID: groupID, Name: name, From: from, To: to,
	})
}
