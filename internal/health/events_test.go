package health

import (
	"testing"
	"time"
)

// The log exists so the Failover page can say why traffic moved. Every property below is one the
// page relies on being true; each was written to fail against a monitor that did not record.

func newTestMonitor() *Monitor {
	return &Monitor{stats: map[string]*stat{}, testURL: "http://x", timeoutMS: 1000}
}

// A first reading is not a recovery. Logging Unknown->Alive would mean every daemon restart filled
// the log with "came back" lines for exits that were never down.
func TestEvents_FirstReadingIsNotAnEvent(t *testing.T) {
	m := newTestMonitor()
	m.demo = true // thresholds of 1, so a single probe commits
	m.record("a", "Exit A", "endpoint", Alive, 40, 1000)
	if ev := m.Events(0); len(ev) != 0 {
		t.Fatalf("bringing an exit up for the first time is not an event, got %+v", ev)
	}
}

// A confirmed outage and its recovery both land, in that order, naming the exit.
func TestEvents_DownThenUp(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	m.record("a", "Exit A", "endpoint", Alive, 40, 1000)
	m.record("a", "Exit A", "endpoint", Down, 0, 2000)
	m.record("a", "Exit A", "endpoint", Alive, 55, 3000)

	ev := m.Events(0)
	if len(ev) != 2 {
		t.Fatalf("want one down and one up, got %d: %+v", len(ev), ev)
	}
	// Newest first.
	if ev[0].Kind != EventUp || ev[0].At != 3000 || ev[0].LatencyMS != 55 {
		t.Errorf("newest entry should be the recovery with its latency, got %+v", ev[0])
	}
	if ev[1].Kind != EventDown || ev[1].At != 2000 {
		t.Errorf("older entry should be the outage, got %+v", ev[1])
	}
	if ev[0].Name != "Exit A" || ev[1].Name != "Exit A" {
		t.Errorf("both entries should name the exit, got %q / %q", ev[0].Name, ev[1].Name)
	}
	if ev[1].From != string(Alive) || ev[1].To != string(Down) {
		t.Errorf("the outage should carry both ends of the transition, got %+v", ev[1])
	}
}

// The whole point of committing after hysteresis: a single dropped probe is not an outage, and must
// not appear in a log a human reads to decide whether an exit is unreliable.
func TestEvents_FlapBelowThresholdIsNotLogged(t *testing.T) {
	m := newTestMonitor() // not demo: real thresholds apply
	m.record("a", "Exit A", "endpoint", Alive, 40, 1000)
	m.record("a", "Exit A", "endpoint", Alive, 41, 2000)
	m.record("a", "Exit A", "endpoint", Down, 0, 3000) // one bad probe
	m.record("a", "Exit A", "endpoint", Alive, 42, 4000)

	if ev := m.Events(0); len(ev) != 0 {
		t.Fatalf("one dropped probe is not an outage, got %+v", ev)
	}
}

// Newest-first with a limit, and correct behaviour once the ring has wrapped — a log that silently
// reorders or loses the newest entries when it fills is worse than no log.
func TestEvents_RingKeepsNewestAfterWrap(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	m.record("a", "Exit A", "endpoint", Alive, 10, 0) // baseline, no event
	// Each pair of records produces exactly two events (down, then up).
	total := eventCap + 20
	at := int64(1)
	for i := 0; i < total; i++ {
		m.record("a", "Exit A", "endpoint", Down, 0, at)
		at++
		m.record("a", "Exit A", "endpoint", Alive, 10, at)
		at++
	}
	ev := m.Events(0)
	if len(ev) != eventCap {
		t.Fatalf("ring should hold exactly %d, got %d", eventCap, len(ev))
	}
	// The newest event is the final recovery, whose timestamp is the last one written.
	if ev[0].At != at-1 {
		t.Errorf("newest entry should be the last write (at=%d), got at=%d", at-1, ev[0].At)
	}
	for i := 1; i < len(ev); i++ {
		if ev[i].At > ev[i-1].At {
			t.Fatalf("entries must be newest-first; index %d (at=%d) is newer than %d (at=%d)",
				i, ev[i].At, i-1, ev[i-1].At)
		}
	}
	if n := len(m.Events(5)); n != 5 {
		t.Errorf("limit should be honoured, want 5 got %d", n)
	}
}

// Two exits interleaved: each entry must name the exit it belongs to, or the log cannot be read.
func TestEvents_AttributedToTheRightExit(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	m.record("a", "Exit A", "endpoint", Alive, 10, 100)
	m.record("b", "Exit B", "endpoint", Alive, 20, 100)
	m.record("b", "Exit B", "endpoint", Down, 0, 200)
	m.record("a", "Exit A", "endpoint", Down, 0, 300)

	ev := m.Events(0)
	if len(ev) != 2 {
		t.Fatalf("want two outages, got %d: %+v", len(ev), ev)
	}
	if ev[0].ID != "a" || ev[1].ID != "b" {
		t.Errorf("newest should be Exit A then Exit B, got %q then %q", ev[0].ID, ev[1].ID)
	}
}

// An empty log is an empty list, not nil — the API encodes it as [] rather than null, and the page
// distinguishes "nothing has happened" from "could not read".
func TestEvents_EmptyIsNotNil(t *testing.T) {
	if ev := newTestMonitor().Events(0); ev == nil {
		t.Fatal("Events must return an empty slice, never nil")
	}
}

// The availability band is read left to right as time, so sample ORDER is the whole meaning. Reading
// the ring from the wrong end turns a recovery into an outage and vice versa — a picture that is
// exactly wrong rather than merely missing.
func TestRecentWindows_OldestFirst(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	m.interval = 10 * time.Second
	// Three failures then two successes: the band must end healthy.
	for _, ok := range []bool{false, false, false, true, true} {
		st := Down
		if ok {
			st = Alive
		}
		m.record("a", "Exit A", "endpoint", st, 10, 100)
	}
	ws := m.RecentWindows()
	if len(ws) != 1 {
		t.Fatalf("want one window, got %d", len(ws))
	}
	got := ws[0].Samples
	want := []bool{false, false, false, true, true}
	if len(got) != len(want) {
		t.Fatalf("want %d samples, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("samples are not oldest-first: got %v, want %v", got, want)
		}
	}
	if ws[0].Full {
		t.Error("five samples is not a full window")
	}
	if ws[0].IntervalS != 10 {
		t.Errorf("nominal interval should be reported, got %d", ws[0].IntervalS)
	}
}

// Once the ring wraps, the oldest sample sits at recentPos — not at slot 0. Getting this wrong
// rotates the band and silently misplaces every outage in it.
func TestRecentWindows_OrderSurvivesWrap(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	m.interval = 10 * time.Second
	// Fill the window with successes, then wrap it with a single failure at the very end.
	for i := 0; i < healthWindow; i++ {
		m.record("a", "Exit A", "endpoint", Alive, 10, int64(i))
	}
	m.record("a", "Exit A", "endpoint", Down, 0, int64(healthWindow))
	w := m.RecentWindows()[0]
	if !w.Full {
		t.Fatal("the window should be full after wrapping")
	}
	if len(w.Samples) != healthWindow {
		t.Fatalf("a full window holds %d samples, got %d", healthWindow, len(w.Samples))
	}
	if w.Samples[len(w.Samples)-1] {
		t.Error("the newest sample is the failure and must be last")
	}
	for i := 0; i < len(w.Samples)-1; i++ {
		if !w.Samples[i] {
			t.Fatalf("only the last sample failed, but index %d is a failure: %v", i, w.Samples)
		}
	}
}

// A target with no probes yet contributes no window at all — an empty band would be drawn as a
// gap in service rather than as an absence of measurement.
func TestRecentWindows_UnprobedTargetIsOmitted(t *testing.T) {
	m := newTestMonitor()
	if ws := m.RecentWindows(); len(ws) != 0 {
		t.Errorf("nothing probed yet, so there is no window to report: %v", ws)
	}
}

// The API states a coverage window and a truncation flag from these two. If OldestEventAt is wrong
// after the ring wraps, the page claims a window that does not contain the entries it is showing.
func TestEvents_OldestAndCount(t *testing.T) {
	m := newTestMonitor()
	m.demo = true
	if got := m.OldestEventAt(); got != 0 {
		t.Errorf("an empty log has no oldest entry, got %d", got)
	}
	m.record("a", "Exit A", "endpoint", Alive, 10, 100) // baseline, no event
	m.record("a", "Exit A", "endpoint", Down, 0, 200)   // first event
	m.record("a", "Exit A", "endpoint", Alive, 10, 300)
	if got := m.OldestEventAt(); got != 200 {
		t.Errorf("before wrapping, the oldest entry is the first one written; want 200 got %d", got)
	}
	if got := m.EventCount(); got != 2 {
		t.Errorf("want 2 events, got %d", got)
	}

	at := int64(1000)
	for i := 0; i < eventCap; i++ {
		m.record("a", "Exit A", "endpoint", Down, 0, at)
		at++
		m.record("a", "Exit A", "endpoint", Alive, 10, at)
		at++
	}
	if got := m.EventCount(); got != eventCap {
		t.Fatalf("ring should be full at %d, got %d", eventCap, got)
	}
	oldest := m.OldestEventAt()
	newest := m.Events(1)[0].At
	if oldest >= newest {
		t.Errorf("after wrapping the oldest (%d) must precede the newest (%d)", oldest, newest)
	}
	// Every entry the log still holds must fall inside the window the API would state.
	for _, e := range m.Events(0) {
		if e.At < oldest {
			t.Fatalf("entry at %d precedes the stated window start %d", e.At, oldest)
		}
	}
}
