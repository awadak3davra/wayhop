package failover

import (
	"errors"
	"testing"
)

type fakeHealth struct{ byID map[string]MemberHealth }

func (f fakeHealth) MemberHealth(ids []string) []MemberHealth {
	out := make([]MemberHealth, 0, len(ids))
	for _, id := range ids {
		if h, ok := f.byID[id]; ok {
			h.ID = id
			out = append(out, h)
		} else {
			out = append(out, MemberHealth{ID: id})
		}
	}
	return out
}

type fakeSelector struct {
	now        map[string]string
	fail       bool
	sels       []Switch // recorded Select calls (Group + To)
	interrupts []string // groups Interrupt() was called for
}

func (f *fakeSelector) Selections() map[string]string { return f.now }
func (f *fakeSelector) Select(group, member string) error {
	if f.fail {
		return errors.New("clash select failed")
	}
	if f.now == nil {
		f.now = map[string]string{}
	}
	f.now[group] = member
	f.sels = append(f.sels, Switch{Group: group, To: member})
	return nil
}
func (f *fakeSelector) Interrupt(group string) error {
	f.interrupts = append(f.interrupts, group)
	return nil
}

func specLatency(id string, members ...string) GroupSpec {
	return GroupSpec{ID: id, Policy: PolicyLatency, Members: members}
}

func specLatencyCfg(id string, cfg Config, members ...string) GroupSpec {
	return GroupSpec{ID: id, Policy: PolicyLatency, Members: members, Cfg: cfg}
}

func TestRunnerEmergencySwitch(t *testing.T) {
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: false}, "b": {Alive: true, LatencyMs: 40}}}
	sel := &fakeSelector{now: map[string]string{"g": "a"}} // routed through the now-dead a
	r := NewRunner()

	sw := r.Tick([]GroupSpec{specLatency("g", "a", "b")}, hs, sel, 1000)
	if len(sw) != 1 || sw[0].To != "b" || sw[0].From != "a" {
		t.Fatalf("emergency: switches=%+v, want one a→b", sw)
	}
	if len(sel.sels) != 1 || sel.sels[0].To != "b" {
		t.Errorf("Select not applied: %+v", sel.sels)
	}
	if r.lastSwitch["g"] != 1000 {
		t.Errorf("lastSwitch=%d, want 1000", r.lastSwitch["g"])
	}
	// F11: an emergency switch hard-cuts the group's stuck connections and is marked Emergency.
	if !sw[0].Emergency {
		t.Errorf("emergency switch should be marked Emergency")
	}
	if len(sel.interrupts) != 1 || sel.interrupts[0] != "g" {
		t.Errorf("emergency switch should Interrupt the group's connections, got %+v", sel.interrupts)
	}
}

func TestRunnerNoChangeNoSelect(t *testing.T) {
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 10}, "b": {Alive: true, LatencyMs: 99}}}
	sel := &fakeSelector{now: map[string]string{"g": "a"}} // already on the fastest
	r := NewRunner()
	if sw := r.Tick([]GroupSpec{specLatency("g", "a", "b")}, hs, sel, 1000); len(sw) != 0 {
		t.Fatalf("stable group should not switch: %+v", sw)
	}
	if len(sel.sels) != 0 {
		t.Errorf("Select should not be called: %+v", sel.sels)
	}
}

// TestRunnerFailbackDampening pins F6: a switch AWAY from a still-healthy member (a failback to a
// faster/preferred member) is held for Config.FailbackHold before it commits.
func TestRunnerFailbackDampening(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 5000}
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 10}, "b": {Alive: true, LatencyMs: 100}}}
	sel := &fakeSelector{now: map[string]string{"g": "b"}} // on the slower b; a is a faster failback target
	r := NewRunner()
	spec := []GroupSpec{specLatencyCfg("g", cfg, "a", "b")}

	if sw := r.Tick(spec, hs, sel, 1000); len(sw) != 0 { // hold starts
		t.Fatalf("failback held at t1, got %+v", sw)
	}
	if sw := r.Tick(spec, hs, sel, 3000); len(sw) != 0 { // 2s < 5s hold
		t.Fatalf("failback still held at t2, got %+v", sw)
	}
	sw := r.Tick(spec, hs, sel, 6500) // 5.5s ≥ 5s hold
	if len(sw) != 1 || sw[0].To != "a" {
		t.Fatalf("failback should commit after the hold, got %+v", sw)
	}
	if sel.now["g"] != "a" {
		t.Errorf("expected group now on a, got %v", sel.now)
	}
	// F11: a graceful failback (b was healthy) must NOT interrupt connections — let them drain.
	if sw[0].Emergency {
		t.Errorf("graceful failback should not be marked Emergency")
	}
	if len(sel.interrupts) != 0 {
		t.Errorf("graceful failback must not Interrupt connections, got %+v", sel.interrupts)
	}
}

// TestRunnerFailbackFlappingNeverCommits pins the anti-flap-failback guarantee: a preferred member
// that recovers then dies before the hold completes resets the hold each cycle, so it never steals
// traffic back from the healthy incumbent.
func TestRunnerFailbackFlappingNeverCommits(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 5000}
	sel := &fakeSelector{now: map[string]string{"g": "b"}}
	r := NewRunner()
	now := int64(1000)
	for i := 0; i < 10; i++ {
		// a is up on even ticks, down on odd — never healthy for the full 5s hold (2s per tick).
		hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: i%2 == 0, LatencyMs: 10}, "b": {Alive: true, LatencyMs: 100}}}
		if sw := r.Tick([]GroupSpec{specLatencyCfg("g", cfg, "a", "b")}, hs, sel, now); len(sw) != 0 {
			t.Fatalf("flapping candidate must never fail back (tick %d): %+v", i, sw)
		}
		now += 2000
	}
	if sel.now["g"] != "b" {
		t.Errorf("should have stayed on the healthy incumbent b, got %v", sel.now)
	}
}

func TestRunnerSelectErrorNotRecorded(t *testing.T) {
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: false}, "b": {Alive: true, LatencyMs: 40}}}
	sel := &fakeSelector{now: map[string]string{"g": "a"}, fail: true}
	r := NewRunner()
	if sw := r.Tick([]GroupSpec{specLatency("g", "a", "b")}, hs, sel, 1000); len(sw) != 0 {
		t.Fatalf("a failed Select must not be reported as a switch: %+v", sw)
	}
	if _, ok := r.lastSwitch["g"]; ok {
		t.Errorf("min-dwell must not be charged for a failed apply: lastSwitch=%v", r.lastSwitch)
	}
}

func TestRunnerInertAndNilSafe(t *testing.T) {
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 10}}}
	sel := &fakeSelector{now: map[string]string{}}
	r := NewRunner()
	if sw := r.Tick(nil, hs, sel, 1000); sw != nil {
		t.Errorf("no groups → nil, got %+v", sw)
	}
	if sw := r.Tick([]GroupSpec{specLatency("g", "a")}, nil, sel, 1000); sw != nil {
		t.Errorf("nil health source → nil, got %+v", sw)
	}
	if sw := r.Tick([]GroupSpec{specLatency("g", "a")}, hs, nil, 1000); sw != nil {
		t.Errorf("nil selector → nil, got %+v", sw)
	}
	var nilRunner *Runner
	if sw := nilRunner.Tick([]GroupSpec{specLatency("g", "a")}, hs, sel, 1000); sw != nil {
		t.Errorf("nil runner → nil, got %+v", sw)
	}
}

// TestRunnerFlapDampingSuppressesFlappyMember pins F7: a fast but chronically-flapping member is
// damped out of selection, so the runner keeps the stable (slower) incumbent even when the flappy
// member's current probe is alive and faster.
func TestRunnerFlapDampingSuppressesFlappyMember(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 1} // isolate the damping effect from dwell/hold
	sel := &fakeSelector{now: map[string]string{"g": "b"}}
	r := NewRunner()
	spec := []GroupSpec{{ID: "g", Policy: PolicyLatency, Members: []string{"a", "b"}, Cfg: cfg}}

	// Flap a up/down repeatedly (each up→down is a flap) to accrue penalty past the suppress threshold.
	now := int64(0)
	for i := 0; i < 8; i++ {
		hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: i%2 == 0, LatencyMs: 5}, "b": {Alive: true, LatencyMs: 100}}}
		r.Tick(spec, hs, sel, now)
		now += 1000
	}
	// a is now alive AND fastest, but suppressed → the runner must keep b.
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 5}, "b": {Alive: true, LatencyMs: 100}}}
	if sw := r.Tick(spec, hs, sel, now); len(sw) != 0 || sel.now["g"] != "b" {
		t.Fatalf("flappy fast member should be damped out; expected to stay on b, got sw=%+v now=%v", sw, sel.now)
	}
}

// TestRunnerFlapDampingNeverEjectsLastAlive pins the max-ejection guard: when the flappy member is
// the ONLY alive one, it must NOT be ejected — routing through a flappy exit beats blackholing all.
func TestRunnerFlapDampingNeverEjectsLastAlive(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 1}
	sel := &fakeSelector{now: map[string]string{"g": "a"}} // already routed through a
	r := NewRunner()
	spec := []GroupSpec{{ID: "g", Policy: PolicyLatency, Members: []string{"a", "b"}, Cfg: cfg}}

	now := int64(0)
	for i := 0; i < 8; i++ {
		hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: i%2 == 0, LatencyMs: 5}, "b": {Alive: false}}}
		r.Tick(spec, hs, sel, now)
		now += 1000
	}
	// a alive (flappy, would-be-suppressed), b dead → a is the last alive → must stay selectable.
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 5}, "b": {Alive: false}}}
	if sw := r.Tick(spec, hs, sel, now); len(sw) != 0 || sel.now["g"] != "a" {
		t.Fatalf("last alive member must not be ejected even if flappy; expected to stay on a, got sw=%+v now=%v", sw, sel.now)
	}
}

type fakeFailures struct{ failing map[string]bool }

func (f fakeFailures) Failing() map[string]bool { return f.failing }

// TestRunnerPassiveOutlierEjection pins F8: a member whose synthetic probe passes but that fails
// REAL traffic is ejected after enough consecutive failures, and the runner moves traffic off it.
func TestRunnerPassiveOutlierEjection(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 1}
	sel := &fakeSelector{now: map[string]string{"g": "b"}}
	r := NewRunner()
	r.SetFailureSource(fakeFailures{failing: map[string]bool{"a": true}}) // a fails real traffic
	spec := []GroupSpec{{ID: "g", Policy: PolicyLatency, Members: []string{"a", "b"}, Cfg: cfg}}

	// a is alive+fastest (probe green) so it gets picked first, but it keeps failing real traffic;
	// after >= ConsecutiveFailures (default 5) it is ejected and traffic moves to the healthy b.
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 5}, "b": {Alive: true, LatencyMs: 100}}}
	now := int64(0)
	for i := 0; i < 8; i++ {
		r.Tick(spec, hs, sel, now)
		now += 1000
	}
	if sel.now["g"] != "b" {
		t.Fatalf("outlier a (probe green, traffic dead) should be ejected and traffic moved to b, now=%v", sel.now)
	}
}

// TestRunnerOutlierNeverEjectsLastAlive pins the max-ejection guard for outliers too.
func TestRunnerOutlierNeverEjectsLastAlive(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 1}
	sel := &fakeSelector{now: map[string]string{"g": "a"}}
	r := NewRunner()
	r.SetFailureSource(fakeFailures{failing: map[string]bool{"a": true}})
	spec := []GroupSpec{{ID: "g", Policy: PolicyLatency, Members: []string{"a", "b"}, Cfg: cfg}}

	// a fails real traffic but b is DEAD → a is the only alive member; it must not be ejected.
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 5}, "b": {Alive: false}}}
	now := int64(0)
	for i := 0; i < 8; i++ {
		r.Tick(spec, hs, sel, now)
		now += 1000
	}
	if sel.now["g"] != "a" {
		t.Fatalf("last alive member must not be ejected even as an outlier; stay on a, got %v", sel.now)
	}
}

func TestRunnerGroupsIndependent(t *testing.T) {
	hs := fakeHealth{byID: map[string]MemberHealth{
		"a": {Alive: false}, "b": {Alive: true, LatencyMs: 40}, // g1: emergency
		"c": {Alive: true, LatencyMs: 10}, "d": {Alive: true, LatencyMs: 99}, // g2: stable on c
	}}
	sel := &fakeSelector{now: map[string]string{"g1": "a", "g2": "c"}}
	r := NewRunner()
	sw := r.Tick([]GroupSpec{specLatency("g1", "a", "b"), specLatency("g2", "c", "d")}, hs, sel, 1000)
	if len(sw) != 1 || sw[0].Group != "g1" || sw[0].To != "b" {
		t.Fatalf("only g1 should switch: %+v", sw)
	}
}
