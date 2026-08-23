package failover

import "testing"

// TestRunnerOutlierEjectionIsEmergency (round-5): an incumbent that is probe-green but failing REAL
// traffic (outlier-ejected) must be moved off as an EMERGENCY — bypassing the failback hold and
// hard-cutting its flows (Interrupt) — not treated as a graceful hold-gated failback. Before the fix,
// emergency was judged from raw probe health only, so the switch waited the full FailbackHold (never
// committing here) and never Interrupted.
func TestRunnerOutlierEjectionIsEmergency(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 60000} // a LONG hold: only an emergency should bypass it
	sel := &fakeSelector{now: map[string]string{"g": "a"}}
	r := NewRunner()
	r.SetFailureSource(fakeFailures{failing: map[string]bool{"a": true}}) // a fails real traffic
	spec := []GroupSpec{{ID: "g", Policy: PolicyLatency, Members: []string{"a", "b"}, Cfg: cfg}}
	hs := fakeHealth{byID: map[string]MemberHealth{"a": {Alive: true, LatencyMs: 5}, "b": {Alive: true, LatencyMs: 100}}}

	moved, lastEmergency := false, false
	now := int64(0)
	for i := 0; i < 8; i++ {
		for _, s := range r.Tick(spec, hs, sel, now) {
			if s.Group == "g" && s.To == "b" {
				moved, lastEmergency = true, s.Emergency
			}
		}
		now += 1000
	}
	if !moved || sel.now["g"] != "b" {
		t.Fatalf("outlier a (probe-green, traffic-dead) must be ejected and traffic moved to b despite the long hold, now=%v", sel.now)
	}
	if !lastEmergency {
		t.Error("a switch off a traffic-dead (outlier-ejected) incumbent must be an EMERGENCY (bypass the failback hold)")
	}
	interrupted := false
	for _, g := range sel.interrupts {
		if g == "g" {
			interrupted = true
		}
	}
	if !interrupted {
		t.Error("an emergency switch must Interrupt the flows stuck on the dead incumbent")
	}
}

// TestRunnerOutlierRecordedOncePerTick (round-5): a member shared by two managed groups must have its
// real-traffic failure counted ONCE per tick, not once per group — otherwise it is ejected after
// ceil(ConsecutiveFailures/groups) ticks instead of ConsecutiveFailures (premature ejection driven by
// group multiplicity, not actual failure count).
func TestRunnerOutlierRecordedOncePerTick(t *testing.T) {
	cfg := Config{MinDwellMS: 1, FailbackHoldMS: 1} // ConsecutiveFailures defaults to 5
	sel := &fakeSelector{now: map[string]string{"g1": "m", "g2": "m"}}
	r := NewRunner()
	r.SetFailureSource(fakeFailures{failing: map[string]bool{"m": true}}) // m fails real traffic
	spec := []GroupSpec{
		{ID: "g1", Policy: PolicyLatency, Members: []string{"m", "x"}, Cfg: cfg},
		{ID: "g2", Policy: PolicyLatency, Members: []string{"m", "y"}, Cfg: cfg},
	}
	hs := fakeHealth{byID: map[string]MemberHealth{
		"m": {Alive: true, LatencyMs: 5}, // probe-green + fastest, but failing real traffic
		"x": {Alive: true, LatencyMs: 100},
		"y": {Alive: true, LatencyMs: 100},
	}}
	now := int64(0)
	tick := func() { r.Tick(spec, hs, sel, now); now += 1000 }

	// After 4 ticks (< the default 5 ConsecutiveFailures), m must NOT be ejected yet. A per-group
	// Record would double-count (m is in two groups) and eject it by ~tick 3, moving traffic off it.
	for i := 0; i < 4; i++ {
		tick()
	}
	if sel.now["g1"] != "m" || sel.now["g2"] != "m" {
		t.Fatalf("m ejected too early (per-group double-count): now=%v, want both still on m after 4 ticks", sel.now)
	}
	// A few more ticks reach the real threshold and m is ejected from both groups.
	for i := 0; i < 3; i++ {
		tick()
	}
	if sel.now["g1"] == "m" || sel.now["g2"] == "m" {
		t.Fatalf("m should be outlier-ejected once the failures reach the threshold: now=%v", sel.now)
	}
}
