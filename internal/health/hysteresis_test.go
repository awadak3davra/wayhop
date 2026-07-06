package health

import "testing"

// TestProbeStateHysteresis proves the flap debounce (real mode, flapThreshold=2): a single
// transient Down probe does NOT flip the state or count a reconnect, while a sustained
// outage (flapThreshold consecutive Downs) does, and recovery then counts exactly one.
func TestProbeStateHysteresis(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}} // demo=false → flapThreshold=2

	m.record("e", "E", "endpoint", Alive, 20, 1000)

	// One transient Down: state holds Alive (debounced).
	m.record("e", "E", "endpoint", Down, 0, 2000)
	if v := toView("e", m.stats["e"], 3000); v.State != "alive" {
		t.Errorf("after one transient Down: state=%s want alive (debounced)", v.State)
	}
	// Recovery without ever committing Down → no reconnect.
	m.record("e", "E", "endpoint", Alive, 25, 3000)
	if v := toView("e", m.stats["e"], 4000); v.Reconnects != 0 {
		t.Errorf("reconnects=%d want 0 (a single transient Down must not inflate it)", v.Reconnects)
	}

	// A sustained outage (flapThreshold consecutive Downs) DOES flip to Down.
	for i := 0; i < flapThreshold; i++ {
		m.record("e", "E", "endpoint", Down, 0, int64(5000+i*1000))
	}
	if v := toView("e", m.stats["e"], 8000); v.State != "down" {
		t.Errorf("after %d consecutive Downs: state=%s want down", flapThreshold, v.State)
	}
	// Recovery is SLOW-IN: the first aliveThreshold-1 Alive probes must HOLD Down (a dead exit
	// can answer one lucky probe), and only the aliveThreshold-th confirms recovery — counting
	// exactly one reconnect. This is the fast-out / slow-in symmetry every LB uses.
	for i := 0; i < aliveThreshold-1; i++ {
		m.record("e", "E", "endpoint", Alive, 30, int64(9000+i*500))
		if v := toView("e", m.stats["e"], 9250); v.State != "down" {
			t.Errorf("after %d/%d Alive probes: state=%s want down (slow-in recovery)", i+1, aliveThreshold, v.State)
		}
		if v := toView("e", m.stats["e"], 9250); v.Reconnects != 0 {
			t.Errorf("reconnects=%d want 0 (recovery not yet confirmed)", v.Reconnects)
		}
	}
	m.record("e", "E", "endpoint", Alive, 30, 10000)
	if v := toView("e", m.stats["e"], 10500); v.State != "alive" {
		t.Errorf("after %d consecutive Alive probes: state=%s want alive", aliveThreshold, v.State)
	}
	if v := toView("e", m.stats["e"], 10500); v.Reconnects != 1 {
		t.Errorf("reconnects=%d want 1 (one confirmed down→alive recovery)", v.Reconnects)
	}
}

// TestRecoveryHysteresisIgnoresLuckyProbe pins the inverted-hysteresis fix (F1): a confirmed-Down
// exit that answers a SINGLE lucky probe interleaved with failures must NEVER flip back to Alive —
// only aliveThreshold CONSECUTIVE Alive probes recover it. Guards against a dead/flapping exit
// re-attracting traffic on one fluke response.
func TestRecoveryHysteresisIgnoresLuckyProbe(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}} // demo=false → aliveThreshold=2

	// Drive to confirmed Down.
	for i := 0; i < flapThreshold; i++ {
		m.record("x", "X", "endpoint", Down, 0, int64(1000+i*1000))
	}
	if v := toView("x", m.stats["x"], 5000); v.State != "down" {
		t.Fatalf("setup: state=%s want down", v.State)
	}
	// Lucky Alive, then Down again, repeated: consecOK never reaches the threshold → stays Down.
	for i := 0; i < 5; i++ {
		m.record("x", "X", "endpoint", Alive, 20, int64(6000+i*2000))
		m.record("x", "X", "endpoint", Down, 0, int64(7000+i*2000))
		if v := toView("x", m.stats["x"], int64(7500+i*2000)); v.State != "down" {
			t.Errorf("iter %d: a lone Alive between Downs flipped state=%s, want down", i, v.State)
		}
	}
	if v := toView("x", m.stats["x"], 20000); v.Reconnects != 0 {
		t.Errorf("reconnects=%d want 0 (never truly recovered)", v.Reconnects)
	}
}
