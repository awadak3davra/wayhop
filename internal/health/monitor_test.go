package health

import "testing"

func TestStatsAccumulation(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	// unknown(init) -> alive(40) -> alive(60) -> down -> down -> alive(50) -> alive(50)
	// Two consecutive Alive probes are needed to confirm recovery (aliveThreshold=2, slow-in);
	// the state flips back to alive on the SECOND one (t=6000).
	m.record("e", "E", "endpoint", Alive, 40, 1000)
	m.record("e", "E", "endpoint", Alive, 60, 2000)
	m.record("e", "E", "endpoint", Down, 0, 3000)
	m.record("e", "E", "endpoint", Down, 0, 4000)
	m.record("e", "E", "endpoint", Alive, 50, 5000)
	m.record("e", "E", "endpoint", Alive, 50, 6000)

	v := toView("e", m.stats["e"], 9000)
	if v.Probes != 6 {
		t.Fatalf("probes=%d want 6", v.Probes)
	}
	if v.SuccessRate != 66 {
		t.Fatalf("success_rate=%d want 66 (4 of 6)", v.SuccessRate)
	}
	if v.AvgLatencyMs != 50 {
		t.Fatalf("avg=%d want 50 ((40+60+50+50)/4)", v.AvgLatencyMs)
	}
	if v.Reconnects != 1 {
		t.Fatalf("reconnects=%d want 1 (one confirmed down->alive recovery)", v.Reconnects)
	}
	if v.UptimeS != 3 {
		t.Fatalf("uptime=%d want 3 (since recovery confirmed at t=6000)", v.UptimeS)
	}
	if v.State != "alive" {
		t.Fatalf("state=%s want alive", v.State)
	}
}

func TestFirstConnectIsNotReconnect(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	m.record("e", "E", "endpoint", Unknown, 0, 1000)
	m.record("e", "E", "endpoint", Alive, 10, 2000) // unknown->alive is the first connect
	if v := toView("e", m.stats["e"], 3000); v.Reconnects != 0 {
		t.Fatalf("reconnects=%d want 0", v.Reconnects)
	}
}
