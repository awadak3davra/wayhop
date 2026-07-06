package failover

import "testing"

func m(id string, alive bool, lat int) MemberHealth {
	return MemberHealth{ID: id, Alive: alive, LatencyMs: lat}
}

func TestDecideLatency(t *testing.T) {
	tests := []struct {
		name        string
		members     []MemberHealth
		current     string
		lastSwitch  int64
		now         int64
		wantDesired string
		wantChanged bool
	}{
		{"empty current selects fastest alive", []MemberHealth{m("a", true, 90), m("b", true, 30)}, "", 0, 0, "b", true},
		{"keep current within tolerance", []MemberHealth{m("a", true, 70), m("b", true, 40)}, "a", 0, 100000, "a", false},
		{"switch when a member is faster beyond tolerance", []MemberHealth{m("a", true, 130), m("b", true, 40)}, "a", 0, 100000, "b", true},
		{"switch off a dead current immediately (emergency, ignores dwell)", []MemberHealth{m("a", false, 0), m("b", true, 50)}, "a", 99000, 100000, "b", true},
		{"no alive member holds current, no change", []MemberHealth{m("a", false, 0), m("b", false, 0)}, "a", 0, 100000, "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, ch := Decide(DecideInput{Policy: PolicyLatency, Members: tt.members, Current: tt.current, LastSwitch: tt.lastSwitch, Now: tt.now})
			if d != tt.wantDesired || ch != tt.wantChanged {
				t.Errorf("Decide = (%q,%v), want (%q,%v)", d, ch, tt.wantDesired, tt.wantChanged)
			}
		})
	}
}

func TestDecideOrdered(t *testing.T) {
	// Strict priority: always prefer the earliest alive member in configured order.
	tests := []struct {
		name        string
		members     []MemberHealth
		current     string
		lastSwitch  int64
		now         int64
		wantDesired string
		wantChanged bool
	}{
		{"first alive is top of order", []MemberHealth{m("nl", true, 200), m("ru", true, 10)}, "", 0, 0, "nl", true},
		{"current down → next healthy in order (emergency)", []MemberHealth{m("nl", false, 0), m("ru", true, 10)}, "nl", 99000, 100000, "ru", true},
		{"higher-priority recovered preempts (non-emergency, dwell elapsed)", []MemberHealth{m("nl", true, 200), m("ru", true, 10)}, "ru", 0, 100000, "nl", true},
		{"higher-priority recovered is HELD within min-dwell", []MemberHealth{m("nl", true, 200), m("ru", true, 10)}, "ru", 99000, 100000, "ru", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _, ch := Decide(DecideInput{Policy: PolicyOrdered, Members: tt.members, Current: tt.current, LastSwitch: tt.lastSwitch, Now: tt.now})
			if d != tt.wantDesired || ch != tt.wantChanged {
				t.Errorf("Decide = (%q,%v), want (%q,%v)", d, ch, tt.wantDesired, tt.wantChanged)
			}
		})
	}
}

func TestDecideSelector(t *testing.T) {
	// keep the manual pick while it is alive; move to first alive only when it dies.
	if d, _, ch := Decide(DecideInput{Policy: PolicySelector, Members: []MemberHealth{m("a", true, 10), m("b", true, 5)}, Current: "a", Now: 100000}); d != "a" || ch {
		t.Errorf("selector kept alive manual pick: got (%q,%v), want (a,false)", d, ch)
	}
	if d, _, ch := Decide(DecideInput{Policy: PolicySelector, Members: []MemberHealth{m("a", false, 0), m("b", true, 5)}, Current: "a", Now: 100000}); d != "b" || !ch {
		t.Errorf("selector moved off dead manual pick: got (%q,%v), want (b,true)", d, ch)
	}
}

func TestDecideMinDwellGatesOptimizationNotEmergency(t *testing.T) {
	// A non-emergency (both alive) faster-member switch is suppressed inside the dwell window...
	in := DecideInput{Policy: PolicyLatency, Members: []MemberHealth{m("a", true, 130), m("b", true, 20)}, Current: "a", LastSwitch: 95000, Now: 100000, Cfg: Config{MinDwellMS: 10000}}
	if d, _, ch := Decide(in); d != "a" || ch {
		t.Errorf("optimization switch within dwell should be held: got (%q,%v), want (a,false)", d, ch)
	}
	// ...but allowed once the dwell has elapsed.
	in.Now = 106000 // 11s since last switch > 10s dwell
	if d, _, ch := Decide(in); d != "b" || !ch {
		t.Errorf("optimization switch after dwell should commit: got (%q,%v), want (b,true)", d, ch)
	}
	// An EMERGENCY (current dead) switch commits even inside the dwell window.
	in2 := DecideInput{Policy: PolicyLatency, Members: []MemberHealth{m("a", false, 0), m("b", true, 20)}, Current: "a", LastSwitch: 99000, Now: 100000, Cfg: Config{MinDwellMS: 10000}}
	if d, _, ch := Decide(in2); d != "b" || !ch {
		t.Errorf("emergency switch must ignore dwell: got (%q,%v), want (b,true)", d, ch)
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}
	if c.tolerance() != defaultToleranceMs {
		t.Errorf("default tolerance = %d, want %d", c.tolerance(), defaultToleranceMs)
	}
	if c.minDwell() != defaultMinDwellMS {
		t.Errorf("default minDwell = %d, want %d", c.minDwell(), defaultMinDwellMS)
	}
	c2 := Config{ToleranceMs: 150, MinDwellMS: 30000}
	if c2.tolerance() != 150 || c2.minDwell() != 30000 {
		t.Errorf("explicit config not honored: %+v", c2)
	}
}
