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

func mt(id string, alive bool, latency int, kbps, at int64) MemberHealth {
	return MemberHealth{ID: id, Alive: alive, LatencyMs: latency, ThroughputKbps: kbps, ThroughputAt: at}
}

func TestDecideThroughputWinnerFallbackAndFreshness(t *testing.T) {
	now := int64(200_000_000)
	fresh := now - 1000
	tests := []struct {
		name    string
		members []MemberHealth
		current string
		want    string
		changed bool
	}{
		{
			name: "highest fresh throughput wins and configured order breaks ties",
			members: []MemberHealth{
				mt("a", true, 10, 100, fresh), mt("b", true, 100, 500, fresh), mt("c", true, 50, 500, fresh),
			},
			want: "b", changed: true,
		},
		{
			name: "no samples uses lowest latency",
			members: []MemberHealth{
				mt("a", true, 100, 0, 0), mt("b", true, 20, 0, 0),
			},
			want: "b", changed: true,
		},
		{
			name: "no samples with a healthy incumbent still uses latency fallback",
			members: []MemberHealth{
				mt("a", true, 100, 0, 0), mt("b", true, 20, 0, 0),
			},
			current: "a", want: "b", changed: true,
		},
		{
			name: "no samples keeps the legacy latency deadband",
			members: []MemberHealth{
				mt("a", true, 70, 0, 0), mt("b", true, 40, 0, 0),
			},
			current: "a", want: "a",
		},
		{
			name: "emergency with one live sample chooses by delay: one figure is not comparable",
			members: []MemberHealth{
				mt("a", false, 1, 1000, fresh), mt("b", true, 100, 200, fresh), mt("c", true, 10, 0, 0),
			},
			current: "a", want: "c", changed: true,
		},
		{
			name: "healthy unsampled incumbent is not pinned: it is left by delay",
			members: []MemberHealth{
				mt("a", true, 100, 0, 0), mt("b", true, 20, 5000, fresh),
			},
			current: "a", want: "b", changed: true,
		},
		{
			name: "healthy unsampled incumbent does not yield to a sampled challenger within the delay deadband",
			members: []MemberHealth{
				mt("a", true, 40, 0, 0), mt("b", true, 20, 5000, fresh), mt("c", true, 30, 9000, fresh),
			},
			current: "a", want: "a",
		},
		{
			name: "unsampled incumbent among two sampled still optimizes by delay",
			members: []MemberHealth{
				mt("a", true, 190, 0, 0), mt("b", true, 60, 100, fresh), mt("c", true, 70, 9000, fresh),
			},
			current: "a", want: "b", changed: true,
		},
		{
			name: "one sampled member and no incumbent: by delay, not by the lone figure",
			members: []MemberHealth{
				mt("a", true, 20, 0, 0), mt("b", true, 150, 90000, fresh), mt("c", true, 30, 0, 0),
			},
			want: "a", changed: true,
		},
		{
			name: "healthy stale incumbent is treated as unsampled",
			members: []MemberHealth{
				mt("a", true, 100, 100, now-throughputSampleFreshWindowMS-1), mt("b", true, 20, 5000, fresh),
			},
			current: "a", want: "b", changed: true,
		},
		{
			name: "sample exactly twenty four hours old is fresh",
			members: []MemberHealth{
				mt("a", true, 100, 300, now-throughputSampleFreshWindowMS), mt("b", true, 10, 200, fresh),
			},
			want: "a", changed: true,
		},
		{
			name: "sample older than twenty four hours is rejected",
			members: []MemberHealth{
				mt("a", true, 10, 0, 0), mt("b", true, 100, 5000, now-throughputSampleFreshWindowMS-1),
			},
			want: "a", changed: true,
		},
		{
			name: "future sample is rejected",
			members: []MemberHealth{
				mt("a", true, 100, 100, fresh), mt("b", true, 10, 5000, now+1), mt("c", true, 120, 50, fresh),
			},
			want: "a", changed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, changed := Decide(DecideInput{Policy: PolicyThroughput, Members: tt.members, Current: tt.current, Now: now})
			if got != tt.want || changed != tt.changed {
				t.Fatalf("Decide = (%q, %v), want (%q, %v)", got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestDecideThroughputDeadbandIsPercentageOnly(t *testing.T) {
	now := int64(100_000)
	tests := []struct {
		name       string
		challenger int64
		cfg        Config
		want       string
		changed    bool
	}{
		{name: "below default twenty percent", challenger: 1199, want: "a"},
		{name: "exact default boundary keeps incumbent", challenger: 1200, want: "a"},
		{name: "beyond default boundary switches", challenger: 1201, want: "b", changed: true},
		{name: "configured percentage", challenger: 1400, cfg: Config{TolerancePct: 40}, want: "a"},
		{name: "beyond configured percentage", challenger: 1401, cfg: Config{TolerancePct: 40}, want: "b", changed: true},
		{name: "absolute milliseconds do not apply", challenger: 1001, cfg: Config{ToleranceMs: 100000, TolerancePct: 1}, want: "a"},
		{name: "absolute milliseconds alone cannot stop a switch", challenger: 1201, cfg: Config{ToleranceMs: 100000}, want: "b", changed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := []MemberHealth{mt("a", true, 100, 1000, now), mt("b", true, 10, tt.challenger, now)}
			got, _, changed := Decide(DecideInput{Policy: PolicyThroughput, Members: members, Current: "a", Now: now, Cfg: tt.cfg})
			if got != tt.want || changed != tt.changed {
				t.Fatalf("Decide = (%q, %v), want (%q, %v)", got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestDecideMixedFiltersBeforeThroughput(t *testing.T) {
	now := int64(100_000)
	cfg := Config{ToleranceMs: 30, TolerancePct: 20, MixedLatencySlackMs: 30}
	members := []MemberHealth{
		mt("dead", false, 1, 10000, now),
		mt("best-latency", true, 20, 100, now),
		mt("eligible-fast", true, 40, 300, now),
		mt("latency-outlier", true, 100, 1000, now),
	}
	got, _, changed := Decide(DecideInput{Policy: PolicyMixed, Members: members, Now: now, Cfg: cfg})
	if got != "eligible-fast" || !changed {
		t.Fatalf("mixed chose (%q, %v), want eligible-fast after dropping dead and outlier", got, changed)
	}

	// Past the slack the cut is twice the best latency, and the boundary is eligible.
	atBoundary := []MemberHealth{
		mt("a", true, 100, 100, now), mt("b", true, 200, 300, now), mt("c", true, 201, 10000, now),
	}
	got, _, _ = Decide(DecideInput{Policy: PolicyMixed, Members: atBoundary, Now: now, Cfg: Config{ToleranceMs: 50, TolerancePct: 20, MixedLatencySlackMs: 50}})
	if got != "b" {
		t.Fatalf("mixed latency threshold excluded its boundary: chose %q, want b", got)
	}

	// The default cut keeps a tunnel that is merely farther away: 192 ms against 60 ms is not an
	// outlier for a media list, 400 ms is.
	real := []MemberHealth{mt("nl", true, 60, 20_000, now), mt("ca", true, 192, 80_000, now), mt("far", true, 400, 200_000, now)}
	got, _, _ = Decide(DecideInput{Policy: PolicyMixed, Members: real, Now: now})
	if got != "ca" {
		t.Fatalf("default mixed cut chose %q, want ca", got)
	}

	// The incumbent keeps its place for one switch deadband past the cut (no flapping at the edge),
	// and loses it beyond that.
	for lat, want := range map[int]string{230: "edge", 270: "nl"} {
		edge := []MemberHealth{mt("nl", true, 60, 20_000, now), mt("edge", true, lat, 80_000, now)}
		got, _, _ = Decide(DecideInput{Policy: PolicyMixed, Members: edge, Current: "edge", Now: now})
		if got != want {
			t.Errorf("incumbent at %d ms: chose %q, want %q", lat, got, want)
		}
	}
}

func TestDecideMixedMissingSamplesAndOutlierIncumbent(t *testing.T) {
	now := int64(100_000)
	cfg := Config{ToleranceMs: 30, TolerancePct: 20, MixedLatencySlackMs: 30}
	members := []MemberHealth{mt("a", true, 20, 0, 0), mt("b", true, 40, 300, now), mt("outlier", true, 100, 0, 0)}
	got, _, changed := Decide(DecideInput{Policy: PolicyMixed, Members: members, Current: "a", Now: now, Cfg: cfg})
	if got != "a" || changed {
		t.Fatalf("eligible unsampled incumbent moved merely for another sample: (%q, %v)", got, changed)
	}

	// An outlier is not protected by incumbent sample safety, even with no usable throughput at all.
	noSamples := []MemberHealth{mt("a", true, 20, 0, 0), mt("b", true, 40, 0, 0), mt("outlier", true, 100, 0, 0)}
	got, _, changed = Decide(DecideInput{Policy: PolicyMixed, Members: noSamples, Current: "outlier", Now: now, Cfg: cfg})
	if got != "a" || !changed {
		t.Fatalf("alive outlier was not replaced by lowest-latency eligible member: (%q, %v)", got, changed)
	}

	for _, kbps := range []int64{1200, 1201} {
		members := []MemberHealth{mt("a", true, 20, 1000, now), mt("b", true, 40, kbps, now)}
		got, _, changed = Decide(DecideInput{Policy: PolicyMixed, Members: members, Current: "a", Now: now, Cfg: cfg})
		want, wantChanged := "a", false
		if kbps == 1201 {
			want, wantChanged = "b", true
		}
		if got != want || changed != wantChanged {
			t.Errorf("challenger %d Kbps: got (%q, %v), want (%q, %v)", kbps, got, changed, want, wantChanged)
		}
	}
}

func TestRunnerThroughputKeepsDwellAndFailbackHold(t *testing.T) {
	cfg := Config{MinDwellMS: 10_000, FailbackHoldMS: 5000}
	health := fakeHealth{byID: map[string]MemberHealth{
		"a": mt("a", true, 100, 1000, 1), "b": mt("b", true, 10, 2000, 1),
	}}
	sel := &fakeSelector{now: map[string]string{"g": "a"}}
	r := NewRunner()
	r.lastSwitch["g"] = 95_000
	spec := []GroupSpec{{ID: "g", Policy: PolicyThroughput, Members: []string{"a", "b"}, Cfg: cfg}}
	if sw := r.Tick(spec, health, sel, 100_000); len(sw) != 0 {
		t.Fatalf("throughput optimization bypassed min-dwell: %+v", sw)
	}
	if sw := r.Tick(spec, health, sel, 106_000); len(sw) != 0 {
		t.Fatalf("throughput optimization bypassed failback hold: %+v", sw)
	}
	if sw := r.Tick(spec, health, sel, 110_000); len(sw) != 0 {
		t.Fatalf("throughput optimization committed before its hold: %+v", sw)
	}
	if sw := r.Tick(spec, health, sel, 112_000); len(sw) != 1 || sw[0].To != "b" {
		t.Fatalf("throughput optimization did not commit after dwell and hold: %+v", sw)
	}
}
