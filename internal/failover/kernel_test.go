package failover

import (
	"errors"
	"reflect"
	"testing"
)

// fakeTables is a routing-table reader/writer: table → link, plus every replace it was asked for.
type fakeTables struct {
	held     map[int]string
	unread   map[int]bool
	writes   []string
	writeErr error
}

func (f *fakeTables) Current(table int) (string, bool) {
	if f.unread[table] {
		return "", false
	}
	return f.held[table], true
}

func (f *fakeTables) Replace(table int, iface string) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, "ip route replace default dev "+iface+" table "+itoa(table))
	f.held[table] = iface
	return nil
}

func itoa(n int) string { return UnitKey{Table: n}.String()[1:] }

const probeTarget = "cp.cloudflare.com:80"

// awg31 is a reference group: one tunnel first in the configured order, then three NDM tunnels.
func awg31(policy Policy) TableUnit {
	return TableUnit{
		Key:        UnitKey{Owner: "group:grp-awg31", Table: 152},
		Name:       "AWG31",
		Policy:     policy,
		Candidates: []string{"ca", "nl1", "nl4", "nl5"},
		Iface:      map[string]string{"ca": "awg1", "nl1": "nwg1", "nl4": "nwg4", "nl5": "nwg5"},
		Targets:    []string{probeTarget},
	}
}

func probes(ms map[string]int) map[ProbeKey]ProbeResult {
	out := map[ProbeKey]ProbeResult{}
	for iface, lat := range ms {
		if lat < 0 {
			out[ProbeKey{iface, probeTarget}] = ProbeResult{Ran: true, Attempts: 3}
			continue
		}
		out[ProbeKey{iface, probeTarget}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: lat}
	}
	return out
}

type monitorStub map[string]MemberHealth

func (m monitorStub) MemberHealth(ids []string) []MemberHealth {
	out := []MemberHealth{}
	for _, id := range ids {
		h := m[id]
		h.ID = id
		out = append(out, h)
	}
	return out
}

// The fault: Apply pins table 152 to ca (the first member), ca answers its own ping target so
// the monitor calls it alive, but the group's probe through awg1 fails. The urltest group must move to
// the fastest member that actually fetched the target, at once, with one route replace.
func TestTableElectorURLTestSkipsAMemberThatFailsTheGroupProbe(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: "awg1"}}
	mon := monitorStub{"ca": {Alive: true, LatencyMs: 20}, "nl1": {Alive: true}, "nl4": {Alive: true}, "nl5": {Alive: true}}
	e := NewTableElector()
	sw := e.Tick([]TableUnit{awg31(PolicyLatency)}, probes(map[string]int{"awg1": -1, "nwg1": 90, "nwg4": 41, "nwg5": 60}), mon, routes, 1_000)
	if want := []string{"ip route replace default dev nwg4 table 152"}; !reflect.DeepEqual(routes.writes, want) {
		t.Fatalf("writes %v, want %v", routes.writes, want)
	}
	if len(sw) != 1 || sw[0].To != "nl4" || sw[0].FromIface != "awg1" || !sw[0].Wrote || !sw[0].Emergency {
		t.Fatalf("switch %+v", sw)
	}
	if e.Committed(UnitKey{"group:grp-awg31", 152}) != "nl4" {
		t.Fatalf("committed %q", e.Committed(UnitKey{"group:grp-awg31", 152}))
	}
}

func TestTableElectorURLTestDeadbandDwellAndHold(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: "nwg1"}}
	el := awg31(PolicyLatency)
	e := NewTableElector()
	now := int64(1_000_000)
	// First tick: nothing of ours in the table, so the fastest commits at once.
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 100, "nwg4": 80, "nwg5": 120}), nil, routes, now)
	if routes.held[152] != "nwg4" {
		t.Fatalf("first election put %q in the table", routes.held[152])
	}
	// nwg1 now 40 ms faster than the incumbent: inside the 50 ms deadband, nothing moves.
	now += 20_000
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 40, "nwg4": 80, "nwg5": 120}), nil, routes, now)
	if len(routes.writes) != 1 {
		t.Fatalf("a member inside the deadband moved the table: %v", routes.writes)
	}
	// nwg5 now 70 ms faster: beyond the deadband, but the incumbent is healthy, so the move waits for
	// the failback hold (30 s) before it commits.
	fast := probes(map[string]int{"awg1": -1, "nwg1": 100, "nwg4": 80, "nwg5": 10})
	now += 20_000
	if sw := e.Tick([]TableUnit{el}, fast, nil, routes, now); len(sw) != 0 {
		t.Fatalf("an optimization committed without the hold: %+v", sw)
	}
	now += 20_000
	if sw := e.Tick([]TableUnit{el}, fast, nil, routes, now); len(sw) != 0 {
		t.Fatalf("committed after 20 s of a 30 s hold: %+v", sw)
	}
	now += 20_000
	sw := e.Tick([]TableUnit{el}, fast, nil, routes, now)
	if len(sw) != 1 || sw[0].To != "nl5" || sw[0].Emergency {
		t.Fatalf("after the hold: %+v", sw)
	}
	if routes.held[152] != "nwg5" {
		t.Fatalf("table holds %q", routes.held[152])
	}
	// A configured tolerance widens the deadband: 70 ms is inside 100 ms.
	wide := el
	wide.Cfg.ToleranceMs = 100
	routes2 := &fakeTables{held: map[int]string{152: ""}}
	e2 := NewTableElector()
	e2.Tick([]TableUnit{wide}, probes(map[string]int{"awg1": -1, "nwg1": -1, "nwg4": 80, "nwg5": -1}), nil, routes2, 1)
	for i := 1; i <= 5; i++ {
		e2.Tick([]TableUnit{wide}, probes(map[string]int{"awg1": -1, "nwg1": -1, "nwg4": 80, "nwg5": 10}), nil, routes2, int64(i)*20_000)
	}
	if routes2.held[152] != "nwg4" {
		t.Fatalf("tolerance 100 ignored: table holds %q", routes2.held[152])
	}
}

func TestTableElectorEmergencyIsImmediate(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: ""}}
	el := awg31(PolicyLatency)
	e := NewTableElector()
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 50, "nwg4": 30, "nwg5": 90}), nil, routes, 1_000)
	// One second later — inside min-dwell and with no hold — the incumbent dies.
	sw := e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 50, "nwg4": -1, "nwg5": 90}), nil, routes, 2_000)
	if len(sw) != 1 || sw[0].To != "nl1" || !sw[0].Emergency {
		t.Fatalf("emergency: %+v", sw)
	}
	want := []string{"ip route replace default dev nwg4 table 152", "ip route replace default dev nwg1 table 152"}
	if !reflect.DeepEqual(routes.writes, want) {
		t.Fatalf("writes %v, want %v", routes.writes, want)
	}
	// The kernel flushed the route of a link that went down: an empty table is an emergency too.
	routes.held[152] = ""
	if sw := e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 50, "nwg4": -1, "nwg5": 90}), nil, routes, 3_000); len(sw) != 1 || routes.held[152] != "nwg1" {
		t.Fatalf("flushed table not restored: %+v, table %q", sw, routes.held[152])
	}
}

func TestTableElectorFallbackTakesFirstAliveInOrder(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: "awg1"}}
	el := awg31(PolicyOrdered)
	e := NewTableElector()
	// ca fails the probe; nl1 is the slowest live member but comes first in the order.
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 300, "nwg4": 20, "nwg5": 30}), nil, routes, 1_000)
	if routes.held[152] != "nwg1" {
		t.Fatalf("fallback chose %q", routes.held[152])
	}
	// ca recovers: a failback to a higher-priority member, held, then committed.
	up := probes(map[string]int{"awg1": 200, "nwg1": 300, "nwg4": 20, "nwg5": 30})
	for now := int64(21_000); now <= 61_000; now += 20_000 {
		e.Tick([]TableUnit{el}, up, nil, routes, now)
	}
	if routes.held[152] != "awg1" {
		t.Fatalf("failback to the first member did not happen: %q", routes.held[152])
	}
}

func TestTableElectorSelectorKeepsThePick(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: "nwg4"}}
	el := awg31(PolicySelector)
	el.Pick = "nl4"
	e := NewTableElector()
	all := probes(map[string]int{"awg1": 5, "nwg1": 5, "nwg4": 200, "nwg5": 5})
	if sw := e.Tick([]TableUnit{el}, all, nil, routes, 1_000); len(sw) != 1 || sw[0].Wrote || routes.held[152] != "nwg4" {
		t.Fatalf("the pick, already in the table, must be adopted without a write: %+v %v", sw, routes.writes)
	}
	// The pick dies: first alive in order.
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 5, "nwg4": -1, "nwg5": 5}), nil, routes, 2_000)
	if routes.held[152] != "nwg1" {
		t.Fatalf("pick down: %q", routes.held[152])
	}
	// The pick comes back: the selector returns to it after the hold.
	for now := int64(22_000); now <= 62_000; now += 20_000 {
		e.Tick([]TableUnit{el}, all, nil, routes, now)
	}
	if routes.held[152] != "nwg4" {
		t.Fatalf("pick back: %q", routes.held[152])
	}
}

func TestTableElectorLeavesTheTableAlone(t *testing.T) {
	el := awg31(PolicyLatency)
	t.Run("every member dead", func(t *testing.T) {
		routes := &fakeTables{held: map[int]string{152: "awg1"}}
		NewTableElector().Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": -1, "nwg4": -1, "nwg5": -1}), nil, routes, 1)
		if len(routes.writes) != 0 {
			t.Fatalf("wrote %v", routes.writes)
		}
	})
	t.Run("unreadable table", func(t *testing.T) {
		routes := &fakeTables{held: map[int]string{}, unread: map[int]bool{152: true}}
		NewTableElector().Tick([]TableUnit{el}, probes(map[string]int{"nwg1": 10}), nil, routes, 1)
		if len(routes.writes) != 0 {
			t.Fatalf("wrote %v", routes.writes)
		}
	})
	t.Run("a failed write commits nothing", func(t *testing.T) {
		routes := &fakeTables{held: map[int]string{152: "awg1"}, writeErr: errors.New("RTNETLINK answers: No such device")}
		e := NewTableElector()
		if sw := e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 10}), nil, routes, 1); len(sw) != 0 || e.Committed(el.Key) != "" {
			t.Fatalf("%+v committed %q", sw, e.Committed(el.Key))
		}
	})
}

// A probe that did not run is not a dead member: the monitor's verdict stands in for it. A member
// with no kernel link is never a candidate. A lossy member stays alive and pays 10 ms per lost percent.
func TestHealthForFallsBackToTheMonitorAndScoresLoss(t *testing.T) {
	el := awg31(PolicyLatency)
	el.Candidates = append(el.Candidates, "socks")
	el.Targets = []string{probeTarget, "149.154.167.51:443"}
	pr := map[ProbeKey]ProbeResult{
		{"awg1", probeTarget}:          {Ran: true, Attempts: 3},
		{"awg1", "149.154.167.51:443"}: {Ran: true, Attempts: 3},
		{"nwg1", probeTarget}:          {Ran: true, Attempts: 3, Successes: 3, MedianMs: 70},
		{"nwg1", "149.154.167.51:443"}: {Ran: true, Attempts: 3, Successes: 3, MedianMs: 90},
		{"nwg5", probeTarget}:          {Ran: true, Attempts: 3, Successes: 2, MedianMs: 40},
		{"nwg5", "149.154.167.51:443"}: {Ran: true, Attempts: 3, Successes: 3, MedianMs: 50},
		{"nwg4", probeTarget}:          {Ran: false},
	}
	mon := monitorStub{"ca": {Alive: true, LatencyMs: 9}, "nl4": {Alive: true, LatencyMs: 33}, "socks": {Alive: true}}
	got, ms := HealthFor(el, pr, mon, 5)
	// nl5: 1 of 6 lost = 16 %, median of the per-target medians 40 → 40 + 160. nl4 keeps the monitor's
	// alive verdict but not its ping latency: others were measured, so it is never preferred (review F6).
	want := []MemberHealth{{ID: "ca"}, {ID: "nl1", Alive: true, LatencyMs: 70}, {ID: "nl4", Alive: true, LatencyMs: unmeasuredScoreMs}, {ID: "nl5", Alive: true, LatencyMs: 200}, {ID: "socks"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if ms["ca"].Source != "probe" || ms["ca"].LossPct != 100 || ms["nl4"].Source != "monitor" || ms["socks"].Source != "none" {
		t.Fatalf("measurements %+v", ms)
	}
}

// The verification rule for an elected table: any candidate's link is correct, nothing else is.
func TestTableUnitAcceptsAnyCandidate(t *testing.T) {
	u := awg31(PolicyLatency)
	for _, iface := range []string{"awg1", "nwg1", "nwg4", "nwg5"} {
		if !u.Accepts(iface) {
			t.Errorf("%s refused", iface)
		}
	}
	for _, iface := range []string{"", "eth3", "nwg0", "ppp0"} {
		if u.Accepts(iface) {
			t.Errorf("%q accepted", iface)
		}
	}
}

// The API's view: current, since, measurements, and an event ring with reasons.
func TestTableElectorState(t *testing.T) {
	routes := &fakeTables{held: map[int]string{152: "awg1"}}
	el := awg31(PolicyLatency)
	e := NewTableElector()
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 50, "nwg4": 30, "nwg5": 90}), nil, routes, 1_000)
	e.Tick([]TableUnit{el}, probes(map[string]int{"awg1": -1, "nwg1": 50, "nwg4": -1, "nwg5": 90}), nil, routes, 2_000)
	st := e.States()
	if len(st) != 1 {
		t.Fatalf("states %+v", st)
	}
	s := st[0]
	if s.ID != "group:grp-awg31@152" || s.Current != "nl1" || s.CurrentIface != "nwg1" || s.Since != 2_000 || s.Reason != ReasonDead {
		t.Fatalf("state %+v", s)
	}
	if len(s.Events) != 2 || s.Events[0].Reason != ReasonDead || s.Events[0].From != "ca" || s.Events[0].RTTTo != 30 ||
		s.Events[1].From != "nl4" || s.Events[1].To != "nl1" || s.Events[1].RTTTo != 50 {
		t.Fatalf("events %+v", s.Events)
	}
	if m := s.Measurements["nl4"]; m.Alive || m.LossPct != 100 {
		t.Fatalf("nl4 %+v", m)
	}
	for i := 0; i < unitEventCap+5; i++ {
		alive := map[string]int{"awg1": -1, "nwg1": 50, "nwg4": -1, "nwg5": -1}
		if i%2 == 1 {
			alive = map[string]int{"awg1": -1, "nwg1": -1, "nwg4": -1, "nwg5": 50}
		}
		e.Tick([]TableUnit{el}, probes(alive), nil, routes, int64(3_000+i))
	}
	if n := len(e.States()[0].Events); n != unitEventCap {
		t.Fatalf("ring holds %d", n)
	}
}

func TestProbeKeysAndPruning(t *testing.T) {
	a := awg31(PolicyLatency)
	b := awg31(PolicyOrdered)
	b.Key = UnitKey{Owner: "group:grp-b", Table: 153}
	b.Iface = map[string]string{"nl1": "nwg1", "ca": ""}
	keys := ProbeKeys([]TableUnit{a, b})
	if len(keys) != 4 || keys[0] != (ProbeKey{"awg1", probeTarget}) {
		t.Fatalf("keys %v", keys)
	}
	routes := &fakeTables{held: map[int]string{152: "", 153: ""}}
	e := NewTableElector()
	pr := probes(map[string]int{"awg1": 5, "nwg1": 6, "nwg4": 7, "nwg5": 8})
	e.Tick([]TableUnit{a, b}, pr, nil, routes, 1)
	if e.Committed(b.Key) != "nl1" {
		t.Fatalf("b: %q", e.Committed(b.Key))
	}
	e.Tick([]TableUnit{a}, pr, nil, routes, 2)
	if e.Committed(b.Key) != "" || len(e.runners) != 1 {
		t.Fatalf("a retired table kept its state")
	}
}

func TestHealthForAttachesThroughputWithoutChangingLatency(t *testing.T) {
	u := awg31(PolicyLatency)
	u.Throughput = map[string]ThroughputSample{
		"ca":  {ThroughputKbps: 1000, ThroughputAt: 900},
		"nl4": {ThroughputKbps: 2000, ThroughputAt: 800},
	}
	health, measurements := HealthFor(u, probes(map[string]int{"awg1": 50, "nwg1": 60, "nwg4": 70, "nwg5": 80}), nil, 1000)
	for i, wantLatency := range []int{50, 60, 70, 80} {
		if !health[i].Alive || health[i].LatencyMs != wantLatency {
			t.Errorf("%s health changed with throughput attached: %+v", u.Candidates[i], health[i])
		}
	}
	for _, id := range []string{"ca", "nl4"} {
		sample := u.Throughput[id]
		m := measurements[id]
		if m.ThroughputKbps != sample.ThroughputKbps || m.ThroughputAt != sample.ThroughputAt {
			t.Errorf("%s measurement lacks throughput: %+v", id, m)
		}
	}
	if health[0].ThroughputKbps != 1000 || health[0].ThroughputAt != 900 || health[2].ThroughputKbps != 2000 || health[2].ThroughputAt != 800 {
		t.Fatalf("health lacks attached samples: %+v", health)
	}
	if health[1].ThroughputKbps != 0 || health[1].ThroughputAt != 0 {
		t.Fatalf("candidate without a sample gained one: %+v", health[1])
	}
}

func TestSwitchReasonTreatsAutomaticModesAsFaster(t *testing.T) {
	measurements := map[string]Measurement{"a": {Alive: true}}
	for _, p := range []Policy{PolicyLatency, PolicyThroughput, PolicyMixed} {
		if got := switchReason(p, "a", "a", measurements); got != ReasonFaster {
			t.Errorf("%s switch reason = %q, want faster", p, got)
		}
	}
	if got := switchReason(PolicyOrdered, "a", "a", measurements); got != ReasonRecovered {
		t.Errorf("ordered switch reason = %q, want recovered", got)
	}
}
