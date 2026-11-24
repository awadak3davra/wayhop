package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"wayhop/internal/failover"
	"wayhop/internal/model"
)

// The review names a pin's end by the router's clock, with the zone. Go's own time.Local
// is UTC on Keenetic and OpenWrt, so a pin ending at 15:00 router time must not read "until 12:00".
func TestFastestPinFindingUsesRouterZone(t *testing.T) {
	old := fastestZone
	fastestZone = func() *time.Location { return time.FixedZone("", 3*3600) }
	defer func() { fastestZone = old }()
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	p := fastestProfile()
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Minute)
	p.RoutingLists[0].Fastest.Pinned, p.RoutingLists[0].Fastest.PinnedUntil = "nl5", until.Unix()
	want := "until " + until.Add(3*time.Hour).Format("2006-01-02 15:04") + " (+03)"
	for _, f := range s.fastestFindings(&p) {
		if f.ID != "routing_list.fastest_pinned" {
			continue
		}
		if !strings.Contains(f.Detail, want) {
			t.Fatalf("pin finding %q, want it to say %q", f.Detail, want)
		}
		return
	}
	t.Fatal("no pin finding")
}

// A pin whose time ran out stays in the stored policy, but the panel's summary shows only
// a pin that holds; the stored policy itself is handed out unchanged.
func TestFastestSummaryDropsExpiredPin(t *testing.T) {
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	summary := func(until int64) fastestSummary {
		p := fastestProfile()
		p.RoutingLists[0].Fastest.Pinned, p.RoutingLists[0].Fastest.PinnedUntil = "nl5", until
		return s.fastestSummaryOf(&p, p.RoutingLists[0], failover.UnitState{}, false)
	}
	now := time.Now().Unix()
	if sum := summary(now - 60); sum.Pinned != "" || sum.PinnedUntil != 0 {
		t.Fatalf("an expired pin is still shown: %q until %d", sum.Pinned, sum.PinnedUntil)
	}
	if sum := summary(now + 600); sum.Pinned != "nl5" || sum.PinnedUntil != now+600 {
		t.Fatalf("a timed pin that holds: %q until %d", sum.Pinned, sum.PinnedUntil)
	}
	if sum := summary(0); sum.Pinned != "nl5" {
		t.Fatalf("a pin until cancelled: %q", sum.Pinned)
	}
}

// A list decides only on its own measurement cycle, so a pin applied between two cycles would
// wait for the next one (up to ten minutes) with the table still on the old tunnel. A change of
// the pin, the exclusions or the all-down choice asks for a cycle on the next tick.
func TestFastestAppliedPinTakesTheTableOnTheNextTick(t *testing.T) {
	profile := fastestProfile()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	group := egressTable(t, plan, "grp-awg31")
	list := egressTable(t, plan, model.ListEgressTag("tg"))
	show := func(iface string) {
		tables.show = map[bool]string{false: "default dev " + iface + " table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	}
	show("nwg1")
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 120, "nwg4": 69, "nwg5": 90})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.listFailoverTick(context.Background())
	if st := s.fastestStates()["tg"]; st.Current != "nl4" {
		t.Fatalf("first cycle elected %q, want nl4", st.Current)
	}
	wroteList := func() []string {
		var out []string
		for _, w := range tables.writes {
			if strings.HasSuffix(w, " "+itoa(list)) {
				out = append(out, w)
			}
		}
		return out
	}
	// An Apply pins nl5 right after the list's cycle: the applied profile carries the pin.
	tables.writes = nil
	show("nwg4")
	s.applyState.rec.Committed.Desired.Profile.RoutingLists[0].Fastest.Pinned = "nl5"
	s.listFailoverTick(context.Background())
	if got := wroteList(); len(got) != 1 || got[0] != "v4 nwg5 "+itoa(list) {
		t.Fatalf("the applied pin did not take the table on the next tick: writes %v", tables.writes)
	}
	if st := s.fastestStates()["tg"]; st.Current != "nl5" || st.List.Mode != "pinned" {
		t.Fatalf("state after the pin: %q / %s", st.Current, st.List.Mode)
	}
	// With nothing changed the tick after it is not a cycle again.
	tables.writes = nil
	show("nwg5")
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 10, "nwg4": -1, "nwg5": -1})
	s.listFailoverTick(context.Background())
	if got := wroteList(); len(got) != 0 {
		t.Fatalf("decided between cycles with nothing changed: %v", got)
	}
	// The pin is removed: the choice is automatic again at once, by a fresh measurement.
	show("nwg5")
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 120, "nwg4": 69, "nwg5": 300})
	s.applyState.rec.Committed.Desired.Profile.RoutingLists[0].Fastest.Pinned = ""
	s.listFailoverTick(context.Background())
	if st := s.fastestStates()["tg"]; st.List.LastCycle == 0 || st.List.Pinned != "" || len(st.List.Matrix["nl5"]) != 2 || st.List.Matrix["nl5"][tgTargets[0]].MedianMs != 300 {
		t.Fatalf("no fresh cycle after the pin was removed: %+v", st.List)
	}
}

// An all-down list's table is emptied in both families. An IPv6 default that outlived the
// IPv4 one (its delete failed, or only IPv4 lost its route) is removed, and asked for again on the
// list's next cycle until it is gone, not tried once with its failure dropped.
func TestFastestAllDownClearsLeftoverIPv6(t *testing.T) {
	unit := failover.TableUnit{
		Key: failover.UnitKey{Owner: "list:l", Table: 160}, Policy: failover.PolicyLatency,
		Candidates: []string{"a", "b"}, Iface: map[string]string{"a": "nwg1", "b": "nwg2"}, Targets: []string{"x"},
		List: &failover.ListPolicy{List: "l", OnAllDown: "block", DeadAfter: 1, Fresh: true},
	}
	dead := map[failover.ProbeKey]failover.ProbeResult{
		{Iface: "nwg1", Target: "x"}:                  {Ran: true, Attempts: 3},
		{Iface: "nwg2", Target: "x"}:                  {Ran: true, Attempts: 3},
		{Iface: failover.ReferenceIface, Target: "x"}: {Ran: true, Attempts: 3, Successes: 3},
	}
	// The kernel's tables, and an IPv6 delete that fails `failing` times.
	run := func(v4 string, failing int) (clears map[bool]int, v6 string, e *failover.TableElector) {
		clears = map[bool]int{}
		kernel := map[bool]string{false: v4, true: "nwg1"}
		e = failover.NewTableElector()
		for cycle := int64(1); cycle <= 3; cycle++ {
			live := map[bool]map[int]string{false: {}, true: {}}
			for fam, dev := range kernel {
				if dev != "" {
					live[fam][160] = dev
				}
			}
			routes := &kernelTableRoutes{s: &Server{}, ctx: context.Background(), live: live,
				io: routeTableIO{clear: func(_ context.Context, v6 bool, _ string, _ int) error {
					clears[v6]++
					if v6 && clears[v6] <= failing {
						return errors.New("simulated IPv6 delete failure")
					}
					kernel[v6] = ""
					return nil
				}}}
			e.Tick([]failover.TableUnit{unit}, dead, nil, routes, cycle*1_000)
		}
		return clears, kernel[true], e
	}
	// The IPv6 delete fails once: it is asked again on the next cycle, then nothing is left to ask.
	clears, v6, e := run("nwg1", 1)
	if v6 != "" || clears[true] != 2 || clears[false] != 1 {
		t.Fatalf("a failed IPv6 clear was not retried until gone: IPv6 default %q, clears v4=%d v6=%d", v6, clears[false], clears[true])
	}
	if st := e.States()[0]; !st.List.AllDown || len(st.Events) != 1 {
		t.Fatalf("one outage, one event: all_down=%v events=%+v", st.List.AllDown, st.Events)
	}
	// IPv4 already lost its route when the list went down: IPv6 is cleared all the same.
	clears, v6, e = run("", 0)
	if v6 != "" || clears[true] != 1 || clears[false] != 0 {
		t.Fatalf("IPv6 kept its tunnel under an empty IPv4 table: IPv6 default %q, clears v4=%d v6=%d", v6, clears[false], clears[true])
	}
	if st := e.States()[0]; !st.List.AllDown || len(st.Events) != 1 || !st.Events[0].Wrote {
		t.Fatalf("the outage that emptied IPv6 is one written event: %+v", st.Events)
	}
}

// Automatic targets that never answered through a tunnel are replaced, not held against
// the tunnels. Four silent first picks must not make two failed cycles (the dead-after default) and
// empty the table as "all down" while targets that answer are still waiting in the pool. The
// trial is bounded by the pool: with every target tried and silent, the tunnels are judged.
func TestFastestUnprovenTargetsDoNotDeclareAllDown(t *testing.T) {
	pool := []string{"t1", "t2", "t3", "t4", "t5", "t6"}
	run := func(answering map[string]bool, cycles int) (*failover.TableElector, map[bool]int, []string) {
		s := &Server{}
		s.fastest.targets = map[string]fastestTargets{
			"l": {list: append([]string(nil), pool[:2]...), pool: pool, next: 2, ok: map[string]bool{}},
		}
		clears := map[bool]int{}
		live := map[bool]map[int]string{false: {160: "nwg1"}}
		e := failover.NewTableElector()
		var targets []string
		for cycle := int64(1); cycle <= int64(cycles); cycle++ {
			targets = append([]string(nil), s.fastest.targets["l"].list...)
			u := failover.TableUnit{
				Key: failover.UnitKey{Owner: "list:l", Table: 160}, Policy: failover.PolicyLatency,
				Candidates: []string{"a", "b"}, Iface: map[string]string{"a": "nwg1", "b": "nwg2"}, Targets: targets,
				List: &failover.ListPolicy{List: "l", OnAllDown: "block", Fresh: true,
					TargetsOnTrial: s.fastestTargetsOnTrial("l", targets)},
			}
			probes := map[failover.ProbeKey]failover.ProbeResult{}
			for _, target := range targets {
				r := failover.ProbeResult{Ran: true, Attempts: 3}
				if answering[target] {
					r.Successes, r.MedianMs = 3, 50
				}
				probes[failover.ProbeKey{Iface: "nwg1", Target: target}] = r
				probes[failover.ProbeKey{Iface: "nwg2", Target: target}] = r
				// The router's own path answers: by the reference alone the tunnels look dead.
				probes[failover.ProbeKey{Iface: failover.ReferenceIface, Target: target}] = failover.ProbeResult{Ran: true, Attempts: 3, Successes: 3}
			}
			routes := &kernelTableRoutes{s: s, ctx: context.Background(), live: live,
				io: routeTableIO{clear: func(_ context.Context, v6 bool, _ string, _ int) error { clears[v6]++; return nil }}}
			e.Tick([]failover.TableUnit{u}, probes, nil, routes, cycle*1_000)
			s.rotateFastestTargets(e.States())
		}
		return e, clears, targets
	}
	// t5 and t6 answer: the third cycle reaches them, and the table was never emptied on the way.
	e, clears, targets := run(map[string]bool{"t5": true, "t6": true}, 3)
	st := e.States()[0]
	if st.List.AllDown || clears[false] != 0 || st.Current != "a" {
		t.Fatalf("declared all down with untried targets: all_down=%v clears=%v current=%q events=%+v", st.List.AllDown, clears, st.Current, st.Events)
	}
	if strings.Join(targets, ",") != "t5,t6" || st.List.TargetsDown {
		t.Fatalf("the third cycle measures the targets that answer: %v, targets_down=%v", targets, st.List.TargetsDown)
	}
	// Nothing in the pool answers: once it is used up the silence is the tunnels', after dead-after
	// cycles as before.
	e, clears, _ = run(nil, 5)
	if st := e.States()[0]; !st.List.AllDown || clears[false] != 1 {
		t.Fatalf("a used-up pool must let the tunnels be judged: all_down=%v clears=%v events=%+v", st.List.AllDown, clears, st.Events)
	}
}

// "Probe now" for a list the router does not run must not be answered "queued" and measured by
// nothing. Only a list with a table of its own in the applied plan is queued.
func TestFastestProbeRefusedForAListTheRouterDoesNotRun(t *testing.T) {
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	if w := doJSON(t, s.handleFastestProbe, "POST", "/x", "ig", nil); w.Code != http.StatusConflict || s.fastest.want["ig"] {
		t.Fatalf("a list without the fastest choice: %d %s, queued=%v", w.Code, w.Body.String(), s.fastest.want["ig"])
	}
	if w := doJSON(t, s.handleFastestProbe, "POST", "/x", "tg", nil); w.Code != http.StatusAccepted || !s.fastest.want["tg"] {
		t.Fatalf("a running list: %d %s", w.Code, w.Body.String())
	}
	// Saved in fastest mode but not applied: the applied plan gives the list no table.
	saved := fastestProfile()
	s2, _ := appliedFailoverServer(t, awg31Profile(), saved, &fakeTables{})
	keeneticPlane(s2)
	if w := doJSON(t, s2.handleFastestProbe, "POST", "/x", "tg", nil); w.Code != http.StatusConflict || s2.fastest.want["tg"] {
		t.Fatalf("staged, not applied: %d %s", w.Code, w.Body.String())
	}
}

// A tunnel inside the proxy core has no interface to point a list's table at. A pin to it is
// refused, marked in the panel's candidates, and an old stored one is not shown as a pin.
func TestFastestPinNeedsAKernelLink(t *testing.T) {
	profile := fastestProfile()
	profile.Endpoints = append(profile.Endpoints, model.Endpoint{ID: "vl", Name: "VLESS", Engine: model.EngineSingBox,
		Protocol: model.ProtoVLESS, Server: "198.51.100.10", Port: 443, Params: map[string]any{"uuid": "u"}, Enabled: true})
	profile.RoutingLists[0].Candidates = []string{"nl1", "nl4", "vl"}
	s, _ := fastestServer(t, profile, &fakeTables{})
	w := doJSON(t, s.handleFastestPin, "POST", "/x", "tg", map[string]any{"candidate": "vl", "minutes": 0})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no interface of its own") {
		t.Fatalf("pin to a proxy-core tunnel: %d %s", w.Code, w.Body.String())
	}
	p := s.store.Profile()
	if f := findList(&p, "tg").Fastest; f.Pinned != "" {
		t.Fatalf("the refused pin was stored: %+v", f)
	}
	if w := doJSON(t, s.handleFastestPin, "POST", "/x", "tg", map[string]any{"candidate": "nl4", "minutes": 0}); w.Code != 200 {
		t.Fatalf("pin to a kernel tunnel: %d %s", w.Code, w.Body.String())
	}
	// A pin stored before the check: not shown as one, and the candidate says why.
	profile.RoutingLists[0].Fastest.Pinned = "vl"
	sum := s.fastestSummaryOf(&profile, profile.RoutingLists[0], failover.UnitState{}, false)
	if sum.Pinned != "" {
		t.Fatalf("a pin the router cannot run is shown: %q", sum.Pinned)
	}
	for _, c := range sum.Candidates {
		if c.NoLink != (c.ID == "vl") {
			t.Fatalf("no_link of %s = %v", c.ID, c.NoLink)
		}
	}
}
