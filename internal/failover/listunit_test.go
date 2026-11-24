package failover

import (
	"fmt"
	"testing"
	"time"
)

func (f *fakeTables) Clear(table int) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, "ip route del default table "+itoa(table))
	delete(f.held, table)
	return nil
}

// tgList is a fastest list over three NDM tunnels with two targets of its own.
func tgList(mut func(*ListPolicy)) TableUnit {
	lp := &ListPolicy{List: "telegram", OnAllDown: "wan", Fresh: true}
	if mut != nil {
		mut(lp)
	}
	return TableUnit{
		Key:        UnitKey{Owner: "list:telegram", Table: 160},
		Name:       "Telegram",
		Policy:     PolicyLatency,
		Candidates: []string{"nl1", "cz", "de"},
		Iface:      map[string]string{"nl1": "nwg1", "cz": "nwg4", "de": "nwg5"},
		Targets:    []string{"149.154.167.51:443", "91.108.56.130:443"},
		Cfg:        Config{ToleranceMs: 30, TolerancePct: 20, MinDwellMS: 120_000},
		List:       lp,
	}
}

// listProbes: iface -> median (negative = every attempt failed), same for both targets.
func listProbes(u TableUnit, ms map[string]int) map[ProbeKey]ProbeResult {
	out := map[ProbeKey]ProbeResult{}
	for iface, lat := range ms {
		for _, t := range u.Targets {
			if lat < 0 {
				out[ProbeKey{iface, t}] = ProbeResult{Ran: true, Attempts: 3}
				continue
			}
			out[ProbeKey{iface, t}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: lat}
		}
	}
	return out
}

func lastReason(t *testing.T, e *TableElector) string {
	t.Helper()
	st := e.States()
	if len(st) != 1 || len(st[0].Events) == 0 {
		t.Fatalf("no events: %+v", st)
	}
	return st[0].Events[len(st[0].Events)-1].Reason
}

func TestListElectsFastestThenNeedsBetterByMsAndPct(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg1"}}
	e := NewTableElector()
	// First cycle: the compile-time pin is not ours; the fastest commits at once.
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	if routes.held[160] != "nwg4" {
		t.Fatalf("table = %s, want nwg4", routes.held[160])
	}
	// de is 25 ms faster (> 30 ms? no) - stays. Then 40 ms faster but < 20 % of 300: stays.
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 44}), nil, routes, 200_000)
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 44}), nil, routes, 260_000)
	if routes.held[160] != "nwg4" {
		t.Fatal("moved for less than the 30 ms threshold")
	}
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 300, "nwg5": 255}), nil, routes, 320_000)
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 300, "nwg5": 255}), nil, routes, 380_000)
	// nl1 is 180 ms faster: beyond max(30 ms, 60 ms). Needs the hold: two cycles.
	if routes.held[160] != "nwg1" {
		t.Fatalf("table = %s, want nwg1 (faster beyond both thresholds)", routes.held[160])
	}
	if r := lastReason(t, e); r != ReasonFaster {
		t.Fatalf("reason %s", r)
	}
}

func TestListDeadOnlyAfterTwoCycles(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": -1, "nwg5": 90}), nil, routes, 61_000)
	if routes.held[160] != "nwg4" {
		t.Fatal("one failed cycle must not hard-cut")
	}
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": -1, "nwg5": 90}), nil, routes, 121_000)
	if routes.held[160] != "nwg5" {
		t.Fatalf("second failed cycle: table = %s, want nwg5", routes.held[160])
	}
	if r := lastReason(t, e); r != ReasonDead {
		t.Fatalf("reason %s", r)
	}
}

func TestListNotFreshDecidesNothing(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	u.List.Fresh = false
	for i := 0; i < 5; i++ {
		e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg4": -1, "nwg1": 10}), nil, routes, int64(20_000*(i+1)))
	}
	if len(routes.writes) != 0 {
		t.Fatalf("decided between cycles: %v", routes.writes)
	}
}

func TestListPinnedExcludedAndUnpinned(t *testing.T) {
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	u := tgList(func(p *ListPolicy) { p.Pinned = "de" })
	pr := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90})
	e.Tick([]TableUnit{u}, pr, nil, routes, 1_000)
	if routes.held[160] != "nwg5" || lastReason(t, e) != ReasonPinned {
		t.Fatalf("pin: table %s", routes.held[160])
	}
	if e.States()[0].List.Mode != "pinned" {
		t.Fatalf("mode %s", e.States()[0].List.Mode)
	}
	// Pinned tunnel dies (two cycles): automatic meanwhile, flagged.
	dead := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": -1})
	e.Tick([]TableUnit{u}, dead, nil, routes, 61_000)
	e.Tick([]TableUnit{u}, dead, nil, routes, 121_000)
	st := e.States()[0]
	if routes.held[160] != "nwg4" || !st.List.PinDead || st.List.Mode != "fallback" {
		t.Fatalf("pin dead: table %s, list %+v", routes.held[160], st.List)
	}
	// Unpinned and the incumbent excluded: leaves at once, reason manual, after an unpinned note.
	u = tgList(func(p *ListPolicy) { p.Excluded = []string{"cz"} })
	e.Tick([]TableUnit{u}, pr, nil, routes, 181_000)
	if routes.held[160] != "nwg5" {
		t.Fatalf("excluded incumbent kept: %s", routes.held[160])
	}
	evs := e.States()[0].Events
	if evs[len(evs)-2].Reason != ReasonUnpinned || evs[len(evs)-1].Reason != ReasonManual {
		t.Fatalf("events %+v", evs[len(evs)-2:])
	}
}

func TestListAllDownModes(t *testing.T) {
	for _, mode := range []string{"wan", "block", "keep"} {
		t.Run(mode, func(t *testing.T) {
			u := tgList(func(p *ListPolicy) { p.OnAllDown = mode; p.DeadAfter = 1 })
			routes := &fakeTables{held: map[int]string{160: "nwg4"}}
			e := NewTableElector()
			e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
			down := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
			// The targets answer by the router's own path: the tunnels are dead by evidence (F2).
			down[ProbeKey{ReferenceIface, u.Targets[0]}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 30}
			e.Tick([]TableUnit{u}, down, nil, routes, 61_000)
			e.Tick([]TableUnit{u}, down, nil, routes, 121_000)
			st := e.States()[0]
			if !st.List.AllDown || st.List.Mode != "all_down" {
				t.Fatalf("not all down: %+v", st.List)
			}
			n := 0
			for _, ev := range st.Events {
				if ev.Reason == ReasonAllDown {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("all_down events = %d, want 1 (no repeat while down)", n)
			}
			if mode == "keep" {
				if routes.held[160] != "nwg4" {
					t.Fatal("keep emptied the table")
				}
			} else if _, ok := routes.held[160]; ok {
				t.Fatalf("%s: table still holds %s", mode, routes.held[160])
			}
			e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": -1, "nwg5": -1}), nil, routes, 181_000)
			if routes.held[160] != "nwg1" || lastReason(t, e) != ReasonRecovered {
				t.Fatalf("recovery: table %s reason %s", routes.held[160], lastReason(t, e))
			}
		})
	}
}

func TestListFlappingCalms(t *testing.T) {
	u := tgList(func(p *ListPolicy) { p.DeadAfter = 1 })
	u.Cfg.MinDwellMS = 1
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	now := int64(1_000)
	for i := 0; i < 10; i++ {
		alive := "nwg4"
		if i%2 == 1 {
			alive = "nwg5"
		}
		e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1, alive: 50}), nil, routes, now)
		now += 60_000
	}
	st := e.States()[0]
	if !st.List.Calm {
		t.Fatalf("not calm after %d switches", switchesWithin(st.Events, now-3600_000))
	}
	flaps := 0
	for _, ev := range st.Events {
		if ev.Reason == ReasonFlapping {
			flaps++
		}
	}
	if flaps == 0 {
		t.Fatal("no flapping note in the journal")
	}
}

func TestListJournalCapSeedAndVersion(t *testing.T) {
	u := tgList(func(p *ListPolicy) { p.DeadAfter = 1 })
	u.Cfg.MinDwellMS = 1
	e := NewTableElector()
	var seed []UnitEvent
	for i := 0; i < 70; i++ {
		seed = append(seed, UnitEvent{At: int64(i), To: "x", Reason: ReasonFaster})
	}
	e.SeedEvents("list:telegram", seed)
	v0 := e.JournalVersion()
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 100_000)
	st := e.States()[0]
	if len(st.Events) != listEventCap {
		t.Fatalf("events = %d, want cap %d", len(st.Events), listEventCap)
	}
	if e.JournalVersion() == v0 {
		t.Fatal("version unchanged after an event")
	}
	j := e.Journals()
	if len(j["list:telegram"]) != listEventCap {
		t.Fatalf("journal %d", len(j["list:telegram"]))
	}
	// A group unit keeps the larger cap.
	if (TableUnit{}).eventCap() != unitEventCap {
		t.Fatal("group cap")
	}
}

func TestListUnitAcceptsAnyCandidate(t *testing.T) {
	u := tgList(nil)
	for _, iface := range []string{"nwg1", "nwg4", "nwg5"} {
		if !u.Accepts(iface) {
			t.Fatalf("%s rejected", iface)
		}
	}
	for _, iface := range []string{"", "eth3", "ppp0", "nwg9"} {
		if u.Accepts(iface) {
			t.Fatalf("%s accepted", iface)
		}
	}
}

func TestListMatrixAndDeadTargets(t *testing.T) {
	u := tgList(nil)
	pr := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90})
	for _, iface := range []string{"nwg1", "nwg4", "nwg5"} {
		pr[ProbeKey{iface, u.Targets[1]}] = ProbeResult{Ran: true, Attempts: 3}
	}
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, pr, nil, routes, 1_000)
	ls := e.States()[0].List
	if c := ls.Matrix["cz"][u.Targets[0]]; !c.OK || c.MedianMs != 69 {
		t.Fatalf("cell %+v", c)
	}
	if c := ls.Matrix["cz"][u.Targets[1]]; c.OK || c.LossPct != 100 {
		t.Fatalf("dead cell %+v", c)
	}
	if fmt.Sprint(ls.DeadTargets) != "[91.108.56.130:443]" {
		t.Fatalf("dead targets %v", ls.DeadTargets)
	}
}

// Review F2: a target that answers through no candidate must not count against them. With every
// target silent everywhere and no answer by the router's own path either, the table is kept and the
// list says its targets are down; it never falls to the provider for it.
func TestListTargetsDownKeepsTable(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	dead := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
	for i, ref := range []bool{false, false, false} {
		pr := map[ProbeKey]ProbeResult{}
		for k, v := range dead {
			pr[k] = v
		}
		if ref {
			pr[ProbeKey{ReferenceIface, u.Targets[0]}] = ProbeResult{Ran: true, Attempts: 3}
		}
		e.Tick([]TableUnit{u}, pr, nil, routes, int64(61_000*(i+1)))
	}
	if routes.held[160] != "nwg4" {
		t.Fatalf("targets nobody answers cleared the table: %q (writes %v)", routes.held[160], routes.writes)
	}
	st := e.States()[0]
	if !st.List.TargetsDown || st.List.Mode != "targets_down" || st.List.AllDown {
		t.Fatalf("state %+v", st.List)
	}
	n := 0
	for _, ev := range st.Events {
		if ev.Reason == ReasonTargetsDown {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("targets_down events = %d, want 1", n)
	}
	// Back: the mode clears.
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 400_000)
	if st := e.States()[0]; st.List.TargetsDown || st.List.Mode != "auto" {
		t.Fatalf("after recovery %+v", st.List)
	}
}

// With the router's own path answering, the candidates are dead by evidence: all-down proceeds.
func TestListAllDownNeedsReferenceEvidence(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	pr := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
	pr[ProbeKey{ReferenceIface, u.Targets[1]}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 40}
	e.Tick([]TableUnit{u}, pr, nil, routes, 61_000)
	e.Tick([]TableUnit{u}, pr, nil, routes, 121_000)
	if _, ok := routes.held[160]; ok {
		t.Fatalf("dead tunnels with the targets reachable elsewhere: table still %s", routes.held[160])
	}
}

// One target silent everywhere, the other answering: candidates are judged by the one that answers.
func TestListDeadTargetDoesNotPenalise(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg1"}}
	e := NewTableElector()
	pr := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90})
	for _, iface := range []string{"nwg1", "nwg4", "nwg5"} {
		pr[ProbeKey{iface, u.Targets[1]}] = ProbeResult{Ran: true, Attempts: 3}
	}
	e.Tick([]TableUnit{u}, pr, nil, routes, 1_000)
	st := e.States()[0]
	if m := st.Measurements["cz"]; !m.Alive || m.LossPct != 0 || m.ScoreMs != 69 {
		t.Fatalf("the dead target was counted: %+v", m)
	}
	if routes.held[160] != "nwg4" {
		t.Fatalf("table %s", routes.held[160])
	}
}

// Review F4: a unit's first cycle (boot, or an Apply that renumbered the table) is no exception to
// "dead after two cycles": one failed cycle keeps the seeded tunnel, the second clears.
func TestListFirstCycleDoesNotClear(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg1"}}
	e := NewTableElector()
	pr := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
	pr[ProbeKey{ReferenceIface, u.Targets[0]}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 30}
	e.Tick([]TableUnit{u}, pr, nil, routes, 1_000)
	if routes.held[160] != "nwg1" {
		t.Fatalf("first failed cycle moved the table: %q, writes %v", routes.held[160], routes.writes)
	}
	if st := e.States()[0]; st.List.AllDown {
		t.Fatalf("all down after one cycle: %+v", st.List)
	}
	e.Tick([]TableUnit{u}, pr, nil, routes, 61_000)
	if _, ok := routes.held[160]; ok {
		t.Fatalf("second failed cycle kept %s", routes.held[160])
	}
}

// allDownProbes: every tunnel silent, the targets reachable by the router's own path.
func allDownProbes(u TableUnit) map[ProbeKey]ProbeResult {
	pr := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
	pr[ProbeKey{ReferenceIface, u.Targets[0]}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 30}
	return pr
}

// Review F5: the plane's reinstall seeds the first tunnel back into an emptied table; while the list
// is all down (wan/block) the elector empties it again.
func TestListAllDownReclearsReseededTable(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 61_000)
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 121_000)
	if _, ok := routes.held[160]; ok {
		t.Fatal("not cleared")
	}
	routes.held[160] = "nwg1" // the netfilter.d hook's `ip route add default dev nwg1 ... || true`
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 181_000)
	if v, ok := routes.held[160]; ok {
		t.Fatalf("re-seeded dead tunnel kept in the table: %s", v)
	}
}

// Review F9: "keep" recovers without a switch; the mode must leave all_down, and a second outage is
// recorded again.
func TestListKeepRecoversMode(t *testing.T) {
	u := tgList(func(p *ListPolicy) { p.OnAllDown = "keep" })
	routes := &fakeTables{held: map[int]string{160: "nwg4"}}
	e := NewTableElector()
	ok := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90})
	e.Tick([]TableUnit{u}, ok, nil, routes, 1_000)
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 61_000)
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 121_000)
	if st := e.States()[0]; st.List.Mode != "all_down" {
		t.Fatalf("mode %s", st.List.Mode)
	}
	e.Tick([]TableUnit{u}, ok, nil, routes, 181_000)
	if st := e.States()[0]; st.List.Mode != "auto" || st.List.AllDown {
		t.Fatalf("after recovery mode %s", st.List.Mode)
	}
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 241_000)
	e.Tick([]TableUnit{u}, allDownProbes(u), nil, routes, 301_000)
	n := 0
	for _, ev := range e.States()[0].Events {
		if ev.Reason == ReasonAllDown {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("all_down events %d, want 2 (the second outage too)", n)
	}
}

// Review F12: an Apply that adds an egress renumbers every list table. The list keeps its journal and
// its failure count on the new table instead of starting over.
func TestListStateFollowsRenumberedTable(t *testing.T) {
	u := tgList(nil)
	routes := &fakeTables{held: map[int]string{160: "nwg4", 161: "nwg1"}}
	e := NewTableElector()
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90}), nil, routes, 1_000)
	before := len(e.States()[0].Events)
	if before == 0 {
		t.Fatal("no events")
	}
	e.Tick([]TableUnit{u}, listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": -1}), nil, routes, 61_000)
	u2 := tgList(nil)
	u2.Key.Table = 161
	e.Tick([]TableUnit{u2}, listProbes(u2, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": -1}), nil, routes, 121_000)
	st := e.States()
	if len(st) != 1 || st[0].Table != 161 {
		t.Fatalf("states %+v", st)
	}
	if len(st[0].Events) < before {
		t.Fatalf("journal lost on renumbering: %d events, had %d", len(st[0].Events), before)
	}
	if st[0].List.Fails["de"] != 2 || st[0].Measurements["de"].Alive {
		t.Fatalf("failure count not carried: fails %v, de %+v", st[0].List.Fails, st[0].Measurements["de"])
	}
	if j := e.Journals(); len(j["list:telegram"]) < before {
		t.Fatalf("persisted journal shrank: %d", len(j["list:telegram"]))
	}
}

// blockingTables holds a Replace until released, like an `ip` call on a wedged router.
type blockingTables struct {
	fakeTables
	entered, release chan struct{}
}

func (b *blockingTables) Replace(table int, iface string) error {
	close(b.entered)
	<-b.release
	return b.fakeTables.Replace(table, iface)
}

// Review F14: the API's view of the elector must not wait for a tick stuck in an `ip` call.
func TestStatesDoNotWaitForTick(t *testing.T) {
	u := tgList(nil)
	e := NewTableElector()
	ok := listProbes(u, map[string]int{"nwg1": 120, "nwg4": 69, "nwg5": 90})
	e.Tick([]TableUnit{u}, ok, nil, &fakeTables{held: map[int]string{160: "nwg4"}}, 1_000)
	bt := &blockingTables{fakeTables: fakeTables{held: map[int]string{160: "nwg1"}}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		e.Tick([]TableUnit{u}, ok, nil, bt, 61_000)
		close(done)
	}()
	<-bt.entered
	got := make(chan int, 1)
	go func() { got <- len(e.States()) }()
	select {
	case n := <-got:
		if n != 1 {
			t.Fatalf("states %d", n)
		}
	case <-time.After(2 * time.Second):
		close(bt.release)
		t.Fatal("States waited for the tick's ip call")
	}
	close(bt.release)
	<-done
}

func TestListUsesSelectedElectionMode(t *testing.T) {
	for _, tt := range []struct {
		policy Policy
		want   string
		iface  string
	}{
		{policy: PolicyThroughput, want: "de", iface: "nwg5"},
		{policy: PolicyMixed, want: "cz", iface: "nwg4"},
	} {
		t.Run(string(tt.policy), func(t *testing.T) {
			now := int64(1_000_000)
			u := tgList(nil)
			u.Policy = tt.policy
			u.Throughput = map[string]ThroughputSample{
				"nl1": {ThroughputKbps: 100, ThroughputAt: now},
				"cz":  {ThroughputKbps: 300, ThroughputAt: now},
				"de":  {ThroughputKbps: 1000, ThroughputAt: now},
			}
			routes := &fakeTables{held: map[int]string{160: "nwg1"}}
			e := NewTableElector()
			// Latency alone would choose nl1. Throughput chooses de; mixed drops de as a latency outlier.
			pr := listProbes(u, map[string]int{"nwg1": 10, "nwg4": 20, "nwg5": 400})
			e.Tick([]TableUnit{u}, pr, nil, routes, now)
			if routes.held[160] != tt.iface || e.Committed(u.Key) != tt.want {
				t.Fatalf("%s chose %q/%q, want %s/%s", tt.policy, routes.held[160], e.Committed(u.Key), tt.want, tt.iface)
			}
			st := e.States()[0]
			if st.Policy != tt.policy || st.Measurements[tt.want].ThroughputKbps != u.Throughput[tt.want].ThroughputKbps {
				t.Fatalf("selected policy/sample not published: %+v", st)
			}
		})
	}
}

func TestListExcludedIncumbentReplacementIsPolicyAware(t *testing.T) {
	now := int64(1_000_000)
	u := tgList(func(p *ListPolicy) { p.Excluded = []string{"nl1"} })
	u.Policy = PolicyThroughput
	u.Throughput = map[string]ThroughputSample{
		"nl1": {ThroughputKbps: 1000, ThroughputAt: now},
		"cz":  {ThroughputKbps: 200, ThroughputAt: now},
		"de":  {ThroughputKbps: 300, ThroughputAt: now},
	}
	routes := &fakeTables{held: map[int]string{160: "nwg1"}}
	e := NewTableElector()
	pr := listProbes(u, map[string]int{"nwg1": 10, "nwg4": 120, "nwg5": 50})
	e.Tick([]TableUnit{u}, pr, nil, routes, now)
	if routes.held[160] != "nwg5" || e.Committed(u.Key) != "de" {
		t.Fatalf("excluded-incumbent replacement fell back to latency: table=%q committed=%q", routes.held[160], e.Committed(u.Key))
	}
}

// leftoverTables is fakeTables with a second family's default in the table.
type leftoverTables struct {
	fakeTables
	other  map[int]string
	clears int
}

func (f *leftoverTables) Leftover(table int) bool { return f.other[table] != "" }

func (f *leftoverTables) Clear(table int) error {
	f.clears++
	delete(f.held, table)
	delete(f.other, table)
	return nil
}

// An all-down list (wan/block) empties its table also when only the family Current does
// not read still holds a default; "keep" leaves it, and a table with nothing left is not written.
func TestListAllDownClearsWhatTheOtherFamilyKept(t *testing.T) {
	for _, mode := range []string{"wan", "block", "keep"} {
		u := tgList(func(lp *ListPolicy) { lp.OnAllDown, lp.DeadAfter = mode, 1 })
		routes := &leftoverTables{fakeTables: fakeTables{held: map[int]string{}}, other: map[int]string{160: "nwg1"}}
		e := NewTableElector()
		dead := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
		for _, t := range u.Targets {
			dead[ProbeKey{ReferenceIface, t}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3}
		}
		e.Tick([]TableUnit{u}, dead, nil, routes, 1_000)
		e.Tick([]TableUnit{u}, dead, nil, routes, 2_000)
		want := 1
		if mode == "keep" {
			want = 0
		}
		if routes.clears != want {
			t.Errorf("%s: %d clears, want %d (other family: %q)", mode, routes.clears, want, routes.other[160])
		}
		if st := e.States()[0]; !st.List.AllDown {
			t.Errorf("%s: not all down", mode)
		}
	}
}

// While a list's automatic targets are on trial, a cycle in which none answers judges no
// tunnel and counts toward no dead verdict, whatever the reference says; without the flag the same
// cycles are the tunnels' failure.
func TestListTargetsOnTrialAreNotHeldAgainstTheTunnels(t *testing.T) {
	for _, trial := range []bool{true, false} {
		u := tgList(func(lp *ListPolicy) { lp.TargetsOnTrial = trial })
		routes := &fakeTables{held: map[int]string{160: "nwg4"}}
		e := NewTableElector()
		silent := listProbes(u, map[string]int{"nwg1": -1, "nwg4": -1, "nwg5": -1})
		for _, t := range u.Targets {
			silent[ProbeKey{ReferenceIface, t}] = ProbeResult{Ran: true, Attempts: 3, Successes: 3}
		}
		for now := int64(1_000); now <= 3_000; now += 1_000 {
			e.Tick([]TableUnit{u}, silent, nil, routes, now)
		}
		st := e.States()[0]
		if trial && (st.List.AllDown || routes.held[160] != "nwg4" || !st.List.TargetsDown || len(st.List.Fails) != 0 || len(st.Events) != 1) {
			t.Errorf("on trial: all_down=%v table=%q targets_down=%v fails=%v events=%+v", st.List.AllDown, routes.held[160], st.List.TargetsDown, st.List.Fails, st.Events)
		}
		if !trial && !st.List.AllDown {
			t.Errorf("proven targets silent while the reference answers: the tunnels are down")
		}
	}
}
