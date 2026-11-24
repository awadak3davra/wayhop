package server

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/failover"
	"wayhop/internal/model"
)

// cidrFastest is fastestProfile with the fastest list renamed so no built-in targets apply: its
// automatic targets come from its own prefixes.
func cidrFastest() model.Profile {
	p := fastestProfile()
	p.RoutingLists[0].ID, p.RoutingLists[0].Name = "corp", "Corp"
	p.RoutingLists[0].Manual = []string{"203.0.113.0/24", "198.51.100.0/22", "example.org"}
	return p
}

// Review F2: the automatic pool tries more than the first host on 443, domains included.
func TestAutoFastestTargetPoolTriesSeveral(t *testing.T) {
	pool := autoFastestTargetPool(cidrFastest().RoutingLists[0])
	got := strings.Join(pool, ",")
	for _, want := range []string{"198.51.100.1:443", "203.0.113.1:443", "example.org:443", "198.51.102.1:443", "198.51.100.1:80"} {
		if !strings.Contains(got, want) {
			t.Fatalf("pool %s lacks %s", got, want)
		}
	}
	if len(pool) > fastestTargetPoolMax {
		t.Fatalf("pool %d over the cap", len(pool))
	}
}

// Review F2: a target that answers through no tunnel while another does is swapped for the next one
// of the pool, and a target that answered once is never swapped because every target went silent.
func TestFastestAutoTargetSwappedWhenSilent(t *testing.T) {
	profile := cidrFastest()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("corp"))
	group := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: "default dev nwg1 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	first := s.fastestTargetsFor(profile.RoutingLists[0], false, 1)
	if len(first) != 2 {
		t.Fatalf("targets %v", first)
	}
	// first[0] answers through every tunnel, first[1] through none.
	pr := handshakes("cp.cloudflare.com:80", map[string]int{"awg1": 50, "nwg1": 50, "nwg4": 40, "nwg5": 60})
	for k, v := range handshakes(first[0], map[string]int{"awg1": 50, "nwg1": 50, "nwg4": 40, "nwg5": 60}) {
		pr[k] = v
	}
	for k, v := range handshakes(first[1], map[string]int{"awg1": -1, "nwg1": -1, "nwg4": -1, "nwg5": -1}) {
		pr[k] = v
	}
	tables.probes = pr
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.listFailoverTick(context.Background())
	now := s.fastestTargetsFor(profile.RoutingLists[0], false, 2)
	if now[0] != first[0] || now[1] == first[1] {
		t.Fatalf("targets %v -> %v: the silent one must be swapped, the answering one kept", first, now)
	}
	if !s.fastest.want["corp"] {
		t.Fatal("the swapped list must be measured on the next tick")
	}
}

// Review F2 end to end: every target silent through every tunnel and by the router's own path: the
// list table keeps its tunnel and the list reports its targets down.
func TestFastestTargetsDownKeepsTableThroughTick(t *testing.T) {
	profile := cidrFastest()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("corp"))
	group := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: "default dev nwg4 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	targets := s.fastestTargetsFor(profile.RoutingLists[0], false, 1)
	pr := handshakes("cp.cloudflare.com:80", map[string]int{"awg1": 50, "nwg1": 50, "nwg4": 40, "nwg5": 60})
	for _, tg := range targets {
		for k, v := range handshakes(tg, map[string]int{"awg1": -1, "nwg1": -1, "nwg4": -1, "nwg5": -1}) {
			pr[k] = v
		}
		pr[failover.ProbeKey{Iface: failover.ReferenceIface, Target: tg}] = failover.ProbeResult{Ran: true, Attempts: 3}
	}
	tables.probes = pr
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.listFailoverTick(context.Background())
	for _, w := range tables.writes {
		if strings.HasPrefix(w, "v4 ") && strings.HasSuffix(w, " "+itoa(list)) || strings.Contains(w, "del") {
			t.Fatalf("moved or cleared the list table: %v", tables.writes)
		}
	}
	st := s.fastestStates()["corp"]
	if st.List == nil || st.List.Mode != "targets_down" {
		t.Fatalf("state %+v", st.List)
	}
}

// Review F13: a list cycle measured while an Apply held the lock is not lost: the next tick measures
// and decides it.
func TestFastestCycleRetriedWhenLockBusy(t *testing.T) {
	profile := fastestProfile()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("tg"))
	group := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: "default dev nwg1 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 120, "nwg4": 69, "nwg5": 90})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.applyMu.Lock()
	s.listFailoverTick(context.Background())
	s.applyMu.Unlock()
	if !s.fastest.want["tg"] {
		t.Fatal("the cycle measured under a busy lock was dropped")
	}
	s.listFailoverTick(context.Background())
	if st := s.fastestStates()["tg"]; st.Current != "nl4" {
		t.Fatalf("next tick did not decide: %+v", st)
	}
}

// Review F6: with a budget too small for every attempt, every key still gets measured (first attempts
// go first, from a moving start), the worker pool stays at its cap, and a down resolver costs one
// timeout, not one per target.
func TestProbeScheduleFairAndBounded(t *testing.T) {
	var keys []failover.ProbeKey
	for i := 0; i < 24; i++ {
		keys = append(keys, failover.ProbeKey{Iface: fmt.Sprintf("nwg%d", i%6), Target: fmt.Sprintf("t%d:443", i/6)})
	}
	var inFlight, peak atomic.Int32
	dial := func(ctx context.Context, _, _ string) (int, bool, bool) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inFlight.Add(-1)
		select {
		case <-time.After(30 * time.Millisecond):
			return 0, false, true // a timed-out handshake
		case <-ctx.Done():
			return 0, false, false
		}
	}
	resolve := func(ctx context.Context, t string) (string, error) { return "198.51.100.1:443", nil }
	// 24 keys x 3 attempts at 8 in flight need 9 rounds; the budget fits about 4.
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Millisecond)
	defer cancel()
	out := probeKeysWith(ctx, keys, resolve, dial)
	for _, k := range keys {
		if r := out[k]; !r.Ran {
			t.Fatalf("key %+v starved: %+v", k, r)
		}
	}
	if peak.Load() > unitProbeConcurrency {
		t.Fatalf("%d in flight, cap %d", peak.Load(), unitProbeConcurrency)
	}
	// Resolver down: every target times out, in parallel.
	slow := func(ctx context.Context, t string) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	started := time.Now()
	probeKeysWith(context.Background(), keys, slow, dial)
	if d := time.Since(started); d > unitResolveTimeout+2*time.Second {
		t.Fatalf("resolving took %v", d)
	}
}

// Review F6: a candidate the cycle did not measure is never preferred over measured ones.
func TestUnmeasuredCandidateNotPreferred(t *testing.T) {
	u := failover.TableUnit{Candidates: []string{"a", "b"}, Iface: map[string]string{"a": "nwg1", "b": "nwg2"}, Targets: []string{"x:443"}}
	probes := map[failover.ProbeKey]failover.ProbeResult{{Iface: "nwg1", Target: "x:443"}: {Ran: true, Attempts: 3, Successes: 3, MedianMs: 120}}
	h, _ := failover.HealthFor(u, probes, staticMonitor{"b": 5}, 1)
	if h[1].ID != "b" || !h[1].Alive || h[1].LatencyMs <= h[0].LatencyMs {
		t.Fatalf("health %+v", h)
	}
}

type staticMonitor map[string]int

func (m staticMonitor) MemberHealth(ids []string) []failover.MemberHealth {
	var out []failover.MemberHealth
	for _, id := range ids {
		lat, ok := m[id]
		out = append(out, failover.MemberHealth{ID: id, Alive: ok, LatencyMs: lat})
	}
	return out
}

// Review F11: the journal reaches flash at most hourly; the shutdown flush covers the rest.
func TestFastestJournalFlashRate(t *testing.T) {
	if fastestJournalEvery < time.Hour {
		t.Fatalf("journal rate %v: a flapping list would rewrite it %d times a day", fastestJournalEvery, int(24*time.Hour/fastestJournalEvery))
	}
}
