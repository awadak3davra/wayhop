package model

import (
	"strings"
	"testing"
)

func fastestProfile() *Profile {
	ext := func(id, iface string, on bool) Endpoint {
		return Endpoint{ID: id, Name: id, Engine: EngineExternal, Protocol: ProtoWireGuard, Enabled: on,
			Params: map[string]any{"interface": iface}}
	}
	return &Profile{
		Endpoints: []Endpoint{ext("a", "nwg1", true), ext("b", "nwg2", true), ext("c", "nwg3", true), ext("off", "nwg4", false)},
		Groups:    []Group{{ID: "g", Members: []string{"b", "c"}}, {ID: "nest", Members: []string{"g", "a"}}},
	}
}

func TestListCandidatesExpandsGroupsAndDedups(t *testing.T) {
	p := fastestProfile()
	got := ListCandidates(p, RoutingList{Candidates: []string{"a", "nest", "c"}})
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("candidates = %v, want a,b,c", got)
	}
	if got := ListCandidates(p, RoutingList{Outbound: "g"}); strings.Join(got, ",") != "b,c" {
		t.Fatalf("outbound group candidates = %v", got)
	}
	if got := ListCandidates(p, RoutingList{Outbound: "direct"}); len(got) != 0 {
		t.Fatalf("direct has no candidates, got %v", got)
	}
}

func TestNormalizeOneCandidateSwitchesFastestOff(t *testing.T) {
	p := fastestProfile()
	rl := RoutingList{ID: "l", Enabled: true, Candidates: []string{"a"}, Outbound: "x", Fastest: &FastestPolicy{Enabled: true}}
	NormalizeRoutingList(p, &rl)
	if rl.Outbound != "a" || rl.Fastest.Enabled {
		t.Fatalf("one candidate: outbound=%q enabled=%v, want a/false", rl.Outbound, rl.Fastest.Enabled)
	}
	if FastestActive(p, rl) {
		t.Fatal("one candidate must not be active")
	}
	rl = RoutingList{ID: "l", Enabled: true, Candidates: []string{"a", "b"}, Fastest: &FastestPolicy{Enabled: true}}
	NormalizeRoutingList(p, &rl)
	if !rl.Fastest.Enabled || !FastestActive(p, rl) {
		t.Fatal("two candidates stay on")
	}
	rl.Enabled = false
	if FastestActive(p, rl) {
		t.Fatal("a disabled list is not active")
	}
}

func TestValidateFastest(t *testing.T) {
	base := func(mut func(*RoutingList)) error {
		p := fastestProfile()
		rl := RoutingList{ID: "l", Enabled: true, Manual: []string{"1.2.3.0/24"}, Candidates: []string{"a", "g"}, Outbound: "a",
			Fastest: &FastestPolicy{Enabled: true}}
		mut(&rl)
		p.RoutingLists = []RoutingList{rl}
		return p.Validate()
	}
	if err := base(func(*RoutingList) {}); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}
	cases := map[string]func(*RoutingList){
		"direct candidate":   func(r *RoutingList) { r.Candidates = []string{"a", "direct"} },
		"unknown candidate":  func(r *RoutingList) { r.Candidates = []string{"a", "zz"} },
		"disabled":           func(r *RoutingList) { r.Candidates = []string{"a", "off"} },
		"outbound mismatch":  func(r *RoutingList) { r.Outbound = "g" },
		"four targets":       func(r *RoutingList) { r.Fastest.Targets = []string{"a.com:1", "b.com:1", "c.com:1", "d.com:1"} },
		"no port":            func(r *RoutingList) { r.Fastest.Targets = []string{"a.com"} },
		"private target":     func(r *RoutingList) { r.Fastest.Targets = []string{"192.168.50.1:443"} },
		"cgnat target":       func(r *RoutingList) { r.Fastest.Targets = []string{"100.64.0.1:443"} },
		"interval low":       func(r *RoutingList) { r.Fastest.IntervalSec = 10 },
		"bad on_all_down":    func(r *RoutingList) { r.Fastest.OnAllDown = "panic" },
		"pin not candidate":  func(r *RoutingList) { r.Fastest.Pinned = "zz" },
		"exclude not member": func(r *RoutingList) { r.Fastest.Excluded = []string{"off"} },
	}
	for name, mut := range cases {
		if err := base(mut); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := base(func(r *RoutingList) {
		r.Fastest.Targets = []string{"149.154.167.51:443", "www.youtube.com:443"}
		r.Fastest.Pinned, r.Fastest.Excluded = "c", []string{"b"}
	}); err != nil {
		t.Fatalf("public targets, pin to an expanded member: %v", err)
	}
}

func TestFastestDefaults(t *testing.T) {
	var f FastestPolicy
	if f.Interval() != 60 || f.DeltaMs() != 30 || f.DeltaPct() != 20 || f.Dwell() != 120 || f.AllDown() != "wan" {
		t.Fatalf("defaults wrong: %+v", f)
	}
	f = FastestPolicy{Pinned: "a", PinnedUntil: 100}
	if !f.PinActive(99) || f.PinActive(100) {
		t.Fatal("pin expiry")
	}
	f.PinnedUntil = 0
	if !f.PinActive(1 << 40) {
		t.Fatal("pin until unpinned")
	}
	if id, ok := ListEgressID(ListEgressTag("tg")); !ok || id != "tg" {
		t.Fatal("egress tag round trip")
	}
}

func TestElectionModeDefaultsForGroupsAndMediaLists(t *testing.T) {
	if got := (Group{}).Election(); got != ElectionLatency {
		t.Fatalf("empty group election = %q, want latency", got)
	}
	if got := (Group{ElectionMode: ElectionMixed}).Election(); got != ElectionMixed {
		t.Fatalf("explicit group election = %q, want mixed", got)
	}

	media := []RoutingList{
		{ID: "svc-telegram"}, {ID: "CIDR-TeLeGrAm"}, {ID: "custom", Name: "YouTube"},
		{ID: "custom", Name: "INSTAGRAM"}, {ID: "svc-meta"}, {ID: "cidr-META"},
	}
	for _, rl := range media {
		if got := (FastestPolicy{}).ElectionFor(rl); got != ElectionMixed {
			t.Errorf("media list %+v defaults to %q, want mixed", rl, got)
		}
	}
	if got := (FastestPolicy{}).ElectionFor(RoutingList{ID: "svc-netflix", Name: "Netflix"}); got != ElectionLatency {
		t.Errorf("ordinary list defaults to %q, want latency", got)
	}
	if got := (FastestPolicy{Mode: ElectionLatency}).ElectionFor(RoutingList{ID: "svc-youtube"}); got != ElectionLatency {
		t.Errorf("explicit latency was replaced by media default: %q", got)
	}
	if got := (FastestPolicy{Mode: ElectionThroughput}).ElectionFor(RoutingList{ID: "ordinary"}); got != ElectionThroughput {
		t.Errorf("explicit throughput = %q", got)
	}
}

func TestValidateElectionModes(t *testing.T) {
	p := fastestProfile()
	p.Groups = []Group{{ID: "g", Type: GroupURLTest, Members: []string{"b", "c"}}}
	for _, mode := range []ElectionMode{"", ElectionLatency, ElectionThroughput, ElectionMixed} {
		p.Groups[0].ElectionMode = mode
		if err := p.Validate(); err != nil {
			t.Errorf("urltest mode %q refused: %v", mode, err)
		}
	}
	for _, typ := range []GroupType{GroupSelector, GroupFallback} {
		for _, mode := range []ElectionMode{"", ElectionLatency} {
			p.Groups[0].Type, p.Groups[0].ElectionMode = typ, mode
			if err := p.Validate(); err != nil {
				t.Errorf("%s mode %q refused: %v", typ, mode, err)
			}
		}
		for _, mode := range []ElectionMode{ElectionThroughput, ElectionMixed} {
			p.Groups[0].Type, p.Groups[0].ElectionMode = typ, mode
			if err := p.Validate(); err == nil {
				t.Errorf("%s accepted automatic election mode %q", typ, mode)
			}
		}
	}
	p.Groups[0].Type, p.Groups[0].ElectionMode = GroupURLTest, ElectionMode("bogus")
	if err := p.Validate(); err == nil {
		t.Error("group accepted an unknown election mode")
	}

	p.Groups = nil
	p.RoutingLists = []RoutingList{{
		ID: "l", Enabled: true, Manual: []string{"1.2.3.0/24"}, Candidates: []string{"a", "b"}, Outbound: "a",
		Fastest: &FastestPolicy{Enabled: true},
	}}
	for _, mode := range []ElectionMode{"", ElectionLatency, ElectionThroughput, ElectionMixed} {
		p.RoutingLists[0].Fastest.Mode = mode
		if err := p.Validate(); err != nil {
			t.Errorf("fastest mode %q refused: %v", mode, err)
		}
	}
	p.RoutingLists[0].Fastest.Mode = ElectionMode("bogus")
	if err := p.Validate(); err == nil {
		t.Error("routing list accepted an unknown fastest mode")
	}
}
