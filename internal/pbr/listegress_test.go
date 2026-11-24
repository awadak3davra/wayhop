package pbr

import (
	"fmt"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// fastestKeenetic is keeneticProfile with a third tunnel and the IP list switched to "fastest" over
// the group plus the extra tunnel.
func fastestKeenetic() *model.Profile {
	p := keeneticProfile()
	p.Endpoints = append(p.Endpoints, model.Endpoint{ID: "czech", Engine: model.EngineExternal, Enabled: true, Server: "192.0.2.9", Params: map[string]any{"interface": "nwg4"}})
	p.RoutingLists[1].Candidates = []string{"czech", "failover_with_wan"}
	p.RoutingLists[1].Outbound = "czech"
	p.RoutingLists[1].Fastest = &model.FastestPolicy{Enabled: true, OnAllDown: model.OnAllDownBlock}
	return p
}

func listEgressByTag(pl *Plan, tag string) (Egress, bool) {
	for _, e := range pl.Egresses {
		if e.Tag == tag {
			return e, true
		}
	}
	return Egress{}, false
}

func TestListEgressOwnMarkAndTableAfterOthers(t *testing.T) {
	p := fastestKeenetic()
	off, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := listEgressByTag(off, model.ListEgressTag("iplist")); ok {
		t.Fatal("without ListEgresses (OpenWrt) no list egress may appear")
	}
	on, _, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	le, ok := listEgressByTag(on, model.ListEgressTag("iplist"))
	if !ok {
		t.Fatalf("no list egress: %+v", on.Egresses)
	}
	if le.Iface != "nwg4" || !le.FailClosed || le.Kind != EgressInterface {
		t.Fatalf("list egress = %+v, want nwg4 (first candidate), fail-closed for on_all_down=block", le)
	}
	last := on.Egresses[len(on.Egresses)-1]
	if last.Tag != le.Tag {
		t.Fatalf("list egress must be numbered last, got order %+v", on.Egresses)
	}
	g, _ := listEgressByTag(on, "failover_with_wan")
	if g.Mark == le.Mark || g.Table == le.Table {
		t.Fatal("list shares mark/table with the group")
	}
	// The other list keeps the group, numbered exactly as in a plan without the fastest list.
	p2 := fastestKeenetic()
	p2.RoutingLists[1].Enabled = false
	base, _, _ := Compile(p2, Options{CollectDomainZones: true, ListEgresses: true})
	gb, _ := listEgressByTag(base, "failover_with_wan")
	if gb.Mark != g.Mark || gb.Table != g.Table {
		t.Fatalf("group renumbered by a list egress: %+v vs %+v", gb, g)
	}
	for _, z := range on.Zones {
		if strings.HasPrefix(z.Name, "list_iplist") && (z.EgressTag != le.Tag || z.Mark != le.Mark) {
			t.Fatalf("zone %s not on the list egress: %+v", z.Name, z)
		}
		if z.Name == "list_youtube" && z.EgressTag != "failover_with_wan" {
			t.Fatalf("youtube moved: %+v", z)
		}
	}
	// Rendered with the Keenetic plane's own scripts: own MARK value, own ip rule and table with a
	// blackhole backstop. Shapes as iptables 1.4.21 / BusyBox ip take them.
	ipt := on.RenderIptablesScript(IpsetOptions{S86Mark: 0x250})
	mustContain(t, ipt, fmt.Sprintf("-m set --match-set wr_list_iplist_4 dst -j MARK --set-xmark 0x%08x/0x00ff0000", le.Mark))
	ip := on.RenderIPScript(Options{})
	mustContain(t, ip, fmt.Sprintf("ip rule add fwmark 0x%08x/0x00ff0000 table %d priority", le.Mark, le.Table))
	// Seeded with add, never replace: a re-install must not put the compile-time pin back over the
	// elected tunnel.
	mustContain(t, ip, fmt.Sprintf("ip route add default dev nwg4 table %d 2>/dev/null || true", le.Table))
	mustContain(t, ip, fmt.Sprintf("ip route replace blackhole default metric 1000 table %d", le.Table))
	if strings.Contains(ip, fmt.Sprintf("route replace default dev nwg4 table %d", le.Table)) {
		t.Fatal("the plane must not replace the list table's default")
	}
}

func TestListEgressNeedsTwoKernelCandidates(t *testing.T) {
	p := fastestKeenetic()
	p.Endpoints = append(p.Endpoints, model.Endpoint{ID: "proxy", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Enabled: true})
	p.RoutingLists[1].Candidates = []string{"czech", "proxy"}
	pl, warns, _ := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
	if _, ok := listEgressByTag(pl, model.ListEgressTag("iplist")); ok {
		t.Fatal("one kernel candidate must not get a list egress")
	}
	if len(warns) == 0 {
		t.Fatal("expected a warning")
	}
	if e, ok := listEgressByTag(pl, "czech"); !ok || e.Iface != "nwg4" {
		t.Fatalf("list must keep its first tunnel: %+v", pl.Egresses)
	}
}

func TestListEgressCap32(t *testing.T) {
	p := fastestKeenetic()
	p.RoutingLists = nil
	for i := 0; i < model.MaxFastestLists+2; i++ {
		p.RoutingLists = append(p.RoutingLists, model.RoutingList{
			ID: fmt.Sprintf("l%02d", i), Enabled: true, Manual: []string{fmt.Sprintf("10.%d.0.0/16", i)},
			Candidates: []string{"czech", "regiona"}, Outbound: "czech", Fastest: &model.FastestPolicy{Enabled: true},
		})
	}
	pl, warns, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	marks := map[uint32]bool{}
	tables := map[int]bool{}
	for _, e := range pl.Egresses {
		if marks[e.Mark] || tables[e.Table] {
			t.Fatalf("duplicate mark/table %+v", e)
		}
		marks[e.Mark], tables[e.Table] = true, true
		if _, ok := model.ListEgressID(e.Tag); ok {
			n++
		}
	}
	if n != model.MaxFastestLists {
		t.Fatalf("list egresses = %d, want %d", n, model.MaxFastestLists)
	}
	over := 0
	for _, w := range warns {
		if strings.Contains(w.Msg, "fastest mode") {
			over++
		}
	}
	if over != 2 {
		t.Fatalf("warnings for lists over the cap = %d, want 2", over)
	}
	if pl.Egresses[len(pl.Egresses)-1].Mark&^pl.Mask != 0 {
		t.Fatal("mark escaped the mask")
	}
}
