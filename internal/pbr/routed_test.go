package pbr

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// bigCIDRs is n distinct /24s in 198.18.0.0/15 (a benchmark range nobody routes).
func bigCIDRs(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("198.%d.%d.0/24", 18+i/256, i%256))
	}
	return out
}

func routedProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.2", Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "ai", Manual: []string{"openai.com"}, Outbound: "awg2", Enabled: true},
			{ID: "geo", Manual: bigCIDRs(300), Outbound: "awg2", Enabled: true},
			{ID: "ads", Manual: bigCIDRs(280), Outbound: model.OutboundBlock, Enabled: true},
			{ID: "home", Manual: bigCIDRs(270), Outbound: model.OutboundDirect, Enabled: true},
		},
	}
}

func routedOptions() Options {
	opt := fastOptions()
	opt.RemoteSets = map[string]RemoteSet{"srs": {Source: "https://example.test/geo.srs", Domains: []string{"r.example"}, CIDRs: bigCIDRs(400)}}
	return opt
}

var nftIntervalSet = regexp.MustCompile(`(?m)^\s*set (\S+) \{ type ipv[46]_addr; flags interval; elements = \{ ([^}]*) \} \}$`)

// TestRoutedLargeLists (live 22.11, libnftables cost per resolver add): in fast mode with names and no
// core TUN, no nft interval set above RoutedPrefixMin is left but the block list's (kept in nft by
// design); the large tunnel list is a table looked up after every fwmark rule, by the
// LAN's devices only and only for unmarked packets; a direct one is dropped; the teardown removes
// rules and tables; the postcheck recognises the rules as the kernel prints them.
func TestRoutedLargeLists(t *testing.T) {
	plan, _, err := Compile(routedProfile(), routedOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	for _, m := range nftIntervalSet.FindAllStringSubmatch(nft, -1) {
		if n := strings.Count(m[2], ",") + 1; n > RoutedPrefixMin && m[1] != "list_ads_4" {
			t.Errorf("set %s holds %d prefixes in nft", m[1], n)
		}
	}
	if !strings.Contains(nft, "set list_ads_4 ") {
		t.Error("the large block list left nft")
	}
	rz := plan.RoutedZones(Options{})
	if len(rz) != 1 || rz[0].Zone.Name != "list_geo" || rz[0].Dev != "awg2" || rz[0].Zone.RouteList != "geo" {
		t.Fatalf("routed zones %+v", rz)
	}
	ip := strings.Join(plan.RenderIP(Options{}), "\n")
	nonWan := len(plan.nonWanEgresses())
	want := fmt.Sprintf("ip rule add iif br-lan fwmark 0x00000000/0x00ff0000 table %d priority %d", rz[0].Table, 150+nonWan+1)
	if !strings.Contains(ip, want) {
		t.Errorf("missing %q in\n%s", want, ip)
	}
	if rz[0].Table < 151+routedTableOffset || rz[0].Pref < 150+nonWan {
		t.Errorf("table %d / priority %d inside the egresses' window", rz[0].Table, rz[0].Pref)
	}
	v4, _ := rz[0].RoutedPrefixes(nil)
	if len(v4) != 300 || rz[0].RouteSpec(v4[0]) != v4[0]+" dev awg2" {
		t.Errorf("routed prefixes %d", len(v4))
	}
	for _, z := range plan.Zones {
		if z.Name == "list_home" && (!z.Routed || len(z.V4) != 0) {
			t.Errorf("the large direct list stayed in nft: %+v", z.Name)
		}
	}
	td := strings.Join(plan.RenderTeardown(Options{}), "\n")
	if !strings.Contains(td, fmt.Sprintf("ip route flush table %d", rz[0].Table)) || !strings.Contains(td, strings.Replace(want, "rule add", "rule del", 1)) {
		t.Errorf("teardown keeps the table or the rule:\n%s", td)
	}
	dump := fmt.Sprintf("%d:\tfrom all iif br-lan fwmark 0/0xff0000 lookup %d\n", rz[0].Pref, rz[0].Table)
	if len(MissingIPRules(want, dump, "", false)) != 0 {
		t.Error("the postcheck does not recognise the rule as the kernel prints it")
	}
	opt := routedOptions()
	opt.LANIfaces = nil
	if p2, _, _ := Compile(routedProfile(), opt); len(p2.RoutedZones(Options{})) != 0 {
		t.Error("routed without the LAN's devices")
	}
}

// TestRoutedWithCoreTUN: with the core's TUN a static large list stays in nft, so its
// prefixes stay in the TUN's route_exclude; a large remote list's prefixes (never in that exclude) are
// still routed, keeping their names' resolver-fed set.
func TestRoutedWithCoreTUN(t *testing.T) {
	p := routedProfile()
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "srs", Source: "https://example.test/geo.srs", Outbound: "awg2", Enabled: true})
	plan, _, err := Compile(p, routedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CorePin {
		t.Fatal("no core pin")
	}
	got := map[string]bool{}
	for _, r := range plan.RoutedZones(Options{}) {
		got[r.Zone.Name] = true
		if v4, _ := r.RoutedPrefixes(routedOptions().RemoteSets); r.Zone.Name == "list_srs" && len(v4) != 400 {
			t.Errorf("remote routed prefixes %d", len(v4))
		}
	}
	if got["list_geo"] || !got["list_srs"] {
		t.Errorf("routed with the TUN: %v", got)
	}
	for _, z := range plan.Zones {
		if z.Name == "list_geo" && len(z.V4) != 300 {
			t.Errorf("the static large list left nft (and the TUN exclude): %d", len(z.V4))
		}
	}
	if nft := plan.RenderNft(); strings.Contains(nft, "rlist_list_srs") || !strings.Contains(nft, "dlist_list_srs_4") {
		t.Error("the large remote list kept its rlist sets, or lost its names' set")
	}
}

// TestRoutedOrderReversesEmit: of two overlapping large lists at different tunnels, the one
// nft would let win (emitted last) is the table looked up first.
func TestRoutedOrderReversesEmit(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.2", Params: map[string]any{"interface": "awg2"}},
			{ID: "awg3", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.3", Params: map[string]any{"interface": "awg3"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "names", Manual: []string{"openai.com"}, Outbound: "awg2", Enabled: true},
			{ID: "a", Manual: bigCIDRs(300), Outbound: "awg2", Enabled: true},
			{ID: "z", Manual: bigCIDRs(300), Outbound: "awg3", Enabled: true},
		},
	}
	plan, _, err := Compile(p, routedOptions())
	if err != nil {
		t.Fatal(err)
	}
	emit := map[string]int{}
	for i, z := range plan.Zones {
		emit[z.Name] = i
	}
	rz := plan.RoutedZones(Options{})
	if len(rz) != 2 || emit[rz[0].Zone.Name] < emit[rz[1].Zone.Name] || rz[0].Pref >= rz[1].Pref {
		t.Errorf("routed order %v vs emit %v", rz, emit)
	}
}

// TestRoutedKeptInNft: device-scoped lists, lists naming private space and hybrid stay as
// they were.
func TestRoutedKeptInNft(t *testing.T) {
	p := routedProfile()
	p.DeviceGroups = []model.DeviceGroup{{ID: "kid", Members: []model.DeviceMember{{IP: "192.168.77.50"}}}}
	p.RoutingLists[1].ScopeMode, p.RoutingLists[1].ScopeGroups = "only", []string{"kid"}
	plan, _, err := Compile(p, routedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RoutedZones(Options{})) != 0 {
		t.Error("a device-scoped large list was routed")
	}
	priv := routedProfile()
	priv.RoutingLists[1].Manual = append(priv.RoutingLists[1].Manual, "10.77.0.0/16")
	pp, _, err := Compile(priv, routedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(pp.RoutedZones(Options{})) != 0 {
		t.Error("a large list naming a private network was routed")
	}
	hy, _, err := Compile(routedProfile(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range hy.Zones {
		if z.Routed {
			t.Errorf("hybrid routed %s", z.Name)
		}
	}
}
