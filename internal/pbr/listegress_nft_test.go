package pbr

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The nft plane (OpenWrt) gives a fastest list its own mark and table exactly as the ipset plane
// (KeeneticOS) does: Compile numbers the egress, RenderNft marks and remembers it, RenderIP installs
// its rule and seeds its table. Shapes below are the router's own: adopted AmneziaWG links awg0/awg1/
// awg2 on a reference OpenWrt router, mask 0x00ff0000, tables from 151.

func nftListProfile() *model.Profile {
	ext := func(id, iface, peer string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineExternal,
			Params: map[string]any{"interface": iface, "endpoint_ip": peer}}
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{ext("nl", "awg0", "198.51.100.48"), ext("ru", "awg1", "198.51.100.14"), ext("fi", "awg2", "198.51.100.144")},
		Groups:    []model.Group{{ID: "grp-ru", Name: "RU", Type: model.GroupFallback, Members: []string{"ru", "fi"}}},
		RoutingLists: []model.RoutingList{
			{ID: "big-heavy", Name: "RU heavy", Outbound: "grp-ru", Enabled: true, Manual: []string{"5.45.192.0/18"}},
			{ID: "tg-calls", Name: "Telegram calls", Outbound: "nl", Candidates: []string{"nl", "fi"}, Enabled: true,
				Manual:  []string{"149.154.160.0/20", "91.108.4.0/22"},
				Fastest: &model.FastestPolicy{Enabled: true}},
		},
	}
}

func nftEgress(t *testing.T, pl *Plan, tag string) Egress {
	t.Helper()
	for _, e := range pl.Egresses {
		if e.Tag == tag {
			return e
		}
	}
	t.Fatalf("no egress %q in %+v", tag, pl.Egresses)
	return Egress{}
}

func TestNftPlaneGivesAFastestListItsOwnMarkAndTable(t *testing.T) {
	plan, _, err := Compile(nftListProfile(), Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	group := nftEgress(t, plan, "grp-ru")
	list := nftEgress(t, plan, model.ListEgressTag("tg-calls"))
	if group.Mark != 0x00020000 || group.Table != 151 || list.Mark != 0x00030000 || list.Table != 152 || list.Iface != "awg0" {
		t.Fatalf("group %+v list %+v: the list is numbered after every other egress and seeded with its first candidate", group, list)
	}
	nft := plan.RenderNft()
	for _, chain := range []string{"wr_mark", "wr_mark_late"} {
		body := nftChain(t, nft, chain)
		for _, line := range []string{
			// the list's addresses take the list's own mark, not its first tunnel's
			"ip daddr @list_tg_calls_4 meta mark set meta mark & 0xff00ffff | 0x00030000\n",
			"ip daddr @list_big_heavy_4 meta mark set meta mark & 0xff00ffff | 0x00020000\n",
			// an established flow keeps the list's mark, whichever tunnel the table points at
			"ct mark & 0x00ff0000 == 0x00030000 meta mark set meta mark & 0xff00ffff | 0x00030000 accept\n",
			"meta mark & 0x00ff0000 == 0x00030000 ct mark set ct mark & 0xff00ffff | 0x00030000", // the chain's last line
		} {
			if !strings.Contains(body, line) {
				t.Errorf("%s lacks %q:\n%s", chain, line, body)
			}
		}
	}
	// Every candidate's device is NATed and MSS-clamped, not only the seeded one: the elector points
	// the table at awg2 without another Apply.
	if !strings.Contains(nft, `oifname { "awg0", "awg1", "awg2" } tcp flags & (fin|syn|rst|ack) == syn tcp option maxseg size set rt mtu`) {
		t.Errorf("wr_mss must clamp on every tunnel a fastest list may be pointed at:\n%s", nft)
	}
	for _, iface := range []string{"awg0", "awg1", "awg2"} {
		if !strings.Contains(nft, `meta nfproto ipv4 oifname "`+iface+`" masquerade`) {
			t.Errorf("no masquerade on %s", iface)
		}
	}
	ip := plan.RenderIP(Options{})
	for _, want := range []string{
		"ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151",
		"ip route replace default dev awg0 table 152",
		"ip route del blackhole default metric 1000 table 152", // no kill switch: nothing may keep dropping
	} {
		if !containsLine(ip, want) {
			t.Errorf("RenderIP lacks %q:\n%s", want, strings.Join(ip, "\n"))
		}
	}
	// The core must not see the list's addresses: they are the plan's zones on either plane.
	var excluded []string
	for _, z := range plan.Zones {
		if z.EgressTag == list.Tag {
			excluded = append(excluded, z.V4...)
		}
	}
	if !reflect.DeepEqual(excluded, []string{"91.108.4.0/22", "149.154.160.0/20"}) {
		t.Errorf("list zone %v", excluded)
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// "Block when every tunnel is down" and a kill switch over the list's tunnels both leave the kill
// switch's blackhole in the list's own table, below the device route, in both families.
func TestNftPlaneFastestListFailsClosed(t *testing.T) {
	p := nftListProfile()
	p.RoutingLists[1].Fastest.OnAllDown = model.OnAllDownBlock
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "2001:67c:4e8::/48")
	// An adopted link is v4-only by posture; WayHop's own AmneziaWG devices carry IPv6.
	for i := range p.Endpoints {
		p.Endpoints[i].Engine = model.EngineAmneziaWG
		p.Endpoints[i].Params = map[string]any{"local_address": []string{"10.8.0.2/32", "fd00:8::2/128"}}
		p.Endpoints[i].Server = "192.0.2.1" + string(rune('0'+i))
	}
	plan, _, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	list := nftEgress(t, plan, model.ListEgressTag("tg-calls"))
	if !list.FailClosed || !plan.HasV6() {
		t.Fatalf("list egress %+v, v6 %v", list, plan.HasV6())
	}
	ip := plan.RenderIP(Options{})
	table := "table " + itoaTest(list.Table)
	for _, want := range []string{
		"ip route replace default dev " + list.Iface + " " + table,
		"ip -6 route replace default dev " + list.Iface + " " + table,
		"ip route replace blackhole default metric 1000 " + table,
		"ip -6 route replace blackhole default metric 2048 " + table,
		"ip -6 rule add fwmark 0x00030000/0x00ff0000 " + table + " priority 151",
	} {
		if !containsLine(ip, want) {
			t.Errorf("RenderIP lacks %q:\n%s", want, strings.Join(ip, "\n"))
		}
	}
	if !strings.Contains(plan.RenderNft(), "ip6 daddr @list_tg_calls_6 meta mark set meta mark & 0xff00ffff | 0x00030000") {
		t.Error("the list's IPv6 addresses must take the list's mark")
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A profile with no fastest list renders byte for byte as it did before the option reached this
// plane: an applied artifact is validated against a re-render of its own plan, so a moved byte would
// turn every router's record invalid on upgrade.
func TestNftPlaneWithoutFastestListsIsUnchanged(t *testing.T) {
	p := nftListProfile()
	p.RoutingLists[1].Fastest = nil
	p.RoutingLists[1].Candidates = nil
	with, _, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	without, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if with.RenderNft() != without.RenderNft() || !reflect.DeepEqual(with.RenderIP(Options{}), without.RenderIP(Options{})) ||
		!reflect.DeepEqual(with.RenderTeardown(Options{}), without.RenderTeardown(Options{})) {
		t.Fatal("ListEgresses changed the render of a plan that has no fastest list")
	}
	// A plan stored before Compile recorded each egress's devices clamps MSS on its egress devices
	// only, as every applied one does today; a new compile clamps on the group's other member too,
	// which the elector may move the table to.
	stored := *with
	stored.Egresses = append([]Egress(nil), with.Egresses...)
	for i := range stored.Egresses {
		stored.Egresses[i].Ifaces = nil
	}
	if nft := stored.RenderNft(); !strings.Contains(nft, `oifname { "awg0", "awg1" } tcp flags`) {
		t.Fatalf("wr_mss of a stored plan without list egresses moved:\n%s", nft)
	}
	if nft := with.RenderNft(); !strings.Contains(nft, `oifname { "awg0", "awg1", "awg2" } tcp flags`) {
		t.Fatalf("wr_mss misses the group's second member:\n%s", nft)
	}
}

// A list whose tunnels live only inside the proxy core, or with one kernel link, gets no egress of
// its own on this plane either: it keeps its first tunnel and the compiler says why.
func TestNftPlaneFastestListNeedsTwoKernelLinks(t *testing.T) {
	p := nftListProfile()
	p.Endpoints = append(p.Endpoints, model.Endpoint{ID: "vl", Name: "vl", Enabled: true, Engine: model.EngineSingBox,
		Protocol: model.ProtoVLESS, Server: "198.51.100.9", Port: 443})
	p.RoutingLists[1].Candidates = []string{"nl", "vl"}
	plan, warns, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range plan.Egresses {
		if _, isList := model.ListEgressID(e.Tag); isList {
			t.Fatalf("one kernel link, yet the list got its own egress: %+v", e)
		}
	}
	said := false
	for _, w := range warns {
		said = said || (w.Scope == "tg-calls" && strings.Contains(w.Msg, "two or more tunnels the kernel routes"))
	}
	if !said {
		t.Fatalf("warnings %+v", warns)
	}
	if nftEgress(t, plan, "nl").Iface != "awg0" {
		t.Fatal("the list keeps its first tunnel's egress")
	}
}
