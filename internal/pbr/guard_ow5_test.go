package pbr

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// secondSegRules is `ip rule show` with the reference router's own source rule (assumed, not
// measured for this test): the second access point's segment goes to table 160.
const secondSegRules = `0:	from all lookup local
30:	from 192.168.70.0/24 lookup 160
31:	from all iif br-guest lookup guest
32:	from 192.168.40.7 lookup 161
33:	not from 192.168.50.0/24 lookup 162
34:	from 192.168.51.0/24 to 10.0.0.0/8 lookup 163
35:	from 192.168.52.0/24 fwmark 0x1 lookup 164
36:	from all iif lo lookup 165
37:	from 192.168.53.0/24 unreachable
38:	from 192.168.54.0/24 ipproto tcp lookup 166
150:	from all fwmark 0x20000/0xff0000 lookup 151
9000:	from all fwmark 0x2024 goto 9002
9001:	from all fwmark 0x2023 lookup 2022
9002:	from all nop
32766:	from all lookup main
32767:	from all lookup default
`

const secondSegRoutes = `default via 192.168.50.1 dev wan proto static src 192.168.50.2
192.168.1.0/24 dev wan proto kernel scope link src 192.168.50.2
192.168.70.0/24 dev br-welcome proto kernel scope link src 192.168.70.1
default dev awg0 table 151 scope link
blackhole default table 151 metric 1000
default dev awg1 table 160 scope link
default via 10.8.0.1 dev tun0 table guest proto static
192.168.70.0/24 dev br-welcome table 160 scope link
blackhole default table 161
local 192.168.50.2 dev wan table local proto kernel scope host src 192.168.50.2
`

// The rules that route a segment by its source are read, and nothing else is: not
// WayHop's marks, not the core's, not a rule with a destination, a negation, a protocol or no lookup.
func TestSourceRulesReadTheOperatorsOwnSourceRouting(t *testing.T) {
	got := SourceRules(secondSegRules)
	want := []SourceRule{
		{Line: "30: from 192.168.70.0/24 lookup 160", Pref: 30, Src: netip.MustParsePrefix("192.168.70.0/24"), Table: "160"},
		{Line: "31: from all iif br-guest lookup guest", Pref: 31, Iif: "br-guest", Table: "guest"},
		{Line: "32: from 192.168.40.7 lookup 161", Pref: 32, Src: netip.MustParsePrefix("192.168.40.7/32"), Table: "161"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("source rules:\n%+v\nwant\n%+v", got, want)
	}
	devs := TableDefaultDevices(secondSegRoutes)
	wantDevs := map[string][]string{"151": {"awg0"}, "160": {"awg1"}, "guest": {"tun0"}}
	if !reflect.DeepEqual(devs, wantDevs) {
		t.Fatalf("table defaults: %v, want %v (the main table's own default names no table; a blackhole has no device)", devs, wantDevs)
	}
}

// publicListOW5 is a kill-switched list of public addresses by the tunnels awg0 and awg1, a block
// list, and (with names) a kill-switched name.
func publicListOW5(names bool) *model.Profile {
	p := namedProfileOW4("198.18.5.0/24")
	if names {
		p.RoutingLists[len(p.RoutingLists)-1].Manual = append(p.RoutingLists[len(p.RoutingLists)-1].Manual, "example.org")
	}
	return p
}

// The second segment shape. The segment 192.168.70.0/24 is routed by the operator's own
// rule into a tunnel that is none of the list's. The guard took that tunnel for the provider and
// dropped the segment's traffic to the list, with WayHop healthy. Told the pair, it lets that
// segment through by that device, and by nothing else: never the provider's device, never another
// segment by that tunnel, and a block list stays blocked.
func TestGuardLetsASourceRoutedSegmentLeaveByItsOwnTunnel(t *testing.T) {
	plan := compileGuard(t, publicListOW5(false))
	welcome := GuardSource{Src: netip.MustParsePrefix("192.168.70.0/24"), Dev: "awg_guest"}
	before := parseGuard(t, plan.RenderNftGuardWith(NamesHold{}))
	wh := guardPkt{saddr: "192.168.70.20", daddr: "198.18.5.9", iif: "br-welcome", oif: "awg_guest"}
	before.want("the fault: the second segment to the list by its own tunnel", wh, "drop")

	program := plan.RenderNftGuardWith(NamesHold{Source: []GuardSource{welcome}})
	if !strings.Contains(program, "\t\tip saddr 192.168.70.0/24 oifname \"awg_guest\" accept\n\t\tcounter drop\n") {
		t.Fatalf("the list's chain lacks the segment's accept ahead of its drop:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("the second segment to the list by its own tunnel", wh, "accept")
	wh.oif = "wan"
	g.want("requirement (A): the second segment to the list by the provider's device", wh, "drop")
	wh.oif = "awg0"
	g.want("the second segment to the list by the list's tunnel", wh, "accept")
	g.want("the LAN to the list by the second segment's tunnel", guardPkt{saddr: "192.168.2.20", daddr: "198.18.5.9", iif: "br-lan", oif: "awg_guest"}, "drop")
	g.want("the LAN to the list by the provider", guardPkt{saddr: "192.168.2.20", daddr: "198.18.5.9", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a block list from the second segment", guardPkt{saddr: "192.168.70.20", daddr: "203.0.113.9", iif: "br-welcome", oif: "awg_guest"}, "drop")

	// A rule that selects by input device.
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Source: []GuardSource{{Iif: "br-guest", Dev: "tun0"}}}))
	g.want("a guest to the list by the guests' tunnel", guardPkt{saddr: "192.168.60.5", daddr: "198.18.5.9", iif: "br-guest", oif: "tun0"}, "accept")
	g.want("a guest to the list by the provider", guardPkt{saddr: "192.168.60.5", daddr: "198.18.5.9", iif: "br-guest", oif: "wan"}, "drop")
	g.want("the LAN by the guests' tunnel", guardPkt{saddr: "192.168.2.20", daddr: "198.18.5.9", iif: "br-lan", oif: "tun0"}, "drop")

	// A pair that names a device known to be the provider's is not rendered, whoever told it; nor is
	// a name that cannot be written into a program.
	bad := []GuardSource{{Src: welcome.Src, Dev: "wan"}, {Src: welcome.Src, Dev: "a b"}, {Src: welcome.Src, Dev: ""}}
	if got, plain := plan.RenderNftGuardWith(NamesHold{Source: bad, LocalPartial: true, Provider: []string{"wan"}}),
		plan.RenderNftGuardWith(NamesHold{LocalPartial: true, Provider: []string{"wan"}}); got != plain {
		t.Errorf("a pair by the provider's device changed the program:\n%s", got)
	}
	// No source routing: the program is what it was.
	if plan.RenderNftGuardWith(NamesHold{Source: nil}) != plan.RenderNftGuard() {
		t.Errorf("a guard without source routing differs from the plain one")
	}
}

// Source routing under the names hold and the learned addresses: the segment keeps its internet by its
// own tunnel while the hold stands, even when that tunnel is none of WayHop's endpoints (the
// operator's one-line way back to another exit), and a learned address is held on the provider.
func TestGuardNamesHoldPassesASourceRoutedSegmentByItsOwnTunnel(t *testing.T) {
	plan := compileGuard(t, publicListOW5(true))
	if len(plan.GuardNameSets) == 0 {
		t.Fatal("setup: the list has no name set")
	}
	hold := NamesHold{Seconds: 600, Pass: []string{"whtun0", "awg0", "awg1", "awg2"}}
	wh := guardPkt{saddr: "192.168.70.20", daddr: "93.184.216.34", iif: "br-welcome", oif: "awg_guest", proto: "udp"}
	parseGuard(t, plan.RenderNftGuardWith(hold)).want("the fault: the second segment under the hold by a tunnel that is no endpoint", wh, "drop")

	hold.Source = []GuardSource{{Src: netip.MustParsePrefix("192.168.70.0/24"), Dev: "awg_guest"}}
	g := parseGuard(t, plan.RenderNftGuardWith(hold))
	g.want("the second segment under the hold by its own tunnel", wh, "accept")
	lan := guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "awg_guest", proto: "udp"}
	g.want("the LAN under the hold by the second segment's tunnel", lan, "drop")
	wh.oif = "wan"
	g.want("the second segment under the hold by the provider", wh, "drop")

	set := plan.GuardNameSets[0].Set + "_4"
	g.learn(set, "93.184.216.34")
	g.protos[GuardHoldSet] = map[string]bool{} // the hold has lapsed
	g.want("a learned address from the second segment by the provider", wh, "drop")
	wh.oif = "awg_guest"
	g.want("a learned address from the second segment by its own tunnel", wh, "accept")
	g.want("a learned address from the LAN by the second segment's tunnel", lan, "drop")
}

// A route of the LAN side was accepted whole when it only overlapped what a list
// judges: 192.0.0.0/8 by an operator's tunnel, over a named 192.168.50.0/24, accepted every public
// address of 192.0.0.0/8 ahead of the zones, the name sets and the hold.
func TestGuardAcceptsAHouseRouteOnlyWhereAListJudgesIt(t *testing.T) {
	p := namedProfileOW4("192.168.50.0/24")
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "cdn", Name: "CDN", Outbound: "grp-office", Enabled: true, Manual: []string{"192.0.0.0/24"}})
	plan := compileGuard(t, p)
	local := localRoutes("awg9", "192.0.0.0/8", "br-lan", "192.168.2.0/24", "br-lab", "192.168.50.128/25")
	program := plan.RenderNftGuardWith(NamesHold{Local: local})
	if strings.Contains(program, "192.0.0.0/8") {
		t.Fatalf("the wide route is accepted whole:\n%s", program)
	}
	for _, want := range []string{`oifname "awg9" ip daddr { 192.168.50.0/24 } accept`, `oifname "br-lab" ip daddr { 192.168.50.128/25 } accept`} {
		if !strings.Contains(program, want) {
			t.Fatalf("guard lacks %q:\n%s", want, program)
		}
	}
	g := parseGuard(t, program)
	g.want("the named network by the LAN's route", guardPkt{saddr: "192.168.2.20", daddr: "192.168.50.9", iif: "br-lan", oif: "awg9"}, "accept")
	g.want("another kill-switched list's public address by the LAN's wide route", guardPkt{saddr: "192.168.2.20", daddr: "192.0.0.9", iif: "br-lan", oif: "awg9"}, "drop")
	g.want("that address by its list's tunnel", guardPkt{saddr: "192.168.2.20", daddr: "192.0.0.9", iif: "br-lan", oif: "awg0"}, "accept")

	// IPv6 under a hold that covers IPv6: the device's own segment is accepted whole, a prefix
	// routed by a gateway (read from whatever table) only where a list judges it.
	local6 := localRoutes("br-lan", "2001:db8:aa::/64", "br-lan", "2001:db8:ff::/48")
	local6[1].Via = true
	program = plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"whtun0"}, V6: true, Local: local6})
	if !strings.Contains(program, `oifname "br-lan" ip6 daddr { 2001:db8:aa::/64 } accept`) || strings.Contains(program, "2001:db8:ff::/48") {
		t.Fatalf("IPv6 routes under a hold:\n%s", program)
	}
}
