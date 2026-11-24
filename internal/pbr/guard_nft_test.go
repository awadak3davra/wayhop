package pbr

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// guardProfile is the reference router's shape under a kill switch: three adopted AmneziaWG links, a
// kill-switched RU group (awg1, awg2), Telegram calls in fastest mode over nl/fi with "block when all
// are down", a block list and a plain tunnel list.
func guardProfile() *model.Profile {
	p := nftListProfile()
	p.Groups[0].KillSwitch = true
	p.RoutingLists[1].Fastest.OnAllDown = model.OnAllDownBlock
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "ads", Name: "Ads", Outbound: model.OutboundBlock, Enabled: true, Manual: []string{"203.0.113.0/24"}},
		model.RoutingList{ID: "plain", Name: "Plain", Outbound: "nl", Enabled: true, Manual: []string{"192.0.2.0/24"}},
	)
	return p
}

func compileGuard(t *testing.T, p *model.Profile) *Plan {
	t.Helper()
	plan, _, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// A kill-switched destination may leave only by its own list's tunnels, whatever marked or routed
// it; a block list's destinations are dropped; a list without a kill switch is not in the guard.
func TestNftGuardHoldsKillSwitchedDestinationsByOutputDevice(t *testing.T) {
	plan := compileGuard(t, guardProfile())
	g := plan.RenderNftGuard()
	if !strings.HasPrefix(g, "table inet wayhop_ks {}\ndelete table inet wayhop_ks\ntable inet wayhop_ks {\n") {
		t.Fatalf("the guard must replace its own table in one transaction:\n%s", g)
	}
	if strings.Contains(g, "wayhop_pbr") {
		t.Fatalf("the guard names the plane's table; a rollback of the plane would take it along:\n%s", g)
	}
	for _, want := range []string{
		"\tset list_big_heavy_4 { type ipv4_addr; flags interval; elements = { 5.45.192.0/18 } }\n",
		"\tset list_tg_calls_4 { type ipv4_addr; flags interval; elements = { 91.108.4.0/22, 149.154.160.0/20 } }\n",
		"\tset list_ads_4 { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }\n",
		"\t\ttype filter hook forward priority filter - 5; policy accept;\n",
		"\t\tip daddr @list_ads_4 counter drop\n",
	} {
		if !strings.Contains(g, want) {
			t.Fatalf("guard lacks %q:\n%s", want, g)
		}
	}
	if strings.Contains(g, "list_plain") {
		t.Fatalf("a list without a kill switch is guarded:\n%s", g)
	}
	// Each kill-switched zone jumps to a verdict chain that lets its own tunnels through and drops
	// the rest. The group may hold awg1 or awg2; the fastest list awg0 or awg2.
	fwd := nftChain(t, g, "ks_forward")
	verdict := func(set string) string {
		t.Helper()
		for _, line := range strings.Split(fwd, "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ip daddr @"+set+" jump "); ok {
				return nftChain(t, g, rest)
			}
		}
		t.Fatalf("no jump for %s in:\n%s", set, fwd)
		return ""
	}
	if got, want := verdict("list_big_heavy_4"), "\t\toifname { \"awg1\", \"awg2\" } accept\n\t\tiifname { \"awg1\", \"awg2\" } accept\n\t\tcounter drop"; got != want {
		t.Fatalf("RU group verdict:\n%s\nwant:\n%s", got, want)
	}
	if got, want := verdict("list_tg_calls_4"), "\t\toifname { \"awg0\", \"awg2\" } accept\n\t\tiifname { \"awg0\", \"awg2\" } accept\n\t\tcounter drop"; got != want {
		t.Fatalf("Telegram verdict:\n%s\nwant:\n%s", got, want)
	}
	// The block is the strongest claim on an address, then the kill-switched lists: first match wins
	// here, last match wins in the marking chain, so the order is the marking chain's reversed.
	if a, b := strings.Index(fwd, "@list_ads_4"), strings.Index(fwd, "@list_tg_calls_4"); a < 0 || b < 0 || a > b {
		t.Fatalf("the block list must be judged before the kill-switched lists:\n%s", fwd)
	}
	if !plan.HasNftGuard() {
		t.Fatal("HasNftGuard is false for a plan with kill-switched lists")
	}
}

// No kill switch, no block: no guard table at all.
func TestNftGuardIsAbsentWithoutAKillSwitch(t *testing.T) {
	plan := compileGuard(t, nftListProfile())
	if plan.HasNftGuard() || plan.RenderNftGuard() != "" {
		t.Fatalf("a plan with nothing fail-closed rendered a guard:\n%s", plan.RenderNftGuard())
	}
}

// The guard matches a zone exactly as the marking chain does: every line the chain marks with a
// guarded zone's mark has its match in the guard, source scoping included, and nothing else.
func TestGuardMatchesFollowTheMarkingChain(t *testing.T) {
	p := guardProfile()
	p.DeviceGroups = []model.DeviceGroup{{ID: "kids", Name: "Kids", Members: []model.DeviceMember{
		{MAC: "aa:bb:cc:dd:ee:01"}, {IP: "192.168.2.50"},
	}}}
	p.RoutingLists[0].ScopeGroups = []string{"kids"}
	p.RoutingLists[0].ScopeMode = "only"
	p.Rules = append(p.Rules, model.Rule{ID: "cam", Outbound: "grp-ru", SourceIPCIDR: []string{"192.168.2.77/32"}})
	plan := compileGuard(t, p)
	mark := plan.RenderNft()
	guard := plan.RenderNftGuard()
	fwd := nftChain(t, guard, "ks_forward")
	n := 0
	for _, gz := range plan.guardedZones() {
		for _, m := range zoneMatches(gz.zone) {
			n++
			if !strings.Contains(mark, "\t\t"+m+" "+plan.markSet(gz.zone.Mark)+"\n") {
				t.Fatalf("zone %s: the guard matches %q, the marking chain has no such line:\n%s", gz.zone.Name, m, mark)
			}
			if !strings.Contains(fwd, "\t\t"+m+" ") && !strings.HasSuffix(fwd, "\t\t"+m) {
				t.Fatalf("zone %s: match %q is not in the guard:\n%s", gz.zone.Name, m, fwd)
			}
		}
	}
	if n < 4 {
		t.Fatalf("only %d guarded matches; the fixture should give a MAC zone, an address zone, a source-only rule and the lists", n)
	}
	for _, want := range []string{
		"ether saddr { aa:bb:cc:dd:ee:01 } ip daddr @list_big_heavy_dm_4 jump ks_",
		"ip saddr @list_big_heavy_di_s4 ip daddr @list_big_heavy_di_4 jump ks_",
		"\tset list_big_heavy_di_s4 { type ipv4_addr; flags interval; elements = { 192.168.2.50/32 } }\n",
		"ip saddr @rule_cam_s4 jump ks_",
	} {
		if !strings.Contains(guard, want) {
			t.Fatalf("guard lacks %q:\n%s", want, guard)
		}
	}
}

// IPv6. A zone that carries IPv6 is guarded like IPv4. A kill-switched list sent to an adopted
// (IPv4-only) tunnel has its IPv6 prefixes in no zone, and in hybrid mode the core's TUN is IPv4-only:
// nothing marks them, so the guard drops them. A list without a kill switch is not held.
func TestNftGuardDropsIPv6ThePlaneCannotCarry(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "2001:4860:4860::/48")
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "2001:67c:4e8::/48", "2606:4700:4700::/48")
	p.RoutingLists[3].Manual = append(p.RoutingLists[3].Manual, "2001:db8:1::/48")
	plan := compileGuard(t, p)
	// The RU group keeps its IPv6 in its zone (a group is not judged IPv4-only), so it is guarded by
	// device; Telegram's first tunnel is an adopted one, so its IPv6 is in no zone.
	want := []string{"2001:67c:4e8::/48", "2606:4700:4700::/48"}
	if !reflect.DeepEqual(plan.GuardV6, want) {
		t.Fatalf("GuardV6 = %v, want %v", plan.GuardV6, want)
	}
	g := plan.RenderNftGuard()
	for _, line := range []string{
		"\tset wh_uncarried6 { type ipv6_addr; flags interval; elements = { 2001:67c:4e8::/48, 2606:4700:4700::/48 } }\n",
		"\t\tip6 daddr @wh_uncarried6 counter drop\n",
		"\t\tip6 daddr @list_big_heavy_6 jump ks_",
	} {
		if !strings.Contains(g, line) {
			t.Fatalf("guard lacks %q:\n%s", line, g)
		}
	}
	// A list made of IPv6 only has no zone and no egress, and is held all the same.
	only6 := guardProfile()
	only6.RoutingLists = only6.RoutingLists[1:2]
	only6.RoutingLists[0].Manual = []string{"2001:67c:4e8::/48"}
	plan = compileGuard(t, only6)
	if len(plan.Zones) != 0 || !plan.HasNftGuard() || !strings.Contains(plan.RenderNftGuard(), "2001:67c:4e8::/48") {
		t.Fatalf("an IPv6-only kill-switched list is not held: zones %v guard:\n%s", plan.Zones, plan.RenderNftGuard())
	}
	// A dual-stack tunnel carries its IPv6: the zone is guarded by device, nothing is "uncarried".
	dual := guardProfile()
	dual.Endpoints = append(dual.Endpoints, model.Endpoint{ID: "own", Name: "own", Enabled: true, Engine: model.EngineAmneziaWG,
		Server: "198.51.100.200", Params: map[string]any{"local_address": []string{"10.9.0.2/32", "fd00::2/128"}}})
	dual.Groups = append(dual.Groups, model.Group{ID: "grp-own", Name: "own", Type: model.GroupFallback, Members: []string{"own"}, KillSwitch: true})
	dual.RoutingLists = []model.RoutingList{{ID: "six", Name: "six", Outbound: "grp-own", Enabled: true,
		Manual: []string{"198.18.0.0/15", "2001:db8:6::/48"}}}
	plan = compileGuard(t, dual)
	g = plan.RenderNftGuard()
	if len(plan.GuardV6) != 0 || !strings.Contains(g, "ip6 daddr @list_six_6 jump ks_0") || !strings.Contains(g, "ip daddr @list_six_4 jump ks_0") {
		t.Fatalf("dual-stack zone: GuardV6 %v guard:\n%s", plan.GuardV6, g)
	}
}

// Marks and tables stay where the applied plan has them. The router today: RU group
// 0x20000 -> 151, the nl tunnel 0x30000 -> 152. Telegram going into fastest mode used to leave its
// old egress unused and renumber; now every surviving egress keeps its slot and the new one takes a
// free slot.
func TestCompileKeepsMarksAndTablesOfTheAppliedPlan(t *testing.T) {
	p := nftListProfile()
	p.RoutingLists[1].Fastest = nil
	p.RoutingLists[1].Candidates = nil
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "aaa", Name: "aaa", Outbound: "fi", Enabled: true, Manual: []string{"192.0.2.0/24"}})
	applied, _, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	was := map[string][2]int{}
	for _, e := range applied.Egresses {
		was[e.Tag] = [2]int{int(e.Mark), e.Table}
	}
	if was["fi"] != [2]int{0x20000, 151} || was["grp-ru"] != [2]int{0x30000, 152} || was["nl"] != [2]int{0x40000, 153} {
		t.Fatalf("fixture numbering moved: %v", was)
	}
	// The "aaa" list goes away (its egress "fi" is unused now), and Telegram goes into fastest mode
	// (its egress "nl" is unused now, a list egress appears).
	next := nftListProfile()
	fresh, _, err := Compile(next, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	if e := nftEgress(t, fresh, "grp-ru"); e.Mark != 0x20000 || e.Table != 151 {
		t.Fatalf("without slots the group is renumbered (the case under test): %+v", e)
	}
	kept, _, err := Compile(next, Options{ListEgresses: true, Slots: SlotsOf(applied, Options{})})
	if err != nil {
		t.Fatal(err)
	}
	if e := nftEgress(t, kept, "grp-ru"); e.Mark != 0x30000 || e.Table != 152 {
		t.Fatalf("the group left its mark and table: %+v", e)
	}
	if e := nftEgress(t, kept, model.ListEgressTag("tg-calls")); e.Mark != 0x20000 || e.Table != 151 {
		t.Fatalf("the new list egress should take the lowest free slot: %+v", e)
	}
	// Egresses stay in mark order, and the rules follow them.
	for i := 1; i < len(kept.Egresses); i++ {
		if kept.Egresses[i-1].Mark >= kept.Egresses[i].Mark {
			t.Fatalf("egresses out of mark order: %+v", kept.Egresses)
		}
	}
	ip := strings.Join(kept.RenderIP(Options{}), "\n")
	for _, want := range []string{
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150",
		"ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151",
		"ip route replace default dev awg1 table 152",
	} {
		if !strings.Contains(ip, want) {
			t.Fatalf("RenderIP lacks %q:\n%s", want, ip)
		}
	}
	// Compiling again from the result changes nothing: the daemon recompiles the applied profile at
	// run time and must land on the applied plan.
	again, _, err := Compile(next, Options{ListEgresses: true, Slots: SlotsOf(kept, Options{})})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Egresses, kept.Egresses) {
		t.Fatalf("recompile moved egresses:\n%+v\n%+v", again.Egresses, kept.Egresses)
	}
	// A slot outside the mark space, or held twice, is not honoured.
	odd, _, err := Compile(next, Options{ListEgresses: true, Slots: map[string]int{"grp-ru": 900, model.ListEgressTag("tg-calls"): 0}})
	if err != nil {
		t.Fatal(err)
	}
	if e := nftEgress(t, odd, "grp-ru"); e.Table != 152 || e.Mark != 0x30000 {
		t.Fatalf("an impossible slot was used or the free one skipped: %+v", e)
	}
}

// Route dumps as the reference OpenWrt router prints them (`ip route show table all`, BusyBox and iproute2 alike).
const (
	owrtRoutes4 = `default dev awg1 table 151 scope link
blackhole default table 151 metric 1000
default dev awg0 table 152 scope link
blackhole default table 152 metric 1000
blackhole default table 153
default via 192.0.2.1 dev wan proto static src 192.0.2.138
192.168.2.0/24 dev br-lan proto kernel scope link src 192.168.2.1
local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1
`
	owrtRoutes6 = `default dev awg1 table 151 metric 1024 pref medium
blackhole default dev lo table 151 metric 2048 pref medium
fd12:b5d7:2f0e::/64 dev br-lan proto static metric 1024 pref medium
`
)

func TestMissingFailClosedRoutesReadsTheRouteDump(t *testing.T) {
	plan := compileGuard(t, guardProfile())
	// ads (block) 151? The numbering is by tag: block, grp-ru, nl, then the list egress.
	tables := map[string]int{}
	for _, e := range plan.Egresses {
		tables[e.Tag] = e.Table
	}
	if tables[model.OutboundBlock] != 151 || tables["grp-ru"] != 152 || tables[model.ListEgressTag("tg-calls")] != 154 {
		t.Fatalf("fixture numbering: %v", tables)
	}
	dump := "blackhole default table 151\n" +
		"default dev awg1 table 152 scope link\nblackhole default table 152 metric 1000\n" +
		"default dev awg0 table 153 scope link\n" +
		"default dev awg0 table 154 scope link\nblackhole default table 154 metric 1000\n"
	if miss := plan.MissingFailClosedRoutes(dump, ""); len(miss) != 0 {
		t.Fatalf("complete dump reported missing: %v", miss)
	}
	// `ip route flush table 154`, and the group's blackhole replaced by one with another metric.
	broken := "blackhole default table 151\n" +
		"default dev awg1 table 152 scope link\nblackhole default table 152 metric 500\n" +
		"default dev awg0 table 153 scope link\n"
	want := []string{
		"ip route blackhole default metric 1000 table 152",
		"ip route blackhole default metric 1000 table 154",
	}
	if miss := plan.MissingFailClosedRoutes(broken, ""); !reflect.DeepEqual(miss, want) {
		t.Fatalf("missing = %v, want %v", miss, want)
	}
	// The router's real shapes parse: tables 151 and 152 fail closed, 153 is a block.
	got := blackholeDefaults(owrtRoutes4)
	if !got[151][1000] || !got[152][1000] || !got[153][0] || len(got[254]) != 0 {
		t.Fatalf("v4 dump parsed as %v", got)
	}
	if got := blackholeDefaults(owrtRoutes6); !got[151][2048] {
		t.Fatalf("v6 dump parsed as %v", got)
	}
}

// The reference router's own `ip rule` plus the line a failover script of its own adds.
const owrtRules = `0:	from all lookup local
30:	from 192.168.33.0/24 lookup 160
50:	from all to 198.51.100.48 lookup main
145:	from all fwmark 0x30000/0xff0000 lookup 153
147:	from all to 10.0.0.0/8 lookup main
148:	from all to 172.16.0.0/12 lookup main
149:	from all to 192.168.0.0/16 lookup main
150:	from all fwmark 0x20000/0xff0000 lookup 151
151:	from all fwmark 0x30000/0xff0000 lookup 152
9000:	from all fwmark 0x2024 goto 9002
9001:	from all fwmark 0x2023 lookup 2022
9002:	from all nop
32766:	from all lookup main
32767:	from all lookup default
32768:	from all lookup 2022
`

func TestForeignRulesFindsTheOperatorsScript(t *testing.T) {
	p := nftListProfile()
	p.RoutingLists[1].Fastest = nil
	p.RoutingLists[1].Candidates = nil
	plan, _, err := Compile(p, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	got := ForeignRules(owrtRules, Options{}, plan.RenderIP(Options{}))
	want := []ForeignRule{
		{Line: "30:	from 192.168.33.0/24 lookup 160", Why: "table", Table: 160},
		{Line: "145:	from all fwmark 0x30000/0xff0000 lookup 153", Why: "mark+table", Mark: 0x30000, Table: 153},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("foreign rules = %+v, want %+v", got, want)
	}
	// WayHop's own rules, sing-box's exact marks and the system's rules are not reported.
	clean := strings.Replace(strings.Replace(owrtRules, "145:	from all fwmark 0x30000/0xff0000 lookup 153\n", "", 1),
		"30:	from 192.168.33.0/24 lookup 160\n", "", 1)
	if got := ForeignRules(clean, Options{}, plan.RenderIP(Options{})); len(got) != 0 {
		t.Fatalf("clean dump reported %+v", got)
	}
	// The postcheck's reader finds every rule of the plan in the router's own dump,
	// and names the one a script deleted.
	program := strings.Join(plan.RenderIP(Options{}), "\n")
	if miss := MissingIPRules(program, owrtRules, "", false); len(miss) != 0 {
		t.Fatalf("the router's dump holds the plan's rules, yet these read as missing: %v", miss)
	}
	gone := strings.Replace(owrtRules, "151:	from all fwmark 0x30000/0xff0000 lookup 152\n", "", 1)
	if miss := MissingIPRules(program, gone, "", false); len(miss) != 1 || miss[0] != "ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151" {
		t.Fatalf("a deleted rule read as %v", miss)
	}
}

// The names hold: one broad rule, bounded by the kernel. Elements with a timeout stand for the hold;
// when nobody renews them the rule matches nothing.
func TestNftGuardNamesHoldIsBoundedByElementTimeouts(t *testing.T) {
	plan := compileGuard(t, guardProfile())
	g := plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"tun0", "awg2", "awg0", "awg1", "awg0"}})
	for _, want := range []string{
		"\tset wh_hold { type inet_proto; flags timeout; elements = { tcp timeout 600s, udp timeout 600s, icmp timeout 600s, ipv6-icmp timeout 600s,",
		"\t\tct direction reply accept\n",
		"\t\toifname { \"awg0\", \"awg1\", \"awg2\", \"tun0\" } accept\n",
		"\t\tiifname { \"awg0\", \"awg1\", \"awg2\", \"tun0\" } accept\n",
		"\t\tmeta mark & 0x00ff0000 == { 0x00010000, 0x00040000 } accept\n", // direct, and the plain list's tunnel
		"\t\tip daddr @wh_private4 accept\n",
		"\t\tip6 daddr @wh_private6 accept\n",
		"\t\tmeta nfproto ipv4 meta l4proto @wh_hold counter drop\n",
	} {
		if !strings.Contains(g, want) {
			t.Fatalf("hold lacks %q:\n%s", want, g)
		}
	}
	// The hold comes after the per-list verdicts: a kill-switched address is judged by its own rule.
	fwd := nftChain(t, g, "ks_forward")
	if a, b := strings.Index(fwd, "@list_tg_calls_4"), strings.Index(fwd, "@wh_hold"); a < 0 || b < a {
		t.Fatalf("the hold precedes the lists:\n%s", fwd)
	}
	if strings.Contains(plan.RenderNftGuard(), "wh_hold") {
		t.Fatal("a guard without a names hold carries one")
	}
	// Strict: no timeout, the operator's kill_switch_boot_hold_lift < 0.
	if s := plan.RenderNftGuardWith(NamesHold{Seconds: -1, Pass: []string{"tun0"}}); !strings.Contains(s, "elements = { tcp, udp, icmp,") {
		t.Fatalf("strict hold still has timeouts:\n%s", s)
	}
	renew := RenderGuardHoldRenew(600)
	if !strings.HasPrefix(renew, "add element inet wayhop_ks wh_hold { tcp timeout 600s }\ndelete element inet wayhop_ks wh_hold { tcp }\nadd element inet wayhop_ks wh_hold { tcp timeout 600s }\n") {
		t.Fatalf("renew program:\n%s", renew)
	}
	if RenderGuardHoldLift() != "flush set inet wayhop_ks wh_hold\n" {
		t.Fatalf("lift program: %q", RenderGuardHoldLift())
	}
	// A names-only kill switch (no address zone at all) still renders the hold.
	names := nftListProfile()
	names.RoutingLists = nil
	only, _, err := Compile(names, Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := only.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"tun0"}}); !strings.Contains(s, "meta l4proto @wh_hold counter drop") {
		t.Fatalf("a plan without zones lost the hold:\n%s", s)
	}
	if GuardProofSet(g) == GuardProofSet(plan.RenderNftGuard()) || !strings.HasPrefix(GuardProofSet(g), "wh_guard_") {
		t.Fatal("the guard's marker must follow its program")
	}
}
