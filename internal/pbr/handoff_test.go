package pbr

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Kill switch precedence. On a Keenetic router a list rl-vpn-max-vk (IP checks,
// domains api.ipify.org, checkip.amazonaws.com, ifconfig.me, direct) had dnsmasq put Cloudflare
// anycast addresses in its set; refilter (grp-awg31) holds 172.64.0.0/13. Its MARK came after
// refilter's and a client PC left by the WAN to every site on that address, ctmark 0x10000.

// liveChainBefore is `iptables-save -t mangle` of WR_PREROUTING on that router before the fix
// (marks as iptables-save prints them).
const liveChainBefore = `-A WR_PREROUTING -m set --match-set wr_bypass_4 dst -j RETURN
-A WR_PREROUTING -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
-A WR_PREROUTING -m set --match-set wr_list_cidr_refilter_4 dst -j MARK --set-xmark 0x30000/0xff0000
-A WR_PREROUTING -m set --match-set wr_list_rl_cascade_4 dst -j MARK --set-xmark 0x40000/0xff0000
-A WR_PREROUTING -m set --match-set wr_list_rl_vpn_max_vk_4 dst -j MARK --set-xmark 0x10000/0xff0000
-A WR_PREROUTING -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
`

// chainMark runs a packet whose destination is in the named sets through iptables-save lines of the
// marking chain and returns its mark (RETURN ends early; CONNMARK restores 0 for a new flow).
func chainMark(t *testing.T, lines string, inSets map[string]bool) uint32 {
	t.Helper()
	var mark uint32
	for _, line := range strings.Split(lines, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" {
			continue
		}
		match := true
		var target []string
		for i := 2; i < len(f); i++ {
			switch f[i] {
			case "--match-set":
				if !inSets[f[i+1]] {
					match = false
				}
				i += 2
			case "--mark":
				v, m, _ := strings.Cut(f[i+1], "/")
				val, _ := strconv.ParseUint(v, 0, 32)
				msk, _ := strconv.ParseUint(m, 0, 32)
				if mark&uint32(msk) != uint32(val) {
					match = false
				}
				i++
			case "-m":
				i++
			case "-j":
				target = f[i+1:]
				i = len(f)
			}
		}
		if !match {
			continue
		}
		switch target[0] {
		case "RETURN":
			return mark
		case "MARK":
			v, m, _ := strings.Cut(target[2], "/")
			val, _ := strconv.ParseUint(v, 0, 32)
			msk, _ := strconv.ParseUint(m, 0, 32)
			mark = mark&^uint32(msk) | uint32(val)
		}
	}
	return mark
}

func dualLANProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg31", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.31", Params: map[string]any{"interface": "nwg5"}},
			{ID: "ru", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.7", Params: map[string]any{"interface": "nwg7"}},
		},
		Groups: []model.Group{
			{ID: "grp-awg31", Type: model.GroupURLTest, Members: []string{"awg31"}},
			{ID: "grp-list-cascade", Type: model.GroupURLTest, Members: []string{"ru"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "cidr-refilter", Enabled: true, Outbound: "grp-awg31", Manual: []string{"172.64.0.0/13", "104.16.0.0/13"}},
			{ID: "rl-cascade", Enabled: true, Outbound: "grp-list-cascade", Manual: []string{"104.16.0.1/32"}},
			{ID: "rl-vpn-max-vk", Enabled: true, Outbound: model.OutboundDirect, Manual: []string{"api.ipify.org", "checkip.amazonaws.com", "ifconfig.me"}},
		},
	}
}

func TestPrecedenceDirectDomainListNeverTakesATunnelAddress(t *testing.T) {
	sets := map[string]bool{"wr_list_cidr_refilter_4": true, "wr_list_rl_vpn_max_vk_4": true}
	if m := chainMark(t, liveChainBefore, sets); m != 0x10000 {
		t.Fatalf("the live chain gives %#x; the regression this pins is that it gave direct", m)
	}
	pl, _, err := Compile(dualLANProfile(), Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	refilter := markFor(t, pl, "list_cidr_refilter")
	rules := mangleRestoreRules(pl.RenderIptablesScript(IpsetOptions{}))
	if m := chainMark(t, rules, sets); m != refilter {
		t.Fatalf("mark %#x, want refilter's %#x:\n%s", m, refilter, rules)
	}
	// Two tunnels overlap: one of them wins, by name, and it is never the direct list.
	both := map[string]bool{"wr_list_cidr_refilter_4": true, "wr_list_rl_cascade_4": true, "wr_list_rl_vpn_max_vk_4": true}
	if m := chainMark(t, rules, both); m == markFor(t, pl, "list_rl_vpn_max_vk") || m&0xff0000 == 0 {
		t.Fatalf("three-way overlap mark %#x", m)
	}
}

func handoffOptions() IpsetOptions {
	return IpsetOptions{LANIfaces: []string{"br0"}, HandoffIface: HandoffIfaceDefault}
}

// The overlap goes to sing-box (the list's own names keep their exit there), and without it to the
// stronger list: the rendered chain, rule and route.
func TestHandoffRender(t *testing.T) {
	pl, _, err := Compile(dualLANProfile(), Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	h := pl.Handoff()
	if len(h.Pairs) != 2 || len(h.Routes) != 1 || h.Routes[0].Mark != markFor(t, pl, "list_rl_vpn_max_vk") ||
		strings.Join(h.Routes[0].Domains, ",") != "api.ipify.org,checkip.amazonaws.com,ifconfig.me" {
		t.Fatalf("hand-off = %+v", h)
	}
	io := handoffOptions()
	script := pl.RenderKeeneticScript(Options{}, io)
	rules := mangleRestoreRules(script)
	pair := fmt.Sprintf("-A WR_PREROUTING -m set --match-set wr_list_rl_vpn_max_vk_4 dst -m set --match-set wr_list_cidr_refilter_4 dst -m mark --mark %s/0x00ff0000 -j MARK --set-xmark 0x20000000/0x20000000\n", hexMark(markFor(t, pl, "list_cidr_refilter")))
	if !strings.Contains(rules, pair) || strings.Index(rules, pair) < strings.Index(rules, "--save-mark") {
		t.Fatalf("pair rule missing or not last:\n%s", rules)
	}
	if strings.Contains(mangleSection(t, script, "ip6tables")[0], "0x20000000") || strings.Count(script, "0x20000000/0x20000000 dst") != 0 {
		t.Fatal("v6 hand-off rendered")
	}
	sets := map[string]bool{"wr_list_cidr_refilter_4": true, "wr_list_rl_vpn_max_vk_4": true}
	refilter := markFor(t, pl, "list_cidr_refilter")
	if m := chainMark(t, rules, sets); m != refilter|HandoffBit {
		t.Fatalf("overlap mark %#x, want %#x", m, refilter|HandoffBit)
	}
	if m := chainMark(t, rules, map[string]bool{"wr_list_rl_vpn_max_vk_4": true}); m&HandoffBit != 0 {
		t.Fatalf("a list-only address handed off: %#x", m)
	}
	mustContain(t, script, "iptables -t mangle -C OUTPUT -m mark --mark 0x10000000/0x10000000 -j WR_PREROUTING_HO 2>/dev/null || iptables -t mangle -A OUTPUT -m mark --mark 0x10000000/0x10000000 -j WR_PREROUTING_HO\n")
	mustContain(t, script, "\nip rule add iif br0 fwmark 0x20000000/0x20000000 table 408 priority 145\n")
	mustContain(t, script, "ip route replace default dev wrho0 table 408 2>/dev/null || true\n")

	// Routing: with the TUN up the overlap enters sing-box; with it gone (table empty) refilter's
	// table takes it; the router's own re-originated packet (iif lo) never loops back into the TUN.
	g, _ := listEgressByTag(pl, "grp-awg31")
	rs := bsRules(t, script, false)
	dst := netip.MustParseAddr("172.64.41.4")
	for _, c := range []struct {
		name, iif string
		populated map[string]bool
		want      string
	}{
		{"sing-box up", "br0", map[string]bool{"408": true, strconv.Itoa(g.Table): true}, "tunnel"},
		{"sing-box down", "br0", map[string]bool{strconv.Itoa(g.Table): true}, "tunnel"},
		{"tunnel down too, no kill switch", "br0", nil, "main"},
	} {
		if got := bsVerdict(rs, nil, c.populated, c.iif, refilter|HandoffBit, dst); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// Which table answered: the hand-off rule precedes refilter's.
	if hand, egress := strings.Index(script, "table 408 priority 145\n"), strings.Index(script, fmt.Sprintf("table %d priority", g.Table)); hand < 0 || egress < 0 {
		t.Fatal("rules missing")
	}
	lo := bsVerdict(rs, nil, map[string]bool{"408": true}, "lo", refilter|HandoffBit|HandoffReturnBit, dst)
	if lo == "tunnel" {
		// "tunnel" here can only be table 408: refilter's table is not populated in this call.
		t.Fatal("sing-box's own packet looped into the hand-off TUN")
	}
	td := pl.RenderTeardownScript(Options{}, io)
	for _, want := range []string{
		"iptables -t mangle -D OUTPUT -m mark --mark 0x10000000/0x10000000 -j WR_PREROUTING_HO 2>/dev/null || true\n",
		"ip rule del iif br0 fwmark 0x20000000/0x20000000 table 408 priority 145 2>/dev/null || true\n",
		"ip route flush table 408 2>/dev/null || true\n",
	} {
		mustContain(t, td, want)
	}
	if strings.Contains(pl.RenderKeeneticScript(Options{}, IpsetOptions{LANIfaces: []string{"br0"}}), "0x20000000") {
		t.Fatal("hand-off rendered without a core to hand off to")
	}
}

// Under a kill switch the precedence is absolute: the kill-switched list's addresses are handed off
// only to a kill-switched domain list.
func TestHandoffKillSwitchAbsolute(t *testing.T) {
	p := dualLANProfile()
	p.Groups[0].KillSwitch = true
	pl, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range pl.Handoff().Pairs {
		if pr.Stronger == "list_cidr_refilter" {
			t.Fatalf("kill-switched refilter handed off to a direct list: %+v", pl.Handoff())
		}
	}
	sets := map[string]bool{"wr_list_cidr_refilter_4": true, "wr_list_rl_vpn_max_vk_4": true, "wr_list_rl_cascade_4": true}
	if m := chainMark(t, mangleRestoreRules(pl.RenderKeeneticScript(Options{}, handoffOptions())), sets); m != markFor(t, pl, "list_cidr_refilter") {
		t.Fatalf("kill-switched list lost an address: %#x", m)
	}
	// Not even to a kill-switched domain list, until sing-box's bind is proven: see
	// TestHandoffNeverWithAFailClosedSide.
	p.Groups[1].KillSwitch = true
	p.RoutingLists[2].Outbound = "grp-list-cascade"
	pl, _, _ = Compile(p, Options{CollectDomainZones: true})
	for _, pr := range pl.Handoff().Pairs {
		if pr.Stronger == "list_cidr_refilter" {
			t.Fatalf("kill-switched refilter handed off: %+v", pl.Handoff())
		}
	}
}

func TestOverlapsNameTheWinner(t *testing.T) {
	pl, _, err := Compile(dualLANProfile(), Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	ov := pl.Overlaps()
	if len(ov) != 1 || ov[0].Loser != "list_cidr_refilter" || ov[0].Winner != "list_rl_cascade" || ov[0].Count != 1 || ov[0].Leaks() {
		t.Fatalf("overlaps = %+v", ov)
	}
	p := dualLANProfile()
	p.Groups[0].KillSwitch = true
	pl, _, _ = Compile(p, Options{CollectDomainZones: true})
	ov = pl.Overlaps()
	if len(ov) != 1 || ov[0].Winner != "list_cidr_refilter" || !ov[0].WinnerFailClosed || ov[0].Leaks() {
		t.Fatalf("kill-switched overlaps = %+v", ov)
	}
	if !(Overlap{LoserFailClosed: true}).Leaks() || (Overlap{LoserFailClosed: true, WinnerBlock: true}).Leaks() {
		t.Fatal("Leaks")
	}
}

// outputChainLines are the rules of the chain mangle OUTPUT jumps to for the hand-off's return bit, as
// the restore commit writes them, and that chain's name.
func outputChainLines(t *testing.T, script string) (string, []string) {
	t.Helper()
	re := regexp.MustCompile(`(?m)^iptables -t mangle -C OUTPUT -m mark --mark 0x10000000/0x10000000 -j (\S+) 2>/dev/null \|\| iptables -t mangle -A OUTPUT -m mark --mark 0x10000000/0x10000000 -j (\S+)$`)
	var m []string
	for _, c := range re.FindAllStringSubmatch(script, -1) {
		if !strings.HasSuffix(c[1], MangleStageSuffix) {
			m = c
		}
	}
	if m == nil || m[1] != m[2] {
		t.Fatalf("no OUTPUT jump for the return bit:\n%s", script)
	}
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "-A "+m[1]+" ") {
			out = append(out, line)
		}
	}
	return m[1], out
}

// Sing-box's return traffic (HandoffReturnBit) must never reach the main table, whatever
// state mangle OUTPUT is in, and its OUTPUT jump must be one the kernel accepts with device-scoped
// lists in the plan (xt_mac is refused in a chain reachable from OUTPUT).
func TestHandoffReturnPathFailsClosed(t *testing.T) {
	p := dualLANProfile()
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "kids", Enabled: true, Outbound: "grp-awg31",
		Manual: []string{"198.18.0.0/24"}, ScopeMode: "only", ScopeGroups: []string{"kids"}})
	p.DeviceGroups = []model.DeviceGroup{{ID: "kids", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:01"}}}}
	pl, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	if !pl.Handoff().Active() {
		t.Fatal("no hand-off in the test plan")
	}
	io := handoffOptions()
	script := pl.RenderKeeneticScript(Options{}, io)
	if !strings.Contains(script, "-m mac --mac-source") {
		t.Fatal("the test plan has no device-scoped rule")
	}
	// 1. OUTPUT jumps to a chain of its own, which has no rule the OUTPUT hook refuses.
	ch, lines := outputChainLines(t, script)
	if ch == io.Chain || ch == "WR_PREROUTING" || len(lines) == 0 {
		t.Fatalf("OUTPUT jumps to %q with %d rules", ch, len(lines))
	}
	for _, l := range lines {
		if strings.Contains(l, "-m mac") || strings.Contains(l, " -i ") {
			t.Fatalf("a rule OUTPUT cannot carry: %q", l)
		}
	}
	// It classifies like the LAN chain: the overlap takes the stronger list's mark.
	sets := map[string]bool{"wr_list_cidr_refilter_4": true, "wr_list_rl_vpn_max_vk_4": true}
	refilter := markFor(t, pl, "list_cidr_refilter")
	if m := chainMark(t, strings.Join(lines, "\n"), sets); m&pl.Mask != refilter {
		t.Fatalf("return traffic classified %#x, want %#x", m, refilter)
	}
	// The jump an older plane put on the LAN chain goes before that chain is rewritten.
	legacy := "while iptables -t mangle -D OUTPUT -m mark --mark 0x10000000/0x10000000 -j WR_PREROUTING 2>/dev/null; do :; done\n"
	if i, r := strings.Index(script, legacy), strings.Index(script, "iptables_restore --noflush"); i < 0 || i > r {
		t.Fatalf("legacy OUTPUT jump removed @%d, LAN chain written @%d", i, r)
	}
	// 2. Routing: with the return bit and no plan mark (OUTPUT never ran: NDM wiped it, the jump was
	// refused) the packet ends in a table whose route is the loopback device; re-marked, the stronger
	// list's table takes it.
	rs := bsRules(t, script, false)
	g, _ := listEgressByTag(pl, "grp-awg31")
	up := map[string]bool{strconv.Itoa(g.Table): true, "408": true}
	dst := netip.MustParseAddr("172.64.41.4")
	if got := bsVerdict(rs, nil, up, "lo", HandoffReturnBit, dst); got != "drop" {
		t.Fatalf("unclassified return traffic: %s, want drop", got)
	}
	if got := bsVerdict(rs, nil, up, "lo", HandoffReturnBit|refilter, dst); got != "tunnel" {
		t.Fatalf("classified return traffic: %s, want tunnel", got)
	}
	mustContain(t, script, fmt.Sprintf("\nip route replace default dev lo table %d\n", HandoffReturnTable(Options{})))
	if got := bsVerdict(bsRules(t, script, true), nil, up, "lo", HandoffReturnBit, netip.MustParseAddr("2606:4700::1")); got != "drop" {
		t.Fatalf("v6 return traffic: %s, want drop", got)
	}
	// 3. Teardown takes the jump, the chain, the rule and the table.
	td := pl.RenderTeardownScript(Options{}, io)
	for _, want := range []string{
		"iptables -t mangle -D OUTPUT -m mark --mark 0x10000000/0x10000000 -j " + ch + " 2>/dev/null || true\n",
		"iptables -t mangle -X " + ch + " 2>/dev/null || true\n",
		fmt.Sprintf("ip route flush table %d 2>/dev/null || true\n", HandoffReturnTable(Options{})),
	} {
		mustContain(t, td, want)
	}
	// A replacement by the same plane retires none of it.
	if r := RetireProgram(td, script, pl.IpsetNames(io)); strings.Contains(r, ch) || strings.Contains(r, "table 409") {
		t.Fatalf("retiring the hand-off by the same plane undoes it:\n%s", r)
	}
}

// Until sing-box's wildcard bind is proven on a router, nothing fail-closed is handed off at all:
// a kill-switched list keeps every address it holds.
func TestHandoffNeverWithAFailClosedSide(t *testing.T) {
	p := dualLANProfile()
	p.Groups[0].KillSwitch = true
	p.Groups[1].KillSwitch = true
	p.RoutingLists[2].Outbound = "grp-list-cascade" // the IP-check list through a kill-switched group
	pl, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Handoff().Pairs) != 0 {
		t.Fatalf("kill-switched lists handed off: %+v", pl.Handoff().Pairs)
	}
	fc := map[string]bool{}
	for _, e := range pl.Egresses {
		fc[e.Tag] = e.FailClosed
	}
	zoneFC := map[string]bool{}
	for _, z := range pl.Zones {
		zoneFC[z.Name] = fc[z.EgressTag]
	}
	for _, pr := range pl.Handoff().Pairs {
		if zoneFC[pr.Domain] || zoneFC[pr.Stronger] {
			t.Fatalf("a fail-closed side handed off: %+v", pr)
		}
	}
}
