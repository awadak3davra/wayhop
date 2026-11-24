package pbr

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Kill switch audit, "NDM rebuild window": between KeeneticOS rebuilding netfilter and its hook
// putting the mangle chain back nothing is marked. These tests follow packets through the RENDERED
// ip rules with the backstop table holding the plan's kill-switched destinations.

const (
	bsLAN  = "br0"
	bsLAN2 = "br1"
)

func backstopProfile() *model.Profile {
	p := keeneticProfile()
	p.Groups[0].KillSwitch = true
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "203.0.113.0/25", "203.0.113.128/25", "2001:67c:4e8::/48")
	// A direct list overlapping the kill-switched one, emitted after it: its mark wins there.
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "ru", Enabled: true, Outbound: model.OutboundDirect, Manual: []string{"149.154.167.99/32"}},
		// A device-scoped kill-switched list: other devices reach these directly by design.
		model.RoutingList{ID: "scoped", Enabled: true, Outbound: "failover_with_wan", Manual: []string{"198.18.0.0/24"},
			ScopeMode: "only", ScopeGroups: []string{"kids"}},
	)
	p.DeviceGroups = []model.DeviceGroup{{ID: "kids", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:01"}}}}
	return p
}

func backstopPlan(t *testing.T) *Plan {
	t.Helper()
	pl, _, err := Compile(backstopProfile(), Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func bsOptions() IpsetOptions { return IpsetOptions{LANIfaces: []string{bsLAN2, bsLAN, bsLAN}} }

type bsRule struct {
	pref       int
	iif        string
	hasMark    bool
	mark, mask uint32
	to         netip.Prefix
	table      string
	blackhole  bool
	// unreachable: a rule of that type (refuses at connect, never routes on).
	unreachable bool
}

// bsRules reads the final (not best-effort) `ip [-6] rule add` lines of a program.
func bsRules(t *testing.T, script string, v6 bool) []bsRule {
	t.Helper()
	prefix := "ip rule add "
	if v6 {
		prefix = "ip -6 rule add "
	}
	var out []bsRule
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, prefix) || strings.Contains(line, "||") || strings.Contains(line, "&&") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, prefix))
		var r bsRule
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "iif":
				i++
				r.iif = f[i]
			case "fwmark":
				i++
				m, k, _ := strings.Cut(f[i], "/")
				mv, _ := strconv.ParseUint(m, 0, 32)
				kv := uint64(0xffffffff)
				if k != "" {
					kv, _ = strconv.ParseUint(k, 0, 32)
				}
				r.hasMark, r.mark, r.mask = true, uint32(mv), uint32(kv)
			case "to":
				i++
				r.to = netip.MustParsePrefix(f[i])
			case "table", "lookup":
				i++
				r.table = f[i]
			case "type":
				i++
				if f[i] != "blackhole" {
					t.Fatalf("unmodelled rule type %q in %q", f[i], line)
				}
				r.blackhole = true
			case "blackhole":
				t.Fatalf("bare %q is refused by BusyBox ip 1.37, use \"type blackhole\": %q", f[i], line)
			case "unreachable":
				r.unreachable = true
			case "priority":
				i++
				r.pref, _ = strconv.Atoi(f[i])
			default:
				t.Fatalf("unmodelled selector %q in %q", f[i], line)
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].pref < out[j].pref })
	return out
}

// bsVerdict routes one packet: "drop", "tunnel" (an egress table with its route) or "main" (WAN).
// populated says which egress tables still hold their tunnel route.
func bsVerdict(rules []bsRule, backstop []netip.Prefix, populated map[string]bool, iif string, mark uint32, dst netip.Addr) string {
	backstopTable := strconv.Itoa(BackstopTable(Options{}))
	for _, r := range rules {
		if r.iif != "" && r.iif != iif {
			continue
		}
		if r.hasMark && mark&r.mask != r.mark {
			continue
		}
		if r.to.IsValid() && !r.to.Contains(dst) {
			continue
		}
		switch {
		case r.blackhole:
			return "drop"
		case r.table == "main" || r.table == "254":
			return "main"
		case r.table == strconv.Itoa(HandoffReturnTable(Options{})):
			return "drop" // its only route is the loopback device: delivered to nothing
		case r.unreachable:
			return "drop"
		case r.table == backstopTable:
			for _, p := range backstop {
				if p.Contains(dst) {
					return "drop"
				}
			}
		case populated[r.table]:
			return "tunnel"
		}
	}
	return "main"
}

func TestKillSwitchBackstopCollectsOnlyWholeLANZones(t *testing.T) {
	pl := backstopPlan(t)
	bs := pl.KillSwitchBackstop(IpsetOptions{})
	// 203.0.113.0/25 + 203.0.113.128/25 aggregate into one /24; the direct list's /32 inside the /20 and
	// the scoped list stay out.
	if want := []netip.Prefix{netip.MustParsePrefix("149.154.160.0/20"), netip.MustParsePrefix("203.0.113.0/24")}; !slices.Equal(bs.V4, want) {
		t.Fatalf("v4 = %v, want %v", bs.V4, want)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("2001:67c:4e8::/48")}; !slices.Equal(bs.V6, want) {
		t.Fatalf("v6 = %v, want %v", bs.V6, want)
	}
	if !slices.Equal(bs.Sets4, []string{"wr_list_youtube_4"}) || !slices.Equal(bs.Sets6, []string{"wr_list_youtube_6"}) {
		t.Fatalf("domain sets = %v %v", bs.Sets4, bs.Sets6)
	}
	// No kill switch, no backstop.
	p := backstopProfile()
	p.Groups[0].KillSwitch = false
	off, _, _ := Compile(p, Options{CollectDomainZones: true})
	if off.KillSwitchBackstop(IpsetOptions{}).Active() {
		t.Fatal("a backstop without a kill switch")
	}
}

func TestAggregatePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"), netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.7/32"), netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.3.0/24"), netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("2001:db8::/33"), netip.MustParsePrefix("2001:db8:8000::/33"),
	}
	got := AggregatePrefixes(in)
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::/32")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if in[0] != netip.MustParsePrefix("10.0.1.0/24") {
		t.Fatal("input modified")
	}
}

// The backstop's rules come before the mangle chain is rewritten, in both families, and every one is
// rewritten make-before-break.
func TestKillSwitchBackstopBeforeMarks(t *testing.T) {
	pl := backstopPlan(t)
	script := pl.RenderKeeneticScript(Options{}, bsOptions())
	mark := strings.Index(script, "iptables_restore --noflush")
	for _, fam := range []string{"ip", "ip -6"} {
		for _, ifc := range []string{bsLAN, bsLAN2} {
			for _, m := range []string{"0x00000000/0x00ff0000", "0x00ff0000/0x00ff0000"} {
				spec := fmt.Sprintf("iif %s fwmark %s table 407", ifc, m)
				stage := strings.Index(script, fam+" rule add "+spec+" priority 139 2>/dev/null || true\n")
				del := strings.Index(script, "while "+fam+" rule del "+spec+" priority 140 2>/dev/null; do :; done\n")
				add := strings.Index(script, "\n"+fam+" rule add "+spec+" priority 140\n")
				drop := strings.Index(script, "while "+fam+" rule del "+spec+" priority 139 2>/dev/null; do :; done\n")
				if stage < 0 || !(stage < del && del < add && add < drop && drop < mark) {
					t.Fatalf("%s %s: stage@%d del@%d add@%d dropstage@%d marks@%d\n%s", fam, spec, stage, del, add, drop, mark, script)
				}
			}
		}
	}
	if strings.Count(script, "iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 140\n") != 2 {
		t.Fatal("a LAN interface listed twice rendered twice")
	}
	// No LAN interface known: no rules, and the plan says it needs one.
	if strings.Contains(pl.RenderKeeneticScript(Options{}, IpsetOptions{}), "table 407") || !pl.BackstopNeedsLAN(IpsetOptions{}) {
		t.Fatal("backstop without LAN interfaces")
	}
}

// The verdicts the operator's rule asks for, with the mangle chain gone (every packet unmarked by
// WayHop), and in steady state.
func TestKillSwitchBackstopVerdicts(t *testing.T) {
	pl := backstopPlan(t)
	script := pl.RenderKeeneticScript(Options{}, bsOptions())
	bs := pl.KillSwitchBackstop(bsOptions())
	g, _ := listEgressByTag(pl, "failover_with_wan")
	wan, _ := listEgressByTag(pl, model.OutboundDirect)
	up := map[string]bool{strconv.Itoa(g.Table): true}
	ndmMark := uint32(0x0ffffaac)
	in := netip.MustParseAddr("203.0.113.7")
	overlap := netip.MustParseAddr("149.154.167.99")
	scoped := netip.MustParseAddr("198.18.0.5")
	other := netip.MustParseAddr("93.184.216.34")
	in6 := netip.MustParseAddr("2001:67c:4e8::1")
	for _, c := range []struct {
		name      string
		v6        bool
		iif       string
		mark      uint32
		dst       netip.Addr
		populated map[string]bool
		want      string
	}{
		{"window: LAN, unmarked, kill-switched dst", false, bsLAN, 0, in, up, "drop"},
		{"window: second LAN segment", false, bsLAN2, 0, in, up, "drop"},
		{"window: device in an NDM access policy", false, bsLAN, ndmMark, in, up, "drop"},
		{"window: v6", true, bsLAN, 0, in6, up, "drop"},
		{"window: the router's own probe (iif lo)", false, "lo", 0, in, up, "main"},
		{"window: a tunnel's own traffic (iif lo)", true, "lo", 0, in6, up, "main"},
		{"window: inbound from the WAN", false, "eth3", 0, in, up, "main"},
		{"window: an unlisted destination", false, bsLAN, 0, other, up, "main"},
		{"window: a device-scoped list's destination", false, bsLAN, 0, scoped, up, "main"},
		{"steady: marked, tunnel up", false, bsLAN, g.Mark, in, up, "tunnel"},
		{"steady: marked, tunnel down", false, bsLAN, g.Mark, in, nil, "drop"},
		{"steady: overlap won by the direct list", false, bsLAN, wan.Mark, overlap, up, "main"},
	} {
		if got := bsVerdict(bsRules(t, script, c.v6), append(append([]netip.Prefix(nil), bs.V4...), bs.V6...), c.populated, c.iif, c.mark, c.dst); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// Every backstop rule names a LAN interface: none can match the router's own traffic.
func TestKillSwitchBackstopNeverCatchesRouterTraffic(t *testing.T) {
	pl := backstopPlan(t)
	io := bsOptions()
	io.LANIfaces = append(io.LANIfaces, "bad name", "")
	script := pl.RenderKeeneticScript(Options{}, io)
	n := 0
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, " table 407") || !strings.Contains(line, " rule ") {
			continue
		}
		n++
		if !strings.Contains(line, " iif "+bsLAN+" ") && !strings.Contains(line, " iif "+bsLAN2+" ") {
			t.Fatalf("backstop rule without a LAN iif: %q", line)
		}
	}
	if n == 0 {
		t.Fatal("no backstop rules")
	}
}

// MissingIPRules reads the backstop rule back in BusyBox's dump shape, so a refused rule fails Apply.
func TestMissingIPRules_Backstop(t *testing.T) {
	script := "ip rule add iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 451\n" +
		"ip rule add iif br0 fwmark 0x00ff0000/0x00ff0000 table 407 priority 451\n" +
		"ip rule add iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 452 2>/dev/null || true\n"
	dump := "0:\tfrom all lookup local \n" +
		"451:\tfrom all iif br0 fwmark 0/0xff0000 lookup 407 \n" +
		"451:\tfrom all iif br0 fwmark 0xff0000/0xff0000 lookup 407 \n" +
		"32766:\tfrom all lookup main \n"
	if got := MissingIPRules(script, dump, "", false); len(got) != 0 {
		t.Fatalf("present rules reported missing: %q", got)
	}
	for name, damaged := range map[string]string{
		"refused":       strings.Replace(dump, "451:\tfrom all iif br0 fwmark 0/0xff0000 lookup 407 \n", "", 1),
		"other iif":     strings.Replace(dump, "iif br0 fwmark 0/", "iif br1 fwmark 0/", 1),
		"no iif at all": strings.Replace(dump, "iif br0 fwmark 0/", "fwmark 0/", 1),
	} {
		if got := MissingIPRules(script, damaged, "", false); len(got) != 1 {
			t.Errorf("%s: missing = %q, want one", name, got)
		}
	}
}

// Teardown removes the backstop; a replaced plane keeps it while the next plan still kill-switches
// and takes it away (after its own program ran) once it does not.
func TestKillSwitchBackstopRetire(t *testing.T) {
	pl := backstopPlan(t)
	io := bsOptions()
	td := pl.RenderTeardownScript(Options{}, io)
	for _, want := range []string{
		"while ip rule del iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 140 2>/dev/null; do :; done\n",
		"while ip -6 rule del iif br1 fwmark 0x00ff0000/0x00ff0000 table 407 priority 139 2>/dev/null; do :; done\n",
		"ip route flush table 407 2>/dev/null || true\n",
		"ip -6 route flush table 407 2>/dev/null || true\n",
	} {
		mustContain(t, td, want)
	}
	same := pl.RenderKeeneticScript(Options{}, io)
	if r := RetireProgram(td, same, pl.IpsetNames(io)); strings.Contains(r, "table 407") || strings.Contains(r, "WR_PREROUTING") ||
		strings.Contains(r, "ipset destroy") || strings.Contains(r, "rule del") {
		t.Fatalf("retiring a plane by the same plane undoes it:\n%s", r)
	}
	p := backstopProfile()
	p.Groups[0].KillSwitch = false
	off, _, _ := Compile(p, Options{CollectDomainZones: true})
	r := RetireProgram(td, off.RenderKeeneticScript(Options{}, io), off.IpsetNames(io))
	mustContain(t, r, "while ip rule del iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 140 2>/dev/null; do :; done\n")
	mustContain(t, r, "ip route flush table 407 2>/dev/null || true\n")
	if strings.Contains(r, "-D PREROUTING -j WR_PREROUTING ") || strings.Contains(r, "-X WR_PREROUTING ") {
		t.Fatalf("the next plane's chain is taken down:\n%s", r)
	}
}

// A kill-switched domain list's names are asked of the sing-box listener alone.
func TestDnsmasqKillSwitchServerPins(t *testing.T) {
	pl := backstopPlan(t)
	if !pl.KillSwitchDomains() {
		t.Fatal("kill-switched domain list not reported")
	}
	io := IpsetOptions{KillSwitchDNS: "127.0.0.1#5353"}
	conf := pl.DnsmasqIpsetConfig(io, 1024)
	mustContain(t, conf, "ipset=/youtu.be/youtube.com/wr_list_youtube_4,wr_list_youtube_6\n")
	mustContain(t, conf, "server=/youtu.be/youtube.com/127.0.0.1#5353\n")
	if strings.Index(conf, "server=") < strings.Index(conf, "ipset=") {
		t.Fatalf("pins before the sets:\n%s", conf)
	}
	// Batched like the ipset lines.
	if lines := strings.Count(pl.DnsmasqIpsetConfig(io, 40), "server=/"); lines != 2 {
		t.Fatalf("server lines at 40 bytes = %d", lines)
	}
	if strings.Contains(pl.DnsmasqIpsetConfig(IpsetOptions{}, 1024), "server=") {
		t.Fatal("a pin without a listener")
	}
	p := backstopProfile()
	p.Groups[0].KillSwitch = false
	off, _, _ := Compile(p, Options{CollectDomainZones: true})
	if off.KillSwitchDomains() || strings.Contains(off.DnsmasqIpsetConfig(io, 1024), "server=") {
		t.Fatal("pinned names without a kill switch")
	}
}

func TestRetireProgramAndReflush(t *testing.T) {
	prev := "ip route replace blackhole default metric 1000 table 151 2>/dev/null || true\n" +
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150\n" +
		"ip route add default dev nwg1 table 151 2>/dev/null || true\n" +
		"ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151\n" +
		"ip route add default dev nwg0 table 152 2>/dev/null || true\n" +
		"ip -6 rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150\n" +
		"ip -6 route add default dev nwg1 table 151 2>/dev/null || true\n"
	next := strings.Replace(strings.Replace(prev, "dev nwg1 table 151", "dev nwg5 table 151", 1),
		"ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151\nip route add default dev nwg0 table 152 2>/dev/null || true\n", "", 1)
	got := ReflushTables(prev, next)
	if !slices.Equal(got, []string{"ip route flush table 151 2>/dev/null || true"}) {
		t.Fatalf("reflush = %q (v6 151 unchanged, 152 gone from the next plane)", got)
	}
	teardown := "iptables() { /opt/sbin/xtables-multi iptables -w \"$@\"; }\n" +
		"while iptables -t mangle -D PREROUTING -j WR_PREROUTING 2>/dev/null; do :; done\n" +
		"iptables -t mangle -F WR_PREROUTING 2>/dev/null || true\n" +
		"while iptables -t mangle -D PREROUTING -j WR_PREROUTING_S 2>/dev/null; do :; done\n" +
		"iptables -t mangle -X WR_PREROUTING_S 2>/dev/null || true\n" +
		"iptables -t nat -D POSTROUTING -o eth3 -m mark --mark 0x00030000/0x00ff0000 -j MASQUERADE 2>/dev/null || true\n" +
		"ip rule del fwmark 0x00020000/0x00ff0000 table 151 priority 150 2>/dev/null || true\n" +
		"ip route flush table 151 2>/dev/null || true\n" +
		"ip rule del fwmark 0x00030000/0x00ff0000 table 152 priority 151 2>/dev/null || true\n" +
		"ip route flush table 152 2>/dev/null || true\n" +
		"ipset destroy wr_list_a_4 2>/dev/null || true\n" +
		"ipset destroy wr_list_gone_4 2>/dev/null || true\n"
	nextScript := next + "iptables -t mangle -C PREROUTING -j WR_PREROUTING 2>/dev/null || iptables -t mangle -A PREROUTING -j WR_PREROUTING\n"
	r := RetireProgram(teardown, nextScript, []string{"wr_list_a_4"})
	want := "iptables() { /opt/sbin/xtables-multi iptables -w \"$@\"; }\n" +
		"iptables -t nat -D POSTROUTING -o eth3 -m mark --mark 0x00030000/0x00ff0000 -j MASQUERADE 2>/dev/null || true\n" +
		"ip rule del fwmark 0x00030000/0x00ff0000 table 152 priority 151 2>/dev/null || true\n" +
		"ip route flush table 152 2>/dev/null || true\n" +
		"ipset destroy wr_list_gone_4 2>/dev/null || true\n"
	if r != want {
		t.Fatalf("retire =\n%s\nwant\n%s", r, want)
	}
}

// liveNDMRules is `ip rule` on a KeeneticOS router with an access policy (NDM's rules at 100-109)
// and an older WayHop plane installed (its rules must not count as foreign).
const liveNDMRules = "0:\tfrom all lookup local\n" +
	"99:\tfrom all iif br0 fwmark 0/0xff0000 lookup 407\n" +
	"100:\tfrom all fwmark 0xffffaac lookup 42\n" +
	"101:\tfrom all fwmark 0xffffaac blackhole\n" +
	"141:\tfrom all fwmark 0x10000000/0x10ff0000 lookup 409\n" +
	"150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n" +
	"451:\tfrom all iif br0 fwmark 0/0xff0000 lookup 407\n" +
	"1000:\tfrom 192.0.2.10 lookup 50\n" +
	"32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n"

// NDM's policy rule routes a policy device's packet before a backstop placed after it,
// and the policy's table has a default route (a policy pinned to the provider): in the rebuild window
// a kill-switched destination left by it. The backstop is placed ahead of the lowest foreign rule the
// live rule list shows, never at a hardcoded NDM number.
func TestKillSwitchBackstopPrecedesNDMPolicyRules(t *testing.T) {
	if got := BackstopPrefFromRules(liveNDMRules, Options{}); got != 99 {
		t.Fatalf("pref from the live rules = %d, want 99 (ahead of NDM's 100)", got)
	}
	if got := BackstopPrefFromRules("0:\tfrom all lookup local\n451:\tfrom all iif br0 fwmark 0/0xff0000 lookup 407\n32766:\tfrom all lookup main\n", Options{}); got != 140 {
		t.Fatalf("pref without foreign rules = %d, want 140 (ahead of every WayHop rule)", got)
	}
	pl := backstopPlan(t)
	io := bsOptions()
	io.BackstopPref = BackstopPrefFromRules(liveNDMRules, Options{})
	script := pl.RenderKeeneticScript(Options{}, io)
	bs := pl.KillSwitchBackstop(io)
	ndmMark := uint32(0x0ffffaac)
	rules := append(bsRules(t, script, false), bsRule{pref: 100, hasMark: true, mark: ndmMark, mask: 0xffffffff, table: "42"})
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].pref < rules[j].pref })
	g, _ := listEgressByTag(pl, "failover_with_wan")
	up := map[string]bool{strconv.Itoa(g.Table): true, "42": true}
	ks := netip.MustParseAddr("203.0.113.7")
	if got := bsVerdict(rules, bs.V4, up, bsLAN, ndmMark, ks); got != "drop" {
		t.Fatalf("window, policy device, kill-switched destination: %s, want drop", got)
	}
	// Anything else of the policy device still goes by NDM's table.
	if got := bsVerdict(rules, bs.V4, up, bsLAN, ndmMark, netip.MustParseAddr("93.184.216.34")); got != "tunnel" {
		t.Fatalf("policy device, unlisted destination: %s, want NDM's table", got)
	}
}

// The backstop covers every interface traffic is forwarded from, not only the bridges:
// a VPN server's clients and a site-to-site tunnel's traffic (awg1) are held in the window as well.
func TestKillSwitchBackstopCoversForwardedTunnels(t *testing.T) {
	pl := backstopPlan(t)
	io := bsOptions()
	io.LANIfaces = append(io.LANIfaces, "awg1", "nwg0")
	script := pl.RenderKeeneticScript(Options{}, io)
	bs := pl.KillSwitchBackstop(io)
	ks := netip.MustParseAddr("203.0.113.7")
	for _, ifc := range []string{"awg1", "nwg0"} {
		if got := bsVerdict(bsRules(t, script, false), bs.V4, nil, ifc, 0, ks); got != "drop" {
			t.Errorf("window, forwarded from %s: %s, want drop", ifc, got)
		}
	}
	// A rule for one more interface, for the mirror to add when one appears after the Apply.
	extra := pl.BackstopRulesFor(Options{}, io, []string{"nwg9"})
	if !strings.Contains(extra, " iif nwg9 ") || strings.Contains(extra, " iif br0 ") {
		t.Fatalf("rules for a new interface:\n%s", extra)
	}
	if got := bsVerdict(bsRules(t, script+extra, false), bs.V4, nil, "nwg9", 0, ks); got != "drop" {
		t.Fatalf("an interface that appeared after the Apply: %s, want drop", got)
	}
}

// After a reboot the kernel sets do not exist, so the hook's marking chain was refused and
// nothing was marked, and table 407 stays empty until the daemon has converged. The program now (1)
// restores the plane's sets from the recorded restore file when one is missing, before anything names
// them, and (2) while the daemon has not yet filled the backstop since boot (no tmpfs stamp), holds
// every unmarked forwarded packet to a non-private destination with a default blackhole in table 407.
func TestKillSwitchBootRestoreAndHold(t *testing.T) {
	pl := backstopPlan(t)
	io := bsOptions()
	io.BootRestore = "/opt/etc/ndm/wayhop-policy.ipset"
	io.BackstopReady = "/tmp/wayhop-backstop.ready"
	script := pl.RenderKeeneticScript(Options{}, io)
	restore := strings.Index(script, "ipset restore -! < /opt/etc/ndm/wayhop-policy.ipset")
	list := strings.Index(script, "ipset list -n")
	firstSet := strings.Index(script, "--match-set ")
	if restore < 0 || list < 0 || list > restore || restore > firstSet {
		t.Fatalf("set restore @%d (list @%d), first set use @%d", restore, list, firstSet)
	}
	for _, n := range pl.IpsetNames(io) {
		if !strings.Contains(script[:restore], n) {
			t.Fatalf("set %s is not checked before the restore", n)
		}
	}
	guard := strings.Index(script, "[ -e /tmp/wayhop-backstop.ready ] || [ -e /tmp/wayhop-backstop.ready.lifted ] || {")
	hold := strings.Index(script, "ip route replace blackhole default table 407")
	hold6 := strings.Index(script, "ip -6 route replace blackhole default table 407")
	rule := strings.Index(script, "\nip rule add iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority")
	if guard < 0 || !(guard < hold && hold < rule) || hold6 < 0 {
		t.Fatalf("hold guard @%d hold @%d v6 @%d first backstop rule @%d", guard, hold, hold6, rule)
	}
	// The throws and the blackhole are one chain, CGNAT and link-local are exempt.
	for _, x := range append(holdExcludes4, holdShared4...) {
		mustContain(t, script, "ip route replace throw "+x+" table 407 && ")
	}
	for _, x := range privateExcludesV6(Options{RulePref: 150}) {
		mustContain(t, script, "ip -6 route replace throw "+x.CIDR+" table 407 && ")
	}
	mustContain(t, script, "ip route replace blackhole default table 407; } 2>/dev/null ||\n")
	// Without a kill switch nothing is held; without a restore file nothing is restored.
	p := backstopProfile()
	p.Groups[0].KillSwitch = false
	off, _, _ := Compile(p, Options{CollectDomainZones: true})
	if s := off.RenderKeeneticScript(Options{}, io); strings.Contains(s, "blackhole default table 407") || !strings.Contains(s, "ipset restore -!") {
		t.Fatal("hold without a kill switch, or no restore for the marks")
	}
	if s := pl.RenderKeeneticScript(Options{}, bsOptions()); strings.Contains(s, "ipset restore") || strings.Contains(s, "default table 407") {
		t.Fatal("restore or hold rendered without their paths")
	}
	// The hold's route lines never make the backstop table one to reflush before a new program.
	v4only := "ip route replace blackhole default table 407 2>/dev/null || true\n"
	if got := ReflushTables(v4only, script); len(got) != 0 {
		t.Fatalf("the backstop table reflushed: %q", got)
	}
}
