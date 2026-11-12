package pbr

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// unpinTestPlan: a tunnel egress whose list names an office range and a supernet of the LAN, a WAN
// (direct) list naming a private range, and a v6 ULA site.
func unpinTestPlan() *Plan {
	return &Plan{
		Table: "wayhop_pbr", Mask: 0x00ff0000,
		Egresses: []Egress{
			{Tag: model.OutboundDirect, Kind: EgressWAN, Table: 254},
			{Tag: "office", Kind: EgressInterface, Iface: "awg0", Mark: 0x00010000, Table: 151},
		},
		Zones: []Zone{
			{Name: "list_office", EgressTag: "office", Mark: 0x00010000,
				V4: []string{"1.2.3.0/24", "10.77.0.0/16", "192.168.0.0/16"}, V6: []string{"fd12:3456::/48"}},
			{Name: "list_home", EgressTag: model.OutboundDirect, V4: []string{"172.16.9.0/24"}},
		},
	}
}

// ipRuleSim evaluates the `ip [-6] rule add` lines of one family against a main table holding a
// connected LAN route and a default route, the way the kernel walks the rule list.
type ipRuleSim struct {
	pref     int
	to       netip.Prefix
	mark     uint32
	mask     uint32
	table    string
	suppress bool
}

func parseIPRules(t *testing.T, cmds []string, v6 bool) []ipRuleSim {
	t.Helper()
	prefix := "ip rule add "
	if v6 {
		prefix = "ip -6 rule add "
	}
	var out []ipRuleSim
	for _, c := range cmds {
		if !strings.HasPrefix(c, prefix) {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(c, prefix))
		var r ipRuleSim
		for i := 0; i+1 < len(f); i += 2 {
			switch f[i] {
			case "to":
				r.to = netip.MustParsePrefix(f[i+1])
			case "fwmark":
				mm := strings.SplitN(f[i+1], "/", 2)
				m, _ := strconv.ParseUint(mm[0], 0, 32)
				k, _ := strconv.ParseUint(mm[1], 0, 32)
				r.mark, r.mask = uint32(m), uint32(k)
			case "lookup", "table":
				r.table = f[i+1]
			case "suppress_prefixlength":
				r.suppress = f[i+1] == "0"
			case "priority":
				r.pref, _ = strconv.Atoi(f[i+1])
			default:
				t.Fatalf("unparsed selector %q in %q", f[i], c)
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].pref < out[j].pref })
	return out
}

// route returns "main:<prefix>" or "table:<n>" for a packet; the tables a fwmark rule names hold a
// default route, so they always answer.
func routeSim(rules []ipRuleSim, mainTable []netip.Prefix, dst netip.Addr, mark uint32) string {
	lookupMain := func(suppress bool) (string, bool) {
		best := netip.Prefix{}
		for _, p := range mainTable {
			if p.Contains(dst) && (!best.IsValid() || p.Bits() > best.Bits()) {
				best = p
			}
		}
		if !best.IsValid() || (suppress && best.Bits() == 0) {
			return "", false
		}
		return "main:" + best.String(), true
	}
	for _, r := range rules {
		if r.to.IsValid() && !r.to.Contains(dst) {
			continue
		}
		if r.mask != 0 && mark&r.mask != r.mark {
			continue
		}
		if r.table == "main" {
			if got, ok := lookupMain(r.suppress); ok {
				return got
			}
			continue
		}
		return "table:" + r.table
	}
	got, _ := lookupMain(false)
	return got
}

// TestListedPrivateDestinationLeavesThroughTheTunnel (RT-09): a private destination a list names is
// routed by its mark, not pinned to the main table's default route (the WAN); the router's own LAN
// prefix stays on main even inside a listed supernet; a private destination nothing names, and
// unmarked traffic, keep the pin.
func TestListedPrivateDestinationLeavesThroughTheTunnel(t *testing.T) {
	plan := unpinTestPlan()
	cmds := plan.RenderIP(Options{})
	const tunnel = 0x00010000
	cases := []struct {
		name  string
		v6    bool
		main  []string
		dst   string
		mark  uint32
		route string
	}{
		{"listed office range, marked", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "10.77.1.1", tunnel, "table:151"},
		{"listed range not on the LAN, marked", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "192.168.77.1", tunnel, "table:151"},
		{"LAN client inside a listed supernet, marked reply", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "192.168.1.50", tunnel, "main:192.168.1.0/24"},
		{"listed range, unmarked", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "10.77.1.1", 0, "main:0.0.0.0/0"},
		{"private range no list names, marked", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "10.99.0.1", tunnel, "main:0.0.0.0/0"},
		{"private range only a direct list names, marked", false, []string{"192.168.1.0/24", "0.0.0.0/0"}, "172.16.9.1", tunnel, "main:0.0.0.0/0"},
		{"listed ULA site, marked", true, []string{"fd00:1::/64", "::/0"}, "fd12:3456::1", tunnel, "table:151"},
		{"ULA LAN, marked reply", true, []string{"fd00:1::/64", "::/0"}, "fd00:1::50", tunnel, "main:fd00:1::/64"},
		{"link-local, marked", true, []string{"fd00:1::/64", "::/0"}, "fe80::1", tunnel, "main:::/0"},
	}
	for _, tc := range cases {
		var mainTable []netip.Prefix
		for _, p := range tc.main {
			mainTable = append(mainTable, netip.MustParsePrefix(p))
		}
		got := routeSim(parseIPRules(t, cmds, tc.v6), mainTable, netip.MustParseAddr(tc.dst), tc.mark)
		if got != tc.route {
			t.Errorf("%s: %s routed %s, want %s\n%s", tc.name, tc.dst, got, tc.route, strings.Join(cmds, "\n"))
		}
	}

	// The guard is installed before the rule it protects and removed after it.
	guard := "ip rule add to 10.77.0.0/16 lookup main suppress_prefixlength 0 priority 144"
	route := "ip rule add to 10.77.0.0/16 fwmark 0x00010000/0x00ff0000 table 151 priority 145"
	if gi, ri := indexOf(cmds, guard), indexOf(cmds, route); gi < 0 || ri < 0 || gi > ri {
		t.Errorf("guard must be added before its per-egress rule (guard %d, rule %d):\n%s", gi, ri, strings.Join(cmds, "\n"))
	}
	down := plan.RenderTeardown(Options{})
	gd := indexOf(down, strings.Replace(guard, " add ", " del ", 1))
	rd := indexOf(down, strings.Replace(route, " add ", " del ", 1))
	if gd < 0 || rd < 0 || rd > gd {
		t.Errorf("teardown must delete the per-egress rule before its guard (rule %d, guard %d):\n%s", rd, gd, strings.Join(down, "\n"))
	}

	// The KeeneticOS shell plane carries the same carve-out, the rules chained on the guard's add.
	script := plan.RenderIPScript(Options{})
	if !strings.Contains(script, guard+" && { "+route+"; }\n") {
		t.Errorf("shell plane must chain the per-egress rule on the guard:\n%s", script)
	}
	tdScript := plan.RenderTeardownScript(Options{}, IpsetOptions{})
	if !strings.Contains(tdScript, strings.Replace(route, " add ", " del ", 1)+" 2>/dev/null || true\n") {
		t.Errorf("shell teardown must remove the carve-out:\n%s", tdScript)
	}
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// TestUnpinnedPrivateNarrowsToTheOverlap: a supernet names each private range it covers and no
// more; a prefix inside another listed one adds nothing; public prefixes, WAN zones and access-policy
// zones add nothing.
func TestUnpinnedPrivateNarrowsToTheOverlap(t *testing.T) {
	plan := &Plan{
		Mask: 0x00ff0000,
		Egresses: []Egress{
			{Tag: model.OutboundDirect, Kind: EgressWAN, Table: 254},
			{Tag: "t", Kind: EgressInterface, Iface: "awg0", Mark: 0x00010000, Table: 151},
			{Tag: "block", Kind: EgressBlackhole, Mark: 0x00020000, Table: 152},
		},
		Zones: []Zone{
			{Name: "a", EgressTag: "t", V4: []string{"10.0.0.0/7", "10.77.0.0/16", "8.8.8.8/32"}},
			{Name: "b", EgressTag: "block", V4: []string{"192.168.50.7"}},
			{Name: "c", EgressTag: model.OutboundDirect, V4: []string{"172.16.0.0/12"}},
			{Name: "d", EgressTag: "ndm-policy:Policy0", NDMPolicy: "Policy0", V4: []string{"172.16.1.0/24"}},
		},
	}
	var got []string
	for _, p := range plan.UnpinnedPrivate() {
		got = append(got, p.String())
	}
	want := []string{"10.0.0.0/8", "192.168.50.7/32"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("UnpinnedPrivate = %v, want %v", got, want)
	}
}
