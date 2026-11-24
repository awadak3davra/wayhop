package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A rule's matchers are ANDed, and a zone carries only its IP and source parts. A rule that
// also names a domain or a destination port must build no zone at all; one built from its CIDRs alone
// routed every flow to those addresses, whatever the domain or port.
func TestCompile_ANDRuleWithUnexpressibleMatcherBuildsNoZone(t *testing.T) {
	ep := model.Endpoint{ID: "ext", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"}}
	for name, rule := range map[string]model.Rule{
		"ip and domain":   {ID: "r1", IPCIDR: []string{"198.51.100.0/24"}, Domain: []string{"example.com"}, Outbound: "ext"},
		"ip and suffix":   {ID: "r1", IPCIDR: []string{"198.51.100.0/24"}, DomainSuffix: []string{"example.com"}, Outbound: "ext"},
		"ip and port":     {ID: "r1", IPCIDR: []string{"198.51.100.0/24"}, Port: []int{443}, Outbound: "ext"},
		"ip and geoip":    {ID: "r1", IPCIDR: []string{"198.51.100.0/24"}, GeoIP: []string{"ru"}, Outbound: "ext"},
		"source and port": {ID: "r1", SourceIPCIDR: []string{"192.168.1.20/32"}, Port: []int{443}, Outbound: "ext"},
		"mac and domain":  {ID: "r1", SourceMAC: []string{"02:00:00:00:00:01"}, Domain: []string{"example.com"}, Outbound: "ext"},
	} {
		p := &model.Profile{Endpoints: []model.Endpoint{ep}, Rules: []model.Rule{rule}}
		pl, warns, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("%s: Compile: %v", name, err)
		}
		if pl != nil && len(pl.Zones) != 0 {
			t.Errorf("%s: zones = %+v, want none", name, pl.Zones)
		}
		if len(warns) == 0 {
			t.Errorf("%s: no warning that the rule stays off the kernel plane", name)
		}
	}
	// The IP-only rule still becomes a zone.
	p := &model.Profile{Endpoints: []model.Endpoint{ep},
		Rules: []model.Rule{{ID: "r1", IPCIDR: []string{"198.51.100.0/24"}, Outbound: "ext"}}}
	pl, _, err := Compile(p, Options{})
	if err != nil || pl == nil || len(pl.Zones) != 1 {
		t.Fatalf("IP-only rule: plan=%+v err=%v, want one zone", pl, err)
	}
}

// The postcheck reads `ip rule` and names each rule the program adds that the kernel lacks.
func TestMissingIPRules(t *testing.T) {
	script := "ip rule del to 10.0.0.0/8 lookup main priority 147 2>/dev/null || true\n" +
		"ip rule add to 10.0.0.0/8 lookup main priority 147\n" +
		"ip rule add to 192.0.2.7/32 lookup main priority 146\n" +
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150\n" +
		"ip rule add fwmark 0x00050000 type blackhole priority 149\n" +
		"ip -6 rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150\n" +
		"ip route add default dev awg1 table 151 2>/dev/null || true\n"
	v4 := "0:\tfrom all lookup local\n" +
		"146:\tfrom all to 192.0.2.7 lookup main\n" +
		"147:\tfrom all to 10.0.0.0/8 lookup main\n" +
		"149:\tfrom all fwmark 0x50000 blackhole\n" +
		"150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n" +
		"32766:\tfrom all lookup main\n"
	v6 := "150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n"
	if got := MissingIPRules(script, v4, v6, true); len(got) != 0 {
		t.Fatalf("healthy dumps: missing = %q", got)
	}
	if got := MissingIPRules(script, v4, "", false); len(got) != 0 {
		t.Fatalf("v6 unknown must not be judged: missing = %q", got)
	}
	if got := MissingIPRules(script, v4, "", true); len(got) != 1 || !strings.HasPrefix(got[0], "ip -6 rule add fwmark") {
		t.Fatalf("v6 rule gone: missing = %q", got)
	}
	for name, damaged := range map[string]string{
		"fwmark rule gone":     strings.Replace(v4, "150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n", "", 1),
		"wrong table":          strings.Replace(v4, "lookup 151", "lookup 152", 1),
		"wrong priority":       strings.Replace(v4, "147:\tfrom all to 10.0.0.0/8", "148:\tfrom all to 10.0.0.0/8", 1),
		"blackhole gone":       strings.Replace(v4, "149:\tfrom all fwmark 0x50000 blackhole\n", "", 1),
		"host exclude changed": strings.Replace(v4, "to 192.0.2.7 ", "to 192.0.2.8 ", 1),
	} {
		if got := MissingIPRules(script, damaged, v6, true); len(got) != 1 {
			t.Errorf("%s: missing = %q, want exactly one", name, got)
		}
	}
}

// The dump format of BusyBox ip on a live KeeneticOS 5.x router (19.11.2026): blackhole rules
// read "lookup unspec blackhole", a full mask is omitted, named tables print by name. Reading it wrong
// would report every rule missing and make supervision reinstall the plane on every tick.
func TestMissingIPRules_KeeneticBusyBoxDump(t *testing.T) {
	script := "ip rule add to 10.0.0.0/8 lookup main priority 147\n" +
		"ip rule add to 172.16.0.0/12 lookup main priority 148\n" +
		"ip rule add to 192.168.0.0/16 lookup main priority 149\n" +
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150\n" +
		"ip rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151\n" +
		"ip rule add fwmark 0x0ffffaac type blackhole priority 146\n" +
		"ip -6 rule add to fc00::/7 lookup main priority 148\n" +
		"ip -6 rule add fwmark 0x00030000/0x00ff0000 table 152 priority 151\n"
	v4 := "0:\tfrom all lookup local \n" +
		"10:\tfrom all fwmark 0xffffa00 lookup main \n" +
		"100:\tfrom all fwmark 0xffffaac lookup 4100 \n" +
		"101:\tfrom all fwmark 0xffffaac lookup unspec blackhole\n" +
		"146:\tfrom all fwmark 0xffffaac lookup unspec blackhole\n" +
		"147:\tfrom all to 10.0.0.0/8 lookup main \n" +
		"148:\tfrom all to 172.16.0.0/12 lookup main \n" +
		"149:\tfrom all to 192.168.0.0/16 lookup main \n" +
		"150:\tfrom all fwmark 0x20000/0xff0000 lookup 151 \n" +
		"151:\tfrom all fwmark 0x30000/0xff0000 lookup 152 \n" +
		"2160:\tfrom 172.20.91.28 lookup 16389 \n" +
		"32766:\tfrom all lookup main \n"
	v6 := "0:\tfrom all lookup local \n" +
		"148:\tfrom all to fc00::/7 lookup main \n" +
		"151:\tfrom all fwmark 0x30000/0xff0000 lookup 152 \n" +
		"2186:\tfrom all lookup 16402 \n"
	if got := MissingIPRules(script, v4, v6, true); len(got) != 0 {
		t.Fatalf("live dump: missing = %q", got)
	}
	gone := strings.Replace(v4, "146:\tfrom all fwmark 0xffffaac lookup unspec blackhole\n", "", 1)
	if got := MissingIPRules(script, gone, v6, true); len(got) != 1 || !strings.Contains(got[0], "blackhole") {
		t.Fatalf("backstop gone: missing = %q", got)
	}
}

// Entries the previous restore stream added and the target's no longer does are deleted, and
// nothing the target keeps is.
func TestIpsetRestoreRemovals(t *testing.T) {
	prev := "create wr_rule_a_4 hash:net family inet hashsize 64 maxelem 1024 -exist\n" +
		"add wr_rule_a_4 198.51.100.0/24 -exist\n" +
		"add wr_rule_a_4 203.0.113.0/24 -exist\n" +
		"create wr_list_b_4 hash:net family inet hashsize 1024 maxelem 65536 timeout 3600 -exist\n" +
		"add wr_list_b_4 192.0.2.0/24 timeout 0 -exist\n"
	target := "create wr_rule_a_4 hash:net family inet hashsize 64 maxelem 1024 -exist\n" +
		"add wr_rule_a_4 198.51.100.0/24 -exist\n" +
		"create wr_list_b_4 hash:net family inet hashsize 1024 maxelem 65536 timeout 3600 -exist\n"
	got := IpsetRestoreRemovals(prev, target)
	want := "del wr_rule_a_4 203.0.113.0/24 -exist\ndel wr_list_b_4 192.0.2.0/24 -exist\n"
	if got != want {
		t.Fatalf("removals =\n%s\nwant\n%s", got, want)
	}
	if got := IpsetRestoreRemovals(target, target); got != "" {
		t.Fatalf("unchanged stream: removals = %q, want none", got)
	}
}
