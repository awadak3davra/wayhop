package pbr

import (
	"strings"
	"testing"

	"velinx/internal/model"
)

// keeneticProfile: a domain list + an IP-CIDR list both routed to a failover group whose first
// kernel member is nwg1; two kernel endpoints (their server IPs become the anti-loop bypass).
func keeneticProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "netherlands", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}},
			{ID: "nd_vps", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.2", Params: map[string]any{"interface": "nwg0"}},
		},
		Groups: []model.Group{
			{ID: "failover_with_wan", Type: model.GroupURLTest, Members: []string{"netherlands", "nd_vps", model.OutboundDirect}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "youtube", Enabled: true, Outbound: "failover_with_wan", Manual: []string{"youtube.com", "*.youtu.be"}},
			{ID: "iplist", Enabled: true, Outbound: "failover_with_wan", Manual: []string{"149.154.160.0/20"}},
		},
	}
}

func TestKeeneticRender_DomainAndIPZones(t *testing.T) {
	p := keeneticProfile()
	plan, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	io := IpsetOptions{S86Mark: 0x250}

	// --- ipset restore: domain set has timeout, IP set has the static CIDR, bypass has servers.
	restore := plan.RenderIpsetRestore(io)
	mustContain(t, restore, "create wr_list_youtube_4 hash:net family inet")
	if !strings.Contains(restore, "wr_list_youtube_4") || !strings.Contains(restore, "timeout 86400") {
		t.Errorf("domain set must be created with a timeout:\n%s", restore)
	}
	mustContain(t, restore, "add wr_list_iplist_4 149.154.160.0/20 -exist")
	mustContain(t, restore, "create wr_bypass_4 hash:net")
	mustContain(t, restore, "add wr_bypass_4 203.0.113.1")
	mustContain(t, restore, "add wr_bypass_4 198.51.100.2")
	if strings.Contains(restore, "add wr_list_youtube_4 youtube.com") {
		t.Error("domain set must NOT get static domain members — dnsmasq populates it")
	}

	// --- dnsmasq: ipset= directive maps the domains to the domain set.
	dq := plan.DnsmasqIpsetConfig(io, 1024)
	mustContain(t, dq, "ipset=/youtu.be/youtube.com/wr_list_youtube_4") // normalizeDomains sorts + strips *.
	if strings.Contains(dq, "iplist") {
		t.Error("IP-only list must NOT appear in the dnsmasq ipset config")
	}

	// --- iptables: bypass RETURN first, S86 guard, MARK both sets, CONNMARK save, jump.
	ipt := plan.RenderIptablesScript(io)
	mustContain(t, ipt, "iptables -t mangle -N WR_PREROUTING")
	mustContain(t, ipt, "-m set --match-set wr_bypass_4 dst -j RETURN")
	mustContain(t, ipt, "-m mark --mark 0x00000250/0xffffffff -j RETURN")
	mustContain(t, ipt, "-m set --match-set wr_list_youtube_4 dst -j MARK --set-xmark")
	mustContain(t, ipt, "-m set --match-set wr_list_iplist_4 dst -j MARK --set-xmark")
	mustContain(t, ipt, "-j CONNMARK --save-mark")
	mustContain(t, ipt, "-C PREROUTING -j WR_PREROUTING")

	// both zones route to the SAME group → SAME mark.
	yMark := markFor(t, plan, "list_youtube")
	iMark := markFor(t, plan, "list_iplist")
	if yMark != iMark {
		t.Errorf("zones to the same group must share a mark: youtube=%#x iplist=%#x", yMark, iMark)
	}
	if yMark&^plan.Mask != 0 {
		t.Errorf("zone mark %#x must fit the plan mask %#x", yMark, plan.Mask)
	}
	if yMark == 0x250 {
		t.Error("WR egress mark must not collide with S86's 0x250")
	}

	// --- ip rule/route: fwmark→table→nwg1 (the group's first kernel member), SEEDED add-not-replace
	// so a hook re-assert never clobbers the failover cron's elected egress.
	ipc := plan.RenderIPScript(Options{})
	mustContain(t, ipc, "ip rule add fwmark")
	mustContain(t, ipc, "ip route add default dev nwg1 table 151 2>/dev/null || true")

	// --- teardown removes the sets + chain + rules.
	td := plan.RenderTeardownScript(Options{}, io)
	mustContain(t, td, "ipset destroy wr_list_youtube_4")
	mustContain(t, td, "iptables -t mangle -D PREROUTING -j WR_PREROUTING")
	mustContain(t, td, "ip route flush table 151")
}

// firstTokenAfter returns the first whitespace token following verb at the start of each line.
func firstTokenAfter(script, verb string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), verb); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				out[f[0]] = true
			}
		}
	}
	return out
}

// restAfter returns the remainder after verb (minus the trailing `2>/dev/null || true` guard).
func restAfter(script, verb string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), " 2>/dev/null || true")
		if rest, ok := strings.CutPrefix(line, verb); ok {
			out[strings.TrimSpace(rest)] = true
		}
	}
	return out
}

// TestApplyTeardownSymmetry: every kernel SET the apply creates is destroyed by the teardown and
// vice versa, and every `ip rule add` has a matching `ip rule del` — so a rollback or re-deploy can
// never leave orphaned ipsets or routing rules. Locks RenderIpsetRestore against IpsetNames (the
// teardown's source) across v4, v6, domain, and bypass sets.
func TestApplyTeardownSymmetry(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "netherlands", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}},
			{ID: "nd_vps", Engine: model.EngineExternal, Enabled: true, Server: "2001:db8::2", Params: map[string]any{"interface": "nwg0"}},
		},
		Groups: []model.Group{
			{ID: "failover_with_wan", Type: model.GroupURLTest, Members: []string{"netherlands", "nd_vps", model.OutboundDirect}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "youtube", Enabled: true, Outbound: "failover_with_wan", Manual: []string{"youtube.com"}},
			{ID: "iplist", Enabled: true, Outbound: "failover_with_wan", Manual: []string{"149.154.160.0/20", "2a00:1450::/32"}},
		},
	}
	plan, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	io := IpsetOptions{S86Mark: 0x250}

	created := firstTokenAfter(plan.RenderIpsetRestore(io), "create ")
	destroyed := firstTokenAfter(plan.RenderTeardownScript(Options{}, io), "ipset destroy ")
	if len(created) == 0 {
		t.Fatal("plan created no sets — the test is not exercising anything")
	}
	sawV6 := false
	for n := range created {
		if strings.HasSuffix(n, "_6") {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Error("test plan must create at least one v6 set so the symmetry is checked for v6 too")
	}
	for n := range created {
		if !destroyed[n] {
			t.Errorf("apply creates set %q but the teardown never destroys it (orphan on rollback)", n)
		}
	}
	for n := range destroyed {
		if !created[n] {
			t.Errorf("teardown destroys set %q the apply never creates", n)
		}
	}

	addRules := restAfter(plan.RenderIPScript(Options{}), "ip rule add ")
	delRules := restAfter(plan.RenderTeardownScript(Options{}, io), "ip rule del ")
	if len(addRules) == 0 {
		t.Fatal("plan added no ip rules — the test is not exercising anything")
	}
	for r := range addRules {
		if !delRules[r] {
			t.Errorf("apply adds ip rule %q but the teardown never deletes it", r)
		}
	}
}

// CollectDomainZones=false (the OpenWrt path) must still drop domains to warnings (unchanged).
// TestKeeneticRender_SourceScoped covers the iptables/ipset source twin: a source-scoped zone
// gets a per-family `_s4` source set (created + populated + torn down), and its mangle MARK rule
// carries the cartesian source matches (`-i`, `-m mac --mac-source`, `-p tcp/udp -m multiport
// --sports`, `--match-set <s> src`) alongside the dest set. The compiler builds the zone on the
// nft plane (Options{}); the iptables renderer reads the same plan.
func TestKeeneticRender_SourceScoped(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "dev", IPCIDR: []string{"8.8.8.0/24"}, SourceIPCIDR: []string{"192.168.1.50/32"},
				SourceIface: []string{"br-guest"}, SourceMAC: []string{"aa:bb:cc:dd:ee:ff"}, SourcePort: []int{443}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	io := IpsetOptions{}
	restore := plan.RenderIpsetRestore(io)
	if !strings.Contains(restore, "create wr_rule_dev_s4 hash:net family inet") {
		t.Errorf("missing source set creation:\n%s", restore)
	}
	if !strings.Contains(restore, "add wr_rule_dev_s4 192.168.1.50/32") {
		t.Errorf("source set not populated:\n%s", restore)
	}
	ipt := plan.RenderIptablesScript(io)
	wantRule := "-i br-guest -m mac --mac-source aa:bb:cc:dd:ee:ff -p tcp -m multiport --sports 443 -m set --match-set wr_rule_dev_s4 src -m set --match-set wr_rule_dev_4 dst -j MARK"
	if !strings.Contains(ipt, wantRule) {
		t.Errorf("missing/wrong source MARK rule; want substring:\n%s\ngot:\n%s", wantRule, ipt)
	}
	// tcp + udp → two rules (multiport requires a proto).
	if c := strings.Count(ipt, "-m multiport --sports 443"); c != 2 {
		t.Errorf("want tcp+udp source-port rules (2), got %d:\n%s", c, ipt)
	}
	// Teardown must destroy the source set too.
	found := false
	for _, n := range plan.IpsetNames(io) {
		if n == "wr_rule_dev_s4" {
			found = true
		}
	}
	if !found {
		t.Errorf("IpsetNames must include the source set for teardown: %v", plan.IpsetNames(io))
	}
}

// TestKeeneticRender_SourceOnly: a source-only zone (no dest) emits a MARK rule with the source
// set but NO dst match. The bypass RETURN runs first so a peer-dst packet never reaches it — no
// nft-style re-assert is needed on the iptables plane.
func TestKeeneticRender_SourceOnly(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "devall", SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ipt := plan.RenderIptablesScript(IpsetOptions{})
	if !strings.Contains(ipt, "-m set --match-set wr_rule_devall_s4 src -j MARK") {
		t.Errorf("missing source-only MARK rule (src set, no dst):\n%s", ipt)
	}
	if strings.Contains(ipt, "wr_rule_devall_4 dst") {
		t.Errorf("source-only zone must carry no dst set:\n%s", ipt)
	}
	if c := strings.Count(ipt, "--match-set wr_bypass_4 dst -j RETURN"); c != 1 {
		t.Errorf("want exactly one bypass RETURN (no re-assert on iptables), got %d:\n%s", c, ipt)
	}
}

func TestKeeneticRender_DomainsOffByDefault(t *testing.T) {
	p := keeneticProfile()
	plan, warns, _ := Compile(p, Options{}) // CollectDomainZones not set
	for _, z := range plan.Zones {
		if len(z.Domains) > 0 {
			t.Errorf("without CollectDomainZones no zone may carry domains: %+v", z)
		}
	}
	// youtube (domain-only) becomes a warning, not a zone.
	var sawWarn bool
	for _, w := range warns {
		if strings.Contains(w.Msg, "non-IP") || strings.Contains(w.Scope, "youtube") {
			sawWarn = true
		}
	}
	if !sawWarn {
		t.Errorf("domain-only list should warn on the OpenWrt path; warns=%v", warns)
	}
}

func mustContain(t *testing.T, hay, needle string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("missing %q in:\n%s", needle, hay)
	}
}

func markFor(t *testing.T, pl *Plan, zoneName string) uint32 {
	t.Helper()
	for _, z := range pl.Zones {
		if z.Name == zoneName {
			return z.Mark
		}
	}
	t.Fatalf("zone %s not found", zoneName)
	return 0
}
