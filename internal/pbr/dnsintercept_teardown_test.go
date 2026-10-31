package pbr

import (
	"regexp"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// dnsTeardownProfile exercises every built-in chain the Keenetic script writes: a kernel tunnel
// (WAN-fallback MASQUERADE and TCPMSS), a v6 list (the ip6tables chain), a domain list and an NDM
// policy slot.
func dnsTeardownProfile() *model.Profile {
	p := ndmPolicyProfile()
	p.Endpoints = append(p.Endpoints, model.Endpoint{ID: "awg", Engine: model.EngineExternal, Enabled: true,
		Server: "192.0.2.10", Params: map[string]any{"interface": "awg1"}})
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "v6", Enabled: true, Outbound: "awg", Manual: []string{"2001:db8::/32", "203.0.113.0/24"}},
		model.RoutingList{ID: "names", Enabled: true, Outbound: "awg", Manual: []string{"example.com"}})
	return p
}

// iptablesAddRE finds the add half of a script line: `<ipt> [-t T] -A|-I CHAIN SPEC`, either the whole
// line or the part after a `-C ... ||` check.
var iptablesAddRE = regexp.MustCompile(`(?:^|\|\| )(iptables|ip6tables)((?: -t \S+)?) -(?:A|I) (\S+) (.*)$`)

// QA-114: the teardown left the DNS redirect and the encrypted-DNS refusals in place, so turning
// interception off, leaving the kernel plane or switching routing off kept hijacking clients' DNS.
// Every rule the script can add must have its delete: rules in a chain NDM owns by an exact -D, rules
// in the plane's own chain by the flush and delete of that chain.
func TestKeeneticTeardownDeletesEveryRuleTheScriptAdds(t *testing.T) {
	plan, _, err := Compile(dnsTeardownProfile(), Options{NDMPolicies: ndmPolicyMarks, CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	// Not br0: the teardown must use the interface the script was rendered for.
	io := IpsetOptions{S86Mark: 0x250, MasqDevices: []string{"wr_a"},
		DNSIntercept: true, DNSInterceptLAN: "br7", DNSRejectEncrypted: true}
	script := plan.RenderIptablesScript(io)
	down := plan.RenderTeardownScript(Options{}, io)

	dnsRules, chains := 0, map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		m := iptablesAddRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ipt, table, chain, spec := m[1], m[2], m[3], m[4]
		chains[ipt+table+" "+chain] = true
		if chain == "WR_PREROUTING" {
			for _, want := range []string{ipt + " -t mangle -F " + chain, ipt + " -t mangle -X " + chain} {
				if !strings.Contains(down, want) {
					t.Errorf("the script fills %s but the teardown never runs %q", chain, want)
				}
			}
			continue
		}
		del := ipt + table + " -D " + chain + " " + spec
		if !strings.Contains(down, del) {
			t.Errorf("the script adds a rule the teardown never deletes:\n  %s\nwant %q", line, del)
			continue
		}
		if strings.Contains(spec, "--dport 53 ") || strings.Contains(spec, "-j REJECT") {
			dnsRules++
			// A lock race or an older build can have added it twice; one -D would leave the other.
			if loop := "while " + del + " 2>/dev/null; do :; done\n"; !strings.Contains(down, loop) {
				t.Errorf("the teardown deletes %q once, not every copy", del)
			}
		}
	}
	// 2 redirects, DoT and one refusal per well-known DoH address.
	if want := 3 + len(WellKnownDoHEndpoints); dnsRules != want {
		t.Errorf("checked %d DNS interception rules, want %d:\n%s", dnsRules, want, script)
	}
	for _, c := range []string{"iptables -t mangle PREROUTING", "ip6tables -t mangle PREROUTING", "iptables -t nat POSTROUTING",
		"iptables -t nat PREROUTING", "iptables FORWARD", "iptables -t mangle FORWARD", "iptables -t mangle WR_PREROUTING"} {
		if !chains[c] {
			t.Errorf("the plan never adds to %s, so the symmetry is not checked there (saw %v)", c, chains)
		}
	}
	if strings.Contains(down, " br0 ") {
		t.Errorf("the teardown assumed br0 for a plane rendered on br7:\n%s", down)
	}
}

// The teardown that runs is the PREVIOUS plane's, and the rules on the router may have come from a
// plane before it, so the deletes cannot depend on this plane's own switches.
func TestKeeneticTeardownRemovesDNSRulesWhateverTheSwitches(t *testing.T) {
	plan := teardownPlan()
	on := plan.RenderTeardownScript(Options{}, IpsetOptions{DNSIntercept: true, DNSInterceptLAN: "br0", DNSRejectEncrypted: true})
	for _, io := range []IpsetOptions{
		{DNSInterceptLAN: "br0"},
		{DNSInterceptLAN: "br0", DNSIntercept: true},
		{DNSInterceptLAN: "br0", DNSRejectEncrypted: true},
	} {
		if got := plan.RenderTeardownScript(Options{}, io); got != on {
			t.Errorf("teardown with %+v differs from the one with both switches on:\n%s\nwant:\n%s", io, got, on)
		}
	}
	mustContain(t, on, "while iptables -t nat -D PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done\n")
	mustContain(t, on, "while iptables -D FORWARD -i br0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null; do :; done\n")
	// No interface recorded: the script could not have installed anything to delete.
	if none := plan.RenderTeardownScript(Options{}, IpsetOptions{}); strings.Contains(none, "--dport 53") || strings.Contains(none, "REJECT") {
		t.Errorf("a teardown with no LAN interface deletes DNS rules on a guessed one:\n%s", none)
	}
}

// QA-115: the refusals are filter-table rules, so the script carries them as a section of their own at
// the top, closed by FilterSectionEnd, where a filter:iptables run of the hook stops before the mangle
// flush and rebuild.
func TestKeeneticScriptPutsTheRefusalsInAFilterSectionFirst(t *testing.T) {
	plan := teardownPlan()
	io := IpsetOptions{DNSIntercept: true, DNSInterceptLAN: "br0", DNSRejectEncrypted: true}
	script := plan.RenderIptablesScript(io)
	head, rest, found := strings.Cut(script, FilterSectionEnd)
	if !found {
		t.Fatalf("no filter section end in:\n%s", script)
	}
	lines := strings.Split(strings.TrimSuffix(head, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "# ") {
		t.Errorf("the section should open with a comment for whoever reads the hook: %q", lines[0])
	}
	if got, want := len(lines)-1, 1+len(WellKnownDoHEndpoints); got != want {
		t.Errorf("filter section has %d rules, want %d:\n%s", got, want, head)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "iptables -C FORWARD -i br0 -p tcp ") || !strings.Contains(line, " || iptables -I FORWARD ") {
			t.Errorf("not a filter FORWARD refusal: %q", line)
		}
	}
	if strings.Contains(rest, "FORWARD -i br0") || strings.Contains(rest, FilterSectionEnd) {
		t.Errorf("a refusal or a second section end after the filter section:\n%s", rest)
	}
	mustContain(t, rest, "iptables -t mangle -F WR_PREROUTING\n")
	mustContain(t, rest, "iptables -t nat -C PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || ")
}

// The fix must not touch a plane without the refusals: with interception off, or on without the
// refusals, the script is byte for byte what it was, whatever LAN interface is recorded for the
// teardown. The redirect lines are spelled out as the renderer wrote them before the fix.
func TestKeeneticScriptWithoutRefusalsIsUnchanged(t *testing.T) {
	plan := teardownPlan()
	plain := plan.RenderIptablesScript(IpsetOptions{})
	for _, io := range []IpsetOptions{
		{DNSInterceptLAN: "br0"},
		{DNSInterceptLAN: "br0", DNSRejectEncrypted: true}, // the gated switch alone installs nothing
	} {
		if got := plan.RenderIptablesScript(io); got != plain {
			t.Errorf("script with %+v differs from the plain one:\n%s\nwant:\n%s", io, got, plain)
		}
	}
	if strings.Contains(plain, FilterSectionEnd) || strings.Contains(plain, "#") {
		t.Errorf("a plain script gained a filter section:\n%s", plain)
	}
	redirect := plan.RenderIptablesScript(IpsetOptions{DNSIntercept: true, DNSInterceptLAN: "br0"})
	want := plain
	for _, proto := range []string{"udp", "tcp"} {
		want += "iptables -t nat -C PREROUTING -i br0 -p " + proto + " --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || " +
			"iptables -t nat -A PREROUTING -i br0 -p " + proto + " --dport 53 -j REDIRECT --to-ports 53\n"
	}
	// teardownPlan has no kernel tunnel, so nothing (TCPMSS) follows the redirect.
	if redirect != want {
		t.Errorf("interception without the refusals changed shape:\n%s\nwant:\n%s", redirect, want)
	}
}
