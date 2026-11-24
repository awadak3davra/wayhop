package pbr

import (
	"strings"
	"testing"
)

func TestFastDNSENforcementGolden(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{
		DynamicDomainSets: true,
		FastDNSEnforce:    true,
		LANIfaces:         []string{"br1", "br0", "br1", "bad name"},
	}
	script := pl.RenderIptablesScript(io)
	for _, lan := range []string{"br0", "br1"} {
		for _, proto := range []string{"udp", "tcp"} {
			spec := "-i " + lan + " -p " + proto + " --dport 53 -j REDIRECT --to-ports 53"
			mustContain(t, script, "iptables -t nat -C PREROUTING "+spec+" 2>/dev/null || iptables -t nat -A PREROUTING "+spec+"\n")
		}
		spec := "-i " + lan + " -p tcp --dport 853 -j REJECT --reject-with tcp-reset"
		mustContain(t, script, "iptables -C FORWARD "+spec+" 2>/dev/null || iptables -I FORWARD "+spec+"\n")
	}
	if strings.Contains(script, "bad name") || strings.Contains(script, "--dport 443") {
		t.Fatalf("fast enforcement has an invalid interface or an unrequested DoH rule:\n%s", script)
	}
	if got := strings.Count(script, FastFilterSectionEnd); got != 1 || strings.Contains(script, FilterSectionEnd) {
		t.Fatalf("fast filter section markers = %d, want 1 and no legacy one", got)
	}
	// IPv6: forwarded DNS and DoT refused (the router's own resolver is INPUT), before the section end.
	for _, lan := range []string{"br0", "br1"} {
		for _, spec := range []string{
			"-i " + lan + " -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
			"-i " + lan + " -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
			"-i " + lan + " -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		} {
			line := "ip6tables -C FORWARD " + spec + " 2>/dev/null || ip6tables -I FORWARD " + spec + "\n"
			mustContain(t, script, line)
			if strings.Index(script, line) > strings.Index(script, FastFilterSectionEnd) {
				t.Fatalf("v6 refusal after the filter section end:\n%s", script)
			}
		}
	}
	if strings.Index(script, "-i br0 -p udp --dport 53 -j REDIRECT") > strings.Index(script, "-i br1 -p udp --dport 53 -j REDIRECT") {
		t.Fatalf("LAN interfaces are not stable and sorted:\n%s", script)
	}

	teardown := pl.RenderTeardownScript(Options{}, io)
	for _, lan := range []string{"br0", "br1"} {
		for _, r := range append(dnsFastRedirectRules(lan), dnsDoTRejectRule(lan)) {
			mustContain(t, teardown, IptablesDeleteEveryCopy(r.table, r.chain, r.spec))
		}
		for _, r := range dnsV6RefuseRules(lan) {
			mustContain(t, teardown, "while ip6tables -D FORWARD "+r.spec+" 2>/dev/null; do :; done\n")
		}
	}
}

func TestFastDNSENforcementWithLegacyInterceptDoesNotDuplicate(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{
		FastDNSEnforce: true, LANIfaces: []string{"br0", "br1"},
		DNSIntercept: true, DNSInterceptLAN: "br0", DNSRejectEncrypted: true,
	}
	script := pl.RenderIptablesScript(io)
	if got := strings.Count(script, "iptables -C FORWARD -i br0 -p tcp --dport 853 "); got != 1 {
		t.Fatalf("br0 DoT rules = %d, want 1:\n%s", got, script)
	}
	if got := strings.Count(script, "iptables -t nat -C PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 "); got != 1 {
		t.Fatalf("br0 udp redirects = %d, want 1 (no addrtype: KeeneticOS lacks xt_addrtype):\n%s", got, script)
	}
	if strings.Contains(script, "addrtype") {
		t.Fatalf("addrtype match rendered:\n%s", script)
	}
	mustContain(t, script, "-i br0 -p tcp -d 1.1.1.1 --dport 443 -j REJECT")
	mustContain(t, script, "-i br1 -p tcp --dport 853 -j REJECT")
}

func TestFastDNSOptionOffPreservesLegacyBytes(t *testing.T) {
	pl := dynamicDomainTestPlan()
	legacy := IpsetOptions{
		DNSIntercept: true, DNSInterceptLAN: "br0", DNSRejectEncrypted: true,
	}
	withLANs := legacy
	withLANs.LANIfaces = []string{"br0", "br1"}
	withLANs.FastDNSEnforce = false
	if got, want := pl.RenderKeeneticScript(Options{}, withLANs), pl.RenderKeeneticScript(Options{}, legacy); got != want {
		t.Fatalf("captured LANs changed non-enforced output:\n%s\nwant\n%s", got, want)
	}
	if got, want := pl.RenderTeardownScript(Options{}, withLANs), pl.RenderTeardownScript(Options{}, legacy); got != want {
		t.Fatalf("captured LANs changed non-enforced teardown:\n%s\nwant\n%s", got, want)
	}
}

// Fast enforcement's rules sit inside the suspension block, in both sections; legacy rules do not.
func TestFastDNSEnforcementSuspendable(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{FastDNSEnforce: true, LANIfaces: []string{"br0"}, DNSIntercept: true, DNSInterceptLAN: "br1", DNSRejectEncrypted: true}
	script := pl.RenderIptablesScript(io)
	if got := strings.Count(script, fastDNSOpenIf); got != 2 || strings.Count(script, fastDNSOpenFi) < 2 {
		t.Fatalf("suspension blocks = %d:\n%s", got, script)
	}
	open := false
	for _, line := range strings.Split(script, "\n") {
		switch {
		case line+"\n" == fastDNSOpenIf:
			open = true
		case line+"\n" == fastDNSOpenFi:
			open = false
		case strings.Contains(line, "--dport 443"):
			if open {
				t.Fatalf("a legacy DoH refusal is suspendable: %s", line)
			}
		case strings.Contains(line, "-i br0 -p udp --dport 53 -j REDIRECT") || strings.HasPrefix(line, "ip6tables -C FORWARD"):
			if !open {
				t.Fatalf("a fast rule outside the block: %s", line)
			}
		}
	}
	if strings.Contains(pl.RenderIptablesScript(IpsetOptions{DNSIntercept: true, DNSInterceptLAN: "br1", DNSRejectEncrypted: true}), FastDNSOpenFlag) {
		t.Fatal("the legacy program carries the suspension flag")
	}
}
