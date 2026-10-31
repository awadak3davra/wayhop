package dnsaudit

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// prof builds a profile with one routing list and a DNS plane wired to it.
func prof(listOutbound, dnsDetour string, coverList bool) model.Profile {
	p := model.Profile{
		RoutingLists: []model.RoutingList{{
			ID: "list-1", Name: "Streaming", Outbound: listOutbound, Enabled: true,
		}},
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{
				{Tag: "tunnel-dns", Type: "https", Server: "dns.example", Detour: dnsDetour, Enabled: true},
				{Tag: "plain-dns", Type: "https", Server: "dns.public", Detour: "", Enabled: true},
			},
			Final: "plain-dns",
		},
	}
	if coverList {
		p.DNS.Rules = []model.DNSRule{{ID: "r1", RuleSets: []string{"list-1"}, Server: "tunnel-dns"}}
	}
	return p
}

// Direct DoH differs from the traffic exit, but the query remains encrypted on the WAN path.
func TestDetectAsymmetric_TunnelledTrafficWithDirectEncryptedDNS(t *testing.T) {
	got := DetectAsymmetric(prof("vpn-nl", "", true), Plane{})

	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if !got[0].Exposed {
		t.Error("the resolver still observes the query from a different source exit")
	}
	if !got[0].Encrypted {
		t.Error("https DNS must be identified as encrypted")
	}
	if got[0].TrafficVia != "vpn-nl" || got[0].DNSVia != "" {
		t.Errorf("unexpected paths: %+v", got[0])
	}
}

func TestDetectAsymmetric_TunnelledTrafficWithDirectPlaintextDNS(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.DNS.Servers[0].Type = "udp"
	got := DetectAsymmetric(p, Plane{})
	if len(got) != 1 || !got[0].Exposed {
		t.Fatalf("want one exposed finding, got %+v", got)
	}
	if got[0].Encrypted {
		t.Error("udp DNS must not be identified as encrypted")
	}
}

// Coherent config: both planes use the same tunnel. Must be silent.
func TestDetectAsymmetric_CoherentIsSilent(t *testing.T) {
	if got := DetectAsymmetric(prof("vpn-nl", "vpn-nl", true), Plane{}); len(got) != 0 {
		t.Errorf("DNS and traffic agree; nothing to report: %+v", got)
	}
}

// Both direct is also coherent — "" and "direct" mean the same thing and must not be treated as a
// mismatch, or every default profile would report a false finding.
func TestDetectAsymmetric_DirectAndEmptyAreEquivalent(t *testing.T) {
	for _, pair := range [][2]string{{"", "direct"}, {"direct", ""}, {"", ""}, {"direct", "direct"}} {
		if got := DetectAsymmetric(prof(pair[0], pair[1], true), Plane{}); len(got) != 0 {
			t.Errorf("outbound %q + detour %q both mean direct; got %+v", pair[0], pair[1], got)
		}
	}
}

// Two different tunnels: not an exposure, but still worth reporting — a geo-targeted answer from one
// exit may not match the other.
func TestDetectAsymmetric_DifferentTunnelsReportedButNotExposed(t *testing.T) {
	got := DetectAsymmetric(prof("vpn-nl", "vpn-cy", true), Plane{})
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if got[0].Exposed {
		t.Error("both paths are tunnelled, so the lookup is not exposed; only the exits disagree")
	}
}

// DNS through a tunnel while traffic goes direct: reported, not exposed.
func TestDetectAsymmetric_TunnelledDNSWithDirectTrafficIsNotExposed(t *testing.T) {
	got := DetectAsymmetric(prof("", "vpn-nl", true), Plane{})
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if got[0].Exposed {
		t.Error("the lookup is protected here; it is the answer's usefulness that is in question")
	}
}

// An uncovered list falls through to `final`. That is a deliberate default, so it is reported ONLY
// when it reproduces the same exposure: tunnelled traffic, directly-resolved default.
func TestDetectAsymmetric_UncoveredListFallsThroughToFinal(t *testing.T) {
	got := DetectAsymmetric(prof("vpn-nl", "vpn-nl", false), Plane{}) // no DNS rule covers the list
	if len(got) != 1 {
		t.Fatalf("tunnelled traffic falling through to a direct default is the same exposure: %+v", got)
	}
	if !got[0].Exposed {
		t.Error("must be marked exposed")
	}

	// Direct traffic falling through to a direct default is simply consistent.
	if q := DetectAsymmetric(prof("", "vpn-nl", false), Plane{}); len(q) != 0 {
		t.Errorf("direct traffic with a direct default is coherent: %+v", q)
	}
}

// A blocked list never sends traffic anywhere, so it cannot be asymmetric.
func TestDetectAsymmetric_BlockedListIgnored(t *testing.T) {
	p := prof("block", "", true)
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("a blocked list routes nothing: %+v", got)
	}
}

// A disabled list, a disabled DNS rule, and a disabled DNS plane must all be ignored rather than
// judged — reporting configuration that is switched off trains people to ignore the report.
func TestDetectAsymmetric_DisabledThingsAreIgnored(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.RoutingLists[0].Enabled = false
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("a disabled list is not applied: %+v", got)
	}

	p = prof("vpn-nl", "", true)
	p.DNS.Enabled = false
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("a disabled DNS plane emits nothing to be inconsistent with: %+v", got)
	}

	p = prof("vpn-nl", "vpn-nl", true)
	p.DNS.Rules[0].Disabled = true // now uncovered → falls through to the direct default
	if got := DetectAsymmetric(p, Plane{}); len(got) != 1 || !got[0].Exposed {
		t.Errorf("a disabled DNS rule means the list falls through to `final`: %+v", got)
	}
}

// A rule that REJECTS a domain never resolves it, so there is no lookup to be asymmetric.
func TestDetectAsymmetric_RejectRuleIsNotAsymmetric(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.DNS.Rules[0].Server = "reject"
	// The default resolver dials direct, so a list that fell through to it would be reported. The
	// reject rule matches first and answers every lookup for the list, so none falls through. This
	// used to clear `final` to get its silence, which only hid that the rule was never counted.
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("a rejected domain is never resolved: %+v", got)
	}
	// Narrowed to AAAA, the rule leaves the A lookups to the default resolver: that is reported.
	p.DNS.Rules[0].QueryType = []string{"AAAA"}
	if got := DetectAsymmetric(p, Plane{}); len(got) != 1 || got[0].DNSServerTag != "plain-dns" {
		t.Errorf("an AAAA-only reject leaves A lookups to the default resolver: %+v", got)
	}
}

// sing-box 1.12 ORs domain and domain_suffix with a rule_set's own domain matches
// (route/rule/rule_abstract.go), so they widen a rule rather than narrow it: a reject rule with both
// still rejects every name in the list, and none of them falls through. geosite is ANDed with the
// lists (the generator wraps them in a logical AND), so it does narrow.
func TestDetectAsymmetric_RejectWidenedByDomainStillClaimsTheList(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.DNS.Rules[0].Server = "reject"
	p.DNS.Rules[0].DomainSuffix = []string{"example.com"}
	p.DNS.Rules[0].Domain = []string{"www.example.net"}
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("{list, domain_suffix, domain} rejects the whole list: %+v", got)
	}
	p.DNS.Rules[0].GeoSite = []string{"netflix"}
	if got := DetectAsymmetric(p, Plane{}); len(got) != 1 || got[0].DNSServerTag != "plain-dns" {
		t.Errorf("{list AND geosite} rejects only the list's names in that geosite: %+v", got)
	}
}

// Without TUN the generator drops a FakeIP server and the rules that target it, while the DNS page
// still shows the rule. The finding names that rule and why it is left out instead of saying no rule
// covers the list.
func TestDetectAsymmetric_DroppedFakeIPRuleIsNamed(t *testing.T) {
	p := prof("vpn-nl", "vpn-nl", false)
	p.DNS.Servers = append(p.DNS.Servers, model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	p.DNS.Rules = []model.DNSRule{{ID: "r1", RuleSets: []string{"list-1"}, Server: "fake"}}
	got := DetectAsymmetric(p, Plane{})
	if len(got) != 1 {
		t.Fatalf("the list falls through to plain-dns, which resolves directly: %+v", got)
	}
	d := got[0].Detail
	if strings.Contains(d, "no DNS rule covers") || !strings.Contains(d, `FakeIP server "fake"`) || !strings.Contains(d, "needs TUN") {
		t.Errorf("the finding must name the FakeIP rule and say FakeIP needs TUN: %q", d)
	}
	// A rule with no FakeIP behind it still reads as uncovered.
	p.DNS.Rules = nil
	if got := DetectAsymmetric(p, Plane{}); len(got) != 1 || !strings.Contains(got[0].Detail, "no DNS rule covers this list") {
		t.Errorf("an uncovered list says so: %+v", got)
	}
}

// Each way the default is chosen reads as one sentence that says once who answers and that it
// resolves directly, not a chain of "which" clauses.
func TestDetectAsymmetric_FallThroughDetailReads(t *testing.T) {
	for _, final := range []string{"plain-dns", "", "fake"} {
		p := prof("vpn-nl", "vpn-nl", false)
		p.DNS.Servers = []model.DNSServer{
			{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true},
			{Tag: "plain-dns", Type: "udp", Server: "192.0.2.53", Enabled: true},
		}
		p.DNS.Final = final
		got := DetectAsymmetric(p, Plane{})
		if len(got) != 1 {
			t.Fatalf("final %q: plain-dns answers the uncovered list directly: %+v", final, got)
		}
		if d := got[0].Detail; strings.Count(d, "which") > 0 || strings.Count(d, "resolve") != 1 {
			t.Errorf("final %q: %q", final, d)
		}
	}
}

// QA-105. With no `final`, sing-box answers unmatched lookups with the first server it creates. An
// empty final used to skip the uncovered-list check altogether, so a plaintext `local` first server
// answered a tunnelled list with no finding, while naming it as final was reported.
func TestDetectAsymmetric_EmptyFinalIsTheFirstEmittedServer(t *testing.T) {
	p := prof("vpn-nl", "vpn-nl", false)
	p.DNS.Servers = append([]model.DNSServer{{Tag: "dns_local", Type: "local", Enabled: true}}, p.DNS.Servers...)
	p.DNS.Final = ""
	got := DetectAsymmetric(p, Plane{})
	if len(got) != 1 || got[0].DNSServerTag != "dns_local" || !got[0].Exposed || got[0].Encrypted {
		t.Fatalf("the first server answers the uncovered list in plaintext, directly: %+v", got)
	}
	// A disabled server is never emitted, so the next one answers: through the list's tunnel here.
	p.DNS.Servers[0].Enabled = false
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("tunnel-dns answers once dns_local is off, and it rides the list's tunnel: %+v", got)
	}
}

// QA-106. A fakeip server sends no lookup anywhere, so a rule pointing a list at it is not a direct
// plaintext resolver. Without TUN the generator drops the server and its rules, so the list is
// judged by where its lookups fall through to.
func TestDetectAsymmetric_FakeIPRule(t *testing.T) {
	p := prof("vpn-nl", "vpn-nl", false)
	p.DNS.Servers = append(p.DNS.Servers, model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	p.DNS.Rules = []model.DNSRule{{ID: "r1", RuleSets: []string{"list-1"}, Server: "fake"}}
	p.DNS.Final = "tunnel-dns"
	if got := DetectAsymmetric(p, Plane{TUN: true}); len(got) != 0 {
		t.Errorf("TUN: the fakeip rule answers the list and sends nothing: %+v", got)
	}
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("no TUN: the list falls through to tunnel-dns, which rides its tunnel: %+v", got)
	}
	p.DNS.Final = "plain-dns" // direct
	if got := DetectAsymmetric(p, Plane{}); len(got) != 1 || got[0].DNSServerTag != "plain-dns" {
		t.Errorf("no TUN: the fall-through to a direct default is reported as before: %+v", got)
	}
	// A fakeip final without TUN is left out by the generator, so the first server answers.
	p.DNS.Final = "fake"
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("no TUN: with the fakeip final dropped, tunnel-dns (first) answers through the tunnel: %+v", got)
	}
	if got := DetectAsymmetric(p, Plane{TUN: true}); len(got) != 0 {
		t.Errorf("TUN: the fakeip final answers and sends nothing: %+v", got)
	}
}

// A nil DNS plane is a pre-DNS profile and must not produce findings.
func TestDetectAsymmetric_NilDNSPlane(t *testing.T) {
	p := model.Profile{RoutingLists: []model.RoutingList{{ID: "l", Outbound: "vpn", Enabled: true}}}
	if got := DetectAsymmetric(p, Plane{}); len(got) != 0 {
		t.Errorf("no DNS plane, nothing to compare: %+v", got)
	}
}

// Every finding must explain itself; a bare pair of tunnel names is not actionable.
func TestDetectAsymmetric_FindingsExplainThemselves(t *testing.T) {
	for _, c := range [][2]string{{"vpn-nl", ""}, {"", "vpn-nl"}, {"vpn-nl", "vpn-cy"}} {
		for _, f := range DetectAsymmetric(prof(c[0], c[1], true), Plane{}) {
			if f.Detail == "" || f.RoutingListID == "" {
				t.Errorf("incomplete finding: %+v", f)
			}
		}
	}
}
