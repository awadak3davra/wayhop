package dnsaudit

import (
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
	got := DetectAsymmetric(prof("vpn-nl", "", true))

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
	got := DetectAsymmetric(p)
	if len(got) != 1 || !got[0].Exposed {
		t.Fatalf("want one exposed finding, got %+v", got)
	}
	if got[0].Encrypted {
		t.Error("udp DNS must not be identified as encrypted")
	}
}

// Coherent config: both planes use the same tunnel. Must be silent.
func TestDetectAsymmetric_CoherentIsSilent(t *testing.T) {
	if got := DetectAsymmetric(prof("vpn-nl", "vpn-nl", true)); len(got) != 0 {
		t.Errorf("DNS and traffic agree; nothing to report: %+v", got)
	}
}

// Both direct is also coherent — "" and "direct" mean the same thing and must not be treated as a
// mismatch, or every default profile would report a false finding.
func TestDetectAsymmetric_DirectAndEmptyAreEquivalent(t *testing.T) {
	for _, pair := range [][2]string{{"", "direct"}, {"direct", ""}, {"", ""}, {"direct", "direct"}} {
		if got := DetectAsymmetric(prof(pair[0], pair[1], true)); len(got) != 0 {
			t.Errorf("outbound %q + detour %q both mean direct; got %+v", pair[0], pair[1], got)
		}
	}
}

// Two different tunnels: not an exposure, but still worth reporting — a geo-targeted answer from one
// exit may not match the other.
func TestDetectAsymmetric_DifferentTunnelsReportedButNotExposed(t *testing.T) {
	got := DetectAsymmetric(prof("vpn-nl", "vpn-cy", true))
	if len(got) != 1 {
		t.Fatalf("want one finding, got %+v", got)
	}
	if got[0].Exposed {
		t.Error("both paths are tunnelled, so the lookup is not exposed; only the exits disagree")
	}
}

// DNS through a tunnel while traffic goes direct: reported, not exposed.
func TestDetectAsymmetric_TunnelledDNSWithDirectTrafficIsNotExposed(t *testing.T) {
	got := DetectAsymmetric(prof("", "vpn-nl", true))
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
	got := DetectAsymmetric(prof("vpn-nl", "vpn-nl", false)) // no DNS rule covers the list
	if len(got) != 1 {
		t.Fatalf("tunnelled traffic falling through to a direct default is the same exposure: %+v", got)
	}
	if !got[0].Exposed {
		t.Error("must be marked exposed")
	}

	// Direct traffic falling through to a direct default is simply consistent.
	if q := DetectAsymmetric(prof("", "vpn-nl", false)); len(q) != 0 {
		t.Errorf("direct traffic with a direct default is coherent: %+v", q)
	}
}

// A blocked list never sends traffic anywhere, so it cannot be asymmetric.
func TestDetectAsymmetric_BlockedListIgnored(t *testing.T) {
	p := prof("block", "", true)
	if got := DetectAsymmetric(p); len(got) != 0 {
		t.Errorf("a blocked list routes nothing: %+v", got)
	}
}

// A disabled list, a disabled DNS rule, and a disabled DNS plane must all be ignored rather than
// judged — reporting configuration that is switched off trains people to ignore the report.
func TestDetectAsymmetric_DisabledThingsAreIgnored(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.RoutingLists[0].Enabled = false
	if got := DetectAsymmetric(p); len(got) != 0 {
		t.Errorf("a disabled list is not applied: %+v", got)
	}

	p = prof("vpn-nl", "", true)
	p.DNS.Enabled = false
	if got := DetectAsymmetric(p); len(got) != 0 {
		t.Errorf("a disabled DNS plane emits nothing to be inconsistent with: %+v", got)
	}

	p = prof("vpn-nl", "vpn-nl", true)
	p.DNS.Rules[0].Disabled = true // now uncovered → falls through to the direct default
	if got := DetectAsymmetric(p); len(got) != 1 || !got[0].Exposed {
		t.Errorf("a disabled DNS rule means the list falls through to `final`: %+v", got)
	}
}

// A rule that REJECTS a domain never resolves it, so there is no lookup to be asymmetric.
func TestDetectAsymmetric_RejectRuleIsNotAsymmetric(t *testing.T) {
	p := prof("vpn-nl", "", true)
	p.DNS.Rules[0].Server = "reject"
	p.DNS.Final = "" // no fall-through either
	if got := DetectAsymmetric(p); len(got) != 0 {
		t.Errorf("a rejected domain is never resolved: %+v", got)
	}
}

// A nil DNS plane is a pre-DNS profile and must not produce findings.
func TestDetectAsymmetric_NilDNSPlane(t *testing.T) {
	p := model.Profile{RoutingLists: []model.RoutingList{{ID: "l", Outbound: "vpn", Enabled: true}}}
	if got := DetectAsymmetric(p); len(got) != 0 {
		t.Errorf("no DNS plane, nothing to compare: %+v", got)
	}
}

// Every finding must explain itself; a bare pair of tunnel names is not actionable.
func TestDetectAsymmetric_FindingsExplainThemselves(t *testing.T) {
	for _, c := range [][2]string{{"vpn-nl", ""}, {"", "vpn-nl"}, {"vpn-nl", "vpn-cy"}} {
		for _, f := range DetectAsymmetric(prof(c[0], c[1], true)) {
			if f.Detail == "" || f.RoutingListID == "" {
				t.Errorf("incomplete finding: %+v", f)
			}
		}
	}
}
