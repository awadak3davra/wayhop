package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestProfileDNSNilByteIdentical is the backward-compat guarantee: a Profile with no DNS plane
// marshals WITHOUT a "dns" key (pointer + omitempty), so every existing profile is byte-identical.
func TestProfileDNSNilByteIdentical(t *testing.T) {
	p := Profile{
		Endpoints: []Endpoint{{ID: "nl", Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "\"dns\"") {
		t.Fatalf("a nil DNS plane must not emit a \"dns\" key, got: %s", b)
	}
	var back Profile
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.DNS != nil {
		t.Errorf("nil DNS must round-trip as nil, got %+v", back.DNS)
	}
}

// dnsBase builds a valid Profile skeleton (an enabled external endpoint, a failover group ending in
// direct, and a routing list) so DNS detours/rule_sets have something to resolve against.
func dnsBase(dns *DNSSettings) *Profile {
	return &Profile{
		Endpoints:    []Endpoint{{ID: "nl", Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
		Groups:       []Group{{ID: "grp", Members: []string{"nl", "direct"}}},
		RoutingLists: []RoutingList{{ID: "ru-list", Manual: []string{"example.ru"}, Outbound: "direct", Enabled: true}},
		DNS:          dns,
	}
}

// TestValidateDNS_DecoupledFromProfile: ValidateDNS gates on DNS-plane correctness ONLY — it accepts a
// valid DNS plane even when an unrelated part of the profile is structurally broken (a routing list
// pointing at a missing endpoint, as the demo seed does), yet still rejects a genuinely bad DNS plane.
// This is what lets the DNS section save without being blocked by pre-existing profile issues.
func TestValidateDNS_DecoupledFromProfile(t *testing.T) {
	p := dnsBase(&DNSSettings{
		Enabled: true,
		Servers: []DNSServer{{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: true}, {Tag: "dns_local", Type: "local", Enabled: true}},
		Final:   "dns_secure", Strategy: "ipv4_only", LeakProof: true,
	})
	// Corrupt an UNRELATED plane: a routing list routed via a non-existent endpoint. Whole-profile
	// Validate must reject this; ValidateDNS must NOT care.
	p.RoutingLists = append(p.RoutingLists, RoutingList{ID: "rl-broken", Manual: []string{"x.example"}, Outbound: "ghost-endpoint", Enabled: true})
	if err := p.Validate(); err == nil {
		t.Fatal("whole-profile Validate should reject a routing list with a dangling outbound")
	}
	if err := p.ValidateDNS(); err != nil {
		t.Fatalf("ValidateDNS must ignore the unrelated routing-list breakage, got: %v", err)
	}
	// But a real DNS fault (leak-proof + plaintext final) is still caught.
	p.DNS.Servers = append(p.DNS.Servers, DNSServer{Tag: "leaky", Type: "udp", Server: "8.8.8.8", Enabled: true})
	p.DNS.Final = "leaky"
	if err := p.ValidateDNS(); err == nil {
		t.Fatal("ValidateDNS must still reject a leak-proof plane with a plaintext final")
	}
}

func TestValidateDNS_SecureFailoverAware(t *testing.T) {
	// The secure, failover-aware default: DoH pinned by IP, detour = the failover group (rides the
	// tunnel while up, falls to direct-DoH when all VPN down), local for in-country, leak-proof.
	dns := &DNSSettings{
		Enabled: true,
		Servers: []DNSServer{
			{Tag: "secure", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: true},
			{Tag: "secure_bk", Type: "https", Server: "9.9.9.9", Detour: "grp", Enabled: true},
			{Tag: "local", Type: "local", Enabled: true},
		},
		Rules:     []DNSRule{{ID: "ru", RuleSets: []string{"ru-list"}, Server: "local"}},
		Final:     "secure",
		Strategy:  "ipv4_only",
		LeakProof: true,
	}
	if err := dnsBase(dns).Validate(); err != nil {
		t.Fatalf("valid secure failover-aware DNS rejected: %v", err)
	}
}

func TestValidateDNS_Errors(t *testing.T) {
	srv := func(s ...DNSServer) *DNSSettings { return &DNSSettings{Enabled: true, Servers: s} }
	cases := []struct {
		name string
		dns  *DNSSettings
		want string
	}{
		{"unknown type", srv(DNSServer{Tag: "a", Type: "doh"}), "unknown type"},
		{"duplicate tag", srv(DNSServer{Tag: "a", Type: "local"}, DNSServer{Tag: "a", Type: "local"}), "duplicate server tag"},
		{"empty tag", srv(DNSServer{Tag: "", Type: "local"}), "empty tag"},
		{"network server needs address", srv(DNSServer{Tag: "a", Type: "https", Server: ""}), "empty server address"},
		{"hostname needs bootstrap", srv(DNSServer{Tag: "a", Type: "https", Server: "cloudflare-dns.com"}), "needs a bootstrap"},
		{"fakeip needs range", srv(DNSServer{Tag: "a", Type: "fakeip"}), "needs an inet4_range"},
		{"leakproof rejects plaintext", &DNSSettings{Enabled: true, LeakProof: true, Servers: []DNSServer{{Tag: "a", Type: "udp", Server: "8.8.8.8"}}}, "not allowed with leak protection"},
		{"fakeip requires independent_cache", &DNSSettings{Enabled: true, FakeIP: true}, "requires independent_cache"},
		{"unknown strategy", &DNSSettings{Enabled: true, Strategy: "fastest"}, "unknown strategy"},
		{"final unknown tag", &DNSSettings{Enabled: true, Final: "ghost", Servers: []DNSServer{{Tag: "a", Type: "local"}}}, "final \"ghost\" is not a defined"},
		{"leakproof final must be encrypted", &DNSSettings{Enabled: true, LeakProof: true, Final: "loc", Servers: []DNSServer{{Tag: "loc", Type: "local"}}}, "ENCRYPTED final"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := dnsBase(c.dns).Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want error containing %q", err, c.want)
			}
		})
	}
}

func TestValidateDNS_RuleAndDetourResolution(t *testing.T) {
	// hostname WITH a bootstrap resolver is fine.
	okBoot := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "boot", Type: "https", Server: "1.1.1.1", Enabled: true},
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "boot", Enabled: true},
	}}
	if err := dnsBase(okBoot).Validate(); err != nil {
		t.Fatalf("hostname+bootstrap rejected: %v", err)
	}
	// detour to a non-existent id fails.
	badDetour := &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "https", Server: "1.1.1.1", Detour: "ghost"}}}
	if err := dnsBase(badDetour).Validate(); err == nil || !strings.Contains(err.Error(), "detour \"ghost\" does not resolve") {
		t.Fatalf("bad detour: got %v", err)
	}
	// rule referencing an undefined server tag fails.
	badRule := &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "local"}}, Rules: []DNSRule{{ID: "r", GeoSite: []string{"cn"}, Server: "nope"}}}
	if err := dnsBase(badRule).Validate(); err == nil || !strings.Contains(err.Error(), "not a defined tag") {
		t.Fatalf("bad rule server: got %v", err)
	}
	// rule_set that isn't a routing list fails.
	badSet := &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "local"}}, Rules: []DNSRule{{ID: "r", RuleSets: []string{"nl"}, Server: "a"}}}
	if err := dnsBase(badSet).Validate(); err == nil || !strings.Contains(err.Error(), "is not a routing list") {
		t.Fatalf("bad rule_set: got %v", err)
	}
	// reject-action rule with a matcher is fine (DNS-level adblock).
	adblock := &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "local"}}, Rules: []DNSRule{{ID: "b", RuleSets: []string{"ru-list"}, Server: "reject"}}}
	if err := dnsBase(adblock).Validate(); err != nil {
		t.Fatalf("reject rule rejected: %v", err)
	}
	// condition-less rule fails (would shadow everything).
	noMatch := &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "local"}}, Rules: []DNSRule{{ID: "c", Server: "a"}}}
	if err := dnsBase(noMatch).Validate(); err == nil || !strings.Contains(err.Error(), "no match condition") {
		t.Fatalf("condition-less rule: got %v", err)
	}
}
