package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// vpnDNSProfile has one OpenVPN and one OpenConnect connection, each with a DNS server asking its
// pushed resolvers and a rule sending the VPN's domains there, and an encrypted default.
func vpnDNSProfile() *Profile {
	return &Profile{
		Endpoints: []Endpoint{
			{ID: "ovpn", Name: "Office", Enabled: true, Engine: EngineSingBox, Protocol: ProtoOpenVPN,
				Server: "vpn.example.com", Port: 1194, Params: map[string]any{"ca": "test-ca"}},
			{ID: "oc", Name: "Lab", Enabled: true, Engine: EngineSingBox, Protocol: ProtoOpenConnect,
				Server: "oc.example.net", Port: 443},
		},
		DNS: &DNSSettings{
			Enabled: true,
			Servers: []DNSServer{
				{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
				{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", AcceptDefaultResolvers: true, AcceptSearchDomain: true, Enabled: true},
				{Tag: "lab-dns", Type: "openconnect", Endpoint: "oc", Enabled: true},
			},
			Rules: []DNSRule{
				{ID: "office", DomainSuffix: []string{"corp.example"}, Server: "office-dns"},
				{ID: "lab", DomainSuffix: []string{"lab.example"}, Server: "lab-dns"},
			},
			Final: "doh",
		},
	}
}

func TestVPNDNSValid(t *testing.T) {
	p := vpnDNSProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := p.ValidateDNS(); err != nil {
		t.Fatalf("ValidateDNS: %v", err)
	}
	// Leak protection refuses plaintext resolvers on the WAN; these are asked through the tunnel.
	p.DNS.LeakProof = true
	if err := p.ValidateDNS(); err != nil {
		t.Fatalf("leak protection with VPN resolvers as rule targets: %v", err)
	}
	for _, ty := range []string{"openvpn", " OpenConnect "} {
		if !IsVPNDNSType(ty) {
			t.Errorf("IsVPNDNSType(%q) = false", ty)
		}
	}
	for _, ty := range []string{"udp", "https", "local", "fakeip", ""} {
		if IsVPNDNSType(ty) {
			t.Errorf("IsVPNDNSType(%q) = true", ty)
		}
	}
}

// Each of these passes `sing-box check` on 1.14.4 and 1.15.0-alpha.13 and stops `sing-box run` at
// startup, or would answer every lookup with NXDOMAIN, so saving refuses it.
func TestVPNDNSRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *Profile)
		want string
	}{
		{"no connection", func(p *Profile) { p.DNS.Servers[1].Endpoint = " " }, "choose the openvpn connection"},
		{"wrong protocol", func(p *Profile) { p.DNS.Servers[2].Endpoint = "ovpn" }, `connection "ovpn" is openvpn, not openconnect`},
		{"not the core's", func(p *Profile) { p.Endpoints[0].Engine = EngineOpenVPN }, "not run by the proxy core"},
		{"two on one connection", func(p *Profile) {
			p.DNS.Servers = append(p.DNS.Servers, DNSServer{Tag: "office-2", Type: "openvpn", Endpoint: "ovpn", Enabled: true})
		}, "allows one DNS server per connection"},
		{"as the default", func(p *Profile) { p.DNS.Final = "office-dns" }, "only answers names its VPN connection pushes"},
		{"as the implicit default", func(p *Profile) {
			p.DNS.Final = ""
			p.DNS.Servers[0], p.DNS.Servers[1] = p.DNS.Servers[1], p.DNS.Servers[0]
		}, `first resolver "office-dns"`},
		{"implicit default behind a fakeip server", func(p *Profile) {
			// Without TUN the fakeip server is dropped and the VPN one behind it answers everything.
			p.DNS.Final = ""
			p.DNS.FakeIP, p.DNS.IndependentCache = true, true
			p.DNS.Servers = append([]DNSServer{{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true},
				p.DNS.Servers[1]}, p.DNS.Servers[0], p.DNS.Servers[2])
		}, `first resolver "office-dns"`},
		{"first, behind a FakeIP default left out without TUN", func(p *Profile) {
			// Final names FakeIP; in fast or mixed mode the generator drops it and its final, and
			// sing-box takes the first server: the VPN one.
			p.DNS.FakeIP, p.DNS.IndependentCache = true, true
			p.DNS.Servers = []DNSServer{p.DNS.Servers[1],
				{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true}, p.DNS.Servers[0], p.DNS.Servers[2]}
			p.DNS.Final = "fake"
		}, `the default resolver "fake" is FakeIP, which is left out in fast and mixed mode, so the first resolver "office-dns"`},
		{"first, behind a switched-off default", func(p *Profile) {
			p.DNS.Servers[0].Enabled = false
			p.DNS.Servers[0], p.DNS.Servers[1] = p.DNS.Servers[1], p.DNS.Servers[0]
		}, `the default resolver "doh" is switched off, so the first resolver "office-dns"`},
		{"as a bootstrap", func(p *Profile) {
			p.DNS.Servers[0].Server, p.DNS.Servers[0].DomainResolver = "dns.example.com", "office-dns"
		}, "cannot bootstrap a hostname"},
	}
	for _, c := range cases {
		p := vpnDNSProfile()
		c.edit(p)
		err := p.ValidateDNS()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// A connection that is gone or switched off is the reference class the review and the store already
// handle by type: the review names the DNS server, and the store refuses to switch the connection off
// underneath an enabled resolver (DisabledRefError).
func TestVPNDNSReferenceClasses(t *testing.T) {
	p := vpnDNSProfile()
	p.DNS.Servers[1].Endpoint = "gone"
	var missing *UnresolvedRefError
	if err := p.Validate(); !errors.As(err, &missing) || missing.Kind != "DNS server" || missing.ID != "office-dns" || missing.Target != "gone" {
		t.Errorf("missing connection: err = %#v", err)
	}
	p = vpnDNSProfile()
	p.Endpoints[0].Enabled = false
	var off *DisabledRefError
	if err := p.Validate(); !errors.As(err, &off) || off.Kind != "DNS server" || off.Target != "ovpn" {
		t.Errorf("connection switched off: err = %#v", err)
	}
	// A switched-off resolver is emitted nowhere, so it may keep naming a connection that is off or
	// gone: that is how deleting or switching off the connection parks it instead of losing it.
	p = vpnDNSProfile()
	p.Endpoints = p.Endpoints[1:]
	p.DNS.Servers[1].Enabled = false
	p.DNS.Rules[0].Disabled = true
	if err := p.Validate(); err != nil {
		t.Errorf("parked resolver: %v", err)
	}
}

// A resolver of any other type marshals exactly as before: the three new fields are omitted.
func TestVPNDNSFieldsOmittedElsewhere(t *testing.T) {
	b, err := json.Marshal(DNSServer{Tag: "doh", Type: "https", Server: "192.0.2.53", Detour: "grp", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tag":"doh","type":"https","server":"192.0.2.53","detour":"grp","enabled":true}`; string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
	b, _ = json.Marshal(vpnDNSProfile().DNS.Servers[1])
	if want := `{"tag":"office-dns","type":"openvpn","endpoint":"ovpn","accept_default_resolvers":true,"accept_search_domain":true,"enabled":true}`; string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
}

// StrandedVPNResolvers names each enabled VPN resolver whose connection cannot serve it, with why; the
// store refuses a write that adds one.
func TestStrandedVPNResolvers(t *testing.T) {
	if got := StrandedVPNResolvers(vpnDNSProfile()); len(got) != 0 {
		t.Fatalf("valid profile: %+v", got)
	}
	cases := []struct {
		edit func(p *Profile)
		want StrandedVPNResolver
	}{
		{func(p *Profile) { p.Endpoints[0].Protocol = ProtoOpenConnect },
			StrandedVPNResolver{Tag: "office-dns", Endpoint: "ovpn", Why: "would be openconnect, not openvpn"}},
		{func(p *Profile) { p.Endpoints[1].Engine = EngineExternal },
			StrandedVPNResolver{Tag: "lab-dns", Endpoint: "oc", Why: "would not be run by the proxy core"}},
		{func(p *Profile) { p.Endpoints[0].Enabled = false },
			StrandedVPNResolver{Tag: "office-dns", Endpoint: "ovpn", Why: "would be switched off"}},
		{func(p *Profile) { p.Endpoints = p.Endpoints[1:] },
			StrandedVPNResolver{Tag: "office-dns", Endpoint: "ovpn", Why: "would no longer exist"}},
	}
	for _, c := range cases {
		p := vpnDNSProfile()
		c.edit(p)
		if got := StrandedVPNResolvers(p); len(got) != 1 || got[0] != c.want {
			t.Errorf("got %+v, want %+v", got, c.want)
		}
	}
	p := vpnDNSProfile()
	p.Endpoints = nil
	p.DNS.Servers[1].Enabled = false
	if got := StrandedVPNResolvers(p); len(got) != 1 || got[0].Tag != "lab-dns" {
		t.Errorf("a switched-off resolver is not stranded: %+v", got)
	}
}
