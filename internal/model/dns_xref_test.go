package model

import (
	"strings"
	"testing"
)

// TestValidateDNS_DomainResolverXref: a hostname upstream's bootstrap domain_resolver must reference
// a DEFINED and ENABLED DNS server tag. The generator emits domain_resolver verbatim and DROPS
// disabled servers, so a typo'd or disabled bootstrap tag becomes a dangling reference sing-box
// FATALs on — Validate must reject it up front with a precise error instead of persisting an
// unappliable profile (Validate is the sole gate on Store.Replace).
func TestValidateDNS_DomainResolverXref(t *testing.T) {
	// dangling: byhost bootstraps against "boot" but no such server exists (typo).
	dangling := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "boot", Enabled: true},
	}}
	if err := dnsBase(dangling).Validate(); err == nil || !strings.Contains(err.Error(), `domain_resolver "boot" is not a defined server tag`) {
		t.Fatalf("dangling domain_resolver: got %v", err)
	}
	// disabled target: "boot" exists but is disabled -> generator drops it -> dangling reference.
	disabled := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "boot", Type: "https", Server: "1.1.1.1", Enabled: false},
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "boot", Enabled: true},
	}}
	if err := dnsBase(disabled).Validate(); err == nil || !strings.Contains(err.Error(), `domain_resolver "boot" targets a disabled server`) {
		t.Fatalf("disabled domain_resolver target: got %v", err)
	}
	// FORWARD reference (bootstrap declared AFTER the citer) must pass — proves the post-loop 2nd pass.
	forward := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "boot", Enabled: true},
		{Tag: "boot", Type: "https", Server: "1.1.1.1", Enabled: true},
	}}
	if err := dnsBase(forward).Validate(); err != nil {
		t.Fatalf("forward-referenced bootstrap rejected: %v", err)
	}
}

// TestValidateDNS_DomainResolverRejectsFakeipLocal: a bootstrap domain_resolver must target a real
// network resolver. A fakeip target only SYNTHESIZES addresses (and is DROPPED in fast/mixed mode,
// leaving a dangling reference sing-box FATALs on); a local target is the device stub. Both must be
// rejected at Validate — the UI picker offers every server type, so an invalid pick is reachable.
func TestValidateDNS_DomainResolverRejectsFakeipLocal(t *testing.T) {
	fake := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true},
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "fake", Enabled: true},
	}}
	if err := dnsBase(fake).Validate(); err == nil || !strings.Contains(err.Error(), "cannot bootstrap a hostname") {
		t.Fatalf("fakeip domain_resolver target: got %v", err)
	}
	local := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "loc", Type: "local", Enabled: true},
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "loc", Enabled: true},
	}}
	if err := dnsBase(local).Validate(); err == nil || !strings.Contains(err.Error(), "cannot bootstrap a hostname") {
		t.Fatalf("local domain_resolver target: got %v", err)
	}
	// A proper network resolver as the bootstrap still passes.
	ok := &DNSSettings{Enabled: true, Servers: []DNSServer{
		{Tag: "boot", Type: "udp", Server: "1.1.1.1", Enabled: true},
		{Tag: "byhost", Type: "https", Server: "dns.google", DomainResolver: "boot", Enabled: true},
	}}
	if err := dnsBase(ok).Validate(); err != nil {
		t.Fatalf("network-resolver bootstrap rejected: %v", err)
	}
}

// TestValidateDNS_ClientSubnet: client_subnet is emitted verbatim as sing-box dns.client_subnet (a
// netip prefix/addr); a malformed value FATALs at config load, so Validate must reject it. A bare IP
// or a CIDR is accepted (sing-box promotes a bare IP to /32 or /128). A trailing-space value is
// tolerated (validated + emitted trimmed).
func TestValidateDNS_ClientSubnet(t *testing.T) {
	mk := func(cs string) *DNSSettings {
		return &DNSSettings{Enabled: true, Servers: []DNSServer{{Tag: "a", Type: "local", Enabled: true}}, ClientSubnet: cs}
	}
	for _, cs := range []string{"notanip", "10.0.0.0/99", "1.2.3.0/24/8", "999.1.1.1"} {
		if err := dnsBase(mk(cs)).Validate(); err == nil || !strings.Contains(err.Error(), "client_subnet") {
			t.Fatalf("malformed client_subnet %q: got %v", cs, err)
		}
	}
	for _, cs := range []string{"", "1.2.3.0/24", "203.0.113.5", "2001:db8::/48", "2001:db8::1", "1.2.3.0/24 "} {
		if err := dnsBase(mk(cs)).Validate(); err != nil {
			t.Fatalf("valid client_subnet %q rejected: %v", cs, err)
		}
	}
}
