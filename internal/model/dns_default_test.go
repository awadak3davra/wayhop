package model

import (
	"strings"
	"testing"
)

// QA-105. With `final` empty, sing-box makes the FIRST server it creates the default resolver, so
// every query no rule matches goes there. Leak protection checked only an explicit final, and the
// panel sets final to "" when the default resolver is deleted (and offers "(first resolver)" in the
// picker). Deleting the encrypted default and keeping the router's `local` resolver first therefore
// passed validation while sing-box sent every unmatched lookup, tunnel lists included, to the
// router's plaintext resolver.
func TestValidateDNS_LeakProtectionCountsTheImplicitDefault(t *testing.T) {
	local := DNSServer{Tag: "dns_local", Type: "local", Enabled: true}
	doh := DNSServer{Tag: "cf", Type: "https", Server: "192.0.2.53", Path: "/dns-query", Detour: "nl", Enabled: true}
	fake := DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true}
	off := DNSServer{Tag: "off", Type: "local", Enabled: false}
	plane := func(servers ...DNSServer) *DNSSettings {
		return &DNSSettings{Enabled: true, LeakProof: true, FakeIP: true, IndependentCache: true, Servers: servers}
	}

	// The trigger: no default chosen, and the first resolver is the plaintext local one.
	err := dnsBase(plane(local, doh)).ValidateDNS()
	if err == nil {
		t.Fatal("leak protection accepted an empty final whose first resolver is the plaintext local one")
	}
	if !strings.Contains(err.Error(), "dns_local") {
		t.Errorf("the refusal must name the resolver that would answer, got %q", err)
	}

	// The same plane with that resolver named as the final was already refused; the two must agree.
	explicit := plane(local, doh)
	explicit.Final = "dns_local"
	if dnsBase(explicit).ValidateDNS() == nil {
		t.Fatal("control: an explicit local final must stay refused")
	}

	// Unchanged: an encrypted first resolver is a valid implicit default.
	if err := dnsBase(plane(doh, local)).ValidateDNS(); err != nil {
		t.Errorf("an encrypted first resolver is a valid default: %v", err)
	}
	// A fakeip server sends no query, and outside TUN the generator drops it, so the resolver
	// behind it is the default that matters: encrypted here, so valid.
	if err := dnsBase(plane(fake, doh, local)).ValidateDNS(); err != nil {
		t.Errorf("fakeip first, then an encrypted resolver, is a valid default: %v", err)
	}
	// ...and plaintext here, so refused.
	if dnsBase(plane(fake, local, doh)).ValidateDNS() == nil {
		t.Error("fakeip first hides the local resolver behind it, which answers outside TUN")
	}
	// A disabled server is never emitted, so it cannot be the default either way.
	if err := dnsBase(plane(off, doh)).ValidateDNS(); err != nil {
		t.Errorf("a disabled first server is not the default: %v", err)
	}
	// Without leak protection nothing here is refused: the audit reports it instead.
	open := plane(local, doh)
	open.LeakProof = false
	if err := dnsBase(open).ValidateDNS(); err != nil {
		t.Errorf("without leak protection an implicit local default is allowed: %v", err)
	}
}
