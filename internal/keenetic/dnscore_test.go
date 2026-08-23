package keenetic

import (
	"testing"

	"wayhop/internal/model"
)

// dnsmasq speaks plain UDP/TCP and nothing else, so an encrypted resolver exists on this router only
// while sing-box runs. The predicate that decides whether a plan needs the core did not look at the
// server TYPE at all — measured on a live Keenetic: two DoH resolvers configured, the core
// installed, the plan still reporting native-only, and dnsmasq answering in plaintext while the
// panel said the lookups were encrypted.
func TestDNSPlaneNeedsCoreForEncryptedResolvers(t *testing.T) {
	encrypted := &model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
		{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Enabled: true}, // detour empty = direct
	}}}
	if !dnsPlaneNeedsCore(encrypted) {
		t.Fatal("a DoH resolver going direct must still require the core")
	}

	for _, typ := range []string{"tls", "quic", "h3"} {
		p := &model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
			{Tag: "t", Type: typ, Server: "1.1.1.1", Enabled: true},
		}}}
		if !dnsPlaneNeedsCore(p) {
			t.Fatalf("%s must require the core", typ)
		}
	}

	// The relaxation this predicate exists for stays: plain resolvers going direct, with no rules, are
	// exactly what dnsmasq does, and must NOT drag the core in.
	plain := &model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
		{Tag: "isp", Type: "udp", Server: "1.1.1.1", Enabled: true},
		{Tag: "local", Type: "local", Enabled: true},
	}}}
	if dnsPlaneNeedsCore(plain) {
		t.Fatal("plaintext resolvers going direct must not require the core")
	}

	// A DISABLED encrypted resolver is not in the datapath and cannot be a reason to start a core.
	off := &model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
		{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Enabled: false},
		{Tag: "isp", Type: "udp", Server: "1.1.1.1", Enabled: true},
	}}}
	if dnsPlaneNeedsCore(off) {
		t.Fatal("a disabled encrypted resolver must not require the core")
	}

	// Nor is a DNS block that is switched off entirely.
	disabled := &model.Profile{DNS: &model.DNSSettings{Enabled: false, Servers: []model.DNSServer{
		{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Enabled: true},
	}}}
	if dnsPlaneNeedsCore(disabled) {
		t.Fatal("a disabled DNS plane must not require the core")
	}
}
