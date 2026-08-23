package server

import (
	"net"
	"testing"
)

// TestIsInternalDialIP_NAT64_6to4 (#11): the SSRF guard must decode the IPv4 embedded in NAT64
// (64:ff9b::/96) and 6to4 (2002::/16) and refuse it when internal — otherwise a hostname resolving
// to e.g. 64:ff9b::7f00:1 (=127.0.0.1) lets the root daemon reach loopback/metadata on a NAT64/CLAT box.
func TestIsInternalDialIP_NAT64_6to4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"64:ff9b::7f00:1", true},       // NAT64 of 127.0.0.1 (loopback)
		{"64:ff9b::a9fe:a9fe", true},    // NAT64 of 169.254.169.254 (cloud metadata)
		{"64:ff9b::ac10:1", true},       // NAT64 of 172.16.0.1 (RFC1918)
		{"2002:7f00:1::", true},         // 6to4 of 127.0.0.1
		{"64:ff9b::808:808", false},     // NAT64 of 8.8.8.8 (public) — allowed
		{"2606:4700:4700::1111", false}, // a real public IPv6 — allowed
		{"::ffff:127.0.0.1", true},      // IPv4-mapped loopback (already handled; regression guard)
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isInternalDialIP(ip); got != c.want {
			t.Errorf("isInternalDialIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
