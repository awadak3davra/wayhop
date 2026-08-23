package netdiag

import (
	"net"
	"testing"
)

// TestIsInternalAddr_NAT64_6to4 (#11): the probe guard mirrors the SSRF dial guard — it must refuse
// the internal IPv4 embedded in NAT64 / 6to4 IPv6 addresses.
func TestIsInternalAddr_NAT64_6to4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"64:ff9b::7f00:1", true},       // NAT64 of 127.0.0.1
		{"2002:7f00:1::", true},         // 6to4 of 127.0.0.1
		{"64:ff9b::808:808", false},     // NAT64 of 8.8.8.8 (public)
		{"2606:4700:4700::1111", false}, // public IPv6
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isInternalAddr(ip); got != c.want {
			t.Errorf("isInternalAddr(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
