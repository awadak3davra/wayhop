package util

import "testing"

// TestWGAllowedIPs: the exported/rendered WireGuard AllowedIPs must include ::/0 for a dual-stack or
// IPv6 endpoint (else its IPv6 leaks outside the tunnel / routes nothing), while a plain IPv4 endpoint
// stays 0.0.0.0/0.
func TestWGAllowedIPs(t *testing.T) {
	mk := func(addrs ...string) map[string]any { return map[string]any{"local_address": addrs} }
	cases := []struct {
		p    map[string]any
		want string
	}{
		{mk("10.0.0.2/32"), "0.0.0.0/0"},
		{mk("fd00::2/128"), "::/0"},
		{mk("10.0.0.2/32", "fd00::2/128"), "0.0.0.0/0, ::/0"},
		{mk(), "0.0.0.0/0"},             // no local address -> default v4
		{map[string]any{}, "0.0.0.0/0"}, // no param at all
		{mk("2606:4700:110:8a36::1"), "::/0"},
	}
	for _, c := range cases {
		if got := WGAllowedIPs(c.p); got != c.want {
			t.Errorf("WGAllowedIPs(%v) = %q, want %q", c.p["local_address"], got, c.want)
		}
	}
}
