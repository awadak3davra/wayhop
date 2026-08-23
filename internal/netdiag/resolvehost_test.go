package netdiag

import "testing"

// TestResolveHostToken: an IPv6-literal host must be bracketed for curl's --resolve; a hostname or
// IPv4 address must pass through unchanged (else curl rejects the entry and the probe falsely reports
// the exit unreachable for an IPv6-literal target).
func TestResolveHostToken(t *testing.T) {
	cases := map[string]string{
		"example.com":          "example.com",
		"1.2.3.4":              "1.2.3.4",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]",
		"::1":                  "[::1]",
		"fe80::1":              "[fe80::1]",
	}
	for in, want := range cases {
		if got := resolveHostToken(in); got != want {
			t.Errorf("resolveHostToken(%q) = %q, want %q", in, got, want)
		}
	}
}
