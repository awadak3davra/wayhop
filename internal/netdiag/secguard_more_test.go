package netdiag

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These tests are SECURITY-focused. netdiag.Ping / Traceroute shell out to the
// system ping/traceroute tools. Although exec.Command does not invoke a shell,
// ValidTarget is the single guard that keeps untrusted, user-supplied targets
// from ever reaching the argv of those commands as anything but a bare host/IP.
// A regression that loosened the regex (e.g. allowing a space, a shell
// metacharacter, or an embedded newline) could turn a "target" field into an
// argument-injection / command-injection vector. The cases below pin the exact
// current accept/reject behavior so any such loosening fails CI.

// netdiagkbupdater_targetCase is one accept/reject expectation.
type netdiagkbupdater_targetCase struct {
	name string
	in   string
	want bool // expected ValidTarget result
}

// netdiagkbupdater_acceptCases are legitimate hosts/IPs that MUST be accepted,
// otherwise diagnostics break for valid targets.
var netdiagkbupdater_acceptCases = []netdiagkbupdater_targetCase{
	{"ipv4-google-dns", "8.8.8.8", true},
	{"ipv4-cloudflare-dns", "1.1.1.1", true},
	{"ipv4-loopback", "127.0.0.1", true},
	{"ipv4-rfc1918", "192.168.50.1", true},
	{"hostname-fqdn", "vpn.example.com", true},
	{"hostname-multi-label", "my-host.sub.example.org", true},
	{"hostname-with-hyphen", "edge-node-1", true},
	{"hostname-single-label", "router", true},
	{"hostname-trailing-dot", "example.com.", true},
	{"hostname-underscore", "_dmarc.example.com", true},
	{"hostname-digits-only-label", "node01.dc2.example.net", true},
	{"ipv6-loopback", "::1", true},
	{"ipv6-full", "2001:db8::1", true},
	{"ipv6-bracketed-loopback", "[::1]", true},
	{"ipv6-bracketed-full", "[2001:db8::1]", true},
	{"max-length-253", strings.Repeat("a", 253), true},
}

// netdiagkbupdater_rejectCases are inputs that MUST be rejected. These cover
// every shell metacharacter and whitespace form an attacker might use to break
// out of a single argv slot or smuggle a second command.
var netdiagkbupdater_rejectCases = []netdiagkbupdater_targetCase{
	{"empty", "", false},
	{"semicolon-rm", "8.8.8.8; rm -rf /", false},
	{"logical-and-evil", "host && evil", false},
	{"logical-or-evil", "host || evil", false},
	{"command-sub-dollar", "$(whoami)", false},
	{"command-sub-backtick", "`id`", false},
	{"embedded-command-sub", "8.8.8.8$(reboot)", false},
	{"pipe", "a|b", false},
	{"ampersand", "a&b", false},
	{"redirect-out", "a>b", false},
	{"redirect-in", "a<b", false},
	{"redirect-append", "a>>b", false},
	{"plain-space", "a b", false},
	{"leading-space", " 8.8.8.8", false},
	{"trailing-space", "8.8.8.8 ", false},
	{"flag-injection-leading-dash-c", "-c 9999", false}, // also contains a space
	{"flag-injection-dash-f-nospace", "-f", false},      // flood-ping flag, no space — caught only by the leading-dash rule
	{"flag-injection-double-dash", "--help", false},     // a bare flag, no space
	{"flag-injection-dash-c-nospace", "-c9999", false},  // flag+value packed, no space
	{"lone-dash", "-", false},
	{"tab", "a\tb", false},
	{"newline-mid", "a\nb", false},
	{"newline-trailing", "8.8.8.8\n", false}, // Go RE2 $ matches end-of-text, not before a trailing \n
	{"newline-then-cmd", "8.8.8.8\n; rm -rf /", false},
	{"carriage-return", "a\rb", false},
	{"null-byte", "a\x00b", false},
	{"double-quote", "a\"b", false},
	{"single-quote", "a'b", false},
	{"backslash", "a\\b", false},
	{"glob-star", "a*b", false},
	{"glob-question", "a?b", false},
	{"paren-open", "a(b", false},
	{"paren-close", "a)b", false},
	{"brace-open", "a{b", false},
	{"brace-close", "a}b", false},
	{"dollar-var", "$HOME", false},
	{"tilde", "~root", false},
	{"hash-comment", "host#comment", false},
	{"bang", "host!", false},
	{"at-sign", "user@host", false},
	{"percent", "a%b", false},
	{"plus", "a+b", false},
	{"equals", "a=b", false},
	{"comma", "a,b", false},
	{"slash", "a/b", false},
	{"caret", "a^b", false},
	{"unicode-letter", "exämple.com", false}, // non-ASCII not allowed by the ASCII-only class
	{"too-long-254", strings.Repeat("a", 254), false},
}

func TestValidTarget_AcceptsLegitimateHostsAndIPs(t *testing.T) {
	for _, tc := range netdiagkbupdater_acceptCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidTarget(tc.in); got != tc.want {
				t.Errorf("ValidTarget(%q) = %v, want %v (legitimate target must be accepted)", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidTarget_RejectsInjectionAndWhitespace(t *testing.T) {
	for _, tc := range netdiagkbupdater_rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidTarget(tc.in); got != tc.want {
				t.Errorf("ValidTarget(%q) = %v, want %v (INJECTION GUARD: must be rejected)", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidTarget_RejectsEveryShellMetacharacter asserts that no single shell
// metacharacter, on its own, is ever accepted as a standalone target. This is a
// belt-and-suspenders sweep so adding any such character to the allowed class
// (a likely regression) is caught immediately.
func TestValidTarget_RejectsEveryShellMetacharacter(t *testing.T) {
	for _, r := range " \t\n\r\x00;&|<>$`'\"\\(){}[]*?~!#@%^=+,/" {
		// '[' and ']' ARE in the allowed class (for bracketed IPv6) and so are
		// accepted standalone; skip them in this single-char sweep.
		if r == '[' || r == ']' {
			continue
		}
		s := string(r)
		if ValidTarget(s) {
			t.Errorf("ValidTarget(%q) = true, want false (metacharacter %q must never be a valid target)", s, r)
		}
	}
}

// TestPing_RejectsInvalidTargetWithoutExecuting proves the guard is actually
// wired into Ping: an injection-style target returns the sentinel "invalid
// target" output without running any external command. Using a context that is
// already cancelled would still surface a non-sentinel result if the guard were
// bypassed and a command were launched, so the sentinel is a reliable signal.
func TestPing_RejectsInvalidTargetWithoutExecuting(t *testing.T) {
	for _, in := range []string{"8.8.8.8; rm -rf /", "$(whoami)", "a b", "`id`", "a|b", "8.8.8.8\n; reboot"} {
		r := Ping(context.Background(), in, 4)
		if r.Output != "invalid target" {
			t.Errorf("Ping(%q).Output = %q, want %q (guard must reject before exec)", in, r.Output, "invalid target")
		}
		if r.Ok {
			t.Errorf("Ping(%q).Ok = true, want false for a rejected target", in)
		}
		if r.Target != in {
			t.Errorf("Ping(%q).Target = %q, want echo of input", in, r.Target)
		}
	}
}

// TestTraceroute_RejectsInvalidTarget proves the guard is wired into Traceroute.
func TestTraceroute_RejectsInvalidTarget(t *testing.T) {
	for _, in := range []string{"8.8.8.8; rm -rf /", "$(whoami)", "a b", "`id`", "a&b", "a>b"} {
		if got := Traceroute(context.Background(), in, 20); got != "invalid target" {
			t.Errorf("Traceroute(%q) = %q, want %q (guard must reject before exec)", in, got, "invalid target")
		}
	}
}

// TestDNSLookup_RejectsInvalidTarget proves the guard is wired into DNSLookup.
func TestDNSLookup_RejectsInvalidTarget(t *testing.T) {
	for _, in := range []string{"8.8.8.8; rm -rf /", "$(whoami)", "a b", "`id`"} {
		l := DNSLookup(context.Background(), in)
		if l.Err != "invalid target" {
			t.Errorf("DNSLookup(%q).Err = %q, want %q", in, l.Err, "invalid target")
		}
		if len(l.IPs) != 0 {
			t.Errorf("DNSLookup(%q).IPs = %v, want none for a rejected target", in, l.IPs)
		}
	}
}

// TestRun_RejectsInvalidTarget proves the top-level Run aggregator refuses an
// unsafe target up front and returns an error instead of running diagnostics.
func TestRun_RejectsInvalidTarget(t *testing.T) {
	for _, in := range []string{"8.8.8.8; rm -rf /", "$(whoami)", "a b", "`id`", "a|b"} {
		rep, err := Run(context.Background(), in)
		if err == nil {
			t.Errorf("Run(%q) err = nil, want non-nil for a rejected target", in)
		}
		if rep.Target != "" {
			t.Errorf("Run(%q) returned a populated report %+v, want zero Report", in, rep)
		}
	}
}

// TestDialPort_RejectsInvalidHostAndPort confirms DialPort applies the same host
// guard and bounds-checks the port, returning false without dialing.
func TestDialPort_RejectsInvalidHostAndPort(t *testing.T) {
	cases := []struct {
		host string
		port int
	}{
		{"8.8.8.8; rm -rf /", 22}, // unsafe host
		{"a b", 22},               // unsafe host
		{"$(whoami)", 443},        // unsafe host
		{"127.0.0.1", 0},          // port below range
		{"127.0.0.1", 65536},      // port above range
		{"127.0.0.1", -1},         // negative port
	}
	for _, c := range cases {
		if DialPort(c.host, c.port, 50*time.Millisecond) {
			t.Errorf("DialPort(%q, %d) = true, want false", c.host, c.port)
		}
	}
}
