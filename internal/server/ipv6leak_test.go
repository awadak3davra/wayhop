package server

import (
	"os"
	"strings"
	"testing"
)

// ipv6LeakCheck's three states, and the one that was wrong.
//
// A probe that did not COMPLETE was reported as `pass` — "IPv6 present but firewalled (OK)" — which
// asserts the absence of the very leak the probe failed to test. The request can fail because
// api6.ipify.org is down or blocked, because its AAAA does not resolve, or because the 6-second
// deadline expired on a loaded router; none of those says the router's v6 egress is closed.
//
// The live HTTP probe cannot run here, so these drive the two pure halves — the address reader and
// the row's own contract — and the wiring is asserted by reading the source. That last part is
// unusual and deliberate: the branch under test is reachable only when a real v6 request fails,
// which a unit test cannot arrange, and asserting nothing would leave the fixed branch untested.

// ipv6HasGlobal has TWO independent guards — the scope field must be 00, and the address must not be
// loopback, link-local or ULA — and a fixture must exercise each ALONE or a mutation that removes one
// sails through on the other. The first version of this test had exactly that hole: dropping the
// scope filter changed nothing, because its only non-global line was fe80, which the prefix guard
// caught anyway. So each case below is rejected by exactly one guard.
//
// Format: addr ifindex prefixlen scope flags dev
func TestIPv6HasGlobal_OnlyARoutableAddressCounts(t *testing.T) {
	for _, tc := range []struct {
		why  string
		in   string
		want bool
	}{
		{"a routable address with global scope", "20010db8000000000000000000000001 02 40 00 00 br-lan\n", true},
		{"link-local: rejected by BOTH guards", "fe800000000000000000000000000001 02 40 20 80 br-lan\n", false},
		{"loopback: rejected by both", "00000000000000000000000000000001 01 80 10 80 lo\n", false},
		// A ULA carries GLOBAL scope (00) in if_inet6 and is not routable on the internet: only the
		// prefix guard rejects it. Remove that guard and this becomes a leak claimed on every router
		// running a private v6 range.
		{"ULA fd00::/8 with global scope: only the prefix guard rejects it",
			"fd000000000000000000000000000001 02 64 00 00 br-lan\n", false},
		{"ULA fc00::/7 with global scope: same", "fc000000000000000000000000000001 02 64 00 00 br-lan\n", false},
		// A routable prefix carrying a NON-global scope: only the scope guard rejects it. Remove that
		// and a site-scoped address is reported as internet-reachable.
		{"a routable prefix at site scope: only the scope guard rejects it",
			"20010db8000000000000000000000009 02 40 40 00 br-lan\n", false},
		{"nothing at all", "", false},
		{"a truncated line is not a finding", "20010db8 02\n", false},
	} {
		if got := ipv6HasGlobal(tc.in); got != tc.want {
			t.Errorf("%s: ipv6HasGlobal = %v, want %v", tc.why, got, tc.want)
		}
	}
}

// The row's contract, asserted against the source, because the failing-probe branch needs a real
// network failure to reach. If this ever reads `pass` again, the check is back to announcing the
// absence of something it did not measure.
func TestIPv6LeakCheck_AnIncompleteProbeIsNotAPass(t *testing.T) {
	src, err := os.ReadFile("healthcheck.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fn := between(string(src), "func ipv6LeakCheck(", "\n}\n")
	if fn == "" {
		t.Fatal("ipv6LeakCheck not found — this test is measuring nothing")
	}
	branch := between(fn, "resp, err := cl.Do(req)", "return row")
	if branch == "" {
		t.Fatal("the probe-failure branch not found — this test is measuring nothing")
	}
	if !strings.Contains(branch, `"warn"`) {
		t.Errorf("a probe that did not complete does not degrade to warn:\n%s", branch)
	}
	if strings.Contains(branch, `"pass"`) {
		t.Errorf("a probe that did not complete is still reported as a pass:\n%s", branch)
	}
	if !strings.Contains(branch, "could not complete") {
		t.Errorf("the summary does not say the test could not complete:\n%s", branch)
	}
	// And the other two states must remain what they were: absence of a global address is a real
	// pass, and a successful probe is a real fail.
	if !strings.Contains(fn, `"pass", "no global IPv6 on the router"`) {
		t.Error("the measured-absence pass was lost")
	}
	if !strings.Contains(fn, `"fail", "IPv6 reaches the internet directly"`) {
		t.Error("the demonstrated-leak fail was lost")
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
