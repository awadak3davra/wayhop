package server

import (
	"os"
	"strings"
	"testing"
)

// TestIPv6CarriedVerdict pins the row the leak check deliberately does not cover. The leak row ends
// with "whether that tunnel actually carries v6 is a separate question"; this is that question, and
// it exists because the answer cost something real: a plain HTTPS GET from a router in exactly this
// state picked its target's AAAA and died with "network is unreachable", then worked on the retry
// over IPv4. Nothing on the panel accounted for the failure.
func TestIPv6CarriedVerdict(t *testing.T) {
	cases := []struct {
		name                                  string
		global, intoTunnel, probed, reachable bool
		want                                  string
	}{
		{"no global v6 at all", false, false, false, false, "na"},
		{"global v6 but not routed into a tunnel", true, false, false, false, "na"},
		{"routed into a tunnel that carries it", true, true, true, true, "pass"},
		{"routed into a tunnel that does not", true, true, true, false, "warn"},
		{"routed, but the probe never ran", true, true, false, false, "warn"},
	}
	for _, c := range cases {
		st, sum, fix := ipv6CarriedVerdict(c.global, c.intoTunnel, c.probed, c.reachable)
		if st != c.want {
			t.Errorf("%s: status %q, want %q", c.name, st, c.want)
			continue
		}
		if st == "na" && sum == "" {
			t.Errorf("%s: says nothing at all", c.name)
		}
		if c.want == "warn" && c.probed && !c.reachable {
			// The measured case. Its remedy must name what the operator can actually do, and must not
			// be silent: this is the row that explains an otherwise inexplicable failed fetch.
			if fix == "" {
				t.Errorf("%s: no remedy on the one verdict that has a cause", c.name)
			}
			if !strings.Contains(strings.ToLower(fix), "default route") {
				t.Errorf("%s: remedy does not name the route to remove: %q", c.name, fix)
			}
			if !strings.Contains(strings.ToLower(sum), "does not carry") {
				t.Errorf("%s: summary does not say the tunnel fails to carry v6: %q", c.name, sum)
			}
		}
		// An unrun probe must never be reported as working: that is the reassuring guess this file's
		// sibling row was already burned by.
		if !c.probed && c.intoTunnel {
			if st == "pass" {
				t.Errorf("%s: claimed a pass without probing", c.name)
			}
			// Both the unrun probe and the failed probe warn, so a gate that reads only the status
			// cannot tell them apart, and the first version of this one could not. "does not carry" is
			// a measurement; "could not test" is the absence of one, and an operator acts differently
			// on each.
			if !strings.Contains(strings.ToLower(sum), "could not test") {
				t.Errorf("%s: an unrun probe reports a measurement it never made: %q", c.name, sum)
			}
			if fix != "" {
				t.Errorf("%s: offers a remedy for a fault it did not establish: %q", c.name, fix)
			}
		}
	}
}

// TestIPv6CarriedRegistered: an unregistered check is dead code that measures nothing.
func TestIPv6CarriedRegistered(t *testing.T) {
	b, err := os.ReadFile("healthcheck.go")
	if err != nil {
		t.Fatalf("read healthcheck.go: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "ipv6CarriedCheck") {
		t.Fatal("ipv6CarriedCheck is not in the battery list, so the row never runs")
	}
}
