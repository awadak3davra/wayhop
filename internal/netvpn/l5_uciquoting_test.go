package netvpn

import (
	"strings"
	"testing"
)

// TestUCIValuesCannotLeaveTheirQuotes (L5): every VALUE this package writes is handed to `sh -c`
// inside single quotes, and q() is the only thing keeping a value inside them.
//
// It had no test at all — no file referenced q(, and none contained the '\” escape it produces.
// A helper that stands between hostile text and a shell command is exactly where a silent regression
// lands, so the property is pinned rather than argued.
func TestUCIValuesCannotLeaveTheirQuotes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abc", "'abc'"},
		{"", "''"},
		// The one that matters: a quote must close, escape and reopen — not end the argument.
		{"a'b", `'a'\''b'`},
		{"'; reboot; '", `''\''; reboot; '\'''`},
	} {
		if got := q(tc.in); got != tc.want {
			t.Errorf("q(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}

	// A rendered command must never contain a bare quote outside the escape sequence: that is the
	// shape of an escape, and the shape of an escape is what a shell reads.
	iface := AWGInterface{
		Name: "awg0", PrivateKey: "k'ey", MTU: 1420,
		Addresses: []string{"10.0.0.2/32"},
		Peers: []AWGPeer{{PublicKey: "p'ub", Description: "a'b; reboot", EndpointHost: "h'ost",
			AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	for _, cmd := range RenderUCIFrom(iface, nil) {
		// Strip the escape sequences, then no lone quote may remain unbalanced.
		bare := strings.ReplaceAll(cmd, `'\''`, "")
		if strings.Count(bare, "'")%2 != 0 {
			t.Errorf("a hostile value left its quoting: %q", cmd)
		}
		if strings.Contains(cmd, "; reboot") && !strings.Contains(cmd, `'\''`) && !strings.Contains(cmd, "'a") {
			t.Errorf("a semicolon reached the command unquoted: %q", cmd)
		}
	}
}

// TestPlanRefusesANameThatWouldBeASecondCommand (L5): the section NAME is the one field rendered
// unquoted — it is part of the uci path ("uci set network.<name>.proto=...") and those commands run
// through `sh -c`. Nothing reaching the builder today is attacker-shaped, but that is a claim about
// TestPlanRefusesANameThatWouldBeASecondCommand (L5): the section NAME is the one field rendered
// unquoted — it is part of the uci path ("uci set network.<name>.proto=...") and those commands run
// through `sh -c`. Nothing reaching the builder today is attacker-shaped: a created tunnel is named
// from its endpoint id, an adopted one from the router's own uci. That is a claim about callers,
// re-made every time a caller is added; this makes it a claim about the builder.
//
// The fixture is the one the rest of this package builds working plans from, and a GOOD name is
// asserted to succeed under exactly the same conditions — without that control the test would pass
// on any builder that refuses everything, which is what its first draft did.
func TestPlanRefusesANameThatWouldBeASecondCommand(t *testing.T) {
	if _, err := BuildPlanFor(newIface("awg0"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow); err != nil {
		t.Fatalf("the control must build: an ordinary name is refused for another reason: %v", err)
	}
	for _, bad := range []string{
		"awg0; reboot", "awg0 && reboot", "awg'0", "awg0`id`", "awg0$(id)", "awg 0", ".awg0",
		"way-too-long-iface", "",
	} {
		if _, err := BuildPlanFor(newIface(bad), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow); err == nil {
			t.Errorf("a plan was built for the name %q", bad)
		}
	}
	for _, good := range []string{"awg0", "wg1", "nwg5", "tun_0", "a.b-c"} {
		if !validUCIName(good) {
			t.Errorf("%q is a normal interface name and must be accepted", good)
		}
	}
}
