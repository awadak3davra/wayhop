package nativedns

import (
	"errors"
	"strings"
	"testing"
)

// Hijack53 and DoHBypassBlocked both derive from `iptables -S`, whose error used to be discarded.
// On a router with no iptables binary — a plausible fw4/nftables-only OpenWrt build — every probe
// returns empty, and the detector then reported as a FINDING that "LAN DNS is not forced through
// the router (no :53 redirect)". The leak verdict errs safe, but that note asserts a measurement
// which never happened.

func TestRulesUnreadable(t *testing.T) {
	missing := errors.New("exec: \"iptables\": executable file not found in $PATH")
	cases := []struct {
		name                 string
		natOut               string
		natErr               error
		filterOut, filterMsg string
		filterErr            error
		want                 bool
	}{
		{name: "both commands missing", natErr: missing, filterErr: missing, want: true},
		{name: "both read cleanly but empty", want: false},
		{name: "nat readable, filter missing", natOut: "-P PREROUTING ACCEPT", filterErr: missing, want: false},
		{name: "nat missing, filter readable", natErr: missing, filterOut: "-P INPUT ACCEPT", want: false},
		// A command that errored but still printed rules told us something.
		{name: "errored yet printed rules", natOut: "-P PREROUTING ACCEPT", natErr: missing, filterErr: missing, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rulesUnreadable(c.natOut, c.natErr, c.filterOut, c.filterErr); got != c.want {
				t.Errorf("rulesUnreadable = %v, want %v", got, c.want)
			}
		})
	}
}

// The whole point: an unreadable firewall must not produce a note claiming the redirect is absent.
func TestRunEffectivePath_MissingIptablesIsReportedAsUnknown(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		switch name {
		case "iptables":
			return "", errors.New("exec: \"iptables\": executable file not found in $PATH")
		case "cat":
			return "nameserver 127.0.0.1\n", nil
		}
		return "", nil
	}
	ep := RunEffectivePath(run)

	if !ep.RulesUnknown {
		t.Fatal("the firewall could not be read, but the result does not say so")
	}
	if !ep.LeakRisk {
		t.Error("with nothing verified the safe verdict is still a leak risk")
	}
	joined := strings.Join(ep.Notes, " | ")
	if !strings.Contains(strings.ToUpper(joined), "UNKNOWN") {
		t.Errorf("the leading note must say the firewall state is unknown, got %q", joined)
	}
	// And it must LEAD, so the honest caveat is not buried under the derived claims.
	if len(ep.Notes) == 0 || !strings.Contains(ep.Notes[0], "Could not read") {
		t.Errorf("the caveat must come first, got %q", ep.Notes)
	}
}

// A router whose firewall IS readable must be unaffected — the caveat only appears when earned.
func TestRunEffectivePath_ReadableFirewallIsNotMarkedUnknown(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		switch name {
		case "iptables":
			return "-P PREROUTING ACCEPT\n-A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 41100\n", nil
		case "cat":
			return "nameserver 127.0.0.1\n", nil
		}
		return "", nil
	}
	ep := RunEffectivePath(run)
	if ep.RulesUnknown {
		t.Error("the firewall was readable; nothing should be marked unknown")
	}
	if !ep.Hijack53 {
		t.Error("the :53 redirect in the ruleset should have been detected")
	}
}

// The fw4 case this whole path exists for: no iptables binary, but a perfectly readable nft
// ruleset. Before the fallback, the detector reported the firewall as unreadable on exactly the
// router family the operator runs.
func TestRunEffectivePath_FallsBackToNftWhenIptablesIsMissing(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		switch name {
		case "iptables":
			return "", errors.New("exec: \"iptables\": executable file not found in $PATH")
		case "nft":
			return `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		meta nfproto ipv4 udp dport 53 counter redirect to :41100 comment "!fw4: Divert-DNS"
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		tcp dport 853 counter reject comment "!fw4: block-DoT"
	}
}
`, nil
		case "cat":
			return "nameserver 127.0.0.1\n", nil
		}
		return "", nil
	}
	ep := RunEffectivePath(run)

	if ep.RulesUnknown {
		t.Error("the firewall WAS readable through nft; nothing should be marked unknown")
	}
	if !ep.Hijack53 {
		t.Error("the :53 redirect in the nft ruleset should have been detected")
	}
	if ep.Hijack53To != "41100" {
		t.Errorf("the redirect target should come from the rule, got %q", ep.Hijack53To)
	}
	if !ep.DoTBypassBlocked {
		t.Error("the :853 reject should register as DoT being handled")
	}
	// The point of this case is that the nft read WORKED — the redirect and the DoT rule were both
	// seen where an empty iptables read had reported nothing. The verdict is still a leak risk, and
	// correctly so: this fixture constrains plain DNS and DoT and leaves DoH untouched.
	if ep.DoHBypassBlocked {
		t.Error("nothing in this ruleset restricts :443 to resolver addresses")
	}
	if !ep.LeakRisk {
		t.Errorf("DoH is unconstrained here, so the verdict must still flag it: %v", ep.Notes)
	}
	for _, n := range ep.Notes {
		if strings.Contains(n, "Could not read") {
			t.Errorf("a caveat about an unreadable firewall survived a successful nft read: %q", n)
		}
	}
}

// When neither tool works, the honest answer from AUD-43 must still stand.
func TestRunEffectivePath_BothToolsMissingIsStillUnknown(t *testing.T) {
	missing := errors.New("executable file not found in $PATH")
	run := func(name string, args ...string) (string, error) {
		if name == "iptables" || name == "nft" {
			return "", missing
		}
		return "", nil
	}
	ep := RunEffectivePath(run)
	if !ep.RulesUnknown {
		t.Fatal("neither tool ran, so the firewall state is unknown")
	}
	if !ep.LeakRisk {
		t.Error("with nothing verified the safe verdict is still a leak risk")
	}
}
