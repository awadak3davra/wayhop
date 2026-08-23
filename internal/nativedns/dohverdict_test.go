package nativedns

import (
	"strings"
	"testing"
)

// The leak verdict may only be cleared when all three bypass routes are shut. It used to be cleared
// by a :853 rule under a field named for DoH, which is a different escape hatch on a different port
// that no port rule can close.
//
// The fixtures are shaped after a real fw4 dump: the redirect lives in a regular chain reached by a
// jump from the nat prerouting base chain, which is how fw4 is built.
const fw4Base = `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "br-lan" jump dstnat_lan
	}
	chain dstnat_lan {
		tcp dport 53 counter redirect to :53
		udp dport 53 counter redirect to :53
	}
	chain input_lan {
%s	}
}
`

func detectFW4(t *testing.T, rules string) EffectivePath {
	t.Helper()
	nf := DetectFromNft(strings.Replace(fw4Base, "%s", rules, 1))
	if !nf.Parsed {
		t.Fatalf("fixture was not recognised as a ruleset — the case below would prove nothing")
	}
	if !nf.Hijack53 {
		t.Fatalf("fixture does not produce the :53 redirect it is built around")
	}
	ep := EffectivePath{Hijack53: nf.Hijack53, DoTBypassBlocked: nf.DoTHandled, DoHBypassBlocked: nf.DoHHandled}
	applyLeakVerdict(&ep)
	return ep
}

// The case the change exists for, and the one that was wrong: the :853 rules the https-dns-proxy
// package installs on every OpenWrt that runs it, with nothing constraining DoH.
func TestLeakVerdict_DoTRulesAloneDoNotClearTheVerdict(t *testing.T) {
	ep := detectFW4(t, "\t\ttcp dport 853 counter jump handle_reject\n\t\tudp dport 853 counter jump handle_reject\n")

	if !ep.DoTBypassBlocked {
		t.Errorf("DoTBypassBlocked = false, want true — the fixture rejects :853")
	}
	if ep.DoHBypassBlocked {
		t.Errorf("DoHBypassBlocked = true, want false — nothing in the fixture constrains :443")
	}
	if !ep.LeakRisk {
		t.Errorf("LeakRisk = false, want true: a client with its own DoH resolver bypasses the router, "+
			"and the only evidence here is a DoT rule. notes=%q", ep.Notes)
	}
	if len(ep.Notes) != 1 || !strings.Contains(ep.Notes[0], "DoH is not constrained") {
		t.Errorf("the note must say WHICH hatch is open; got %q", ep.Notes)
	}
}

// The AX3000T's actual shape: the same :853 rules plus a resolver-set restriction on :443.
func TestLeakVerdict_ResolverSetOn443ClosesTheLastHatch(t *testing.T) {
	ep := detectFW4(t, "\t\ttcp dport 853 counter jump handle_reject\n"+
		"\t\tiifname \"br-lan\" tcp dport { 443, 853 } ip daddr @doh_v4 reject with tcp reset\n"+
		"\t\tiifname \"br-lan\" udp dport 443 ip daddr @doh_v4 drop\n")

	if !ep.DoHBypassBlocked {
		t.Fatalf("DoHBypassBlocked = false, want true — :443 is restricted to a resolver set")
	}
	if ep.LeakRisk {
		t.Errorf("LeakRisk = true, want false when all three routes are constrained; notes=%q", ep.Notes)
	}
	if len(ep.Notes) != 1 || !strings.Contains(ep.Notes[0], "all three") {
		t.Errorf("note = %q, want the all-three-constrained wording", ep.Notes)
	}
}

// A blanket :443 rule is not DoH handling. The test router rejects udp/443 from the LAN to force TCP
// for QUIC; reading that as a DoH block would clear the verdict on a box with no DNS policy at all.
func TestLeakVerdict_BlanketPort443RuleIsNotDoHBlocking(t *testing.T) {
	ep := detectFW4(t, "\t\tiifname \"br-lan\" udp dport 443 counter reject comment \"QUIC block: force TCP\"\n"+
		"\t\ttcp dport 853 counter jump handle_reject\n")

	if ep.DoHBypassBlocked {
		t.Errorf("DoHBypassBlocked = true for a rule that names no destination — a QUIC block is not "+
			"a DNS policy; notes=%q", ep.Notes)
	}
	if !ep.LeakRisk {
		t.Errorf("LeakRisk = false, want true — nothing here constrains DoH")
	}
}

// The iptables spelling of the same constraint, since the detector reads that first where it exists.
func TestDetectEffectivePath_IptablesResolverSetCountsAsDoHBlocking(t *testing.T) {
	nat := "-A PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53"
	filter := "-A FORWARD -p tcp --dport 853 -j REJECT\n" +
		"-A FORWARD -p tcp --dport 443 -m set --match-set doh_v4 dst -j DROP"

	ep := DetectEffectivePath("", "", nat, nat+"\n"+filter)
	if !ep.Hijack53 {
		t.Fatalf("fixture does not produce the :53 redirect it is built around")
	}
	if !ep.DoTBypassBlocked || !ep.DoHBypassBlocked {
		t.Fatalf("DoT=%v DoH=%v, want both true", ep.DoTBypassBlocked, ep.DoHBypassBlocked)
	}
	if ep.LeakRisk {
		t.Errorf("LeakRisk = true, want false; notes=%q", ep.Notes)
	}

	// Without the set restriction the same port rule proves nothing.
	loose := strings.Replace(filter, " -m set --match-set doh_v4 dst", "", 1)
	ep2 := DetectEffectivePath("", "", nat, nat+"\n"+loose)
	if ep2.DoHBypassBlocked {
		t.Errorf("DoHBypassBlocked = true for `--dport 443 -j DROP` with no destination — that rule " +
			"blocks the web, not a resolver list")
	}
	if !ep2.LeakRisk {
		t.Errorf("LeakRisk = false, want true once the DoH constraint is gone")
	}
}
