package nativedns

import "testing"

// Fixtures are a SANITIZED subset of a real KeeneticOS 5.01 device (doc-range IPs, no home topology),
// kept structurally faithful so the parser is tested against the real netstat/iptables-S shapes.
const (
	realResolvConf = "nameserver 1.1.1.1\noptions timeout:1 attempts:1 rotate\n"

	realNetstat = `Active Internet connections (only servers)
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN      928/dnsmasq
tcp        0      0 :::53                   :::*                    LISTEN      928/dnsmasq
udp        0      0 0.0.0.0:53              0.0.0.0:*                           928/dnsmasq
udp        0      0 :::53                   :::*                                928/dnsmasq
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1/init
`
	// NDM force-redirects marked LAN :53 to a local resolver port (41100). Sanitized router/LAN IPs.
	realNat = `-N _NDM_DNS_REDIRECT
-A PREROUTING -j _NDM_DNS_REDIRECT
-A _NDM_HOTSPOT_DNSREDIR -d 192.0.2.1/32 -i br0 -p udp -m mark --mark 0xffffaaa -m pkttype --pkt-type unicast -m udp --dport 53 -j REDIRECT --to-ports 41100
-A _NDM_HOTSPOT_DNSREDIR -d 192.0.2.1/32 -i br0 -p tcp -m mark --mark 0xffffaaa -m pkttype --pkt-type unicast -m tcp --dport 53 -j REDIRECT --to-ports 41100
`
)

func TestDetectEffectivePath_RealKeenetic(t *testing.T) {
	ep := DetectEffectivePath(realResolvConf, realNetstat, realNat, realNat)

	if len(ep.Upstreams) != 1 || ep.Upstreams[0] != "1.1.1.1" {
		t.Errorf("upstreams = %v, want [1.1.1.1]", ep.Upstreams)
	}
	// 4 dnsmasq :53 listeners (tcp/udp x v4/v6); the :80 line must be ignored.
	if len(ep.Listeners) != 4 {
		t.Fatalf("want 4 :53 listeners, got %d: %#v", len(ep.Listeners), ep.Listeners)
	}
	for _, l := range ep.Listeners {
		if l.Process != "dnsmasq" {
			t.Errorf("listener process = %q, want dnsmasq", l.Process)
		}
		if l.Proto != "tcp" && l.Proto != "udp" {
			t.Errorf("listener proto = %q", l.Proto)
		}
	}
	if !ep.Hijack53 || ep.Hijack53To != "41100" {
		t.Errorf("want :53 hijack to 41100, got hijack=%v to=%q", ep.Hijack53, ep.Hijack53To)
	}
	if ep.DoHBypassBlocked {
		t.Error("no :853 rule present — DoHBypassBlocked must be false")
	}
	// Redirect present but DoT unblocked => a client using its own DoH/DoT still leaks.
	if !ep.LeakRisk {
		t.Error("LeakRisk must be true: :53 hijacked but DoT/DoH bypass not blocked")
	}
}

// A :853 REJECT is DoT handling and nothing more. This case used to assert that it cleared the leak
// verdict, which is the conflation the detector was built on: DoH rides ordinary HTTPS on :443, so a
// rule about :853 is not evidence about it. The expectation is corrected here rather than the code,
// because the evidence comes from the protocols and from the test router's own ruleset, not from either.
func TestDetectEffectivePath_DoTBlockedStillLeaksOverDoH(t *testing.T) {
	nat := `-A _NDM_HOTSPOT_DNSREDIR -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 41100`
	filter := `-A FORWARD -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset`
	ep := DetectEffectivePath(realResolvConf, realNetstat, nat, nat+"\n"+filter)
	if !ep.Hijack53 {
		t.Error("want hijack53")
	}
	if !ep.DoTBypassBlocked {
		t.Error("a :853 REJECT must set DoTBypassBlocked")
	}
	if ep.DoHBypassBlocked {
		t.Error("a :853 rule says nothing about DoH and must not set DoHBypassBlocked")
	}
	if !ep.LeakRisk {
		t.Error("DoH is unconstrained, so a client with its own DoH resolver still bypasses the router")
	}
}

func TestDetectEffectivePath_OpenBoxIsLeakRisk(t *testing.T) {
	// No :53 redirect, no :853 block: nothing constrains client DNS -> leak risk.
	ep := DetectEffectivePath(realResolvConf, realNetstat, "", "")
	if ep.Hijack53 || ep.DoHBypassBlocked {
		t.Errorf("expected no hijack/no block, got %+v", ep)
	}
	if !ep.LeakRisk {
		t.Error("an unconstrained box must be flagged LeakRisk")
	}
}

func TestDetectEffectivePath_EmptyIsSafe(t *testing.T) {
	ep := DetectEffectivePath("", "", "", "") // non-router host: no panic, low-signal result
	if len(ep.Listeners) != 0 || len(ep.Upstreams) != 0 || ep.Hijack53 {
		t.Errorf("empty inputs must yield an empty path, got %+v", ep)
	}
}

func TestRunEffectivePath_Hijack53Gaps(t *testing.T) {
	ipAddr := "1: lo    inet 127.0.0.1/8 scope host lo\n" +
		"2: br0    inet 192.168.77.1/24 brd 192.168.1.255 scope global br0\n" +
		"3: br1    inet 192.168.2.1/24 brd 192.168.2.255 scope global br1\n"

	t.Run("rule bound to br0 gives gap br1", func(t *testing.T) {
		run := func(name string, args ...string) (string, error) {
			switch name {
			case "iptables":
				if len(args) >= 3 && args[1] == "nat" {
					return "-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n", nil
				}
				return "", nil
			case "ip":
				return ipAddr, nil
			default:
				return "", nil
			}
		}
		ep := RunEffectivePath(run)
		if len(ep.Hijack53Gaps) != 1 || ep.Hijack53Gaps[0] != "br1" {
			t.Fatalf("want Hijack53Gaps [br1], got %v", ep.Hijack53Gaps)
		}
	})

	t.Run("rule with no interface gives no gap", func(t *testing.T) {
		run := func(name string, args ...string) (string, error) {
			switch name {
			case "iptables":
				if len(args) >= 3 && args[1] == "nat" {
					return "-A PREROUTING -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n", nil
				}
				return "", nil
			case "ip":
				return ipAddr, nil
			default:
				return "", nil
			}
		}
		ep := RunEffectivePath(run)
		if len(ep.Hijack53Gaps) != 0 {
			t.Fatalf("want no Hijack53Gaps, got %v", ep.Hijack53Gaps)
		}
	})
}

// The shape a real Keenetic has: its own redirects name every bridge but only for lookups addressed to
// the router, and WayHop's interception covers one bridge.
func TestHijack53GapsIgnoreRedirectsForTheRoutersOwnAddress(t *testing.T) {
	nat := "-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n" +
		"-A _NDM_HOTSPOT_DNSREDIR -d 192.168.78.1/32 -i br0 -p udp -m mark --mark 0xffffaaa -m udp --dport 53 -j REDIRECT --to-ports 41100\n" +
		"-A _NDM_HOTSPOT_DNSREDIR -d 10.1.30.1/32 -i br1 -p udp -m mark --mark 0xffffaaa -m udp --dport 53 -j REDIRECT --to-ports 41100\n"
	addrs := "37: br0    inet 192.168.78.1/24 scope global br0\n38: br1    inet 10.1.30.1/24 scope global br1\n"
	got := detectHijack53Gaps(readBypassRules(nat, nat).routes[GapPlain53], addrs, nil, false, "")
	if len(got) != 1 || got[0] != "br1" {
		t.Errorf("gaps = %v, want br1 alone", got)
	}
}

func TestHijack53GapsSkipTheBridgeFacingTheProvider(t *testing.T) {
	addrs := "3: br-wan    inet 10.0.0.2/24 scope global br-wan\n4: br-lan    inet 192.168.77.1/24 scope global br-lan\n"
	nat := "-A PREROUTING -i br-lan -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n"
	got := detectHijack53Gaps(readBypassRules(nat, nat).routes[GapPlain53], addrs, nil, false, "default via 10.0.0.1 dev br-wan")
	if len(got) != 0 {
		t.Errorf("gaps = %v, want none", got)
	}
}
