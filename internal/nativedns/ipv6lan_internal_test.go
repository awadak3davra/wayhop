package nativedns

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The LAN the IPv6 check looks at is the interfaces the DNS rules are bound to by name. A negated
// binding (`! -i eth3`) covers every interface but the one it names, typically the WAN, and says
// nothing about which interface faces the clients.
func TestReadBypassRules_NegatedInterfaceIsNotTheLAN(t *testing.T) {
	r := readBypassRules(
		"-A PREROUTING ! -i eth3 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n"+
			"-A PREROUTING -i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53\n", "")
	if !r.hijack53 || r.hijack53To != "53" {
		t.Errorf("the redirect must still be read, got %+v", r)
	}
	if named, seen := r.guards("eth3"); named || seen {
		t.Errorf("eth3 is the interface the negated rule leaves out: named=%v seen=%v", named, seen)
	}
	if named, _ := r.guards("br0"); !named {
		t.Error("br0 is bound by name")
	}
	if named, seen := r.guards("br1"); named || !seen {
		t.Errorf("br1 is covered by the negated rule but not named: named=%v seen=%v", named, seen)
	}
}

// The comparison reads the verdict a rule jumps to, not a chain name that contains one. KeeneticOS
// writes `-j _NDM_IC_REDIRECT` (an empty chain) on :53 in ip6tables; read loosely it was an IPv6
// redirect. Mark-conditioned redirects (its hotspot DNS rules, in both families) shut the route
// only for the marked devices.
func TestReadBypassRules_StrictTargetAndConditions(t *testing.T) {
	r := readBypassRules(
		"-A _NDM_DNS_REDIRECT -p udp -m udp --dport 53 -j _NDM_IC_REDIRECT\n"+
			"-A _NDM_HOTSPOT_DNSREDIR -i br0 -p udp -m mark --mark 0xffffaaa -m pkttype --pkt-type unicast -m udp --dport 53 -j REDIRECT --to-ports 41100\n",
		"")
	if !r.hijack53 {
		t.Error("the loose IPv4 signal is unchanged: a :53 nat rule naming REDIRECT reads as a hijack")
	}
	if shut, plain := r.routes[GapPlain53].on("br0"); !shut || plain {
		t.Errorf("br0: want shut by the conditional REDIRECT only, got shut=%v plain=%v", shut, plain)
	}
	if shut, _ := r.routes[GapPlain53].on("br2"); shut {
		t.Error("the jump to _NDM_IC_REDIRECT is not a redirect, and the hotspot rule is bound to br0")
	}
}

// Like is held to like: an unconditional IPv4 redirect needs an unconditional IPv6 one, a
// conditional IPv4 one is matched by any IPv6 rule with a real verdict.
func TestGapsOn_LikeForLike(t *testing.T) {
	plainV4 := readBypassRules("-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53", "")
	condV4 := readBypassRules("-A X -i br0 -p udp -m mark --mark 0x1 -m udp --dport 53 -j REDIRECT --to-ports 41100", "")
	condV6 := readBypassRules("-A X -i br0 -p udp -m mark --mark 0x1 -m udp --dport 53 -j DNAT --to-destination [2001:db8::1]:53", "")
	plainV6 := readBypassRules("-A PREROUTING -i br+ -p udp -m udp --dport 53 -j REDIRECT --to-ports 53", "")
	for _, c := range []struct {
		name   string
		v4, v6 bypassRules
		want   string
	}{
		{"plain v4, nothing v6", plainV4, bypassRules{}, GapPlain53},
		{"plain v4, conditional v6", plainV4, condV6, GapPlain53},
		{"plain v4, wildcard plain v6", plainV4, plainV6, ""},
		{"conditional v4, conditional v6", condV4, condV6, ""},
		{"conditional v4, nothing v6", condV4, bypassRules{}, GapPlain53},
	} {
		if got := strings.Join(gapsOn("br0", c.v4, c.v6), ","); got != c.want {
			t.Errorf("%s: gaps %q, want %q", c.name, got, c.want)
		}
	}
}

// Only an address a client could use to reach a public resolver counts: not link-local, not ULA,
// not loopback, and the interface name loses a VLAN parent suffix.
func TestRoutableIPv6Interfaces(t *testing.T) {
	got := routableIPv6Interfaces("1: lo    inet6 ::1/128 scope host\n" +
		"5: br0    inet6 fe80::1/64 scope link\n" +
		"5: br0    inet6 fd00:db8::1/64 scope global\n" +
		"6: eth0.2@eth0    inet6 2001:db8:1::2/64 scope global\n" +
		"7: br1    inet 192.0.2.1/24 scope global br1\n" +
		"8: br2    inet6 2001:db8:2::1/64 scope global dynamic\n")
	if len(got) != 2 || got[0] != "eth0.2" || got[1] != "br2" {
		t.Errorf("routableIPv6Interfaces = %q, want [eth0.2 br2]", got)
	}
}

// Every table is read, in the shape both iproute2 and BusyBox print: a route in another table carries
// `table T` after its device, and a typed route (unreachable, blackhole) leads with its type.
func TestIPv6DefaultRouteInterfaces(t *testing.T) {
	var asked []string
	run := func(name string, args ...string) (string, error) {
		asked = append(asked, name+" "+strings.Join(args, " "))
		return "default from 2001:db8::/48 via fe80::1 dev eth0.2 proto static metric 512 pref medium\n" +
			"default via fe80::2 dev wan6 metric 1024\n" +
			"default via fe80::3 dev pppoe-wan table 100 proto static metric 512 pref medium\n" +
			"default via fe80::4 dev wan2 table 200 \n" + // BusyBox: no proto, a trailing space
			"unreachable default dev lo table 300 metric 1024 pref medium\n" +
			"blackhole default dev lo table 1003 metric 4000 pref medium\n" +
			"2001:db8:2::/64 dev br-lan proto static metric 1024\n", nil
	}
	got := ipv6DefaultRouteInterfaces(run)
	if len(got) != 4 || !got["eth0.2"] || !got["wan6"] || !got["pppoe-wan"] || !got["wan2"] {
		t.Errorf("ipv6DefaultRouteInterfaces = %v, want eth0.2, wan6, pppoe-wan and wan2", got)
	}
	if len(asked) != 1 || asked[0] != "ip -6 route show table all default" {
		t.Errorf("every table is read in one call, got %q", asked)
	}
}

// An `ip` that refuses `table all` is read from main, as before.
func TestIPv6DefaultRouteInterfacesFallsBackToMain(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		if slices.Contains(args, "all") {
			return "", errors.New("ip: invalid argument 'all' to 'table'")
		}
		return "default via fe80::2 dev wan6 metric 1024\n", nil
	}
	if got := ipv6DefaultRouteInterfaces(run); len(got) != 1 || !got["wan6"] {
		t.Errorf("ipv6DefaultRouteInterfaces = %v, want wan6 from main", got)
	}
}

// A blanket FORWARD refusal is told from one that leaves some packets through.
func TestReadBypassRules_RefuseAll(t *testing.T) {
	r := readBypassRules("", "-A FORWARD -i br0 -j REJECT --reject-with icmp6-port-unreachable\n"+
		"-A FORWARD ! -i eth3 -m comment --comment \"!fw: lan\" -j DROP\n"+
		"-A FORWARD -i br1 -p udp -j DROP\n"+
		"-A zone_lan_forward -j REJECT --reject-with icmp6-port-unreachable\n")
	for iface, want := range map[string]bool{"br0": true, "br1": true, "eth3": false} {
		if got := r.refusesAll(iface); got != want {
			t.Errorf("refusesAll(%s) = %v, want %v", iface, got, want)
		}
	}
	if r := readBypassRules("", "-A FORWARD -i br1 -p udp -j DROP\n-A FORWARD -i br1 -o eth3 -j DROP\n"); r.refusesAll("br1") {
		t.Error("a refusal limited to a protocol or an outgoing interface is not a blanket one")
	}
}
