package nativedns_test

import (
	"errors"
	"strings"
	"testing"

	"wayhop/internal/nativedns"
	"wayhop/internal/pbr"
)

// interceptScript renders the Keenetic DNS intercept exactly as an Apply would (the :53 REDIRECT on
// br0, the :853 REJECT and the :443 REJECTs to the well-known DoH addresses) for a plan that also
// carries a live IPv6 datapath, and splits its iptables commands into what `iptables -t nat -S` and
// `iptables -S` would print back. v6 is every ip6tables command that names a port.
func interceptScript(t *testing.T) (nat, filter, v6 []string) {
	t.Helper()
	io := pbr.IpsetOptions{WanIface: "eth3", DNSIntercept: true, DNSInterceptLAN: "br0", DNSRejectEncrypted: true}
	pl := &pbr.Plan{
		Mask: 0x00ff0000,
		Egresses: []pbr.Egress{
			{Tag: "wan", Kind: pbr.EgressWAN, Table: 254},
			{Tag: "nl", Kind: pbr.EgressInterface, Iface: "nwg1", Mark: 0x00010000, Table: 151},
		},
		Zones: []pbr.Zone{{Name: "yt", EgressTag: "nl", Mark: 0x00010000, Domains: []string{"example.com"}}},
	}
	script := pl.RenderIptablesScript(io)
	if !strings.Contains(script, "ip6tables -t mangle") {
		t.Fatalf("precondition: the plan must carry an IPv6 datapath:\n%s", script)
	}
	for _, ln := range strings.Split(script, "\n") {
		i := strings.Index(ln, "|| ")
		if i < 0 {
			continue
		}
		cmd := ln[i+3:]
		if strings.HasPrefix(cmd, "ip6tables ") {
			if strings.Contains(cmd, "--dport") {
				v6 = append(v6, cmd)
			}
			continue
		}
		if !strings.HasPrefix(cmd, "iptables ") {
			continue
		}
		cmd = strings.Replace(strings.TrimPrefix(cmd, "iptables "), "-I ", "-A ", 1)
		switch {
		case strings.HasPrefix(cmd, "-t nat "):
			nat = append(nat, strings.TrimPrefix(cmd, "-t nat "))
		case strings.HasPrefix(cmd, "-t "):
		default:
			filter = append(filter, cmd)
		}
	}
	return nat, filter, v6
}

// router answers RunEffectivePath's probes. addrs is `ip -o addr`; v6nat/v6filter are what
// ip6tables prints (nil = the read failed).
func router(nat, filter []string, addrs string, v6nat, v6filter []string) nativedns.Runner {
	return routerWithRoutes(nat, filter, addrs, "", v6nat, v6filter)
}

// routerWithRoutes is router with `ip -6 route show default` answering v6routes.
func routerWithRoutes(nat, filter []string, addrs, v6routes string, v6nat, v6filter []string) nativedns.Runner {
	return func(name string, args ...string) (string, error) {
		switch {
		case name == "ip" && len(args) > 0 && args[0] == "-6":
			return v6routes, nil
		case name == "iptables" && len(args) == 3 && args[1] == "nat":
			return strings.Join(nat, "\n"), nil
		case name == "iptables" && len(args) == 1:
			return strings.Join(filter, "\n"), nil
		case name == "ip6tables" && len(args) == 3 && args[1] == "nat":
			return strings.Join(v6nat, "\n"), nil
		case name == "ip6tables" && len(args) == 1:
			return strings.Join(v6filter, "\n"), nil
		case name == "cat":
			return "nameserver 127.0.0.1\n", nil
		case name == "ip":
			return addrs, nil
		}
		return "", nil
	}
}

const (
	addrsV4Only = "1: lo    inet 127.0.0.1/8 scope host lo\n" +
		"5: br0    inet 192.0.2.1/24 brd 192.0.2.255 scope global br0\n" +
		"5: br0    inet6 fe80::1/64 scope link\n" +
		"5: br0    inet6 fd00:db8::1/64 scope global\n"
	addrsV6LAN = addrsV4Only + "5: br0    inet6 2001:db8:24::1/64 scope global dynamic\n"
)

// QA-107. WayHop installs the DNS intercept with iptables only, so on a LAN with IPv6 a client reaches
// a v6 resolver on :53, :853 or :443 untouched. RunEffectivePath never read ip6tables and cleared the
// leak verdict ("all three bypass routes are constrained"), and the DNS page then told the operator
// that clients could not route around it.
func TestRunEffectivePath_IPv6LANWithoutIPv6RulesIsALeakRisk(t *testing.T) {
	nat, filter, v6 := interceptScript(t)
	if len(v6) != 0 {
		t.Fatalf("precondition: this fixture is the iptables-only intercept, got ip6tables rules %q", v6)
	}
	ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, nil, nil))
	if !ep.LeakRisk {
		t.Errorf("the LAN has IPv6 and nothing intercepts or refuses DNS over it, yet LeakRisk=false, notes %q", ep.Notes)
	}
	joined := strings.Join(ep.Notes, " | ")
	if !strings.Contains(joined, "IPv6") {
		t.Errorf("the notes must say IPv6 is the open route, got %q", joined)
	}
	if strings.Contains(joined, "all three bypass routes are constrained") {
		t.Errorf("the notes still claim every route is shut: %q", joined)
	}
}

// Unchanged where the trigger is absent: a router whose LAN has no routable IPv6 (only link-local
// and ULA) keeps the verdict the IPv4 rules earn.
func TestRunEffectivePath_IPv4OnlyLANKeepsItsVerdict(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	ep := nativedns.RunEffectivePath(router(nat, filter, addrsV4Only, nil, nil))
	if ep.LeakRisk || !ep.Hijack53 || !ep.DoTBypassBlocked || !ep.DoHBypassBlocked {
		t.Errorf("an IPv4-only LAN with the full intercept is not a leak risk, got %+v", ep)
	}
}

// The gaps are named, so the panel can say which route IPv6 leaves open.
func TestRunEffectivePath_IPv6GapsNameTheOpenRoutes(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, nil, nil))
	want := []string{nativedns.GapPlain53, nativedns.GapDoT, nativedns.GapDoH}
	if strings.Join(ep.IPv6Gaps, ",") != strings.Join(want, ",") {
		t.Errorf("IPv6Gaps = %q, want %q", ep.IPv6Gaps, want)
	}
	// The IPv4 measurement itself is unchanged: those rules are there.
	if !ep.Hijack53 || !ep.DoTBypassBlocked || !ep.DoHBypassBlocked {
		t.Errorf("the IPv4 rules must still read as present, got %+v", ep)
	}
}

// The same routes shut in ip6tables close the gap, so a dual-stack intercept clears the verdict.
func TestRunEffectivePath_IPv6RulesCloseTheGap(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	v6nat := []string{"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53"}
	v6filter := []string{
		"-A FORWARD -i br0 -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A FORWARD -d 2001:db8::53/128 -i br0 -p tcp -m tcp --dport 443 -j REJECT --reject-with tcp-reset",
	}
	ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, v6nat, v6filter))
	if ep.LeakRisk || len(ep.IPv6Gaps) != 0 {
		t.Errorf("IPv6 shut the same way as IPv4 is not a leak risk, got gaps %q notes %q", ep.IPv6Gaps, ep.Notes)
	}
	// One route left open over IPv6 is still named, alone.
	ep = nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, v6nat, v6filter[:1]))
	if !ep.LeakRisk || strings.Join(ep.IPv6Gaps, ",") != nativedns.GapDoH {
		t.Errorf("only DoH is open over IPv6, got risk=%v gaps %q", ep.LeakRisk, ep.IPv6Gaps)
	}
}

// A routable IPv6 address on an interface the DNS rules do not guard (the WAN, say) is not the LAN's,
// so the IPv4 verdict stands; ip6tables is not even read.
func TestRunEffectivePath_IPv6OffTheLANIsNotTheLANs(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	addrs := addrsV4Only + "3: eth3    inet6 2001:db8:ff::2/64 scope global dynamic\n"
	read := false
	base := router(nat, filter, addrs, nil, nil)
	run := func(name string, args ...string) (string, error) {
		if name == "ip6tables" {
			read = true
		}
		return base(name, args...)
	}
	ep := nativedns.RunEffectivePath(run)
	if ep.LeakRisk || len(ep.IPv6Gaps) != 0 || read {
		t.Errorf("IPv6 on the WAN only must not change the verdict: risk=%v gaps=%q ip6tables read=%v", ep.LeakRisk, ep.IPv6Gaps, read)
	}
}

// ip6tables that cannot be read confirms nothing for IPv6: the gaps stand and the note says why.
func TestRunEffectivePath_UnreadableIPv6FirewallIsNotCoverage(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	base := router(nat, filter, addrsV6LAN, nil, nil)
	run := func(name string, args ...string) (string, error) {
		if name == "ip6tables" {
			return "", errors.New("exec: \"ip6tables\": executable file not found in $PATH")
		}
		return base(name, args...)
	}
	ep := nativedns.RunEffectivePath(run)
	if !ep.LeakRisk || len(ep.IPv6Gaps) != 3 {
		t.Errorf("an unread IPv6 firewall shuts nothing, got risk=%v gaps=%q", ep.LeakRisk, ep.IPv6Gaps)
	}
	if !strings.Contains(strings.Join(ep.Notes, " "), "could not be read") {
		t.Errorf("the note must say the IPv6 firewall was not read, got %q", ep.Notes)
	}
}

// QA-107 on the router it was found on. KeeneticOS fills ip6tables with DNS rules of its own: a jump
// on :53 to an empty chain named _NDM_IC_REDIRECT, and hotspot redirects on br0 that apply only to
// marked devices (shapes read from a live Keenetic, addresses replaced). Neither does what WayHop's
// unconditional IPv4 redirect does, so the IPv6 :53 route is still open; read loosely, either one
// passed for an IPv6 redirect and the gap went unreported on exactly that platform.
func TestRunEffectivePath_KeeneticOwnIPv6DNSRulesDoNotCloseTheGap(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	ndm6 := []string{
		"-A PREROUTING -j _NDM_DNS_REDIRECT",
		"-A _NDM_DNS_REDIRECT -j _NDM_HOTSPOT_DNSREDIR",
		"-A _NDM_DNS_REDIRECT -p udp -m udp --dport 53 -j _NDM_IC_REDIRECT",
		"-A _NDM_DNS_REDIRECT -p tcp -m tcp --dport 53 -j _NDM_IC_REDIRECT",
		"-A _NDM_DNS_REDIRECT -p udp -m udp --dport 53 -j _NDM_DNS_FLT_REDIR",
		"-A _NDM_HOTSPOT_DNSREDIR -i br0 -p udp -m mark --mark 0xffffaaa -m pkttype --pkt-type unicast -m udp --dport 53 -j REDIRECT --to-ports 41100",
		"-A _NDM_HOTSPOT_DNSREDIR -i br0 -p tcp -m mark --mark 0xffffaaa -m pkttype --pkt-type unicast -m tcp --dport 53 -j DNAT --to-destination [2001:db8::53]:53",
	}
	ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, ndm6, []string{"-P FORWARD ACCEPT"}))
	if strings.Join(ep.IPv6Gaps, ",") != "53,dot,doh" || !ep.LeakRisk {
		t.Errorf("KeeneticOS's conditional IPv6 :53 rules are not WayHop's redirect: gaps %q risk=%v", ep.IPv6Gaps, ep.LeakRisk)
	}
}

// Rules bound to no interface (fw3 writes its zone rules that way) cannot say which interface is the
// LAN. An interface the IPv6 default route leaves through is the uplink, not a LAN: a routable
// address there alone must not raise a gap, while one on another interface still does.
func TestRunEffectivePath_UnboundRulesSkipTheIPv6Uplink(t *testing.T) {
	nat := []string{"-A zone_lan_prerouting -p udp -m udp --dport 53 -j REDIRECT --to-ports 53"}
	filter := []string{"-A zone_lan_forward -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset"}
	wan := "3: eth0.2@eth0    inet6 2001:db8:ff::2/64 scope global dynamic\n"
	routes := "default from 2001:db8::/48 via fe80::1 dev eth0.2 proto static metric 512 pref medium\n"
	ep := nativedns.RunEffectivePath(routerWithRoutes(nat, filter, addrsV4Only+wan, routes, nil, nil))
	if len(ep.IPv6Gaps) != 0 {
		t.Errorf("IPv6 on the uplink only is not the LAN's: gaps %q notes %q", ep.IPv6Gaps, ep.Notes)
	}
	ep = nativedns.RunEffectivePath(routerWithRoutes(nat, filter, addrsV6LAN+wan, routes, nil, nil))
	if strings.Join(ep.IPv6Gaps, ",") != "53,dot" || !ep.LeakRisk {
		t.Errorf("br0 holds a routable IPv6 address and nothing shuts IPv6 there: gaps %q risk=%v", ep.IPv6Gaps, ep.LeakRisk)
	}
}

// The uplink's IPv6 default can sit in a table of its own (policy routing on a PPPoE uplink), with
// none in main. Read from main alone, pppoe-wan passed for a LAN: with fw3's unbound zone rules (the
// interface is on the jump) the verdict named three IPv6 gaps and said pppoe-wan was the LAN.
func TestRunEffectivePath_IPv6UplinkDefaultInAnotherTable(t *testing.T) {
	nat := []string{
		"-A PREROUTING -i br-lan -j zone_lan_prerouting",
		"-A zone_lan_prerouting -p udp -m udp --dport 53 -j REDIRECT --to-ports 53",
	}
	filter := []string{"-A zone_lan_forward -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset"}
	wan := "9: pppoe-wan    inet6 2001:db8:ff::2/64 scope global dynamic\n"
	base := routerWithRoutes(nat, filter, addrsV4Only+wan, "", nil, nil) // main: no IPv6 default
	run := func(name string, args ...string) (string, error) {
		if name == "ip" && strings.Join(args, " ") == "-6 route show table all default" {
			return "default from 2001:db8::/48 via fe80::1 dev pppoe-wan table 100 proto static metric 512 pref medium\n", nil
		}
		return base(name, args...)
	}
	ep := nativedns.RunEffectivePath(run)
	if len(ep.IPv6Gaps) != 0 || strings.Contains(strings.Join(ep.Notes, " "), "pppoe-wan") {
		t.Errorf("pppoe-wan is the uplink, its default is in table 100: gaps %q notes %q", ep.IPv6Gaps, ep.Notes)
	}
}

// IPv6 forwarding refused outright on the LAN shuts every route there, whatever port it would use.
// Only a blanket rule counts: one limited to a protocol, a state or another interface does not.
func TestRunEffectivePath_IPv6ForwardingRefusedOutright(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	for _, blanket := range []string{
		"-A FORWARD -i br0 -j REJECT --reject-with icmp6-port-unreachable",
		"-A FORWARD -i br+ -m comment --comment \"no IPv6 out of the LAN\" -j DROP",
		"-A FORWARD -j DROP",
	} {
		ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, nil, []string{"-P FORWARD ACCEPT", blanket}))
		if len(ep.IPv6Gaps) != 0 || ep.LeakRisk {
			t.Errorf("%q refuses every IPv6 packet from br0: gaps %q risk=%v", blanket, ep.IPv6Gaps, ep.LeakRisk)
		}
	}
	for _, partial := range []string{
		"-A FORWARD -i br0 -p tcp -j REJECT --reject-with tcp-reset",
		"-A FORWARD -m conntrack --ctstate INVALID -j DROP",
		"-A FORWARD -i br1 -j REJECT --reject-with icmp6-port-unreachable",
		"-A FORWARD -i br0 -o eth3 -j REJECT --reject-with icmp6-port-unreachable",
	} {
		ep := nativedns.RunEffectivePath(router(nat, filter, addrsV6LAN, nil, []string{partial}))
		if strings.Join(ep.IPv6Gaps, ",") != "53,dot,doh" || !ep.LeakRisk {
			t.Errorf("%q leaves IPv6 DNS from br0 open: gaps %q risk=%v", partial, ep.IPv6Gaps, ep.LeakRisk)
		}
	}
}

// The note is read by people: one finding per sentence, not a chain of clauses joined by "so".
func TestRunEffectivePath_IPv6NoteIsPlainSentences(t *testing.T) {
	nat, filter, _ := interceptScript(t)
	unreadable := func(name string, args ...string) (string, error) {
		if name == "ip6tables" {
			return "", errors.New("exec: \"ip6tables\": executable file not found in $PATH")
		}
		return router(nat, filter, addrsV6LAN, nil, nil)(name, args...)
	}
	for _, run := range []nativedns.Runner{router(nat, filter, addrsV6LAN, nil, nil), unreadable} {
		ep := nativedns.RunEffectivePath(run)
		note := ep.Notes[len(ep.Notes)-1]
		if !strings.HasPrefix(note, "The LAN also has IPv6: br0 holds a routable address. The :53 redirect") {
			t.Errorf("the note leads with where IPv6 is, then what covers IPv4 only: %q", note)
		}
		for _, sentence := range strings.Split(note, ". ") {
			if strings.Count(sentence, " so ") > 1 {
				t.Errorf("one finding per sentence, got %q in %q", sentence, note)
			}
		}
	}
}
