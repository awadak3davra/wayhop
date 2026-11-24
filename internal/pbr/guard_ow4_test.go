package pbr

import (
	"net/netip"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// providerRoutes is routes of devices that are not the LAN side: the uplink, the physical port
// under a PPPoE session, a device no firewall zone holds.
func providerRoutes(pairs ...string) []GuardLocal {
	out := localRoutes(pairs...)
	for i := range out {
		out[i].House = false
	}
	return out
}

// namedProfileOW4 is a kill-switched list that names one private network, by the tunnels awg0 and
// awg1 (two members: a group of one lets any of the plan's tunnels through, see NOTES).
func namedProfileOW4(cidr string) *model.Profile {
	p := guardProfile()
	p.Groups = append(p.Groups, model.Group{ID: "grp-office", Name: "Office", Type: model.GroupFallback, Members: []string{"nl", "ru"}, KillSwitch: true})
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "office", Name: "Office", Outbound: "grp-office", Enabled: true, Manual: []string{cidr}})
	return p
}

// The collision. The office is 192.168.78.0/24 and so is the segment between the
// router and the provider's box. The accept for "the router's own routes" passed the whole list by
// the provider's device, ahead of the kill switch.
func TestGuardDropsANamedNetworkOnTheProvidersSegmentWithTheSameNumbers(t *testing.T) {
	plan := compileGuard(t, namedProfileOW4("192.168.78.0/24"))
	local := append(localRoutes("br-lan", "192.168.2.0/24"), providerRoutes("wan", "192.168.78.0/24")...)
	program := plan.RenderNftGuardWith(NamesHold{Local: local})
	if strings.Contains(program, `oifname "wan"`) {
		t.Errorf("the provider's device is accepted for a network the list names:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("the office by the provider's segment", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.10", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the office's resolver by the provider's segment", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.1", iif: "br-lan", oif: "wan", proto: "udp"}, "drop")
	g.want("the office by its tunnel", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.10", iif: "br-lan", oif: "awg0"}, "accept")
	g.want("the office answers", guardPkt{saddr: "192.168.78.10", daddr: "192.168.2.20", iif: "awg0", oif: "br-lan", reply: true}, "accept")
	g.want("the internet answers a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
}

// Dual access. The default route is on pppoe-wan, and the provider's own 10.0.0.0/8 is
// routed by the physical port wan (DHCP option 121). wan carries no default route: it was taken for a
// device of the LAN, and the office inside 10.0.0.0/8 left by it.
func TestGuardDropsANamedNetworkOnThePortUnderAPPPoESession(t *testing.T) {
	plan := compileGuard(t, namedProfileOW4("10.77.0.0/16"))
	local := append(localRoutes("br-lan", "192.168.2.0/24"), providerRoutes("wan", "10.0.0.0/8", "wan", "10.64.0.0/10", "pppoe-wan", "100.64.0.1/32")...)
	program := plan.RenderNftGuardWith(NamesHold{Local: local})
	g := parseGuard(t, program)
	g.want("the office by the port under PPPoE", guardPkt{saddr: "192.168.2.20", daddr: "10.77.1.1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the office by the PPPoE session", guardPkt{saddr: "192.168.2.20", daddr: "10.77.1.1", iif: "br-lan", oif: "pppoe-wan"}, "drop")
	g.want("the office by its tunnel", guardPkt{saddr: "192.168.2.20", daddr: "10.77.1.1", iif: "br-lan", oif: "awg0"}, "accept")
	// The rest of the provider's range is not the list's: private space the plane keeps on main.
	g.want("the provider's own network", guardPkt{saddr: "192.168.2.20", daddr: "10.1.2.3", iif: "br-lan", oif: "wan"}, "accept")

	// A segment of the LAN inside the named network is still the LAN's.
	local = append(local, localRoutes("br-lab", "10.77.5.0/24")...)
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Local: local}))
	g.want("the lab segment", guardPkt{saddr: "192.168.2.20", daddr: "10.77.5.9", iif: "br-lan", oif: "br-lab"}, "accept")
	g.want("the lab's address by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.77.5.9", iif: "br-lan", oif: "wan"}, "drop")

	// One of the plan's tunnels is never the LAN side, whatever the firewall says about its zone.
	local = append(local, localRoutes("awg2", "10.77.8.0/24")...)
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Local: local}))
	g.want("the office by another tunnel", guardPkt{saddr: "192.168.2.20", daddr: "10.77.8.1", iif: "br-lan", oif: "awg2"}, "drop")
}

// A list that only sweeps private space (0.0.0.0/0) keeps what it had: the page of the modem on the
// uplink's own segment stays reachable. A network another list names inside it does not.
func TestGuardKeepsTheModemsPageForAListThatOnlySweepsPrivateSpace(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "0.0.0.0/0")
	plan := compileGuard(t, p)
	j := plan.judgedPrivate()
	if len(j.named4) != 0 || len(j.swept4) != 3 {
		t.Fatalf("setup: named %v swept %v", j.named4, j.swept4)
	}
	local := append(localRoutes("br-lan", "192.168.2.0/24"), providerRoutes("wan", "192.168.78.0/24")...)
	program := plan.RenderNftGuardWith(NamesHold{Local: local})
	if !strings.Contains(program, `oifname "wan" ip daddr { 192.168.78.0/24 } accept`) {
		t.Errorf("the uplink's own segment is not accepted for a list that only sweeps it:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("the modem's page", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.1", iif: "br-lan", oif: "wan"}, "accept")
	g.want("a reply to the LAN", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("private space the router has no route for", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "wan"}, "drop")

	// Both at once: the modem's segment is swept by one list and named by another.
	p.Groups = append(p.Groups, model.Group{ID: "grp-office", Name: "Office", Type: model.GroupFallback, Members: []string{"nl"}, KillSwitch: true})
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "office", Name: "Office", Outbound: "grp-office", Enabled: true, Manual: []string{"192.168.78.0/24"}})
	plan = compileGuard(t, p)
	j = plan.judgedPrivate()
	if len(j.named4) != 1 || len(j.swept4) != 3 {
		t.Fatalf("setup: named %v swept %v", j.named4, j.swept4)
	}
	// The plane's own answer does not change with the split.
	if got := plan.UnpinnedPrivate(); len(got) != 3 || got[2] != netip.MustParsePrefix("192.168.0.0/16") {
		t.Errorf("the plane unpins %v", got)
	}
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Local: local}))
	g.want("a named network on the modem's segment", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a reply to the LAN", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
}

// When the guard was not told all of the LAN's routes, a LAN it does not know keeps
// its answers: the reply direction passes by any device that is not the provider's or a tunnel. A
// new connection to a kill-switched destination is judged as always.
func TestGuardLetsAnswersThroughWhenItWasNotToldAllOfTheHouse(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "0.0.0.0/0")
	plan := compileGuard(t, p)
	whole := plan.RenderNftGuardWith(NamesHold{})
	g := parseGuard(t, whole)
	g.want("setup: a LAN the guard was not told about", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "drop")

	partial := plan.RenderNftGuardWith(NamesHold{LocalPartial: true, Provider: []string{"wan", "pppoe-wan", `x"; drop`}})
	if strings.Contains(partial, "drop\"") {
		t.Errorf("a device name was written as it came:\n%s", partial)
	}
	g = parseGuard(t, partial)
	g.want("an answer to the LAN", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("an answer to a guest segment", guardPkt{saddr: "93.184.216.34", daddr: "10.0.9.20", iif: "awg0", oif: "br-guest", reply: true}, "accept")
	g.want("a new connection by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a reply direction by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "wan", reply: true}, "drop")
	g.want("a reply direction by the PPPoE session", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "pppoe-wan", reply: true}, "drop")
	g.want("a reply direction by another tunnel", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "awg0", reply: true}, "drop")
	g.want("a public kill-switched address by the provider", guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the same as a reply direction", guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wan", reply: true}, "drop")

	// A plan whose kill switch covers no private destination does not change with it.
	plain := compileGuard(t, guardProfile())
	if a, b := plain.RenderNftGuardWith(NamesHold{}), plain.RenderNftGuardWith(NamesHold{LocalPartial: true, Provider: []string{"wan"}}); a != b {
		t.Errorf("the program of a plan with no judged private destination changed:\n%s", b)
	}
}

// A device whose side is not known (no firewall zone holds it, or its zone holds the uplink too)
// keeps its answers, by that device and to its own segment only. A new connection to a network a
// list names is not opened by a guess, and a tunnel or the core's TUN is never such a device.
func TestGuardLetsAnswersThroughToADeviceOfUnknownSide(t *testing.T) {
	plan := compileGuard(t, namedProfileOW4("192.168.0.0/16"))
	unsure := func(pairs ...string) []GuardLocal {
		out := providerRoutes(pairs...)
		for i := range out {
			out[i].Candidate = true
		}
		return out
	}
	local := append(unsure("br-lan", "192.168.2.0/24", "awg0", "192.168.77.0/24", "tun9", "192.168.99.0/30"), providerRoutes("wan", "192.168.78.0/24")...)
	program := plan.RenderNftGuardWith(NamesHold{Local: local, Pass: []string{"tun9"}})
	if !strings.Contains(program, `oifname "br-lan" ct direction reply ip daddr { 192.168.2.0/24 } accept`) ||
		strings.Contains(program, `oifname "awg0" ct direction reply`) || strings.Contains(program, `oifname "tun9" ct direction reply`) ||
		strings.Contains(program, `oifname "wan"`) {
		t.Errorf("answers to a device of unknown side:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("the internet answers a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("a new connection to the LAN from another segment", guardPkt{saddr: "10.8.0.2", daddr: "192.168.2.20", iif: "wg0", oif: "br-lan"}, "drop")
	g.want("an answer by that device to another network", guardPkt{saddr: "93.184.216.34", daddr: "192.168.40.20", iif: "wan", oif: "br-lan", reply: true}, "drop")
	g.want("the named network by the provider's segment", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.10", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a reply direction by the provider's segment", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.10", iif: "br-lan", oif: "wan", reply: true}, "drop")
	g.want("the named network by its tunnel", guardPkt{saddr: "192.168.2.20", daddr: "192.168.78.10", iif: "br-lan", oif: "awg0"}, "accept")

	// Told that the LAN is not known in full, the one broad rule says it instead.
	if partial := plan.RenderNftGuardWith(NamesHold{Local: local, LocalPartial: true}); strings.Contains(partial, `oifname "br-lan" ct direction reply`) {
		t.Errorf("both rules for one thing:\n%s", partial)
	}
	// A plan whose kill switch covers no private destination does not change with it.
	plain := compileGuard(t, guardProfile())
	if a, b := plain.RenderNftGuardWith(NamesHold{}), plain.RenderNftGuardWith(NamesHold{Local: local}); a != b {
		t.Errorf("the program of a plan with no judged private destination changed:\n%s", b)
	}
}

// With an IPv6 hold, only the LAN's routes are accepted ahead of it: the
// public prefix on the provider's link is not.
func TestGuardIPv6HoldPassesOnlyTheHousesOwnPrefixes(t *testing.T) {
	plan := compileGuard(t, guardProfile())
	local := append(localRoutes("br-lan", "2001:db8:aa::/64"), providerRoutes("wan", "2001:db8:bb::/64")...)
	program := plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"whtun0", "awg0", "awg1", "awg2"}, V6: true, Local: local})
	if !strings.Contains(program, `oifname "br-lan" ip6 daddr { 2001:db8:aa::/64 } accept`) || strings.Contains(program, "2001:db8:bb::/64") {
		t.Errorf("the IPv6 routes ahead of the hold:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("a connection from outside to a LAN host", guardPkt{v6: true, saddr: "2606:4700::1", daddr: "2001:db8:aa::5", iif: "wan", oif: "br-lan"}, "accept")
	g.want("a new connection to the provider's link", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2001:db8:bb::9", iif: "br-lan", oif: "wan"}, "drop")
}

// The elements of one anonymous set do not overlap: the provider's pushed 10.0.0.0/8 beside its
// connected 10.64.0.0/18 on the same device, and a named network inside a swept range.
func TestGuardRendersNoOverlappingElements(t *testing.T) {
	p := namedProfileOW4("10.77.0.0/16")
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "0.0.0.0/0")
	plan := compileGuard(t, p)
	program := plan.RenderNftGuardWith(NamesHold{LocalPartial: true,
		Local: providerRoutes("wan", "10.64.0.0/18", "wan", "10.0.0.0/8", "wan", "192.168.78.0/24")})
	for _, want := range []string{`oifname "wan" ip daddr { 10.0.0.0/8, 192.168.78.0/24 } accept`,
		"ct direction reply ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"} {
		if !strings.Contains(program, want) {
			t.Errorf("no %q in:\n%s", want, program)
		}
	}
}
