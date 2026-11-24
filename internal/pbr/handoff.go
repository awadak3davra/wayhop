package pbr

import (
	"fmt"
	"strings"
)

// handoff.go lets a domain list keep its own names on an address it shares with a stronger list.
//
// IP-level marking cannot tell two sites on one address apart. A domain list sent direct (for
// example IP-check sites: api.ipify.org, checkip.amazonaws.com, ifconfig.me) has dnsmasq put
// shared Cloudflare/AWS anycast addresses in its set; refilter holds the same addresses. Whichever
// mark comes last takes every site on them. Precedence (orderZonesForEmit) now gives the address to
// the stronger list, and the hand-off gives the domain list's OWN names back to it:
//
//   - In the mangle chain, after every zone's mark, a packet to an address in both the domain list's
//     set and a stronger list's set gets HandoffBit as well (two set matches in one rule).
//   - An ip rule before every egress rule sends LAN packets with HandoffBit into HandoffTable, whose
//     only route is the sing-box hand-off TUN. sing-box sniffs SNI/Host: the domain list's names leave
//     by its egress (a direct outbound with that egress's mark), everything else by a direct outbound
//     marked HandoffReturnBit, which a mangle OUTPUT chain of its own (HandoffOutputChain: the LAN
//     chain's destination rules without any device match, which the OUTPUT hook refuses) classifies
//     like LAN traffic, so it takes the stronger list's mark and egress.
//   - The return bit has routing of its own that cannot fall back to the main table:
//     while OUTPUT has not classified a packet (NDM wiped mangle OUTPUT, the jump is missing) it is
//     looked up in HandoffReturnTable, whose only route is the loopback device, so connect() succeeds,
//     the re-mark in OUTPUT reroutes the packet, and an unclassified one is delivered to nothing.
//     Behind that table a blackhole rule holds the bit should the route be gone.
//   - Without sing-box (core stopped, device gone) the table is empty, the lookup goes on, and the
//     packet's own mark routes it: the stronger list wins, never direct for a name not in the list.
//
// Under a kill switch the precedence is absolute: nothing fail-closed is handed off at all, on either
// side, until sing-box's wildcard bind (handoffcore.go) is proven on a router: bound to the WAN device
// despite it, a hand-off outbound would leave by the WAN whatever its mark.
// IPv4 only: the hand-off TUN carries no IPv6, and a v6 overlap stays with the stronger list.

const (
	// HandoffBit and HandoffReturnBit are outside the plan's mask and outside NDM's policy marks
	// (0x0ffffaXX, the top nibble clear), so neither is ever read as the other.
	HandoffBit       uint32 = 0x20000000
	HandoffReturnBit uint32 = 0x10000000
	// HandoffIfaceDefault is the hand-off TUN's device, HandoffAddr its address (clear of the
	// compatibility TUNs, which count up from 172.19.8.0/30).
	HandoffIfaceDefault = "wrho0"
	HandoffAddr         = "172.19.255.253/30"
)

// HandoffTable is the routing table holding the route into the hand-off TUN.
func HandoffTable(opt Options) int {
	opt.withDefaults()
	return opt.TableBase + 257
}

// HandoffReturnTable is the routing table of sing-box's return traffic before mangle OUTPUT has
// classified it: its only route is the loopback device.
func HandoffReturnTable(opt Options) int {
	opt.withDefaults()
	return opt.TableBase + 258
}

// handoffRulePref precedes every egress rule (RulePref+i) and the private excludes (RulePref-3..-1).
func handoffRulePref(opt Options) int { return opt.RulePref - 5 }

// The return bit's rules come before every other WayHop rule: the table rule, its make-before-break
// copy, and the blackhole rule behind them.
func handoffReturnRulePref(opt Options) int  { return opt.RulePref - 9 }
func handoffReturnStagePref(opt Options) int { return opt.RulePref - 8 }
func handoffReturnHoldPref(opt Options) int  { return opt.RulePref - 7 }

// HandoffOutputChain names the mangle chain OUTPUT jumps to for the return bit.
func HandoffOutputChain(io IpsetOptions) string {
	io.withDefaults()
	return io.Chain + "_HO"
}

// handoffReturnSpecs are the return bit's v4 rule selector (the bit set, no plan mark yet) and the v6
// one (any packet with the bit: there is no v6 classification at all).
func (pl *Plan) handoffReturnSpecs() (v4, v6 string) {
	bit := hexMark(HandoffReturnBit)
	return fmt.Sprintf("fwmark %s/%s", bit, hexMark(HandoffReturnBit|pl.Mask)), fmt.Sprintf("fwmark %s/%s", bit, bit)
}

// HandoffPair is one overlap the hand-off resolves: a domain zone and a stronger zone after it.
type HandoffPair struct {
	Domain, Stronger string
}

// HandoffRoute is what sing-box does with one domain zone's names: leave with Mark.
type HandoffRoute struct {
	Zone    string
	Domains []string
	Mark    uint32
}

// Handoff is the plan's overlaps that sing-box resolves by name.
type Handoff struct {
	Pairs  []HandoffPair
	Routes []HandoffRoute
}

// Active reports whether there is anything to hand off.
func (h Handoff) Active() bool { return len(h.Pairs) > 0 }

// Handoff lists the overlaps of the plan's domain zones with the stronger zones emitted after them.
// Both must cover every source (a device scope does not survive the round trip through sing-box,
// which re-originates the connection from the router), the stronger one must carry IPv4 and route
// elsewhere, and neither may be fail-closed (see the file comment).
func (pl *Plan) Handoff() Handoff {
	fc := map[string]bool{}
	kind := map[string]EgressKind{}
	for _, e := range pl.Egresses {
		fc[e.Tag] = e.Kind == EgressInterface && e.FailClosed
		kind[e.Tag] = e.Kind
	}
	var h Handoff
	for i, x := range pl.Zones {
		if !zoneHasDomains(x) || x.SrcScoped || x.NDMPolicy != "" || kind[x.EgressTag] == EgressBlackhole {
			continue
		}
		paired := false
		for _, y := range pl.Zones[i+1:] {
			if y.SrcScoped || y.Mark == x.Mark || kind[y.EgressTag] == EgressBlackhole ||
				(len(y.V4) == 0 && !zoneHasDomains(y)) || fc[y.EgressTag] || fc[x.EgressTag] {
				continue
			}
			h.Pairs = append(h.Pairs, HandoffPair{Domain: x.Name, Stronger: y.Name})
			paired = true
		}
		if paired {
			h.Routes = append(h.Routes, HandoffRoute{Zone: x.Name, Domains: x.Domains, Mark: x.Mark})
		}
	}
	return h
}

// handoffOn reports whether io asks for the hand-off and it can be rendered.
func (pl *Plan) handoffOn(io IpsetOptions) bool {
	return io.HandoffIface != "" && validOffloadDev.MatchString(io.HandoffIface) &&
		len(lanIfaces(io.LANIfaces)) > 0 && pl.Handoff().Active()
}

// handoffChainSpecs are the v4 chain rules that add HandoffBit to an overlap's packets. They go last,
// after the access policies' slot rewrite, which sets the whole mark.
func (pl *Plan) handoffChainSpecs(io IpsetOptions) []string {
	// The stronger zone's mark must be the one the packet ended with: an address a third, kill-switched
	// list also holds is that list's, and is not handed off on behalf of the weaker pair.
	markOf := map[string]uint32{}
	for _, z := range pl.Zones {
		markOf[z.Name] = z.Mark
	}
	var out []string
	for _, p := range pl.Handoff().Pairs {
		for _, d := range pl.handoffZoneSets(io, p.Domain) {
			for _, st := range pl.handoffZoneSets(io, p.Stronger) {
				out = append(out, fmt.Sprintf("-m set --match-set %s dst -m set --match-set %s dst -m mark --mark %s/%s -j MARK --set-xmark %s/%s",
					d, st, hexMark(markOf[p.Stronger]), hexMark(pl.Mask), hexMark(HandoffBit), hexMark(HandoffBit)))
			}
		}
	}
	return out
}

// handoffZoneSets is a zone's v4 destination sets: its own set and, in fast mode (DynamicDomainSets),
// the wd_ set its names' answers go to. Without the dynamic sets it is the one set it always was.
func (pl *Plan) handoffZoneSets(io IpsetOptions, zone string) []string {
	out := []string{io.setName(zone, "4")}
	if !io.DynamicDomainSets {
		return out
	}
	for _, z := range pl.Zones {
		if z.Name == zone && zoneHasDomains(z) {
			return append(out, io.dynamicSetName(zone, "4"))
		}
	}
	return out
}

// handoffOutputJump classifies sing-box's re-originated hand-off traffic like LAN traffic, in chain ch.
func handoffOutputJump(ch string) string {
	return fmt.Sprintf("-m mark --mark %s/%s -j %s", hexMark(HandoffReturnBit), hexMark(HandoffReturnBit), ch)
}

// legacyOutputJumpDelete removes the OUTPUT jump into the LAN chain an earlier plane installed. The LAN
// chain holds `-m mac` rules for device-scoped lists, which the kernel refuses in a chain reachable from
// OUTPUT: with that jump in place the restore commit of a chain with a mac rule is refused. It goes
// before the LAN chain is written, whether or not this plane hands off.
func legacyOutputJumpDelete(ch string) string {
	return fmt.Sprintf("while iptables -t mangle -D OUTPUT %s 2>/dev/null; do :; done\n", handoffOutputJump(ch))
}

// handoffOutputSpecs is the OUTPUT chain: the LAN chain's destination-only rules, so a packet takes the
// same mark it would take arriving from the LAN, without anything that names a device or an input
// interface (refused in OUTPUT), the access policies' rewrite or the hand-off's own bit.
func (pl *Plan) handoffOutputSpecs(io IpsetOptions) []string {
	mask := hexMark(pl.Mask)
	var out []string
	if len(pl.BypassV4) > 0 {
		out = append(out, fmt.Sprintf("-m set --match-set %s dst -j RETURN", io.SetPrefix+"bypass_4"))
	}
	if io.S86Mark != 0 {
		out = append(out, fmt.Sprintf("-m mark --mark %s/0xffffffff -j RETURN", hexMark(io.S86Mark)))
	}
	out = append(out, fmt.Sprintf("-j CONNMARK --restore-mark --nfmask %s --ctmask %s", mask, mask))
	for _, z := range pl.Zones {
		if z.SrcScoped || z.NDMPolicy != "" || (len(z.V4) == 0 && !zoneHasDomains(z)) {
			continue
		}
		for _, set := range pl.handoffZoneSets(io, z.Name) {
			out = append(out, fmt.Sprintf("-m set --match-set %s dst -j MARK --set-xmark %s/%s", set, hexMark(z.Mark), mask))
		}
	}
	return append(out, fmt.Sprintf("-j CONNMARK --save-mark --nfmask %s --ctmask %s", mask, mask))
}

// renderHandoffIP writes the hand-off rule (LAN interfaces only: sing-box's own packets carry the bit
// too, from the OUTPUT classification, and must not loop back) and the route into the TUN. The route
// is best-effort: with the TUN not up yet the table stays empty and the stronger list routes.
//
// Then the return bit's routing, installed before sing-box can set the bit and before the
// OUTPUT chain re-marks anything: its table's loopback route (not best-effort: the postcheck reads it
// back), the table rule make-before-break, and a blackhole rule behind them for the bit with no plan
// mark, should the route be gone. v6 has no classification at all, so its return traffic is refused.
func (pl *Plan) renderHandoffIP(b *strings.Builder, opt Options, io IpsetOptions) {
	if !pl.handoffOn(io) {
		return
	}
	opt.withDefaults()
	bit := hexMark(HandoffBit)
	b.WriteString("# overlap hand-off: a domain list's own names on an address a stronger list holds go by sing-box.\n")
	for _, ifc := range lanIfaces(io.LANIfaces) {
		spec := fmt.Sprintf("iif %s fwmark %s/%s table %d priority %d", ifc, bit, bit, HandoffTable(opt), handoffRulePref(opt))
		fmt.Fprintf(b, "ip rule del %s 2>/dev/null || true\n", spec)
		fmt.Fprintf(b, "ip rule add %s\n", spec)
	}
	fmt.Fprintf(b, "ip route replace default dev %s table %d 2>/dev/null || true\n", io.HandoffIface, HandoffTable(opt))
	b.WriteString("# sing-box's return traffic: never the main table, whatever state mangle OUTPUT is in.\n")
	v4, v6 := pl.handoffReturnSpecs()
	fmt.Fprintf(b, "ip route replace default dev lo table %d\n", HandoffReturnTable(opt))
	writeTableRule(b, "ip", fmt.Sprintf("%s table %d", v4, HandoffReturnTable(opt)), handoffReturnRulePref(opt), handoffReturnStagePref(opt))
	hold := fmt.Sprintf("%s type blackhole priority %d", v4, handoffReturnHoldPref(opt))
	fmt.Fprintf(b, "ip rule del %s 2>/dev/null || true\nip rule add %s\n", hold, hold)
	hold6 := fmt.Sprintf("%s type blackhole priority %d", v6, handoffReturnHoldPref(opt))
	fmt.Fprintf(b, "ip -6 rule del %s 2>/dev/null || true\nip -6 rule add %s\n", hold6, hold6)
}

// renderHandoffChainTeardown removes what re-marks the hand-off's return traffic: the OUTPUT jump and
// the OUTPUT chain. It runs first in the teardown, before any rule that routes a mark goes. (A jump an
// earlier plane put into the LAN chain is removed by that plane's own teardown, and by every program
// before it writes the LAN chain.)
func (pl *Plan) renderHandoffChainTeardown(b *strings.Builder, io IpsetOptions) {
	if !pl.handoffOn(io) {
		return
	}
	ch := HandoffOutputChain(io)
	for _, c := range []string{ch, ch + MangleStageSuffix} {
		fmt.Fprintf(b, "iptables -t mangle -D OUTPUT %s 2>/dev/null || true\n", handoffOutputJump(c))
		fmt.Fprintf(b, "iptables -t mangle -F %s 2>/dev/null || true\n", c)
		fmt.Fprintf(b, "iptables -t mangle -X %s 2>/dev/null || true\n", c)
	}
}

func (pl *Plan) renderHandoffTeardown(b *strings.Builder, opt Options, io IpsetOptions) {
	if !pl.handoffOn(io) {
		return
	}
	opt.withDefaults()
	bit := hexMark(HandoffBit)
	for _, ifc := range lanIfaces(io.LANIfaces) {
		fmt.Fprintf(b, "ip rule del iif %s fwmark %s/%s table %d priority %d 2>/dev/null || true\n",
			ifc, bit, bit, HandoffTable(opt), handoffRulePref(opt))
	}
	fmt.Fprintf(b, "ip route flush table %d 2>/dev/null || true\n", HandoffTable(opt))
	v4, v6 := pl.handoffReturnSpecs()
	for _, pref := range []int{handoffReturnRulePref(opt), handoffReturnStagePref(opt)} {
		fmt.Fprintf(b, "ip rule del %s table %d priority %d 2>/dev/null || true\n", v4, HandoffReturnTable(opt), pref)
	}
	fmt.Fprintf(b, "ip rule del %s type blackhole priority %d 2>/dev/null || true\n", v4, handoffReturnHoldPref(opt))
	fmt.Fprintf(b, "ip -6 rule del %s type blackhole priority %d 2>/dev/null || true\n", v6, handoffReturnHoldPref(opt))
	fmt.Fprintf(b, "ip route flush table %d 2>/dev/null || true\n", HandoffReturnTable(opt))
}
