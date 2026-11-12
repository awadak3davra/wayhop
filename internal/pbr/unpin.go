package pbr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// RT-09: privateExcludes pin every RFC1918/ULA destination to the main table ahead of the fwmark
// rules, so a zone that NAMES such a destination (an office 10.77.0.0/16 behind an AmneziaWG, a ULA
// site) was marked and then sent out of the main table's default route, the WAN. The pin exists for
// LAN replies and router-local traffic, which reach their destination through the main table's
// connected routes, never through its default route.
//
// So for exactly the private destinations a zone names, rules sit ahead of the pin:
//
//	to <dst> lookup main suppress_prefixlength 0   (the guard)
//	to <dst> fwmark <mark>/<mask> table <egress>   (one per non-WAN egress)
//
// The guard answers from the main table only with a route more specific than the default: the
// router's own LAN prefixes (connected routes) and static routes stay on main, so a reply to a LAN
// client whose address falls inside a listed range is never sent into a tunnel. Anything else falls
// past it; a marked packet then takes its egress table, an unmarked one reaches the pin and main as
// before. Private destinations no zone names keep the pin unchanged. The per-egress rules take any
// WayHop mark, not only the naming zone's: the mark is the marking plane's decision, and the pin
// would otherwise still send a packet another zone marked to the same destination out of the WAN.
// Cost: (1 + egresses) rules per listed private prefix, evaluated for every routed packet.
//
// fe80::/10 is never carved out: a link-local destination has no meaning beyond its own link.
var unpinnablePrivate = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// unpinGuardPref and unpinRoutePref sit ahead of the private excludes (RulePref-3..-1) and of the
// KeeneticOS policy backstop (RulePref-4).
func unpinGuardPref(opt Options) int { return opt.RulePref - 6 }
func unpinRoutePref(opt Options) int { return opt.RulePref - 5 }

// UnpinnedPrivate returns the private destinations this plan routes by mark despite the private
// excludes: every zone prefix routed through a WayHop table (a non-WAN egress) that overlaps a private
// range, narrowed to the overlap. Sorted, v4 before v6, with any prefix inside another dropped.
func (pl *Plan) UnpinnedPrivate() []netip.Prefix {
	if pl == nil {
		return nil
	}
	tabled := map[string]bool{}
	for _, e := range pl.nonWanEgresses() {
		tabled[e.Tag] = true
	}
	var out []netip.Prefix
	for _, z := range pl.Zones {
		// An access-policy zone is routed by NDM's own rules, ahead of all of these.
		if z.NDMPolicy != "" || !tabled[z.EgressTag] {
			continue
		}
		for _, c := range append(append([]string(nil), z.V4...), z.V6...) {
			p, ok := parseZonePrefix(c)
			if !ok {
				continue
			}
			for _, r := range unpinnablePrivate {
				switch {
				case !p.Overlaps(r):
				case p.Bits() >= r.Bits():
					out = append(out, p) // inside the range
				default:
					out = append(out, r) // a supernet names the whole range, and no more of private space
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr().Is4() != out[j].Addr().Is4() {
			return out[i].Addr().Is4()
		}
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	// After the sort a prefix's container, if any, is the last kept one of its family.
	var kept []netip.Prefix
	for _, p := range out {
		if n := len(kept); n > 0 && kept[n-1].Addr().Is4() == p.Addr().Is4() && kept[n-1].Contains(p.Addr()) && kept[n-1].Bits() <= p.Bits() {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

func parseZonePrefix(c string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(c); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(c); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// unpinCommands renders the carve-out for one family as `ip [-6] rule add|del` argv lines. An add
// puts each guard ahead of its per-egress rules, so no moment exists where a listed destination that
// is also a LAN prefix can be marked into a tunnel; a del removes in the reverse order.
func (pl *Plan) unpinCommands(opt Options, v6 bool, verb string) []string {
	ip := "ip"
	if v6 {
		ip = "ip -6"
	}
	var cmds []string
	for _, g := range pl.unpinGroups(opt, v6) {
		if verb == "del" {
			for _, r := range g.routes {
				cmds = append(cmds, ip+" rule del "+r)
			}
			cmds = append(cmds, ip+" rule del "+g.guard)
			continue
		}
		cmds = append(cmds, ip+" rule "+verb+" "+g.guard)
		for _, r := range g.routes {
			cmds = append(cmds, ip+" rule "+verb+" "+r)
		}
	}
	return cmds
}

// unpinScript is the carve-out on the KeeneticOS shell plane, delete-then-add like every rule there.
// The per-egress rules are chained on the guard's add: an ip that refuses suppress_prefixlength
// leaves the pin in force (the behaviour before RT-09) instead of a listed destination that is also a
// LAN prefix being routed into a tunnel without its guard.
func (pl *Plan) unpinScript(opt Options, v6 bool) string {
	ip := "ip"
	if v6 {
		ip = "ip -6"
	}
	var b strings.Builder
	for _, g := range pl.unpinGroups(opt, v6) {
		b.WriteString(unpinDelScript(ip, g))
		fmt.Fprintf(&b, "%s rule add %s && {", ip, g.guard)
		for _, r := range g.routes {
			fmt.Fprintf(&b, " %s rule add %s;", ip, r)
		}
		b.WriteString(" }\n")
	}
	return b.String()
}

// unpinTeardownScript removes the shell plane's carve-out for one family.
func (pl *Plan) unpinTeardownScript(opt Options, v6 bool) string {
	ip := "ip"
	if v6 {
		ip = "ip -6"
	}
	var b strings.Builder
	for _, g := range pl.unpinGroups(opt, v6) {
		b.WriteString(unpinDelScript(ip, g))
	}
	return b.String()
}

func unpinDelScript(ip string, g unpinGroup) string {
	var b strings.Builder
	for _, r := range g.routes {
		fmt.Fprintf(&b, "%s rule del %s 2>/dev/null || true\n", ip, r)
	}
	fmt.Fprintf(&b, "%s rule del %s 2>/dev/null || true\n", ip, g.guard)
	return b.String()
}

// unpinGroup is one listed private destination: its guard selector and its per-egress rule selectors
// (everything after `ip [-6] rule add|del`).
type unpinGroup struct {
	guard  string
	routes []string
}

// unpinGroups renders the selectors for one family; v6 selects the IPv6 destinations.
func (pl *Plan) unpinGroups(opt Options, v6 bool) []unpinGroup {
	egresses := pl.nonWanEgresses()
	if len(egresses) == 0 {
		return nil
	}
	var out []unpinGroup
	for _, p := range pl.UnpinnedPrivate() {
		if p.Addr().Is6() != v6 {
			continue
		}
		g := unpinGroup{guard: fmt.Sprintf("to %s lookup main suppress_prefixlength 0 priority %d", p, unpinGuardPref(opt))}
		for _, e := range egresses {
			g.routes = append(g.routes, fmt.Sprintf("to %s fwmark %s/%s table %d priority %d",
				p, hexMark(e.Mark), hexMark(pl.Mask), e.Table, unpinRoutePref(opt)))
		}
		out = append(out, g)
	}
	return out
}
