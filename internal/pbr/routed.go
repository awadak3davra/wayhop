package pbr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"wayhop/internal/model"
)

// Large lists by routing table (fast DNS plane on OpenWrt).
//
// dnsmasq puts every resolved address of a listed name into an nft set through libnftables, and
// libnftables builds its cache of the WHOLE ruleset for each add. On a router with nft 1.1.6 and
// kernel 6.12, any `nft add element` cost 0.27 s with the live ruleset, a second copy
// of one 10 909-prefix interval set doubled it to 0.54 s, and a listed name's first answer took
// 0.8-1.6 s while the warm-up held dnsmasq at 35-40 % CPU and stalled the resolver up to 5 s. The
// separate wayhop_dns table does not help: the cost is the ruleset's, not the target table's.
//
// So in fast mode with names, a list whose static (or remote) prefixes exceed RoutedPrefixMin leaves
// nftables: its prefixes become routes in a routing table of its own (`<prefix> dev <tunnel>`, or
// `blackhole <prefix>` for a block list), looked up by one rule per LAN device
// `iif <lan> fwmark 0/<mask> lookup <table>` placed after every fwmark rule and before main. Hence:
//   - every nft-marked zone (names, small lists, direct lists' WAN mark, device-scoped lists, the
//     tunnels' own server addresses in bypass) keeps precedence: their packets carry a plan mark and
//     never reach the rule; the large lists rank below every other list, strongest (block) first among
//     themselves;
//   - the router's own traffic (iif lo) and sing-box's sockets are not routed by them, as nft's
//     prerouting chain never marked them either;
//   - a direct large list is dropped: unmarked traffic goes by the main table anyway, and nothing ranks
//     below a direct list.
// Kept in nft (Review says what it costs): block lists (the kill-switch guard and source rules such as
// a guest segment's from-rule ahead of every plane rule must still see them), lists naming
// or sweeping private space, rules, device-scoped lists, lists at a group or a fastest list (the
// elector re-points their table, a route per prefix would not follow), kill-switched egresses,
// core-only lists (the core pin needs their addresses in nft), and every list when the LAN's devices
// are not known. The routes go with their device when it goes down (the lookup then falls through to
// main, as the egress table's own default route does); the daemon puts them back with it.

// RoutedPrefixMin is the size above which a list's prefixes are routed instead of set in nft.
const RoutedPrefixMin = 256

// routedTableOffset places the large lists' tables above the egress and hand-off tables.
const routedTableOffset = 260

// routedMax bounds how many large lists get a table of their own.
const routedMax = 32

// routeLarge moves the prefixes of the large lists out of nftables (see above). lan is the LAN's
// devices, remote the remote lists' content (sizes only).
func (pl *Plan) routeLarge(p *model.Profile, lan []string, remote map[string]RemoteSet) {
	if len(lan) == 0 || len(pl.DlistSets()) == 0 {
		return
	}
	egress := map[string]Egress{}
	for _, e := range pl.Egresses {
		egress[e.Tag] = e
	}
	n := 0
	for i := range pl.Zones {
		z := &pl.Zones[i]
		if z.NDMPolicy != "" || z.SrcScoped || len(z.SrcV4)+len(z.SrcV6)+len(z.SrcMAC)+len(z.SrcIface)+len(z.SrcPort) > 0 {
			continue
		}
		// With the core's TUN (CorePin) a static prefix has to stay in the TUN's route_exclude, which
		// pbr fills from nft zones: out of it, the core, which leaves a pure-IP kernel list out of its
		// rules, would carry it by its default exit while the pin waits. A remote list's
		// prefixes were never in that exclude (the core matches the rule-set itself), so they still go.
		static := !pl.CorePin
		size := len(z.V4) + len(z.V6)
		if !static {
			size = 0
		}
		if z.RemoteList != "" {
			size += len(remote[z.RemoteList].CIDRs)
		}
		if size <= RoutedPrefixMin {
			continue
		}
		e, ok := egress[z.EgressTag]
		if !ok {
			continue
		}
		switch e.Kind {
		case EgressWAN:
		case EgressInterface:
			_, fastest := model.ListEgressID(e.Tag)
			if e.FailClosed || len(e.Ifaces) > 0 || fastest || e.Iface == "" || (p != nil && p.GroupByID(e.Tag) != nil) {
				continue
			}
		default:
			continue
		}
		// Only lists: a rule's zone has no list id for the core to carry it by while the TUN waits.
		if z.origin.Kind != ZoneFromList || z.origin.ID == "" {
			continue
		}
		// A list naming or sweeping private space keeps nft: the plane's unpin rules are
		// planned from nft prefixes, and the private excludes at a lower priority would send it main.
		if touchesPrivate(z.V4, z.V6, remote[z.RemoteList].CIDRs) {
			continue
		}
		if e.Kind != EgressWAN {
			if n >= routedMax {
				continue
			}
			n++
		}
		z.Routed, z.RouteList = true, z.origin.ID
		if static {
			z.RouteV4, z.RouteV6 = z.V4, z.V6
			z.V4, z.V6 = nil, nil
		}
		z.RemoteRouted = z.RemoteList != ""
	}
	if n > 0 {
		pl.LANIfaces = sortedUnique(append(append([]string(nil), pl.LANIfaces...), lan...))
	}
}

// TouchesPrivate is touchesPrivate for the daemon (a remote refresh of a routed list).
func TouchesPrivate(lists ...[]string) bool { return touchesPrivate(lists...) }

// RemoteRoutedLists names the remote lists whose prefixes the plan routes by tables.
func (pl *Plan) RemoteRoutedLists() map[string]bool {
	out := map[string]bool{}
	if pl == nil {
		return out
	}
	for _, z := range pl.Zones {
		if z.RemoteRouted {
			out[z.RemoteList] = true
		}
	}
	return out
}

// touchesPrivate reports a prefix that overlaps a private range a zone can name (OverlapsUnpinnable).
func touchesPrivate(lists ...[]string) bool {
	for _, l := range lists {
		for _, c := range l {
			if p, err := parsePrefixLoose(c); err == nil && OverlapsUnpinnable(p) {
				return true
			}
		}
	}
	return false
}

// RoutedZone is one large list routed by a table of its own.
type RoutedZone struct {
	Zone  Zone
	Table int
	Pref  int
	// Dev is the egress device; "" means blackhole (a block list).
	Dev string
}

// RoutedZones lists the large lists with a table, strongest first, with the table and the rule
// priority opt gives them.
func (pl *Plan) RoutedZones(opt Options) []RoutedZone {
	if pl == nil {
		return nil
	}
	opt.withDefaults()
	egress := map[string]Egress{}
	for _, e := range pl.Egresses {
		egress[e.Tag] = e
	}
	// First match wins among the tables, the last mark wins in nft (pl.Zones is in nft's emit order):
	// the tables go in the reverse of that order.
	var zs []Zone
	for i := len(pl.Zones) - 1; i >= 0; i-- {
		if z := pl.Zones[i]; z.Routed && egress[z.EgressTag].Kind != EgressWAN {
			zs = append(zs, z)
		}
	}
	base := opt.RulePref + len(pl.nonWanEgresses()) + 1
	out := make([]RoutedZone, 0, len(zs))
	for k, z := range zs {
		r := RoutedZone{Zone: z, Table: opt.TableBase + routedTableOffset + k, Pref: base + k}
		if egress[z.EgressTag].Kind == EgressInterface {
			r.Dev = egress[z.EgressTag].Iface
		}
		out = append(out, r)
	}
	return out
}

// routedV6 reports whether a routed zone carries IPv6.
func (r RoutedZone) routedV6() bool {
	return len(r.Zone.RouteV6) > 0 || (r.Zone.RemoteRouted && !r.Zone.DNSNoV6)
}

// routedRules renders the large lists' rules ("add" or "del").
func (pl *Plan) routedRules(opt Options, verb string) []string {
	var out []string
	for _, r := range pl.RoutedZones(opt) {
		for _, lan := range pl.LANIfaces {
			out = append(out, fmt.Sprintf("ip rule %s iif %s fwmark %s/%s table %d priority %d", verb, lan, hexMark(0), hexMark(pl.Mask), r.Table, r.Pref))
			if r.routedV6() {
				out = append(out, fmt.Sprintf("ip -6 rule %s iif %s fwmark %s/%s table %d priority %d", verb, lan, hexMark(0), hexMark(pl.Mask), r.Table, r.Pref))
			}
		}
	}
	return out
}

// routedFlush renders the teardown of the large lists' tables.
func (pl *Plan) routedFlush(opt Options) []string {
	var out []string
	for _, r := range pl.RoutedZones(opt) {
		out = append(out, fmt.Sprintf("ip route flush table %d", r.Table))
		if r.routedV6() {
			out = append(out, fmt.Sprintf("ip -6 route flush table %d", r.Table))
		}
	}
	return out
}

// RoutedPrefixes is what a routed zone's table must hold, by family: its static prefixes and, for a
// remote list, the content in force (remote, by list id). Canonical, sorted, de-duplicated.
func (r RoutedZone) RoutedPrefixes(remote map[string]RemoteSet) (v4, v6 []string) {
	all := append(append([]string(nil), r.Zone.RouteV4...), r.Zone.RouteV6...)
	if r.Zone.RemoteRouted {
		all = append(all, remote[r.Zone.RemoteList].CIDRs...)
	}
	seen := map[string]bool{}
	for _, c := range all {
		p, err := parsePrefixLoose(c)
		if err != nil {
			continue
		}
		s := p.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		if p.Addr().Is4() {
			v4 = append(v4, s)
		} else if !r.Zone.DNSNoV6 {
			v6 = append(v6, s)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// parsePrefixLoose reads a prefix or a bare address (as a host prefix), masked.
func parsePrefixLoose(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// RouteSpec is the route body for one prefix of r: `<prefix> dev <dev>` or `blackhole <prefix>`.
func (r RoutedZone) RouteSpec(prefix string) string {
	if r.Dev == "" {
		return "blackhole " + prefix
	}
	return prefix + " dev " + r.Dev
}

// RoutedPrefixCount is how many prefixes the routed zones hold (static and remote), for Review's RAM
// estimate.
func (pl *Plan) RoutedPrefixCount(remote map[string]RemoteSet) int {
	n := 0
	for _, r := range pl.RoutedZones(Options{}) {
		v4, v6 := r.RoutedPrefixes(remote)
		n += len(v4) + len(v6)
	}
	return n
}
