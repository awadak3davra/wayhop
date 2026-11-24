package pbr

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// guard_nft.go is the kill switch's backstop on the nft plane (OpenWrt), the counterpart of the
// routing backstop the Keenetic plane has (backstop.go).
//
// Everything else the kill switch does there is a chain of four things, each of which can be missing
// on its own: the mark (table inet wayhop_pbr), the `ip rule` that sends the mark to a table, the
// tunnel's route in that table, and the blackhole behind it. Lose the nft table (an Apply rolled
// back, a `nft flush ruleset`, the seconds of boot before WayHop runs), or one ip rule (another
// script, `ip rule flush`), or the blackhole (`ip route flush table N`), and a kill-switched
// destination is routed by the main table: the provider.
//
// The guard does not ask how the packet was routed. It is a table of its own, `inet wayhop_ks`, with
// one forward chain: a packet to a kill-switched destination may leave the router only through one of
// that list's own tunnels; through anything else it is dropped. A block list's destinations are
// dropped outright. It reads no mark, no rule and no route, so none of the four can open it.
//
//   - Its own table: the plane's install, rollback and teardown replace or delete `wayhop_pbr`; none
//     of them names `wayhop_ks`. It is loaded before the plane and removed only by an Apply whose
//     plan has nothing to guard, or by routing being switched off. fw4 touches only `inet fw4`.
//   - One `nft -f` transaction replaces it, so there is no moment without it.
//   - It matches by output device NAME: it holds before the tunnel devices exist, which is what lets
//     the same program be loaded at boot, before the network is up (RenderNftGuardBoot's caller).
//   - Forwarded traffic only. The router's own packets (the tunnels' handshakes to their servers,
//     probes bound to a device, feed downloads) are not forwarded and are left alone, as on KeeneticOS.
//   - Source-scoped lists are guarded with the same source match as the marking chain: nft can tell
//     devices apart where a routing rule cannot.
//   - IPv6: zones that carry IPv6 are guarded like IPv4. Prefixes the plane cannot carry at all (a
//     kill-switched list sent to an IPv4-only tunnel, Plan.GuardV6) are dropped: in hybrid mode the
//     core's TUN is IPv4-only, so nothing else would stop them.
//
//   - Never what the plane itself keeps on the main table: private and link-local destinations are
//     accepted first, so no list, whatever it holds, can stop a reply to the LAN, to
//     another LAN segment or to a WireGuard server's client.
//   - Except the private destinations the plane does NOT keep there (unpin.go): the ones a
//     kill-switched list names, an office network behind a tunnel. Those are judged like any
//     kill-switched address, after the router's own routes to them.
//   - Of those routes, a network the list NAMES is accepted only on the LAN side: by a device
//     of a firewall zone that is not the provider's. The provider's own segment with the same
//     numbers (the modem's LAN, a range the provider pushes by DHCP) is where the kill switch exists
//     to keep that traffic from, so there it is dropped. A range the list only sweeps
//     (0.0.0.0/0) keeps every route of the router's, the modem's page included.
//
// What it cannot see: names. A list's domains are matched by the core on OpenWrt, not by an address
// set. The addresses those names were reached at are learned by the daemon into sets with timeouts
// and held like any other kill-switched address (Plan.GuardNameSets); for an address nobody has
// learned yet, NamesHold covers the core being down.

// GuardTable is the nft table of the kill-switch guard.
const GuardTable = "wayhop_ks"

// guardPriority puts the guard ahead of fw4's forward chain (filter) and of the flow-offload chain
// (filter - 1), so a flow to a guarded destination is judged before anything can offload it.
const guardPriority = "filter - 5"

// guardedZone is one zone the guard covers and the devices its traffic may leave by (none: drop).
type guardedZone struct {
	zone  Zone
	allow []string
}

// guardedZones lists the fail-closed and block zones, strongest first: the marking chain lets the
// LAST matching zone win, and these ranks are the tail of its order (orderZonesForEmit), so walking
// them backwards and stopping at the first match gives the same winner.
func (pl *Plan) guardedZones() []guardedZone {
	if pl == nil {
		return nil
	}
	byTag := map[string]Egress{}
	for _, e := range pl.Egresses {
		byTag[e.Tag] = e
	}
	var out []guardedZone
	for i := len(pl.Zones) - 1; i >= 0; i-- {
		z := pl.Zones[i]
		if z.NDMPolicy != "" {
			continue
		}
		e, ok := byTag[z.EgressTag]
		switch {
		case !ok:
		case e.Kind == EgressBlackhole:
			out = append(out, guardedZone{zone: z})
		case e.Kind == EgressInterface && e.FailClosed:
			allow := e.Devices()
			if len(e.Ifaces) == 0 {
				// A plan stored before Compile recorded each egress's devices (the one a router holds
				// when it is upgraded) names only the first member, and the elector may have moved the
				// table to another: letting only the first through would drop the list on its working
				// tunnel. Any of the plan's tunnels then; never the provider.
				allow = sortedUnique(append(allow, pl.MasqIfaces...))
			}
			out = append(out, guardedZone{zone: z, allow: allow})
		}
	}
	return out
}

// HasNftGuard reports whether the plan has anything for the guard to hold.
func (pl *Plan) HasNftGuard() bool {
	return pl != nil && (len(pl.guardedZones()) > 0 || len(pl.GuardV6) > 0 || len(pl.GuardNameSets) > 0)
}

// zoneMatches returns, for one zone, the match of every line the marking chain renders for it
// (everything before the mark statement), with the family each one applies to ("ip", "ip6", or ""
// for a family-agnostic source-only line). It follows RenderNft's zone loop condition for condition;
// TestGuardMatchesFollowTheMarkingChain holds the two together.
func zoneMatches(z Zone) []string {
	pre := z.srcMatchPrefix()
	neg := ""
	if z.SrcNegate {
		neg = "!= "
	}
	var out []string
	if len(z.V4) > 0 && (z.SrcNegate || len(z.SrcV4) > 0 || len(z.SrcV6) == 0) {
		src := ""
		if len(z.SrcV4) > 0 {
			src = fmt.Sprintf("ip saddr %s@%s_s4 ", neg, z.Name)
		}
		out = append(out, fmt.Sprintf("%s%sip daddr @%s_4", pre, src, z.Name))
	}
	if len(z.V6) > 0 && (z.SrcNegate || len(z.SrcV6) > 0 || len(z.SrcV4) == 0) {
		src := ""
		if len(z.SrcV6) > 0 {
			src = fmt.Sprintf("ip6 saddr %s@%s_s6 ", neg, z.Name)
		}
		out = append(out, fmt.Sprintf("%s%sip6 daddr @%s_6", pre, src, z.Name))
	}
	if len(z.V4) == 0 && len(z.V6) == 0 && z.SrcScoped {
		wrote := false
		if len(z.SrcV4) > 0 {
			out = append(out, fmt.Sprintf("%sip saddr %s@%s_s4", pre, neg, z.Name))
			wrote = true
		}
		if len(z.SrcV6) > 0 {
			out = append(out, fmt.Sprintf("%sip6 saddr %s@%s_s6", pre, neg, z.Name))
			wrote = true
		}
		if !wrote && pre != "" {
			out = append(out, strings.TrimSuffix(pre, " "))
		}
	}
	return out
}

// NamesHold is what the guard is told about the traffic it cannot match by a compiled address: the
// kill-switched lists' NAMES, which only the core routes. See RenderNftGuardWith.
type NamesHold struct {
	// Seconds is how long the broad hold stands without being renewed. Zero: no broad hold (the
	// learned-address sets are rendered all the same). Negative: it never lapses on its own
	// (kill_switch_boot_hold_lift < 0, the operator's "strict").
	Seconds int
	// Pass is every device forwarded traffic of a kill-switched name may leave by: the core's TUN and
	// the kernel tunnels. Anything else is the provider.
	Pass []string
	// V6 says the broad hold covers IPv6 too. Only when the core's TUN carries IPv6: with an
	// IPv4-only TUN all IPv6 of the LAN leaves beside the core whether it runs or not, and a hold
	// that is renewed while the core runs would drop it for good.
	V6 bool
	// Local is the router's own routes, read by the daemon from the main table: every prefix more
	// specific than a default route, with the device it leaves by (the private segment of an uplink
	// too). It is what `suppress_prefixlength 0` answers from on the routing plane (unpin.go), and
	// the guard accepts a packet to such a prefix by that prefix's own device before it judges a
	// private destination a kill-switched list names. Not part of the names hold; it
	// travels here because the server tells the guard both at once. Only the entries a rule needs are
	// rendered, so a plan with no such list renders the same program whatever the routes are.
	//
	// Which entries a rule may use depends on what the list says. A private network a
	// kill-switched list NAMES is accepted only by a route of the LAN side (GuardLocal.House). A
	// private range a list only SWEEPS is accepted by any of the router's routes, as before.
	Local []GuardLocal
	// LocalPartial says Local is not everything the LAN side has: the daemon's bound on it was
	// reached, or the firewall's zones could not be read, so no device is known to be the LAN's.
	// The guard then lets the reply direction of a connection through to a judged private
	// destination by any device that is not known to be the provider's or a tunnel: a
	// LAN the guard was not told about keeps its answers. A new connection to such a destination is
	// judged as always.
	LocalPartial bool
	// Provider is the devices known to be the provider's side: a default route, the interface that
	// carries one, a firewall zone that faces the provider. Only the rule LocalPartial adds reads it.
	Provider []string
	// Source is the operator's own source routing (guard_source.go): the segments a
	// rule of the router's sends to a tunnel by their source, each with that tunnel's device. A packet
	// a kill switch would drop passes when it comes from such a segment and leaves by its device.
	// Only tunnels that are not the provider's side are told. Like Local, it is not part of the names
	// hold and every plan gets it.
	Source []GuardSource
}

// GuardLocal is one route of the router's own: a prefix and the device it is reached by.
type GuardLocal struct {
	Dev    string
	Prefix netip.Prefix
	// House says the device is on the LAN side: it is in a firewall zone, it is not a device of
	// the uplink's interface, none of its zones faces the provider, and it carries no default route
	// itself. Never inferred from the absence of a default route alone: the physical
	// port under a PPPoE session has none and is the provider's. Never from masquerading either: a
	// LAN zone that masquerades is still the LAN.
	House bool
	// Via says the route goes by a gateway: a network behind the device, not its own segment.
	Via bool
	// Candidate says the device is not known to be the provider's, and not known to be the LAN's
	// either: no firewall zone holds it, or its zone also holds the uplink. A route of such a device
	// accepts answers only (the reply direction of a connection) to a judged private destination,
	// never a new connection to a network a list names.
	Candidate bool
}

// judged is the private destinations the guard judges, by how the lists state them.
type judged struct {
	named4, named6 []string // a kill-switched zone states the prefix itself
	swept4, swept6 []string // a private range covered only by a broader prefix
}

func (j judged) v4() []string { return append(append([]string(nil), j.named4...), j.swept4...) }
func (j judged) v6() []string { return append(append([]string(nil), j.named6...), j.swept6...) }
func (j judged) any() bool    { return len(j.named4)+len(j.named6)+len(j.swept4)+len(j.swept6) > 0 }

// GuardJudgedPrivate is the private destinations the guard judges. named: the networks a
// kill-switched list states, held to the list's tunnels and to the LAN's own side. swept: the
// private ranges such a list covers only by a broader prefix. Review reads both to say what the
// provider's side has a route into.
func (pl *Plan) GuardJudgedPrivate() (named, swept []netip.Prefix) {
	if pl == nil || len(pl.guardedZones()) == 0 {
		return nil, nil
	}
	return pl.judgedSplit()
}

// TunnelDevices is every device a tunnel of the plan may hold.
func (pl *Plan) TunnelDevices() []string {
	if pl == nil {
		return nil
	}
	return pl.tunnelDevices()
}

// judgedPrivate is the private destinations the guard judges instead of accepting them with the rest
// of private space: the ones the plane routes by mark (UnpinnedPrivate) on behalf of a kill switch.
//
//   - Every private prefix a kill-switched zone names.
//   - When a kill-switched zone matches by source alone ("everything from this device"), every
//     prefix the plane unpins at all: the unpin rules take any mark, so that device's packet to an
//     office network another list names is sent to the device's own fail-closed table.
//
// A block list's private prefixes alone are not judged (a bogon feed names all of private space, and
// judging it would let that list stop the LAN): the plane's blackhole holds them.
func (pl *Plan) judgedPrivate() judged {
	var j judged
	named, swept := pl.judgedSplit()
	for _, p := range named {
		if p.Addr().Is4() {
			j.named4 = append(j.named4, p.String())
		} else {
			j.named6 = append(j.named6, p.String())
		}
	}
	for _, p := range swept {
		if p.Addr().Is4() {
			j.swept4 = append(j.swept4, p.String())
		} else {
			j.swept6 = append(j.swept6, p.String())
		}
	}
	return j
}

// judgedSplit is judgedPrivate as prefixes, named and swept (unpinnedSplit).
func (pl *Plan) judgedSplit() (named, swept []netip.Prefix) {
	if pl == nil {
		return nil, nil
	}
	byTag := map[string]Egress{}
	for _, e := range pl.Egresses {
		byTag[e.Tag] = e
	}
	closed := func(z Zone) bool {
		e, ok := byTag[z.EgressTag]
		return ok && e.Kind == EgressInterface && e.FailClosed
	}
	bySource := false
	for _, z := range pl.Zones {
		bySource = bySource || z.NDMPolicy == "" && closed(z) && len(z.V4)+len(z.V6) == 0
	}
	if bySource {
		tabled := map[string]bool{}
		for _, e := range pl.nonWanEgresses() {
			tabled[e.Tag] = true
		}
		return pl.unpinnedSplit(func(z Zone) bool { return tabled[z.EgressTag] })
	}
	return pl.unpinnedSplit(closed)
}

// tunnelDevices is every device a tunnel egress of the plan may hold, and the tunnels that need
// masquerading: never the LAN side, whatever zone they are in.
func (pl *Plan) tunnelDevices() []string {
	devs := append([]string(nil), pl.MasqIfaces...)
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface {
			devs = append(devs, e.Devices()...)
		}
	}
	return sortedUnique(devs)
}

// localBySide splits the router's routes into the LAN side and everything else: the provider's
// devices, the plan's tunnels, and devices whose side is not known. unsure is the last of these: the
// routes of other that may yet be the LAN's (GuardLocal.Candidate), never a tunnel's or the
// core's TUN (pass).
func (pl *Plan) localBySide(local []GuardLocal, pass []string) (house, other, unsure []GuardLocal) {
	tunnel := map[string]bool{}
	for _, d := range pl.tunnelDevices() {
		tunnel[d] = true
	}
	notHouse := map[string]bool{pl.CoreTun: true}
	for _, d := range pass {
		notHouse[d] = true
	}
	for _, l := range local {
		if l.House && !tunnel[l.Dev] {
			house = append(house, l)
			continue
		}
		other = append(other, l)
		if l.Candidate && !tunnel[l.Dev] && !notHouse[l.Dev] {
			unsure = append(unsure, l)
		}
	}
	return house, other, unsure
}

// compactCIDRs sorts prefixes and drops any that lies inside another: the elements of one anonymous
// set must not overlap (10.0.0.0/8 pushed by the provider beside its connected 10.64.0.0/18).
func compactCIDRs(in []string) []string {
	var ps []netip.Prefix
	for _, c := range in {
		if p, err := netip.ParsePrefix(c); err == nil {
			ps = append(ps, p.Masked())
		}
	}
	var out []string
	for _, p := range compactPrefixes(ps) {
		out = append(out, p.String())
	}
	return out
}

// guardDevNames keeps the names that can be written into a program, sorted, each once.
func guardDevNames(devs []string) []string {
	var out []string
	for _, d := range devs {
		if guardDevName(d) {
			out = append(out, d)
		}
	}
	return sortedUnique(out)
}

// guardJudgedChain is where a packet to a judged private destination meets the zones' rules.
const guardJudgedChain = "ks_routed"

// localRules renders the accepts for the router's own routes: one rule per device and family,
// `oifname "br-lan" ip daddr { 192.168.1.0/24 } accept`. A route is rendered when it overlaps one of
// the prefixes in want, and only where it does: a route wider than the judged prefix
// (192.0.0.0/8 over a named 192.168.50.0/24) accepts the judged prefix, not the public addresses
// around it, which the zones, the learned names and the hold below still have to judge. For IPv6
// with all6 set a route is rendered whole when it is the device's own segment (no gateway): the
// kernel lists the IPv6 routes of every table in one file, and a routed prefix read from another
// table is not the LAN. Bound to the route's device: an entry that has gone stale (the device is
// down, the prefix now lies behind the default route) accepts nothing that leaves by the provider.
// match, when set, narrows every rule ("ct direction reply ").
func localRules(local []GuardLocal, want []string, all6 bool, match string) []string {
	var wanted []netip.Prefix
	for _, w := range want {
		if p, err := netip.ParsePrefix(w); err == nil {
			wanted = append(wanted, p)
		}
	}
	byDev := map[string][2][]string{}
	for _, l := range local {
		if !guardDevName(l.Dev) || !l.Prefix.IsValid() {
			continue
		}
		p := l.Prefix.Masked()
		var keep []string
		if all6 && p.Addr().Is6() && !l.Via {
			keep = []string{p.String()}
		} else {
			for _, w := range wanted {
				switch w = w.Masked(); {
				case !w.Overlaps(p):
				case p.Bits() < w.Bits():
					keep = append(keep, w.String()) // the route is wider: only what is judged
				default:
					keep = append(keep, p.String())
				}
			}
		}
		if len(keep) == 0 {
			continue
		}
		fams := byDev[l.Dev]
		i := 0
		if p.Addr().Is6() {
			i = 1
		}
		fams[i] = append(fams[i], keep...)
		byDev[l.Dev] = fams
	}
	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	var out []string
	for _, d := range devs {
		for i, fam := range []string{"ip", "ip6"} {
			if elems := compactCIDRs(byDev[d][i]); len(elems) > 0 {
				out = append(out, fmt.Sprintf("oifname %q %s%s daddr { %s } accept", d, match, fam, strings.Join(elems, ", ")))
			}
		}
	}
	return out
}

// guardDevName reports whether a device name read from the kernel can be written into a program as
// it is: the characters Linux device names are made of, and no more than its 15.
func guardDevName(dev string) bool {
	if dev == "" || len(dev) > 15 {
		return false
	}
	for _, c := range dev {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '@'
		if !ok {
			return false
		}
	}
	return true
}

// holdProtos are the transport protocols the hold's set names. nft has no "any" element; these are
// what a LAN sends to the internet.
var holdProtos = []string{"tcp", "udp", "icmp", "ipv6-icmp", "sctp", "dccp", "gre", "esp", "ah", "udplite"}

// holdPrivate4 and holdPrivate6 are never the provider's side: LAN to LAN, the modem's own page,
// carrier-grade NAT, link-local, multicast.
var (
	holdPrivate4 = []string{"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"}
	holdPrivate6 = []string{"::/127", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// GuardNameSetSize is the kernel's bound on one learned-address set. The daemon keeps at most half
// of it per set (its own count restarts with the daemon while the kernel's elements live on).
const GuardNameSetSize = 8192

// guardNamesChain is the verdict chain every learned-address set jumps to.
const guardNamesChain = "ks_names"

// RenderNftGuard renders the guard for this plan with no names hold. "" when there is nothing to guard.
func (pl *Plan) RenderNftGuard() string { return pl.RenderNftGuardWith(NamesHold{}) }

// RenderNftGuardWith renders the guard's whole table as one self-replacing `nft -f` program.
//
// The chain, in order:
//
//  0. Only when a kill switch covers a private destination (judgedPrivate): the
//     router's own routes to such a destination are accepted by their own device (the nft form of the
//     plane's `lookup main suppress_prefixlength 0`), then a packet to it meets the zones' rules of
//     step 2 in a chain of its own. An office network behind a kill-switched tunnel leaves by that
//     tunnel or not at all; what no zone claims falls through to step 1. In order:
//     the routes of the LAN side; answers to the routes of a device whose side is not known; a
//     network a list names; every other route of the router's, for the ranges a list only sweeps;
//     those ranges.
//  1. What the plane itself never sends to a tunnel: private and link-local destinations (the ip
//     rules ahead of the fwmark rules look them up in the main table). Accepted before any drop, from
//     the same lists the plane uses. Without it a source-only kill-switched rule
//     dropped the device's answers to the LAN and to a WireGuard server's clients, and a block or
//     kill-switched list that covers private space (a bogon feed, 0.0.0.0/0) dropped every reply to a
//     LAN client: the whole LAN, with WayHop healthy, written to flash and loaded at every boot.
//  2. The block lists and the kill-switched address zones, strongest first. A kill-switched zone's
//     packet is accepted when it leaves by one of the list's tunnels, or came in by one (its reply to
//     a host with a public address); otherwise dropped.
//  3. IPv6 the plane cannot carry (Plan.GuardV6).
//  4. The learned addresses of kill-switched names (Plan.GuardNameSets): one pair of
//     sets with timeouts per list or rule, filled by the daemon. Such an address may leave by the
//     core's TUN or by a tunnel, never by the provider, core running or not, in every routing mode.
//  5. The broad names hold, below.
//
// Inside steps 2, 4 and 5, after the list's own tunnels and before the drop: the operator's own
// source routing (NamesHold.Source). A segment a rule of the router's sends to a
// tunnel by its source leaves by that tunnel; a block list's drop is not opened.
//
// The hold is the one broad rule the guard has. A kill-switched name whose address nobody has
// learned yet is forwarded like any other traffic while the core is not running (the boot, a crash,
// a restart), and no rule can tell it apart. The hold drops every NEW-direction forwarded packet to
// a public address that would leave by a device that is not the core's TUN or a tunnel, unless the
// marking chain marked it for an exit the operator did not kill-switch (the direct exit, a list that
// may fall back to the provider). With the core up that is nothing a client sends: TCP
// is redirected into the core before the forward hook, UDP and ICMP leave by the TUN.
//
// The hold is bounded by the kernel, not by a process: it is a set whose elements carry a timeout.
// The daemon renews them while the core runs; when nobody renews them (the daemon is dead, the core
// has been down for the whole period) they expire and the rule matches nothing. So a WayHop failure
// holds the LAN for at most hold.Seconds, and never needs WayHop to let go.
func (pl *Plan) RenderNftGuardWith(hold NamesHold) string {
	if pl == nil {
		return ""
	}
	zones := pl.guardedZones()
	held := hold.Seconds != 0 && len(hold.Pass) > 0
	if len(zones) == 0 && len(pl.GuardV6) == 0 && len(pl.GuardNameSets) == 0 && !held {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", GuardTable, GuardTable)
	fmt.Fprintf(&b, "table inet %s {\n", GuardTable)
	for _, g := range zones {
		z := g.zone
		for _, set := range []struct {
			suffix, typ string
			elems       []string
		}{
			{"_4", "ipv4_addr", z.V4}, {"_6", "ipv6_addr", z.V6},
			{"_s4", "ipv4_addr", z.SrcV4}, {"_s6", "ipv6_addr", z.SrcV6},
		} {
			if len(set.elems) > 0 {
				fmt.Fprintf(&b, "\tset %s%s { type %s; flags interval; elements = { %s } }\n",
					z.Name, set.suffix, set.typ, nftElements(set.elems))
			}
		}
	}
	if len(pl.GuardV6) > 0 {
		fmt.Fprintf(&b, "\tset wh_uncarried6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftElements(pl.GuardV6))
	}
	for _, n := range pl.GuardNameSets {
		fmt.Fprintf(&b, "\tset %s_4 { type ipv4_addr; flags timeout; size %d; }\n", n.Set, GuardNameSetSize)
		fmt.Fprintf(&b, "\tset %s_6 { type ipv6_addr; flags timeout; size %d; }\n", n.Set, GuardNameSetSize)
	}
	if held {
		elems := make([]string, len(holdProtos))
		for i, p := range holdProtos {
			elems[i] = holdElement(p, hold.Seconds)
		}
		fmt.Fprintf(&b, "\tset %s { type inet_proto; flags timeout; elements = { %s } }\n", GuardHoldSet, strings.Join(elems, ", "))
		fmt.Fprintf(&b, "\tset wh_private4 { type ipv4_addr; flags interval; elements = { %s } }\n", nftElements(holdPrivate4))
		fmt.Fprintf(&b, "\tset wh_private6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftElements(holdPrivate6))
	}
	// One small chain per kill-switched zone: the verdict for a packet that matched the zone. `accept`
	// ends the guard's chain for the packet (fw4's own forward chain still judges it); the drop is final.
	// The operator's own source routing: ahead of every drop a kill switch makes, and
	// of none a block list makes.
	var sourced strings.Builder
	for _, r := range sourceAccepts(hold.Source, hold.Provider) {
		fmt.Fprintf(&sourced, "\t\t%s\n", r)
	}
	var rules []string
	n := 0
	for _, g := range zones {
		matches := zoneMatches(g.zone)
		if len(matches) == 0 {
			continue
		}
		verdict := "counter drop"
		if len(g.allow) > 0 {
			chain := "ks_" + strconv.Itoa(n)
			n++
			// By one of the list's own tunnels, in either direction: out is the list's traffic, in is
			// its reply on the way to a host the first rules did not already let through (a LAN with
			// public addresses, IPv6).
			// Then a segment the router's own rule routes by source, by that rule's tunnel: for that
			// segment it is the way out the operator chose, and never the provider's device.
			fmt.Fprintf(&b, "\tchain %s {\n\t\toifname %s accept\n\t\tiifname %s accept\n%s\t\tcounter drop\n\t}\n",
				chain, nftStrSet(g.allow), nftStrSet(g.allow), sourced.String())
			verdict = "jump " + chain
		}
		for _, m := range matches {
			rules = append(rules, m+" "+verdict)
		}
	}
	pass := sortedUnique(append(append([]string(nil), hold.Pass...), pl.MasqIfaces...))
	if len(pl.GuardNameSets) > 0 {
		fmt.Fprintf(&b, "\tchain %s {\n", guardNamesChain)
		if len(pass) > 0 {
			fmt.Fprintf(&b, "\t\toifname %s accept\n\t\tiifname %s accept\n", nftStrSet(pass), nftStrSet(pass))
		}
		b.WriteString(sourced.String())
		b.WriteString("\t\tcounter drop\n\t}\n")
	}
	j := pl.judgedPrivate()
	if len(rules) == 0 {
		j = judged{}
	}
	if j.any() {
		// Falling off its end returns to the base chain: the private accept below.
		fmt.Fprintf(&b, "\tchain %s {\n", guardJudgedChain)
		for _, r := range rules {
			fmt.Fprintf(&b, "\t\t%s\n", r)
		}
		b.WriteString("\t}\n")
	}
	fmt.Fprintf(&b, "\tchain %s {\n", GuardChain)
	fmt.Fprintf(&b, "\t\ttype filter hook forward priority %s; policy accept;\n", guardPriority)
	// The router's own routes on the LAN side first. With an IPv6 hold they also let a connection
	// opened from outside reach a LAN host with a public address: the hold sees only
	// its replies as such.
	house, other, unsure := pl.localBySide(hold.Local, hold.Pass)
	for _, r := range localRules(house, append(j.v4(), j.v6()...), held && hold.V6, "") {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	if !hold.LocalPartial {
		// A device whose side is not known (no firewall zone holds it, or its zone holds the uplink
		// too): answers pass to its own segment, by that device only. A new connection to it is
		// judged below, so a network a list names is never opened by a guess. With LocalPartial the
		// rule that follows says the same for every such device at once.
		for _, r := range localRules(unsure, append(j.v4(), j.v6()...), false, "ct direction reply ") {
			fmt.Fprintf(&b, "\t\t%s\n", r)
		}
	}
	if hold.LocalPartial && j.any() {
		// The LAN side was not told in full: its answers pass, by anything that is
		// not known to be the provider's or a tunnel. New connections are judged below as always.
		not := ""
		if away := guardDevNames(append(append([]string(nil), hold.Provider...), pl.tunnelDevices()...)); len(away) > 0 {
			not = "oifname != " + nftStrSet(away) + " "
		}
		if v4 := compactCIDRs(j.v4()); len(v4) > 0 {
			fmt.Fprintf(&b, "\t\t%sct direction reply ip daddr { %s } accept\n", not, nftElements(v4))
		}
		if v6 := compactCIDRs(j.v6()); len(v6) > 0 {
			fmt.Fprintf(&b, "\t\t%sct direction reply ip6 daddr { %s } accept\n", not, nftElements(v6))
		}
	}
	// A network a list names is judged before any other route of the router's is asked:
	// the provider's segment with the same numbers is not a way to it.
	if len(j.named4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } jump %s\n", nftElements(j.named4), guardJudgedChain)
	}
	if len(j.named6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } jump %s\n", nftElements(j.named6), guardJudgedChain)
	}
	// A range a list only sweeps keeps every route the router has into it, the uplink's own segment
	// too: the page of the modem or of the router upstream.
	for _, r := range localRules(other, append(append([]string(nil), j.swept4...), j.swept6...), false, "") {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	if len(j.swept4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } jump %s\n", nftElements(j.swept4), guardJudgedChain)
	}
	if len(j.swept6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } jump %s\n", nftElements(j.swept6), guardJudgedChain)
	}
	fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", nftElements(planePrivateV4))
	fmt.Fprintf(&b, "\t\tip6 daddr { %s } accept\n", nftElements(planePrivateV6))
	for _, r := range rules {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	if len(pl.GuardV6) > 0 {
		b.WriteString("\t\tip6 daddr @wh_uncarried6 counter drop\n")
	}
	for _, n := range pl.GuardNameSets {
		fmt.Fprintf(&b, "\t\tip daddr @%s_4 jump %s\n", n.Set, guardNamesChain)
		fmt.Fprintf(&b, "\t\tip6 daddr @%s_6 jump %s\n", n.Set, guardNamesChain)
	}
	if held {
		// Replies, and connections opened from outside (a port forward's answers), are not the LAN
		// asking for a name. A mark of an exit that is not kill-switched is the operator's own "this
		// may go by the provider": the direct exit, and a list whose tunnels are all down and whose
		// table was emptied on purpose (on_all_down "wan").
		holdPass := nftStrSet(sortedUnique(hold.Pass))
		fmt.Fprintf(&b, "\t\tct direction reply accept\n")
		fmt.Fprintf(&b, "\t\toifname %s accept\n", holdPass)
		fmt.Fprintf(&b, "\t\tiifname %s accept\n", holdPass)
		b.WriteString(sourced.String())
		if marks := pl.openMarks(); len(marks) == 1 {
			fmt.Fprintf(&b, "\t\tmeta mark & %s == %s accept\n", hexMark(pl.Mask), marks[0])
		} else if len(marks) > 1 {
			fmt.Fprintf(&b, "\t\tmeta mark & %s == { %s } accept\n", hexMark(pl.Mask), strings.Join(marks, ", "))
		}
		b.WriteString("\t\tip daddr @wh_private4 accept\n")
		b.WriteString("\t\tip6 daddr @wh_private6 accept\n")
		family := "meta nfproto ipv4 "
		if hold.V6 {
			family = ""
		}
		fmt.Fprintf(&b, "\t\t%smeta l4proto @%s counter drop\n", family, GuardHoldSet)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// openMarks is the marks of the exits no kill switch covers, in mark order: the direct exit and
// every tunnel egress that is not fail-closed. Block egresses and kill-switched ones are not in it.
func (pl *Plan) openMarks() []string {
	seen := map[uint32]bool{}
	var marks []uint32
	for _, e := range pl.Egresses {
		open := e.Kind == EgressWAN || e.Kind == EgressInterface && !e.FailClosed
		if open && e.Mark != 0 && !seen[e.Mark] {
			seen[e.Mark] = true
			marks = append(marks, e.Mark)
		}
	}
	sort.Slice(marks, func(i, j int) bool { return marks[i] < marks[j] })
	out := make([]string, len(marks))
	for i, m := range marks {
		out[i] = hexMark(m)
	}
	return out
}

// GuardedElements counts the addresses and prefixes the guard holds a copy of: each
// exists in the kernel twice, in the plane's sets and in the guard's, and once more on flash.
func (pl *Plan) GuardedElements() int {
	if pl == nil {
		return 0
	}
	n := len(pl.GuardV6)
	for _, g := range pl.guardedZones() {
		n += len(g.zone.V4) + len(g.zone.V6) + len(g.zone.SrcV4) + len(g.zone.SrcV6)
	}
	return n
}

// GuardHoldSet is the set whose elements are the names hold: while it has any, the hold stands.
const GuardHoldSet = "wh_hold"

// RenderGuardHoldRenew renews the hold for another period. Each `add element` of an element the set
// already holds would be refused without the delete; the pair inside one transaction renews it with
// no moment in which the set is empty.
func RenderGuardHoldRenew(seconds int) string {
	var b strings.Builder
	for _, p := range holdProtos {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", GuardTable, GuardHoldSet, holdElement(p, seconds))
		fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", GuardTable, GuardHoldSet, p)
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", GuardTable, GuardHoldSet, holdElement(p, seconds))
	}
	return b.String()
}

// RenderGuardHoldLift lets the hold go now: the set is emptied, the rule stays and matches nothing.
func RenderGuardHoldLift() string {
	return fmt.Sprintf("flush set inet %s %s\n", GuardTable, GuardHoldSet)
}

func holdElement(proto string, seconds int) string {
	if seconds < 0 {
		return proto
	}
	return fmt.Sprintf("%s timeout %ds", proto, seconds)
}

// GuardHoldRemaining reads `nft list set inet wayhop_ks wh_hold` and says how long the hold still
// stands: the longest `expires` among its elements, in whole seconds. 0 for a set
// whose elements have all timed out. ok is false when the listing shows an element without an
// expiry (a strict hold) or is not a listing of the set at all.
//
//	elements = { tcp timeout 10m expires 9m58s912ms, udp timeout 10m expires 9m58s912ms }
func GuardHoldRemaining(listing string) (seconds int, ok bool) {
	if !strings.Contains(listing, "set "+GuardHoldSet) {
		return 0, false
	}
	_, elems, has := strings.Cut(listing, "elements = {")
	if !has {
		return 0, true
	}
	elems, _, _ = strings.Cut(elems, "}")
	for _, el := range strings.Split(elems, ",") {
		f := strings.Fields(el)
		if len(f) == 0 {
			continue
		}
		at := -1
		for i, w := range f {
			if w == "expires" {
				at = i
			}
		}
		if at < 0 || at+1 >= len(f) {
			return 0, false
		}
		d, good := nftDuration(f[at+1])
		if !good {
			return 0, false
		}
		if d > seconds {
			seconds = d
		}
	}
	return seconds, true
}

// nftDuration reads a duration as nft prints it (1d2h3m4s567ms) into whole seconds, rounded up.
func nftDuration(s string) (int, bool) {
	total, ms, num, digits := 0, 0, 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			num, digits = num*10+int(c-'0'), true
		case !digits:
			return 0, false
		case c == 'm' && i+1 < len(s) && s[i+1] == 's':
			ms, num, digits = num, 0, false
			i++
		case c == 'd':
			total, num, digits = total+num*86400, 0, false
		case c == 'h':
			total, num, digits = total+num*3600, 0, false
		case c == 'm':
			total, num, digits = total+num*60, 0, false
		case c == 's':
			total, num, digits = total+num, 0, false
		default:
			return 0, false
		}
	}
	if digits {
		return 0, false
	}
	if ms > 0 {
		total++
	}
	return total, true
}

// RenderGuardLearn renders the program that puts learned addresses into a name set's kernel sets,
// each with its timeout in seconds. An address the set already holds is deleted and added again in
// the same transaction, which is how nft renews an element's timeout. "" for nothing to add.
func RenderGuardLearn(set string, addrs map[string]int) string {
	keys := make([]string, 0, len(addrs))
	for a := range addrs {
		keys = append(keys, a)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, a := range keys {
		ttl := addrs[a]
		if ttl <= 0 {
			continue
		}
		name := set + "_4"
		if strings.Contains(a, ":") {
			name = set + "_6"
		}
		fmt.Fprintf(&b, "add element inet %s %s { %s timeout %ds }\n", GuardTable, name, a, ttl)
		fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", GuardTable, name, a)
		fmt.Fprintf(&b, "add element inet %s %s { %s timeout %ds }\n", GuardTable, name, a, ttl)
	}
	return b.String()
}

// GuardProofSet names the marker a loaded guard carries: postcheck asks for it by name, so a guard
// that is absent, or is another plan's, reads as drift.
func GuardProofSet(program string) string {
	sum := sha256.Sum256([]byte(program))
	return fmt.Sprintf("wh_guard_%x", sum[:16])
}

// GuardChain is the guard's one base chain; its last rule carries the marker.
const GuardChain = "ks_forward"

// GuardProofProgram adds the marker to a guard that has just been loaded: the last rule of its
// chain, as that rule's comment. It used to be a set beside the chain, which a `flush
// chain` or a `flush table` left in place: the rules were gone and the guard still read as loaded.
// The rule itself changes nothing: the chain's policy is accept.
func GuardProofProgram(program string) string {
	return fmt.Sprintf("add rule inet %s %s accept comment \"%s\"\n", GuardTable, GuardChain, GuardProofSet(program))
}

// GuardProofPresent reads `nft list chain inet wayhop_ks ks_forward` and says whether the chain is
// the one program loaded: its marker is there, and so are rules ahead of it.
func GuardProofPresent(listing, program string) bool {
	marker := "comment \"" + GuardProofSet(program) + "\""
	rules := 0
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "chain ") ||
			strings.HasPrefix(line, "type ") || line == "}" {
			continue
		}
		rules++
		if strings.Contains(line, marker) {
			// The two private-destination rules are always there; a chain flushed and given only the
			// marker back would not have them.
			return rules >= 3
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// MissingFailClosedRoutes names the kill-switch routes a route dump lacks: for every fail-closed
// egress its `blackhole default metric 1000` (IPv6: 2048), for a block egress its `blackhole default`.
// v4 and v6 are `ip [-6] route show table all` (the table is read from each line); v6 is judged only
// when the plan installs IPv6 routes. A tunnel's own `default dev` route is not judged: the elector
// owns it, and it is legitimately absent while every tunnel is down.
func (pl *Plan) MissingFailClosedRoutes(v4, v6 string) []string {
	if pl == nil {
		return nil
	}
	var out []string
	check := func(dump, fam string, metric int) {
		have := blackholeDefaults(dump)
		for _, e := range pl.nonWanEgresses() {
			switch {
			case e.Kind == EgressBlackhole:
				if len(have[e.Table]) == 0 {
					out = append(out, fmt.Sprintf("%s route blackhole default table %d", fam, e.Table))
				}
			case e.Kind == EgressInterface && e.FailClosed:
				if !have[e.Table][metric] {
					out = append(out, fmt.Sprintf("%s route blackhole default metric %d table %d", fam, metric, e.Table))
				}
			}
		}
	}
	check(v4, "ip", failClosedMetric)
	if pl.hasV6() {
		check(v6, "ip -6", failClosedMetricV6)
	}
	return out
}

// blackholeDefaults reads the `blackhole default` routes of a `route show table all` dump: table ->
// the metrics present (0 for a route printed without one). Shapes, iproute2 and BusyBox alike:
//
//	blackhole default table 151 metric 1000
//	blackhole default dev lo table 151 metric 2048 pref medium     (IPv6)
func blackholeDefaults(dump string) map[int]map[int]bool {
	out := map[int]map[int]bool{}
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "blackhole" || f[1] != "default" {
			continue
		}
		table, metric := 254, 0
		for i := 2; i+1 < len(f); i++ {
			switch f[i] {
			case "table":
				if n, err := strconv.Atoi(f[i+1]); err == nil {
					table = n
				} else {
					table = -1
				}
			case "metric":
				metric, _ = strconv.Atoi(f[i+1])
			}
		}
		if out[table] == nil {
			out[table] = map[int]bool{}
		}
		out[table][metric] = true
	}
	return out
}

// ForeignRule is an `ip rule` line that is not WayHop's and reads WayHop's marks or tables.
type ForeignRule struct {
	Line string
	// Why is "mark" (it matches bits inside the plan's mask), "table" (it looks up a table in
	// WayHop's range), or both joined by "+".
	Why string
	// Mark is the bits of the rule's fwmark inside WayHop's mask (0 when it reads none), and Table
	// the table it looks up (0 when that is not a number). They say whose traffic the
	// rule takes and where to.
	Mark  uint32
	Table int
}

// ForeignRules finds the rules in an `ip rule` dump that would steer WayHop's marked traffic, or send
// traffic into one of WayHop's tables, and that the plan does not install itself. The
// case it was written for: an operator's own failover script that adds
// `pref 145 fwmark 0x30000/0xff0000 lookup 153`, written when 0x30000 was the list it meant; it wins
// over WayHop's rule (lower priority number) for whichever list holds that mark today. own is every
// rule line WayHop installs: the target plan's and the applied plan's RenderIP.
func ForeignRules(dump string, opt Options, own []string) []ForeignRule {
	opt.withDefaults()
	mine := map[ipRuleKey]bool{}
	for _, line := range own {
		for _, lead := range []string{"ip rule add ", "ip -6 rule add "} {
			if rest, ok := strings.CutPrefix(line, lead); ok {
				if k, ok := parseRuleSpec(strings.Fields(rest)); ok {
					mine[k] = true
				}
			}
		}
	}
	keys := parseRuleDump(dump)
	lines := make([]ruleLine, 0, len(keys))
	for _, line := range strings.Split(dump, "\n") {
		if rl, ok := parseRuleLine(line); ok {
			lines = append(lines, rl)
		}
	}
	var out []ForeignRule
	for i, rl := range lines {
		if i >= len(keys) || mine[keys[i]] {
			continue
		}
		var why []string
		mask := rl.fwmask
		if rl.fwmark != 0 && mask == 0 {
			mask = 0xffffffff
		}
		// A mark rule concerns WayHop when the bits it tests include WayHop's and the value it asks
		// for there is one WayHop sets: sing-box's exact `fwmark 0x2024` asks for zero in them.
		if mask&uint64(opt.MarkMask) != 0 && rl.fwmark&uint64(opt.MarkMask) != 0 {
			why = append(why, "mark")
		}
		if n, err := strconv.Atoi(rl.lookup); err == nil && n >= opt.TableBase && n <= opt.TableBase+255 {
			why = append(why, "table")
		}
		if len(why) > 0 {
			fr := ForeignRule{Line: rl.original, Why: strings.Join(why, "+")}
			if mask&uint64(opt.MarkMask) != 0 {
				fr.Mark = uint32(rl.fwmark) & opt.MarkMask
			}
			fr.Table, _ = strconv.Atoi(rl.lookup)
			out = append(out, fr)
		}
	}
	return out
}
