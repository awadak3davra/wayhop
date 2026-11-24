package pbr

// The fast DNS plane (routing mode "fast", Phase 2; docs/ARCHITECTURE_NATIVE_FIRST.md (development repository) "Phase 2").
//
// In fast mode no capture-all TUN sees LAN traffic, so a list or rule that matches names cannot be
// matched by the core. dnsmasq can: with `nftset=` it puts the A/AAAA answers for a list's names into
// a set of this plan's own table as it answers the client, and wr_mark marks that set exactly as the
// list's static set. Lists whose outbound only the core can carry (a proxy, a plugin) keep the TUN,
// and wr_corepin pins every other LAN flow past the core's redirect: a nat chain one step before the
// core's binds the connection's NAT (a DNAT to its own destination), and netfilter runs a later nat
// chain only while that binding is not set. UDP and ICMP follow, because the core marks such a flow
// for its TUN in that same nat chain (owrt-1122 notes, "UDP").
//
// Everything here lives in `table inet <Plan.Table>`, so RenderNft's atomic replace, RenderTeardown
// and the baseline restore already own it. The dynamic sets are the one thing a replace would lose:
// the daemon reads their elements before an Apply and loads them back in the same transaction
// (ParseDlistElements, RenderDlistCarry).

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// RemoteSet is a remote rule-set list's content as the daemon decompiled it (Options.RemoteSets).
type RemoteSet struct {
	// Source is the URL the content was fetched from: content of another URL is not the list's.
	Source string
	// Domains are the rule-set's domain and domain_suffix entries (both are suffixes to dnsmasq).
	Domains []string
	// CIDRs are its ip_cidr entries.
	CIDRs []string
	// Unrepresentable names the matchers the kernel and the resolver cannot express (domain_keyword,
	// domain_regex, geosite, ports, processes...). A list with any is not fast-pathed.
	Unrepresentable []string
}

// DlistTimeout is how long an address stays in a dlist set after the resolver added it or a packet
// to it last passed wr_mark: the marking line refreshes it (`update @set { ip daddr }`), so an
// address in use never expires under a long UDP flow. dnsmasq adds elements
// without a timeout of their own, so the set's default applies.
const DlistTimeout = "6h"

// DlistSize bounds one dlist set: a full set takes no new address (dnsmasq's add and the refresh
// fail quietly), which is the bound on the kernel memory a hostile resolver answer can cost.
const DlistSize = 65536

// DlistSet names the resolver-fed set of a zone for one family (4 or 6).
func DlistSet(zone string, family int) string { return fmt.Sprintf("dlist_%s_%d", zone, family) }

// RlistSet names the set of a zone that holds its remote rule-set's prefixes (Zone.RemoteList).
func RlistSet(zone string, family int) string { return fmt.Sprintf("rlist_%s_%d", zone, family) }

// FastCanaryName is the name the snippet answers itself (FastCanaryAddr): a resolver on :53 that
// answers it is dnsmasq with the snippet loaded, not another resolver in front of it.
const (
	FastCanaryName = "wayhop-canary.home.arpa"
	FastCanaryAddr = "192.0.2.53"
)

// fastZones is every zone the fast DNS plane renders a set for: the marking zones, then the core
// ones. NDM policy zones never reach the nft plane.
func (pl *Plan) fastZones() []Zone {
	out := make([]Zone, 0, len(pl.Zones)+len(pl.CoreZones))
	for _, z := range pl.Zones {
		if z.NDMPolicy == "" {
			out = append(out, z)
		}
	}
	return append(out, pl.CoreZones...)
}

// DlistSets is every dlist set the plan declares, in render order.
func (pl *Plan) DlistSets() []string {
	var out []string
	for _, z := range pl.fastZones() {
		if !zoneHasDomains(z) {
			continue
		}
		out = append(out, DlistSet(z.Name, 4))
		if z.DlistV6() {
			out = append(out, DlistSet(z.Name, 6))
		}
	}
	return out
}

// WANMark is the mark of the plan's WAN egress (0 if none).
func (pl *Plan) WANMark() uint32 {
	if pl == nil {
		return 0
	}
	return pl.markByKind(EgressWAN)
}

// DlistSetsBeyondWAN names the dlist sets whose zone sends its addresses somewhere other than the WAN
// (a tunnel, block, or the core): a flow to such an address that was saved with the WAN mark before
// the name took it is stale (ctflush.Fresh.Stale).
func (pl *Plan) DlistSetsBeyondWAN() map[string]bool {
	out := map[string]bool{}
	if pl == nil {
		return out
	}
	kind := map[string]EgressKind{}
	for _, e := range pl.Egresses {
		kind[e.Tag] = e.Kind
	}
	add := func(z Zone) {
		out[DlistSet(z.Name, 4)] = true
		if z.DlistV6() {
			out[DlistSet(z.Name, 6)] = true
		}
	}
	for _, z := range pl.Zones {
		if zoneHasDomains(z) && z.NDMPolicy == "" && kind[z.EgressTag] != EgressWAN {
			add(z)
		}
	}
	for _, z := range pl.CoreZones {
		if zoneHasDomains(z) {
			add(z)
		}
	}
	return out
}

// V6Refused reports a zone whose names' IPv6 addresses are refused instead of routed (polish 1b): its
// egress is an IPv4-only tunnel (DNSNoV6), so an AAAA answer used by a client would otherwise leave by
// the provider, outside the tunnel the list asks for. The resolver fills the zone's _6 set as usual;
// wd_v6only rejects forwarded IPv6 to it (TCP with a reset, the rest with ICMPv6 administratively
// prohibited) while the packet's mark would send it by the provider, so a dual-stack client falls back
// to the IPv4 address at once (Happy Eyeballs) and that one is routed into the tunnel. Same posture as
// the kill switch's Plan.GuardV6 for the IPv4-only tunnels' IPv6 prefixes, and like it all-device
// zones only: a device scope cannot be told apart for IPv6 once the zone's sources were cut to IPv4.
func (z Zone) V6Refused() bool {
	return z.DNSNoV6 && !z.SrcScoped && z.NDMPolicy == "" && zoneHasDomains(z)
}

// DlistV6 reports whether the zone has a resolver-fed IPv6 set: it routes IPv6, or refuses it.
func (z Zone) DlistV6() bool { return !z.DNSNoV6 || z.V6Refused() }

// HasFastDNS reports whether the plan carries anything of the fast DNS plane.
func (pl *Plan) HasFastDNS() bool {
	return pl != nil && (len(pl.DlistSets()) > 0 || len(pl.CoreZones) > 0 || pl.DNSEnforce)
}

// RemoteLists names the remote lists the plan's zones carry, each once, sorted.
func (pl *Plan) RemoteLists() []string {
	var out []string
	if pl == nil {
		return out
	}
	for _, z := range pl.fastZones() {
		if z.RemoteList != "" {
			out = append(out, z.RemoteList)
		}
	}
	return sortedUnique(out)
}

// RemoteSources is, per remote list the plan carries, the source URL it was reviewed with ("" on a
// plan stored before Zone.RemoteSource existed).
func (pl *Plan) RemoteSources() map[string]string {
	out := map[string]string{}
	if pl == nil {
		return out
	}
	for _, z := range pl.fastZones() {
		if z.RemoteList != "" && out[z.RemoteList] == "" {
			out[z.RemoteList] = z.RemoteSource
		}
	}
	return out
}

// RemoteDirect reports, per remote list, whether every zone carrying it sends it by the WAN (what such
// a list cannot match goes direct anyway, so matchers the plane cannot express do not matter).
func (pl *Plan) RemoteDirect() map[string]bool {
	out := map[string]bool{}
	if pl == nil {
		return out
	}
	kind := map[string]EgressKind{}
	for _, e := range pl.Egresses {
		kind[e.Tag] = e.Kind
	}
	for _, z := range pl.Zones {
		if z.RemoteList == "" {
			continue
		}
		d, seen := out[z.RemoteList]
		out[z.RemoteList] = (d || !seen) && kind[z.EgressTag] == EgressWAN
	}
	for _, z := range pl.CoreZones {
		if z.RemoteList != "" {
			out[z.RemoteList] = false
		}
	}
	return out
}

// fastSetDecls renders, in the plan's own table, the remote lists' prefix sets (empty: filled by
// RenderRemoteElements), the core zones' static sets and the core pin's devices. The resolver-fed
// dlist sets are NOT here: they live in the small DNS table (RenderNftDNS).
func (pl *Plan) fastSetDecls() string {
	var b strings.Builder
	for _, z := range pl.fastZones() {
		if z.RemoteList != "" && !z.RemoteRouted {
			fmt.Fprintf(&b, "\tset %s { type ipv4_addr; flags interval; }\n", RlistSet(z.Name, 4))
			if !z.DNSNoV6 {
				fmt.Fprintf(&b, "\tset %s { type ipv6_addr; flags interval; }\n", RlistSet(z.Name, 6))
			}
		}
	}
	for _, z := range pl.CoreZones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\tset %s_4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V4))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\tset %s_6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V6))
		}
	}
	if pl.CorePinActive() {
		fmt.Fprintf(&b, "\tset %s { type ifname; }\n", CorePinSet)
	}
	return b.String()
}

// CorePinSet holds the input devices wr_corepin pins (the LAN's), filled after the table is loaded.
const CorePinSet = "corepin_lan"

// CoreMark is the mark the DNS table's chain gives a packet to a core-only zone's resolver-fed
// address: inside the plan's mask, never an egress (Compile refuses a plan where it would be one), so
// no ip rule routes by it. wr_corepin returns for it instead of looking the dlist sets up, which live
// in the other table. A kernel zone that also holds the address marks it afterwards in wr_mark, and
// then the kernel carries it.
const CoreMark uint32 = 0x00ff0000

// ScopedDirectMark is the mark the DNS table gives a device-scoped direct zone's names: like the WAN
// mark it matches no ip rule (the main table routes it), but it is its own value, so wr_mark's guard
// can rank it above the tunnels as the single chain did. wr_mark saves it into
// the connmark as the WAN mark. Compile refuses a plan whose egress would hold it.
const ScopedDirectMark uint32 = 0x00fe0000

// dnsMark is the mark a zone's resolver-fed addresses get in the DNS table.
func (pl *Plan) dnsMark(z Zone) uint32 {
	if z.SrcScoped && pl.rankOf(z) == 3 {
		return ScopedDirectMark
	}
	return z.Mark
}

// scopedDirectNames reports a device-scoped direct zone with names (ScopedDirectMark in use).
func (pl *Plan) scopedDirectNames() bool {
	for _, z := range pl.Zones {
		if zoneHasDomains(z) && z.NDMPolicy == "" && pl.dnsMark(z) == ScopedDirectMark {
			return true
		}
	}
	return false
}

// ScopedDirectSaveLine saves ScopedDirectMark into the connmark as the WAN mark ("" when unused).
func (pl *Plan) scopedDirectSaveLine() string {
	if !pl.scopedDirectNames() {
		return ""
	}
	wan := pl.markByKind(EgressWAN)
	return fmt.Sprintf("meta mark & %s == %s ct mark set ct mark & %s | %s",
		hexMark(pl.Mask), hexMark(ScopedDirectMark), hexMark(^pl.Mask), hexMark(wan))
}

// DNSTable is the small table of the resolver-fed sets: dnsmasq's nftset adds go through libnftables,
// which reads the whole target table first, so this one must hold nothing but those sets and their
// few chains (live 22.11: with the lists' static prefixes beside them, every answer for a listed name
// cost dnsmasq a parse of ~4700 lines and it stalled the LAN's DNS).
func (pl *Plan) DNSTable() string {
	if pl == nil || pl.Table == "" {
		return "wayhop_dns"
	}
	return strings.TrimSuffix(pl.Table, "_pbr") + "_dns"
}

// RenderPinElements renders the program that sets the pinned devices: the LAN's when ready (every
// remote list the plan carries has its content loaded), none otherwise. "" without a core pin.
func (pl *Plan) RenderPinElements(ready bool) string {
	if !pl.CorePinActive() {
		return ""
	}
	out := fmt.Sprintf("flush set inet %s %s\n", pl.Table, CorePinSet)
	if ready {
		out += fmt.Sprintf("add element inet %s %s %s\n", pl.Table, CorePinSet, nftStrSet(pl.LANIfaces))
	}
	return out
}

// rankOf is a zone's precedence class as Compile ordered the zones (zoneRank), from the plan's
// egresses: what dnsGuard compares.
func (pl *Plan) rankOf(z Zone) int {
	kind, closed := map[string]EgressKind{}, map[string]bool{}
	for _, e := range pl.Egresses {
		kind[e.Tag] = e.Kind
		closed[e.Tag] = e.FailClosed
	}
	return zoneRank(z, kind, closed)
}

// dnsGuard is the condition every marking line of wr_mark carries when the plan has resolver-fed sets.
// Their marks are set first, in the DNS table's chain (priority mangle - 1); wr_mark then marks by the
// static sets, last mark wins, as before. A static line must not take an address from a STRONGER zone's
// resolver-fed set (a blocked name on an address a tunnel list also covers): it applies only when the
// current mark is not the mark of a dlist zone ranked above this zone. A zone of the same rank or below
// is overridden, which is what the single chain did (names emitted before addresses inside a rank).
// A device-scoped direct zone's names carry ScopedDirectMark, ranked as that zone, so they beat a
// tunnel list's address as before. "" for a plan without names.
func (pl *Plan) dnsGuard(z Zone) string {
	if len(pl.DlistSets()) == 0 {
		return ""
	}
	minRank := map[uint32]int{}
	for _, d := range pl.Zones {
		if !zoneHasDomains(d) || d.NDMPolicy != "" {
			continue
		}
		r, m := pl.rankOf(d), pl.dnsMark(d)
		if old, ok := minRank[m]; !ok || r < old {
			minRank[m] = r
		}
	}
	mine := pl.rankOf(z)
	var higher []string
	for m, r := range minRank {
		if r > mine && m != z.Mark {
			higher = append(higher, hexMark(m))
		}
	}
	if len(higher) == 0 {
		return ""
	}
	sort.Strings(higher)
	return fmt.Sprintf("meta mark & %s != { %s } ", hexMark(pl.Mask), strings.Join(higher, ", "))
}

// RenderNftDNS renders the DNS table: the dlist sets, copies of the source sets their zones need, and
//   - wd_mark (prerouting, mangle - 1, before wr_mark): per zone in the plan's precedence order, an
//     address of a dlist set is marked with the zone's egress (refreshing its timeout); a core zone's addresses get CoreMark (wr_corepin returns for it) and their own
//     refresh;
//   - wd_mark_late (dstnat + 3, ICMP/UDP only): the same marks again after sing-box's absolute
//     re-mark at dstnat + 2; wr_mark_late moves to dstnat + 4 behind it;
//   - wd_v6only (forward, filter - 2): IPv6 to the names of a zone sent to an IPv4-only tunnel is
//     refused while nothing routes it elsewhere (Zone.V6Refused).
//
// Self-flushing like RenderNft, appended to its program (one transaction). "" without names.
func (pl *Plan) RenderNftDNS() string {
	if len(pl.DlistSets()) == 0 {
		return ""
	}
	t := pl.DNSTable()
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", t, t)
	fmt.Fprintf(&b, "table inet %s {\n", t)
	for _, z := range pl.fastZones() {
		if !zoneHasDomains(z) {
			continue
		}
		fmt.Fprintf(&b, "\tset %s { type ipv4_addr; flags dynamic,timeout; timeout %s; size %d; }\n", DlistSet(z.Name, 4), DlistTimeout, DlistSize)
		if z.DlistV6() {
			fmt.Fprintf(&b, "\tset %s { type ipv6_addr; flags dynamic,timeout; timeout %s; size %d; }\n", DlistSet(z.Name, 6), DlistTimeout, DlistSize)
		}
		// A scoped zone's source sets are small (device addresses): copied, so its lines need nothing
		// from the plan's table.
		if len(z.SrcV4) > 0 {
			fmt.Fprintf(&b, "\tset %s_s4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.SrcV4))
		}
		if len(z.SrcV6) > 0 {
			fmt.Fprintf(&b, "\tset %s_s6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.SrcV6))
		}
	}
	var lines, late []string
	for _, z := range pl.Zones {
		if !zoneHasDomains(z) || z.NDMPolicy != "" {
			continue
		}
		pre := z.srcMatchPrefix()
		neg := ""
		if z.SrcNegate {
			neg = "!= "
		}
		if z.SrcNegate || len(z.SrcV4) > 0 || len(z.SrcV6) == 0 {
			src := ""
			if len(z.SrcV4) > 0 {
				src = fmt.Sprintf("ip saddr %s@%s_s4 ", neg, z.Name)
			}
			d := DlistSet(z.Name, 4)
			l := fmt.Sprintf("%s%sip daddr @%s update @%s { ip daddr } %s", pre, src, d, d, pl.markSet(pl.dnsMark(z)))
			lines, late = append(lines, l), append(late, l)
		}
		if !z.DNSNoV6 && (z.SrcNegate || len(z.SrcV6) > 0 || len(z.SrcV4) == 0) {
			src := ""
			if len(z.SrcV6) > 0 {
				src = fmt.Sprintf("ip6 saddr %s@%s_s6 ", neg, z.Name)
			}
			d := DlistSet(z.Name, 6)
			l := fmt.Sprintf("%s%sip6 daddr @%s update @%s { ip6 daddr } %s", pre, src, d, d, pl.markSet(pl.dnsMark(z)))
			lines, late = append(lines, l), append(late, l)
		}
	}
	for _, z := range pl.CoreZones {
		if !zoneHasDomains(z) {
			continue
		}
		d4 := DlistSet(z.Name, 4)
		lines = append(lines, fmt.Sprintf("ip daddr @%s update @%s { ip daddr } %s", d4, d4, pl.markSet(CoreMark)))
		if !z.DNSNoV6 {
			d6 := DlistSet(z.Name, 6)
			lines = append(lines, fmt.Sprintf("ip6 daddr @%s update @%s { ip6 daddr } %s", d6, d6, pl.markSet(CoreMark)))
		}
	}
	b.WriteString("\tchain wd_mark {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "\t\t%s\n", l)
	}
	b.WriteString("\t}\n")
	if len(late) > 0 {
		b.WriteString("\tchain wd_mark_late {\n")
		b.WriteString("\t\ttype filter hook prerouting priority dstnat + 3; policy accept;\n")
		b.WriteString("\t\tmeta l4proto != { icmp, udp, ipv6-icmp } return\n")
		for _, l := range late {
			fmt.Fprintf(&b, "\t\t%s\n", l)
		}
		b.WriteString("\t}\n")
	}
	if refused := pl.v6RefusedLines(); len(refused) > 0 {
		b.WriteString("\tchain wd_v6only {\n")
		b.WriteString("\t\ttype filter hook forward priority filter - 2; policy accept;\n")
		for _, l := range refused {
			fmt.Fprintf(&b, "\t\t%s\n", l)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// v6RefusedLines renders wd_v6only's rules (Zone.V6Refused): forwarded IPv6 to an address of such a
// zone's names is rejected while its mark would send it by the provider (none, the WAN's, or the core
// mark, which no ip rule routes either). A stronger zone, a static prefix of another list or a
// device-scoped direct name that routes the address elsewhere has put its own mark by then, and is
// left alone.
func (pl *Plan) v6RefusedLines() []string {
	var sets []string
	for _, z := range pl.Zones {
		if z.V6Refused() {
			sets = append(sets, DlistSet(z.Name, 6))
		}
	}
	// The core-only lists' names too, while the core's TUN carries no IPv6.
	if pl.coreV6Refused() {
		for _, z := range pl.CoreZones {
			if zoneHasDomains(z) && z.DlistV6() {
				sets = append(sets, DlistSet(z.Name, 6))
			}
		}
	}
	if len(sets) == 0 {
		return nil
	}
	marks := []string{hexMark(0)}
	for _, m := range []uint32{pl.markByKind(EgressWAN), CoreMark} {
		if m != 0 {
			marks = append(marks, hexMark(m))
		}
	}
	marks = sortedUnique(marks)
	var out []string
	for _, d := range sets {
		cond := fmt.Sprintf("ip6 daddr @%s meta mark & %s == { %s }", d, hexMark(pl.Mask), strings.Join(marks, ", "))
		out = append(out, cond+" meta l4proto tcp reject with tcp reset", cond+" reject with icmpv6 type admin-prohibited")
	}
	return out
}

// coreV6Refused reports that IPv6 to the core-only lists' destinations is refused: the
// core pin lets those flows go on to the core, but its TUN carries IPv6 only when a kill switch over
// names asks for it (Plan.GuardNames, generator TunV6), which fast mode with names never has. Without
// it such IPv6 would find no core route and leave by the provider. Refused (TCP reset, else ICMPv6
// administratively prohibited), a dual-stack client takes the IPv4 address, which the core carries.
// Hybrid mode has the same IPv4-only TUN and still lets that IPv6 out; only fast mode refuses it.
func (pl *Plan) coreV6Refused() bool {
	return pl != nil && pl.FastDNS && pl.CorePin && !pl.GuardNames
}

// coreV6Lines renders wr_core_v6's rules: forwarded IPv6 to a core-only list's static or remote
// prefixes, refused while no zone has marked it for an egress the kernel carries.
func (pl *Plan) coreV6Lines() []string {
	if !pl.coreV6Refused() {
		return nil
	}
	var sets []string
	for _, z := range pl.CoreZones {
		if len(z.V6) > 0 {
			sets = append(sets, z.Name+"_6")
		}
		if z.RemoteList != "" && !z.DNSNoV6 {
			sets = append(sets, RlistSet(z.Name, 6))
		}
	}
	marks := []string{hexMark(0)}
	if m := pl.markByKind(EgressWAN); m != 0 {
		marks = append(marks, hexMark(m))
	}
	marks = sortedUnique(marks)
	var out []string
	for _, s := range sets {
		cond := fmt.Sprintf("ip6 daddr @%s meta mark & %s == { %s }", s, hexMark(pl.Mask), strings.Join(marks, ", "))
		out = append(out, cond+" meta l4proto tcp reject with tcp reset", cond+" reject with icmpv6 type admin-prohibited")
	}
	return out
}

// CorePinActive reports whether wr_corepin renders: core-only lists exist and the LAN's devices
// are known.
func (pl *Plan) CorePinActive() bool { return pl != nil && pl.CorePin && len(pl.LANIfaces) > 0 }

// DNSEnforceActive reports whether the LAN DNS redirect and the DoT reject render.
func (pl *Plan) DNSEnforceActive() bool { return pl != nil && pl.DNSEnforce && len(pl.LANIfaces) > 0 }

// fastChains renders wr_corepin and the DNS enforcement chains.
//
// wr_dns runs before wr_corepin (dstnat - 2 against dstnat - 1): a pinned connection's NAT is bound,
// and a redirect in a later nat chain would never run for it.
func (pl *Plan) fastChains() string {
	var b strings.Builder
	lan := nftStrSet(pl.LANIfaces)
	if pl.DNSEnforceActive() {
		b.WriteString("\tchain wr_dns {\n")
		b.WriteString("\t\ttype nat hook prerouting priority dstnat - 2; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname %s fib daddr type != local meta l4proto { tcp, udp } th dport 53 redirect to :53\n", lan)
		b.WriteString("\t}\n")
		b.WriteString("\tchain wr_dot {\n")
		b.WriteString("\t\ttype filter hook forward priority filter - 2; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname %s tcp dport 853 reject with tcp reset\n", lan)
		b.WriteString("\t}\n")
	}
	if pl.CorePinActive() {
		b.WriteString("\tchain wr_corepin {\n")
		b.WriteString("\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n")
		// Only what arrives from the LAN: the core's TUN, the uplink and the router's own output
		// (this is prerouting) are never pinned. The LAN's devices are in corepin_lan, filled at the
		// install only once every remote list's content is loaded (RenderPinElements): until then
		// nothing is pinned and the core, which carries every list by name while the TUN exists,
		// routes all of it.
		fmt.Fprintf(&b, "\t\tiifname != @%s return\n", CorePinSet)
		b.WriteString("\t\tfib daddr type local return\n")
		names := false
		for _, z := range pl.CoreZones {
			names = names || zoneHasDomains(z)
			if len(z.V4) > 0 {
				fmt.Fprintf(&b, "\t\tip daddr @%s_4 return\n", z.Name)
			}
			if z.RemoteList != "" {
				fmt.Fprintf(&b, "\t\tip daddr @%s return\n", RlistSet(z.Name, 4))
			}
			if len(z.V6) > 0 {
				fmt.Fprintf(&b, "\t\tip6 daddr @%s_6 return\n", z.Name)
			}
			if z.RemoteList != "" && !z.DNSNoV6 {
				fmt.Fprintf(&b, "\t\tip6 daddr @%s return\n", RlistSet(z.Name, 6))
			}
		}
		// The core zones' resolver-fed addresses: marked CoreMark by the DNS table's chain.
		if names {
			fmt.Fprintf(&b, "\t\tmeta mark & %s == %s return\n", hexMark(pl.Mask), hexMark(CoreMark))
		}
		b.WriteString("\t\tmeta nfproto ipv4 dnat ip to ip daddr\n")
		b.WriteString("\t\tmeta nfproto ipv6 dnat ip6 to ip6 daddr\n")
		b.WriteString("\t}\n")
	}
	if lines := pl.coreV6Lines(); len(lines) > 0 {
		b.WriteString("\tchain wr_core_v6 {\n")
		b.WriteString("\t\ttype filter hook forward priority filter - 2; policy accept;\n")
		for _, l := range lines {
			fmt.Fprintf(&b, "\t\t%s\n", l)
		}
		b.WriteString("\t}\n")
	}
	return b.String()
}

// RenderRemoteElements renders the program that fills the remote lists' prefix sets from the
// daemon's RAM copy (remote, by list id): each set flushed and filled, so a reload replaces it. Sets
// of a list without content are flushed and left empty. "" when the plan carries no remote list.
func (pl *Plan) RenderRemoteElements(remote map[string]RemoteSet) string {
	return pl.RenderRemoteElementsOnly(remote, nil)
}

// RenderRemoteElementsOnly is RenderRemoteElements for the lists only names (nil: every list).
func (pl *Plan) RenderRemoteElementsOnly(remote map[string]RemoteSet, only map[string]bool) string {
	if pl == nil {
		return ""
	}
	var b strings.Builder
	for _, z := range pl.fastZones() {
		if z.RemoteList == "" || z.RemoteRouted || (only != nil && !only[z.RemoteList]) {
			continue
		}
		v4, v6, _ := classifyCIDRs(remote[z.RemoteList].CIDRs)
		fams := []struct {
			fam   int
			elems []string
		}{{4, v4}, {6, v6}}
		for _, f := range fams {
			if f.fam == 6 && z.DNSNoV6 {
				continue
			}
			name := RlistSet(z.Name, f.fam)
			fmt.Fprintf(&b, "flush set inet %s %s\n", pl.Table, name)
			for elems := f.elems; len(elems) > 0; {
				n := min(len(elems), dlistCarryChunk)
				fmt.Fprintf(&b, "add element inet %s %s { %s }\n", pl.Table, name, strings.Join(elems[:n], ", "))
				elems = elems[n:]
			}
		}
	}
	return b.String()
}

// FastNames is every name the snippet would carry, by zone: the zone's own and its remote list's
// (remote, by list id, as the daemon holds them).
func (pl *Plan) FastNames(remote map[string][]string) map[string][]string {
	out := map[string][]string{}
	if pl == nil {
		return out
	}
	for _, z := range pl.fastZones() {
		names := z.Domains
		if z.RemoteList != "" {
			names = append(append([]string(nil), z.Domains...), remote[z.RemoteList]...)
		}
		if doms := normalizeDomains(names); len(doms) > 0 {
			out[z.Name] = doms
		}
	}
	return out
}

// FastNameCount is how many names the snippet carries across every zone.
func (pl *Plan) FastNameCount(remote map[string][]string) int {
	n := 0
	for _, doms := range pl.FastNames(remote) {
		n += len(doms)
	}
	return n
}

// InvalidFastNames lists, per zone, the names RenderFastDnsmasq leaves out as unusable by dnsmasq.
func (pl *Plan) InvalidFastNames(remote map[string][]string) map[string][]string {
	out := map[string][]string{}
	for zone, doms := range pl.FastNames(remote) {
		for _, d := range doms {
			if !ValidDnsmasqName(d) {
				out[zone] = append(out[zone], d)
			}
		}
	}
	return out
}

// CarrySets names the dlist sets of pl whose addresses may be carried over from prev: the zone's
// names are the same in both plans (an address of a name taken out of a block
// list must not stay blocked). A zone of a remote list carries when it carries the same list; the
// list's content is the RAM copy's and is not compared. prev nil (no installed plan known): every set.
func (pl *Plan) CarrySets(prev *Plan) map[string]bool {
	out := map[string]bool{}
	if pl == nil {
		return out
	}
	old := map[string]Zone{}
	if prev != nil {
		for _, z := range prev.fastZones() {
			old[z.Name] = z
		}
	}
	for _, z := range pl.fastZones() {
		if !zoneHasDomains(z) {
			continue
		}
		if prev != nil {
			o, ok := old[z.Name]
			if !ok || o.RemoteList != z.RemoteList || strings.Join(normalizeDomains(o.Domains), "\n") != strings.Join(normalizeDomains(z.Domains), "\n") {
				continue
			}
		}
		out[DlistSet(z.Name, 4)] = true
		if z.DlistV6() {
			out[DlistSet(z.Name, 6)] = true
		}
	}
	return out
}

// ParseNftSetListings reads the output of several `list set` commands (one `nft -f -` run): the
// elements of each set by name.
func ParseNftSetListings(out string) map[string][]DlistElement {
	res := map[string][]DlistElement{}
	for {
		i := strings.Index(out, "\tset ")
		if i < 0 {
			i = strings.Index(out, " set ")
		}
		if i < 0 {
			return res
		}
		rest := out[i+5:]
		name := strings.Fields(rest)
		if len(name) == 0 {
			return res
		}
		// The set's block ends where the next set (or table) starts.
		end := len(rest)
		if j := strings.Index(rest, "\tset "); j >= 0 {
			end = j
		}
		if j := strings.Index(rest, "table "); j >= 0 && j < end {
			end = j
		}
		res[name[0]] = append(res[name[0]], ParseDlistElements(rest[:end])...)
		out = rest[end:]
	}
}

// --- dnsmasq ---------------------------------------------------------------------------------

// FastDnsmasqHeader starts the snippet the daemon writes into dnsmasq's conf-dir.
const FastDnsmasqHeader = "# WayHop fast path: names of routing lists resolved into nft sets (generated; do not edit)"

// fastDnsmasqLineMax bounds one nftset= line. dnsmasq reads its configuration with a fixed buffer
// (about two domain names long); a line well under 1 KiB is safe on every build.
const fastDnsmasqLineMax = 900

// fastDnsmasqLineNames bounds the names of one nftset= line (keen-pbr #114: long lines with many
// names broke some dnsmasq builds).
const fastDnsmasqLineNames = 50

// fastDnsmasqTargetMax bounds the target sets of one line, so a name and its targets stay inside
// fastDnsmasqLineMax.
const fastDnsmasqTargetMax = fastDnsmasqLineMax - 260

// ValidDnsmasqName reports a name dnsmasq can take in an nftset= line: at most 253 characters, labels
// of 1-63 letters, digits, '-' or '_', not starting or ending with '-'.
func ValidDnsmasqName(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// validNames keeps the names dnsmasq can take.
func validNames(doms []string) []string {
	out := doms[:0:0]
	for _, d := range doms {
		if ValidDnsmasqName(d) {
			out = append(out, d)
		}
	}
	return out
}

// RenderFastDnsmasq renders the dnsmasq snippet of the fast DNS plane: per zone with names, one or more
// `nftset=/a/b/.../4#inet#<table>#dlist_<zone>_4,6#inet#<table>#dlist_<zone>_6` lines, the names
// chunked so no line exceeds fastDnsmasqLineMax, and the canary the daemon asks for to tell that the
// resolver on :53 is this dnsmasq with this snippet. remote is the remote lists' names by list id
// (RAM). "" when no zone carries names.
func (pl *Plan) RenderFastDnsmasq(remote map[string][]string) string {
	snippet, _ := pl.fastDnsmasq(remote)
	return snippet
}

// OverfullFastNames are the names whose zones do not all fit one nftset line: the snippet leaves them
// out, Review refuses the plan (dnsmasq takes one entry per name, so a dropped
// zone's set would never get the name's addresses), and a live reload reports them in Diagnostics.
func (pl *Plan) OverfullFastNames(remote map[string][]string) []string {
	_, over := pl.fastDnsmasq(remote)
	sort.Strings(over)
	return over
}

func (pl *Plan) fastDnsmasq(remote map[string][]string) (string, []string) {
	if pl == nil {
		return "", nil
	}
	// dnsmasq takes ONE nftset entry per query: the longest matching name, the last one read among
	// equals. A name in several zones, or under a name of another zone, would
	// fill one set only. So the targets are computed per name: every zone holding the name or any name
	// above it, and names with the same targets share lines.
	names := pl.FastNames(remote)
	zoneOf := map[string]Zone{}
	byName := map[string][]string{} // name -> zones holding it
	for _, z := range pl.fastZones() {
		zoneOf[z.Name] = z
		for _, d := range validNames(names[z.Name]) {
			byName[d] = append(byName[d], z.Name)
		}
	}
	if len(byName) == 0 {
		return "", nil
	}
	var overfull []string
	targetsOf := func(d string) []string {
		seen := map[string]bool{}
		var zs []string
		for n := d; ; {
			for _, z := range byName[n] {
				if !seen[z] {
					seen[z] = true
					zs = append(zs, z)
				}
			}
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
		}
		sort.Strings(zs)
		return zs
	}
	groups := map[string][]string{} // target string -> names
	var order []string
	render := func(zs []string) string {
		var t4, t6 []string
		for _, zn := range zs {
			t4 = append(t4, fmt.Sprintf("4#inet#%s#%s", pl.DNSTable(), DlistSet(zn, 4)))
			if zoneOf[zn].DlistV6() {
				t6 = append(t6, fmt.Sprintf("6#inet#%s#%s", pl.DNSTable(), DlistSet(zn, 6)))
			}
		}
		return strings.Join(append(t4, t6...), ",")
	}
	for d := range byName {
		zs := targetsOf(d)
		target := render(zs)
		if len(target) > fastDnsmasqTargetMax {
			// Left out (polish 1a): Review refuses such a plan, but a remote list refreshed at run time
			// can create one. Kept with only some of its zones, the name would fill those sets and never
			// the others, so devices of a dropped zone would go a stronger zone's way; left out, the name
			// goes the way its addresses' static entries say, and Diagnostics names it.
			overfull = append(overfull, d)
			continue
		}
		if _, ok := groups[target]; !ok {
			order = append(order, target)
		}
		groups[target] = append(groups[target], d)
	}
	sort.Strings(order)
	var lines []string
	for _, target := range order {
		doms := groups[target]
		sort.Strings(doms)
		lines = append(lines, chunkNftset(doms, target, fastDnsmasqLineMax)...)
	}
	lines = append(lines, "address=/"+FastCanaryName+"/"+FastCanaryAddr)
	return FastDnsmasqHeader + "\n" + strings.Join(lines, "\n") + "\n", overfull
}

// chunkNftset packs names into nftset= lines of at most fastDnsmasqLineNames names, no longer than max (a single name longer than the room
// left still gets a line of its own: dnsmasq rejects nothing for it, and a name is at most 253).
func chunkNftset(doms []string, target string, max int) []string {
	var out []string
	var cur []string
	size := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, "nftset=/"+strings.Join(cur, "/")+"/"+target)
			cur, size = nil, 0
		}
	}
	fixed := len("nftset=/") + len("/") + len(target)
	for _, d := range doms {
		add := len(d)
		if len(cur) > 0 {
			add++ // the separating slash
		}
		if len(cur) > 0 && (fixed+size+add > max || len(cur) >= fastDnsmasqLineNames) {
			flush()
			add = len(d)
		}
		cur = append(cur, d)
		size += add
	}
	flush()
	return out
}

// DnsmasqHasNftset reports whether `dnsmasq --version` lists nftset among its compile-time options
// (dnsmasq-full; the plain dnsmasq package prints no-nftset or nothing).
func DnsmasqHasNftset(version string) bool {
	for _, f := range strings.Fields(version) {
		if f == "nftset" {
			return true
		}
	}
	return false
}

// DnsmasqConfDirs reads the conf-dir lines of the running dnsmasq configurations (OpenWrt writes one
// per instance, /var/etc/dnsmasq.conf.<section>, with `conf-dir=/tmp/dnsmasq.<section>.d`). files maps
// a path to its content. Each directory once, sorted; a `conf-dir=<dir>,<filter>` keeps the directory.
func DnsmasqConfDirs(files map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, text := range files {
		for _, ln := range strings.Split(text, "\n") {
			ln = strings.TrimSpace(ln)
			v, ok := strings.CutPrefix(ln, "conf-dir=")
			if !ok {
				continue
			}
			dir, _, _ := strings.Cut(v, ",")
			dir = strings.TrimSpace(dir)
			if !(strings.HasPrefix(dir, "/") || filepath.IsAbs(dir)) || seen[dir] {
				continue
			}
			seen[dir] = true
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

// --- dynamic set carry-over -----------------------------------------------------------------

// DlistElement is one address in a dlist set and the seconds it has left (0: the set's default).
type DlistElement struct {
	Addr string
	Left int
}

// ParseDlistElements reads the elements of an `nft list set` listing: each address with the time
// its expiry leaves (`expires 5h59m48s896ms`). Anything that is not an address is skipped.
func ParseDlistElements(listing string) []DlistElement {
	i := strings.Index(listing, "elements = {")
	if i < 0 {
		return nil
	}
	body := listing[i+len("elements = {"):]
	if j := strings.Index(body, "}"); j >= 0 {
		body = body[:j]
	}
	var out []DlistElement
	for _, item := range strings.Split(body, ",") {
		f := strings.Fields(item)
		if len(f) == 0 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		e := DlistElement{Addr: a.String()}
		for k := 1; k+1 < len(f); k++ {
			if f[k] == "expires" {
				if s, ok := nftDuration(f[k+1]); ok {
					e.Left = s
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// dlistCarryChunk bounds the elements of one `add element` statement.
const dlistCarryChunk = 256

// RenderDlistCarry renders the program that puts carried elements back into the plan's dlist sets:
// only into sets the plan declares, each address once per set, with the time it had left. "" for
// nothing to add.
func (pl *Plan) RenderDlistCarry(sets map[string][]DlistElement) string {
	if pl == nil || len(sets) == 0 {
		return ""
	}
	var b strings.Builder
	for _, name := range pl.DlistSets() {
		v6 := strings.HasSuffix(name, "_6")
		seen := map[string]bool{}
		var elems []string
		for _, e := range sets[name] {
			a, err := netip.ParseAddr(e.Addr)
			if err != nil || a.Is6() != v6 || seen[a.String()] {
				continue
			}
			seen[a.String()] = true
			el := a.String()
			if e.Left > 0 {
				el += " timeout " + strconv.Itoa(e.Left) + "s"
			}
			elems = append(elems, el)
		}
		for len(elems) > 0 {
			n := min(len(elems), dlistCarryChunk)
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", pl.DNSTable(), name, strings.Join(elems[:n], ", "))
			elems = elems[n:]
		}
	}
	return b.String()
}

// ParseDlistCarry reads a program RenderDlistCarry wrote back into elements by set.
func ParseDlistCarry(program string) map[string][]DlistElement {
	out := map[string][]DlistElement{}
	for _, ln := range strings.Split(program, "\n") {
		f := strings.Fields(ln)
		// add element inet <table> <set> { ... }
		if len(f) < 6 || f[0] != "add" || f[1] != "element" || f[2] != "inet" {
			continue
		}
		set := f[4]
		start, end := strings.Index(ln, "{"), strings.LastIndex(ln, "}")
		if start < 0 || end < start {
			continue
		}
		for _, item := range strings.Split(ln[start+1:end], ",") {
			g := strings.Fields(item)
			if len(g) == 0 {
				continue
			}
			a, err := netip.ParseAddr(g[0])
			if err != nil {
				continue
			}
			e := DlistElement{Addr: a.String()}
			if len(g) >= 3 && g[1] == "timeout" {
				if s, ok := nftDuration(g[2]); ok {
					e.Left = s
				}
			}
			out[set] = append(out[set], e)
		}
	}
	return out
}
