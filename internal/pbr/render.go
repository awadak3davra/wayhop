package pbr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// hexMark formats a 32-bit fwmark/mask.
func hexMark(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// markSet renders the nft expression that sets our mark bits while preserving any
// non-owned bits (so it coexists with fw4's own marks).
func (pl *Plan) markSet(mark uint32) string {
	return fmt.Sprintf("meta mark set meta mark & %s | %s", hexMark(^pl.Mask), hexMark(mark))
}

// connmarkRestoreLines renders the L2 restore-first rules for the TOP of wr_mark: for each egress
// mark, if an established connection's saved connmark (set by `ct mark set meta mark` at the chain's
// end) carries that egress's owned bits, re-adopt it and `accept`. So a long-lived flow keeps its
// chosen exit even after its destination later leaves an (e.g. DNS-populated, expiring) set, instead
// of falling to the WAN default mid-connection — a censored-traffic leak / dropped call. This is the
// nft mirror of the ipset/iptables plane's `CONNMARK --restore-mark --nfmask M --ctmask M`
// (render_ipset.go). nft CANNOT express a single masked meta↔ct merge — real `nft -f` rejects
// `meta mark set meta mark & ~M | ct mark & M` with "Right hand side of binary operation (|) must be
// constant" (the exact form reverted from 0.3.5). So instead we compare `ct mark` to each egress's
// CONSTANT mark and re-apply that constant via the proven markSet form — valid nft AND it preserves
// non-owned (fw4) bits. Terminating (`accept`): a pinned flow short-circuits the per-zone
// re-classification below, which is precisely the egress affinity L2 exists to provide. Marks are
// de-duped; a 0 mark (no egress chosen) is skipped so unpinned flows fall through to normal matching.
func (pl *Plan) connmarkRestoreLines() []string {
	var out []string
	seen := map[uint32]bool{}
	for _, e := range pl.Egresses {
		if e.Mark == 0 || seen[e.Mark] {
			continue
		}
		seen[e.Mark] = true
		out = append(out, fmt.Sprintf("ct mark & %s == %s %s accept",
			hexMark(pl.Mask), hexMark(e.Mark), pl.markSet(e.Mark)))
	}
	return out
}

func nftElements(cidrs []string) string { return strings.Join(cidrs, ", ") }

// nftStrSet renders an anonymous nft set of quoted strings (iface names). nft accepts trailing-*
// wildcards inside an iifname set (validated on-device), so SrcIface entries pass through verbatim.
func nftStrSet(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = `"` + s + `"`
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

// nftRawSet renders an anonymous nft set of raw tokens (MAC addresses).
func nftRawSet(ss []string) string { return "{ " + strings.Join(ss, ", ") + " }" }

// nftIntSet renders an anonymous nft set of integers (ports).
func nftIntSet(ns []int) string {
	q := make([]string, len(ns))
	for i, n := range ns {
		q[i] = strconv.Itoa(n)
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

// srcMatchPrefix renders the family-agnostic nft source-match terms (iface, mac, port) for a
// source-scoped zone, in a stable order, each as an anonymous set. Returns "" when the zone has
// none. The caller appends the family-specific `ip/ip6 saddr @<name>_s4/_s6` term after this.
func (z *Zone) srcMatchPrefix() string {
	var parts []string
	op := " " // positive match; " != " inverts every source term for an "except" (negated) zone
	if z.SrcNegate {
		op = " != "
	}
	if len(z.SrcIface) > 0 {
		parts = append(parts, "iifname"+op+nftStrSet(z.SrcIface))
	}
	if len(z.SrcMAC) > 0 {
		parts = append(parts, "ether saddr"+op+nftRawSet(z.SrcMAC))
	}
	if len(z.SrcPort) > 0 {
		// th sport needs a transport header — guard with l4proto so non-tcp/udp packets skip it.
		parts = append(parts, "meta l4proto { tcp, udp } th sport"+op+nftIntSet(z.SrcPort))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + " "
}

// RenderNft returns the full nftables ruleset for this plan's OWN table (applied via
// `nft -f -`). It only ever touches `table inet <pl.Table>`, so it coexists with fw4
// and sing-box's auto_redirect table and survives `fw4 reload` (re-apply on reload).
func (pl *Plan) RenderNft() string {
	var b strings.Builder
	// Self-flushing idiom: one atomic `nft -f` transaction that recreates our table from
	// scratch (ensure-exists → delete → recreate) so apply is idempotent with no gap.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", pl.Table, pl.Table)
	fmt.Fprintf(&b, "table inet %s {\n", pl.Table)

	// Phase 1b flow-offload datapath (opt-in; nil unless Options.Offload was set). The
	// flowtable + the mark-gated flow-add chain live in OUR table, so they tear down with
	// it (fail-safe-safe) and never touch fw4. The forward chain runs AFTER prerouting
	// (where wr_mark set the fwmark), so carve-out flows (any owned mark bit set) hit the
	// `return` and are NEVER offloaded — keeping their per-packet PBR (and the UDP calls it
	// carries) intact; only general (mark 0) traffic is added to the flowtable.
	if ft := pl.Flowtable; ft != nil && len(ft.Devices) > 0 {
		b.WriteString("\tflowtable ft {\n\t\thook ingress priority filter - 1;\n")
		fmt.Fprintf(&b, "\t\tdevices = { %s };\n", strings.Join(ft.Devices, ", "))
		if ft.HW {
			b.WriteString("\t\tflags offload;\n")
		}
		b.WriteString("\t}\n")
	}

	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\tset bypass4 { type ipv4_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV4))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\tset bypass6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV6))
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\tset %s_4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V4))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\tset %s_6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V6))
		}
		// Source-scoped zones (Phase C): a separate saddr set per family so the wr_mark line
		// can match `ip saddr @<name>_s4` in addition to its dest set.
		if len(z.SrcV4) > 0 {
			fmt.Fprintf(&b, "\tset %s_s4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.SrcV4))
		}
		if len(z.SrcV6) > 0 {
			fmt.Fprintf(&b, "\tset %s_s6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.SrcV6))
		}
	}

	// Chain name must NOT be an nft reserved keyword — `chain mark { ... }` fails to
	// parse ("unexpected mark"), since `mark` is a keyword (meta mark / ct mark). Use a
	// namespaced identifier instead. (Caught only by a real `nft -f` on-device; the unit
	// tests use a mock runner and never parsed the ruleset.)
	b.WriteString("\tchain wr_mark {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// Anti-loop bypass FIRST + TERMINATING (#12/#13): tunnel peer/server IPs must egress via WAN and
	// STOP here — `accept` short-circuits both the L2 restore and the per-zone match below. Without the
	// accept (and with the bypass below the restore, as before), a peer IP that happens to fall inside a
	// routed CIDR (a broad geo/ASN list, or a /16 carve-out) got marked into the tunnel = the classic
	// routing loop, and an established peer flow whose connmark carried a tunnel mark was re-pinned by
	// the L2 restore. Bypass-first-terminating closes both, and mirrors the ipset plane's precedence.
	wanMark := pl.markByKind(EgressWAN)
	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr @bypass4 %s accept\n", pl.markSet(wanMark))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr @bypass6 %s accept\n", pl.markSet(wanMark))
	}
	// L2 restore-first connmark: re-adopt an established flow's previously-chosen egress (saved into
	// the connmark by `ct mark set meta mark` at the chain end) and accept, BEFORE re-classifying it
	// below — so a flow stays on its tunnel even after its dest leaves an expiring set. Peer IPs were
	// already accepted above, so the restore can't re-pin them. See connmarkRestoreLines for why this
	// is per-egress (nft can't express a masked meta↔ct merge).
	for _, line := range pl.connmarkRestoreLines() {
		fmt.Fprintf(&b, "\t\t%s\n", line)
	}
	sourceOnly := false
	for _, z := range pl.Zones {
		// Source-scoped zones prepend source matches so ONLY traffic from the matching source
		// gets the mark (the dest set still bounds it to the rule's destinations — so this line
		// never matches a tunnel peer IP, which lives in @bypass and was marked WAN above; no
		// bypass re-assert is needed for source+dest zones). pre = the family-agnostic terms
		// (iface/mac/port); the per-family `ip/ip6 saddr @<name>_s4/_s6` is added after it.
		pre := z.srcMatchPrefix()
		// Cross-family guard: if the zone carries a source IP but NOT in this family (e.g. a v6
		// source on a v4 dest line), the source can't constrain this family's traffic — emitting
		// it would mark the dest for every source (an over-route). Skip that line. A zone with no
		// source IP (plain dest, or iface/mac/port only) is unaffected.
		neg := ""
		if z.SrcNegate {
			neg = "!= " // "except" zone: mark for every source NOT in the group's IP set
		}
		// Negated (except) zone: ALWAYS emit a family's dest line — the `!=` terms only carve out
		// exceptions, so a family whose exception lives in the OTHER family (e.g. a v6-only member on
		// a v4 dest, un-excludable on the v4 plane) still routes everyone in this family. Without the
		// SrcNegate escape the guard below would drop the line → the whole list silently routes nobody
		// on that family. Positive zones keep the original cross-family guard (a v6-only source on a v4
		// dest can't constrain v4, so skip it rather than over-route all v4).
		if len(z.V4) > 0 && (z.SrcNegate || len(z.SrcV4) > 0 || len(z.SrcV6) == 0) {
			src := ""
			if len(z.SrcV4) > 0 {
				src = fmt.Sprintf("ip saddr %s@%s_s4 ", neg, z.Name)
			}
			fmt.Fprintf(&b, "\t\t%s%sip daddr @%s_4 %s\n", pre, src, z.Name, pl.markSet(z.Mark))
		}
		if len(z.V6) > 0 && (z.SrcNegate || len(z.SrcV6) > 0 || len(z.SrcV4) == 0) {
			src := ""
			if len(z.SrcV6) > 0 {
				src = fmt.Sprintf("ip6 saddr %s@%s_s6 ", neg, z.Name)
			}
			fmt.Fprintf(&b, "\t\t%s%sip6 daddr @%s_6 %s\n", pre, src, z.Name, pl.markSet(z.Mark))
		}
		// Source-only zone (no dest): matches EVERY destination from the matching source. Emit a
		// per-family saddr line when the source carries IPs; otherwise one family-agnostic line
		// (iface/mac/port). Never emit a condition-less line (pre=="" with no saddr would mark
		// everything) — a SrcScoped zone always has at least one matcher, but guard regardless.
		if len(z.V4) == 0 && len(z.V6) == 0 && z.SrcScoped {
			wrote := false
			if len(z.SrcV4) > 0 {
				fmt.Fprintf(&b, "\t\t%sip saddr @%s_s4 %s\n", pre, z.Name, pl.markSet(z.Mark))
				wrote = true
			}
			if len(z.SrcV6) > 0 {
				fmt.Fprintf(&b, "\t\t%sip6 saddr @%s_s6 %s\n", pre, z.Name, pl.markSet(z.Mark))
				wrote = true
			}
			if !wrote && pre != "" {
				fmt.Fprintf(&b, "\t\t%s%s\n", pre, pl.markSet(z.Mark))
				wrote = true
			}
			if wrote {
				sourceOnly = true
			}
		}
	}
	// Re-assert the anti-loop bypass AFTER any source-only line: such a line has no dest, so it
	// also matches a tunnel-peer IP — re-mark peer-destined traffic back to WAN (last matching
	// mark wins) so a tunnel's own packets to its peer never loop back into the tunnel.
	if sourceOnly {
		if len(pl.BypassV4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr @bypass4 %s\n", pl.markSet(wanMark))
		}
		if len(pl.BypassV6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr @bypass6 %s\n", pl.markSet(wanMark))
		}
	}
	// Save the chosen egress fwmark into the connmark so the connection's exit is visible in
	// /proc/net/nf_conntrack (the Dashboard reads `mark=` to attribute each connection to its
	// tunnel/WAN). Informational only — it does not affect routing (the meta mark above does).
	b.WriteString("\t\tct mark set meta mark\n")
	b.WriteString("\t}\n")

	// Flow-offload chain (Phase 1b): only when a flowtable is present. Base chain on the
	// forward hook just BEFORE fw4's (priority filter-1) with policy accept, so it adds
	// flows without short-circuiting fw4's filtering (accept is non-terminating across base
	// chains; only the per-packet offload decision is ours). Carve-outs (mark != 0) return
	// before the flow-add; general (mark 0) tcp/udp is offloaded to @ft.
	if pl.Flowtable != nil && len(pl.Flowtable.Devices) > 0 {
		b.WriteString("\tchain wr_offload {\n")
		b.WriteString("\t\ttype filter hook forward priority filter - 1; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta mark & %s != 0x0 return\n", hexMark(pl.Mask))
		b.WriteString("\t\tmeta l4proto { tcp, udp } flow add @ft\n")
		b.WriteString("\t}\n")
	}

	// TCP MSS clamping chain (QW1): SYN packets forwarded out any kernel tunnel egress have
	// their MSS option rewritten to `rt mtu` (the kernel's per-flow route MTU, updated by
	// ICMP frag-needed PMTU discovery). Without this, the AWG/WG encapsulation overhead
	// (~120 B typically → 1500-byte LAN frames become ~1380-byte tunnel frames) silently
	// fragments large TCP flows or causes PMTU blackholes — the primary cause of slow sites
	// and long TLS-handshake setup delays. `rt mtu` is dynamic, so it self-adjusts when the
	// path MTU changes (no hard-coded value). Only SYN packets carry the MSS option: at most
	// one match per TCP connection, negligible overhead. Chain lives in OUR self-flushing
	// table → RenderTeardown's `delete table` removes it atomically (fail-safe-safe).
	if ifaces := pl.mssIfaces(); len(ifaces) > 0 {
		b.WriteString("\tchain wr_mss {\n")
		b.WriteString("\t\ttype filter hook forward priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\toifname %s tcp flags & (fin|syn|rst|ack) == syn tcp option maxseg size set rt mtu\n", nftStrSet(ifaces))
		b.WriteString("\t}\n")
	}

	// Forwarded-LAN MASQUERADE on every tunnel egress dev. Forwarded LAN traffic steered out
	// an adopted/owned kernel tunnel iface (an EgressInterface egress) keeps its private
	// (RFC1918) source unless we SNAT it to the tunnel's source — the peer would otherwise have
	// no route back (the exact black-hole from project history; the Keenetic iptables path
	// already MASQUERADEs every failover member — this nft path was the gap). We match on
	// oifname (the egress dev), NOT fwmark: by POSTROUTING the packet is already on the tunnel
	// dev, so masquerade is a harmless no-op for the router's own egress (already tunnel-src'd)
	// and only rewrites forwarded LAN flows. One line per UNIQUE iface so a failover re-election
	// to another member dev stays NATed. The chain lives in THIS plan's own self-flushing table,
	// so RenderTeardown's `delete table inet <pl.Table>` removes it automatically (fail-safe).
	// v4 ONLY: mirror render_ipset.go's fail-closed posture — no v6 MASQUERADE (no v6 LAN on
	// target; v6 forwarded flows stay in the tunnel table rather than leak).
	// WAN-fallback MASQUERADE companion to the tunnel-iface lines above. If a failover/
	// no-kill-switch policy ever routes WR-marked forwarded traffic OUT the WAN uplink dev (an
	// EgressWAN egress that carries a concrete Iface — e.g. a "direct" fallback that hands
	// general/failover flows to the WAN netdev instead of the main-table fall-through), those
	// forwarded LAN flows would leave un-NATed and the upstream would have no route back — the
	// same black-hole the tunnel masquerade prevents, mirroring render_ipset.go's WAN-fallback
	// SNAT (which MASQUERADEs WAN-marked forwarded traffic via Options.WanIface). Here the WAN
	// iface is read from the compiled Plan's EgressWAN.Iface (empty today → this stays a
	// byte-identical no-op for every current plan and protects the render/render_masq goldens).
	// Same posture as the tunnel lines: v4-only, oifname-matched (not fwmark), deduped against
	// the tunnel ifaces, and inside THIS plan's self-flushing table so RenderTeardown removes it.
	tunIfaces := pl.masqIfaces()
	wanIfaces := pl.masqWanIfaces(tunIfaces)
	if len(tunIfaces) > 0 || len(wanIfaces) > 0 {
		b.WriteString("\tchain wr_nat {\n")
		b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
		for _, ifc := range tunIfaces {
			fmt.Fprintf(&b, "\t\tmeta nfproto ipv4 oifname \"%s\" masquerade\n", ifc)
		}
		for _, ifc := range wanIfaces {
			fmt.Fprintf(&b, "\t\tmeta nfproto ipv4 oifname \"%s\" masquerade\n", ifc)
		}
		b.WriteString("\t}\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func (pl *Plan) markByKind(k EgressKind) uint32 {
	for _, e := range pl.Egresses {
		if e.Kind == k {
			return e.Mark
		}
	}
	return 0
}

// ipRuleExclude is a destination CIDR pinned to the main table at a given priority.
type ipRuleExclude struct {
	CIDR     string
	Priority int
}

// privateExcludes returns ip-rule exclusions that keep LAN/private-destination traffic
// on the main table, just BELOW the fwmark rules. Without them the CONNMARK-restore
// re-marks an established flow's RETURN packets (internet→LAN) with the tunnel mark, and
// since each table holds only `default dev <tunnel>`, the reply to a LAN client loops
// back out the tunnel instead of reaching it — a real SYN_RECV stall seen live on the
// Keenetic. RFC1918 dsts never belong on a tunnel egress (the censored sets are public),
// so this is safe; priorities sit just under RulePref so they win over the fwmark rules.
func privateExcludes(opt Options) []ipRuleExclude {
	return excludesFor(opt, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
}

// privateExcludesV6 is the IPv6 analogue: ULA + link-local stay on the main table so a
// v6 LAN/local-dst reply isn't re-marked onto a tunnel table (same loop the v4 exclusion
// prevents). Emitted only when the plan actually marks v6.
func privateExcludesV6(opt Options) []ipRuleExclude {
	return excludesFor(opt, []string{"fc00::/7", "fe80::/10"})
}

func excludesFor(opt Options, cidrs []string) []ipRuleExclude {
	opt.withDefaults()
	out := make([]ipRuleExclude, len(cidrs))
	for j, c := range cidrs {
		out[j] = ipRuleExclude{c, opt.RulePref - len(cidrs) + j}
	}
	return out
}

// hasV6 reports whether this plan marks any IPv6 traffic — a bypass-v6 peer OR any zone that
// marks v6 (a v6 dest CIDR, a v6 source CIDR, or a family-agnostic source-only zone whose only
// matcher is iface/mac/port and so applies to BOTH families). Used to gate the symmetric
// ip -6 rule / ip -6 route commands: a v4-only plan must emit no `ip -6` at all.
//
// It MUST stay in exact lockstep with the wr_mark chain (RenderNft): every construct there that
// can set the tunnel mark on a v6 packet needs a matching `ip -6 rule fwmark`, else that marked
// v6 packet finds no fwmark rule, falls through to the main v6 table, and LEAKS to WAN unencrypted.
// The zone half of that test is exactly hasV6Zone() (the Keenetic ipset plane already got it
// right) — reuse it so the nft and ipset planes can never diverge again. (Earlier this checked
// only BypassV6/z.V6, so the SrcV6 and family-agnostic source-only cases leaked v6.)
func (pl *Plan) hasV6() bool {
	return len(pl.BypassV6) > 0 || pl.hasV6Zone()
}

// failClosedMetric is the route metric for a kill-switched egress's blackhole fallback. It must be
// strictly greater than the tunnel route's metric (0) so the `default dev <iface>` route wins while
// the iface is up, and only the blackhole remains once that route is flushed on link-down.
const failClosedMetric = 1000

// RenderIP returns the idempotent `ip rule`/`ip route` (and symmetric `ip -6 rule`/
// `ip -6 route` when the plan marks v6) commands to install the plan.
// WAN-marked traffic (the bypass) needs no rule — it falls through to the main table.
func (pl *Plan) RenderIP(opt Options) []string {
	opt.withDefaults()
	v6 := pl.hasV6()
	var cmds []string
	for _, x := range privateExcludes(opt) {
		cmds = append(cmds, fmt.Sprintf("ip rule add to %s lookup main priority %d", x.CIDR, x.Priority))
	}
	if v6 {
		for _, x := range privateExcludesV6(opt) {
			cmds = append(cmds, fmt.Sprintf("ip -6 rule add to %s lookup main priority %d", x.CIDR, x.Priority))
		}
	}
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule add fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		if v6 {
			cmds = append(cmds, fmt.Sprintf("ip -6 rule add fwmark %s/%s table %d priority %d",
				hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		}
		switch e.Kind {
		case EgressInterface:
			cmds = append(cmds, fmt.Sprintf("ip route replace default dev %s table %d", e.Iface, e.Table))
			if v6 {
				cmds = append(cmds, fmt.Sprintf("ip -6 route replace default dev %s table %d", e.Iface, e.Table))
			}
			if e.FailClosed {
				// Kill switch: a fail-closed fallback in the SAME table at a high metric. While the
				// tunnel iface is up its `default dev` route (metric 0) wins; if the iface goes down
				// the kernel flushes that route and this blackhole (no iface dependency) catches the
				// fwmark'd traffic and DROPS it — instead of the lookup falling through to the main
				// table (WAN). The high metric keeps it strictly below the live tunnel route.
				// (Verified on-device: busybox iproute2 accepts `blackhole default metric N table N`
				// and orders it below the metric-0 dev route.)
				cmds = append(cmds, fmt.Sprintf("ip route replace blackhole default metric %d table %d", failClosedMetric, e.Table))
				if v6 {
					cmds = append(cmds, fmt.Sprintf("ip -6 route replace blackhole default metric %d table %d", failClosedMetric, e.Table))
				}
			}
		case EgressBlackhole:
			cmds = append(cmds, fmt.Sprintf("ip route replace blackhole default table %d", e.Table))
			if v6 {
				// `replace` (not `add`) for idempotency, matching every sibling route line — `add`
				// errors `RTNETLINK: File exists` on a re-assert that skips the preceding flush.
				cmds = append(cmds, fmt.Sprintf("ip -6 route replace blackhole default table %d", e.Table))
			}
		}
	}
	return cmds
}

// ipTeardown returns just the `ip rule`/`ip route` removal commands (no nft).
func (pl *Plan) ipTeardown(opt Options) []string {
	opt.withDefaults()
	v6 := pl.hasV6()
	var cmds []string
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule del fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		if v6 {
			cmds = append(cmds, fmt.Sprintf("ip -6 rule del fwmark %s/%s table %d priority %d",
				hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		}
		cmds = append(cmds, fmt.Sprintf("ip route flush table %d", e.Table))
		if v6 {
			cmds = append(cmds, fmt.Sprintf("ip -6 route flush table %d", e.Table))
		}
	}
	for _, x := range privateExcludes(opt) {
		cmds = append(cmds, fmt.Sprintf("ip rule del to %s lookup main priority %d", x.CIDR, x.Priority))
	}
	if v6 {
		for _, x := range privateExcludesV6(opt) {
			cmds = append(cmds, fmt.Sprintf("ip -6 rule del to %s lookup main priority %d", x.CIDR, x.Priority))
		}
	}
	return cmds
}

// RenderTeardown returns the commands to remove everything RenderNft/RenderIP installed.
func (pl *Plan) RenderTeardown(opt Options) []string {
	return append([]string{fmt.Sprintf("nft delete table inet %s", pl.Table)}, pl.ipTeardown(opt)...)
}

// masqIfaces returns the unique kernel tunnel ifnames that need a forwarded-LAN MASQUERADE.
// The set is plan.MasqIfaces (populated by Compile from all enabled EngineExternal endpoints)
// so an adopted tunnel that only carries IPv6 CIDRs — filtered from zones by the v4-only
// posture — still gets a MASQUERADE rule. Empty for plans with no external-interface endpoints.
func (pl *Plan) masqIfaces() []string { return pl.MasqIfaces }

// masqWanIfaces returns the unique WAN uplink ifnames that need the WAN-fallback forwarded-LAN
// MASQUERADE: any EgressWAN egress that carries a concrete Iface (a no-kill-switch / failover
// fallback that routes WR-marked forwarded traffic out the WAN netdev rather than the main-table
// fall-through). Empty for every current plan — Compile leaves EgressWAN.Iface "" — so the nft
// output is byte-identical to today (the no-op the render/render_masq goldens depend on). Any
// iface already covered by the tunnel-masquerade lines (`skip`) is dropped so the WAN line is
// never a duplicate of a tunnel line, and the result is de-duped + stable-sorted for determinism.
func (pl *Plan) masqWanIfaces(skip []string) []string {
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range pl.Egresses {
		if e.Kind != EgressWAN || e.Iface == "" || skipped[e.Iface] || seen[e.Iface] {
			continue
		}
		seen[e.Iface] = true
		out = append(out, e.Iface)
	}
	sort.Strings(out)
	return out
}

// mssIfaces returns unique sorted kernel tunnel ifnames needing TCP MSS clamping — every
// EgressInterface egress in this plan. Derives directly from pl.Egresses so it is
// self-consistent independent of whether MasqIfaces was populated by Compile.
func (pl *Plan) mssIfaces() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface && e.Iface != "" && !seen[e.Iface] {
			seen[e.Iface] = true
			out = append(out, e.Iface)
		}
	}
	sort.Strings(out)
	return out
}

// nonWanEgresses returns interface/blackhole egresses in stable (mark) order.
func (pl *Plan) nonWanEgresses() []Egress {
	var out []Egress
	for _, e := range pl.Egresses {
		if e.Kind != EgressWAN {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mark < out[j].Mark })
	return out
}
