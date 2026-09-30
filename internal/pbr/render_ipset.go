package pbr

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// render_ipset.go is the legacy iptables/ipset renderer: kernel ipset (hash:net) + iptables
// mangle MARK + dnsmasq ipset= + ip rule/route — the iptables/ipset equivalent of RenderNft,
// retained as a pure renderer for the explicitly-probed OpenWrt fw3 compatibility path. WayHop
// 0.5.5 has no production Keenetic policy-rule adapter: the earlier externally-orchestrated route
// was retired rather than being allowed to bypass the authenticated Apply transaction. The emitted syntax
// was originally verified against the KeeneticOS 4.9 / iptables 1.4.21 stack, but that historical
// compatibility is not a production Keenetic capability claim. It reuses the SAME compiled Plan
// (zones/marks/tables/bypass) as the nft path; only the datapath primitive differs. Output is idempotent
// shell text (re-run safe), because the Keenetic applies via shell scripts and a netfilter.d
// hook re-asserts the rules after every NDM firewall rebuild. See docs/ARCHITECTURE_NATIVE_FIRST.md (development repository).

// IpsetOptions tune the Keenetic kernel-set sizing.
type IpsetOptions struct {
	Chain         string // iptables mangle chain (default WR_PREROUTING)
	SetPrefix     string // ipset name prefix (default "wr_")
	WanIface      string // WAN uplink for the WAN-fallback MASQUERADE (default eth3)
	DomainMaxElem int    // maxelem for DNS-populated (domain) sets (default 131072)
	DomainTimeout int    // seconds; entries expire so a DNS-set can't grow unbounded (default 86400)
	S86Mark       uint32 // skip-marking guard: a packet already carrying this exact mark RETURNs (S86 RU-routing 0x250); 0 = no guard

	// DNSIntercept redirects clients' plain DNS (udp/tcp 53) to the router's own resolver, so a
	// device with a hardcoded 8.8.8.8 is answered by the resolver this router actually manages.
	// Measured need: the NAS on a live LAN resolves through 1.1.1.1 directly, which walks
	// past every domain rule the DNS page shows — the page even says so, and could do nothing about it.
	DNSIntercept bool
	// DNSInterceptLAN is the interface clients arrive on (default br0 on KeeneticOS). Redirecting on
	// the WAN side would capture the router's own upstream queries and loop them back into itself.
	DNSInterceptLAN string
	// DNSRejectEncrypted additionally refuses DoT (tcp/853) and the well-known public DoH endpoints,
	// so a client that hardcodes an ENCRYPTED resolver falls back to plain 53 — which the redirect
	// above then catches. It cannot capture DoH to an arbitrary host: that is HTTPS to an address
	// nobody can distinguish without breaking TLS, and pretending otherwise would be a lie about
	// what this feature covers.
	DNSRejectEncrypted bool

	// MasqDevices are tunnel devices NDM does not own - the ones WayHop's userspace AmneziaWG
	// creates - that need forwarded-LAN MASQUERADE. NDM NATs its own interfaces; nobody NATs these,
	// and a forwarded LAN packet would leave with its private source, which the server's cryptokey
	// routing drops (the peer's allowed IPs are the tunnel address). The router's own tunnels are
	// deliberately not listed: their NAT stays NDM's. v4 only, like every MASQUERADE on this plane.
	MasqDevices []string
}

// masqDevices is MasqDevices de-duplicated and sorted, so a re-render is byte-identical.
func (o IpsetOptions) masqDevices() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range o.MasqDevices {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// WellKnownDoHEndpoints are the public resolvers a device is most likely to have baked in. Refusing
// 443 to exactly these makes such a client fall back to plain DNS, which the redirect catches; every
// other DoH destination is indistinguishable from ordinary HTTPS and stays out of reach.
//
// The list is deliberately short and anycast-only — these addresses have been stable for years and
// belong to the resolver operators themselves, so it is an identity list, not routing data.
var WellKnownDoHEndpoints = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"94.140.14.14", "94.140.15.15", // AdGuard
	"77.88.8.8", "77.88.8.1", // Yandex
}

func (o *IpsetOptions) withDefaults() {
	if o.Chain == "" {
		o.Chain = "WR_PREROUTING"
	}
	if o.SetPrefix == "" {
		o.SetPrefix = "wr_"
	}
	if o.WanIface == "" {
		o.WanIface = "eth3"
	}
	if o.DomainMaxElem == 0 {
		o.DomainMaxElem = 131072
	}
	if o.DomainTimeout == 0 {
		o.DomainTimeout = 86400
	}
}

// setName returns the kernel ipset name for a zone+family, capped to ipset's 31-char limit
// (a long id is truncated and disambiguated with a short hash so two long ids never collide).
func (io IpsetOptions) setName(zone, fam string) string {
	n := io.SetPrefix + zone + "_" + fam // e.g. wr_list_youtube_4
	if len(n) <= 31 {
		return n
	}
	h := sha1.Sum([]byte(zone))
	suf := "_" + hex.EncodeToString(h[:])[:6] + "_" + fam
	keep := 31 - len(suf)
	return (io.SetPrefix + zone)[:keep] + suf
}

// srcSetName returns the kernel ipset name holding a source-scoped zone's SOURCE CIDRs (matched
// with `--match-set ... src`), distinct from the zone's dest set by an "s" family marker
// (e.g. wr_rule_dev_s4 vs the dest wr_rule_dev_4).
func (io IpsetOptions) srcSetName(zone, fam string) string {
	return io.setName(zone, "s"+fam)
}

// iptablesSourceMatchCombos returns the OR-expansion of a zone's family-agnostic source matches
// (iface × mac × proto) as iptables match-arg fragments — iptables v1.4.21 has no anonymous sets,
// so multiple ifaces/MACs/protocols become multiple rules. Each fragment is the leading match for
// ONE rule (the source-IP set + dest set are appended per-family by the caller). A zone with no
// iface/mac/port yields a single empty fragment (one rule carrying just the set matches). A
// trailing-* iface wildcard is translated to iptables' "+" suffix.
func (z Zone) iptablesSourceMatchCombos() []string {
	ifaces := z.SrcIface
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	macs := z.SrcMAC
	if len(macs) == 0 {
		macs = []string{""}
	}
	protos := []string{""}
	ports := ""
	if len(z.SrcPort) > 0 {
		protos = []string{"tcp", "udp"}
		ps := make([]string, len(z.SrcPort))
		for i, p := range z.SrcPort {
			ps[i] = strconv.Itoa(p)
		}
		ports = strings.Join(ps, ",")
	}
	var out []string
	for _, ifc := range ifaces {
		for _, mac := range macs {
			for _, proto := range protos {
				var m string
				if ifc != "" {
					oifc := ifc
					if strings.HasSuffix(oifc, "*") { // nft trailing-* wildcard → iptables "+"
						oifc = oifc[:len(oifc)-1] + "+"
					}
					m += " -i " + oifc
				}
				if mac != "" {
					m += " -m mac --mac-source " + mac
				}
				if proto != "" {
					m += " -p " + proto + " -m multiport --sports " + ports
				}
				out = append(out, m)
			}
		}
	}
	return out
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// staticSizing returns hashsize+maxelem for a static (non-DNS) set given its element count.
func staticSizing(n int) (hashsize, maxelem int) {
	maxelem = nextPow2(n + n/3 + 1)
	if maxelem < 1024 {
		maxelem = 1024
	}
	hashsize = maxelem / 8
	if hashsize < 64 {
		hashsize = 64
	}
	if hashsize > 65536 {
		hashsize = 65536
	}
	return hashsize, maxelem
}

// hasDomains reports whether the zone is DNS-populated (dnsmasq fills its ipset at query-time).
func zoneHasDomains(z Zone) bool { return len(z.Domains) > 0 }

// IpsetNames returns every kernel set name this plan owns (for teardown `ipset destroy`).
func (pl *Plan) IpsetNames(io IpsetOptions) []string {
	io.withDefaults()
	var out []string
	if len(pl.BypassV4) > 0 {
		out = append(out, io.SetPrefix+"bypass_4")
	}
	if len(pl.BypassV6) > 0 {
		out = append(out, io.SetPrefix+"bypass_6")
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 || zoneHasDomains(z) {
			out = append(out, io.setName(z.Name, "4"))
		}
		if len(z.V6) > 0 || zoneHasDomains(z) { // a domain zone also owns an inet6 set (dual-stack)
			out = append(out, io.setName(z.Name, "6"))
		}
		if len(z.SrcV4) > 0 {
			out = append(out, io.srcSetName(z.Name, "4"))
		}
		if len(z.SrcV6) > 0 {
			out = append(out, io.srcSetName(z.Name, "6"))
		}
	}
	return out
}

// RenderIpsetRestore returns an `ipset restore -!` stream that atomically creates and populates
// every set: static V4/V6 CIDRs become permanent members; DNS-populated (domain) sets are
// created empty WITH a timeout (dnsmasq adds resolved IPs at query-time, hence ~0 standing RAM
// for an 81k-domain list). `-exist`/`-!` make it re-runnable.
func (pl *Plan) RenderIpsetRestore(io IpsetOptions) string {
	io.withDefaults()
	var b strings.Builder
	createNet := func(name, fam string, hashsize, maxelem, timeout int) {
		fmt.Fprintf(&b, "create %s hash:net family %s hashsize %d maxelem %d", name, fam, hashsize, maxelem)
		if timeout > 0 {
			fmt.Fprintf(&b, " timeout %d", timeout)
		}
		b.WriteString(" -exist\n")
	}
	if len(pl.BypassV4) > 0 {
		hs, me := staticSizing(len(pl.BypassV4))
		createNet(io.SetPrefix+"bypass_4", "inet", hs, me, 0)
		for _, c := range pl.BypassV4 {
			fmt.Fprintf(&b, "add %sbypass_4 %s -exist\n", io.SetPrefix, c)
		}
	}
	if len(pl.BypassV6) > 0 {
		hs, me := staticSizing(len(pl.BypassV6))
		createNet(io.SetPrefix+"bypass_6", "inet6", hs, me, 0)
		for _, c := range pl.BypassV6 {
			fmt.Fprintf(&b, "add %sbypass_6 %s -exist\n", io.SetPrefix, c)
		}
	}
	for _, z := range pl.Zones {
		dns := zoneHasDomains(z)
		if len(z.V4) > 0 || dns {
			name := io.setName(z.Name, "4")
			if dns {
				createNet(name, "inet", 1024, io.DomainMaxElem, io.DomainTimeout)
			} else {
				hs, me := staticSizing(len(z.V4))
				createNet(name, "inet", hs, me, 0)
			}
			for _, c := range z.V4 {
				// In a timeout set, static members are added with `timeout 0` (never expire).
				if dns {
					fmt.Fprintf(&b, "add %s %s timeout 0 -exist\n", name, c)
				} else {
					fmt.Fprintf(&b, "add %s %s -exist\n", name, c)
				}
			}
		}
		if len(z.V6) > 0 || dns {
			name := io.setName(z.Name, "6")
			if dns {
				// A domain zone is dual-stack: dnsmasq adds the AAAA answers to this inet6
				// timeout set (see DnsmasqIpsetConfig's set4,set6 target), so a tunnel-routed
				// domain's IPv6 traffic is marked/routed too instead of leaking direct to WAN.
				createNet(name, "inet6", 1024, io.DomainMaxElem, io.DomainTimeout)
			} else {
				hs, me := staticSizing(len(z.V6))
				createNet(name, "inet6", hs, me, 0)
			}
			for _, c := range z.V6 {
				if dns {
					fmt.Fprintf(&b, "add %s %s timeout 0 -exist\n", name, c)
				} else {
					fmt.Fprintf(&b, "add %s %s -exist\n", name, c)
				}
			}
		}
		// Source sets (Phase C): a source-scoped zone's SOURCE CIDRs get their own `_s4`/`_s6`
		// set, matched with `--match-set ... src` in the mangle chain (the dest set, if any,
		// still bounds the rule).
		if len(z.SrcV4) > 0 {
			name := io.srcSetName(z.Name, "4")
			hs, me := staticSizing(len(z.SrcV4))
			createNet(name, "inet", hs, me, 0)
			for _, c := range z.SrcV4 {
				fmt.Fprintf(&b, "add %s %s -exist\n", name, c)
			}
		}
		if len(z.SrcV6) > 0 {
			name := io.srcSetName(z.Name, "6")
			hs, me := staticSizing(len(z.SrcV6))
			createNet(name, "inet6", hs, me, 0)
			for _, c := range z.SrcV6 {
				fmt.Fprintf(&b, "add %s %s -exist\n", name, c)
			}
		}
	}
	return b.String()
}

// RenderIptablesScript returns idempotent shell that (re)builds the mangle MARK chain: flush
// our own chain, RETURN bypass + S86-marked traffic (so the kept RU-routing keeps precedence),
// MARK each zone's set to its egress fwmark (preserving non-owned bits), save the mark to the
// connmark for Dashboard attribution, and ensure the PREROUTING jump exists. v6 via ip6tables.
func (pl *Plan) RenderIptablesScript(io IpsetOptions) string {
	io.withDefaults()
	mask := hexMark(pl.Mask)
	var b strings.Builder
	emit := func(ipt, fam string) {
		ch := io.Chain
		fmt.Fprintf(&b, "%s -t mangle -N %s 2>/dev/null || true\n", ipt, ch)
		fmt.Fprintf(&b, "%s -t mangle -F %s\n", ipt, ch)
		// Anti-loop bypass first: tunnel server IPs RETURN (unmarked → main table → WAN).
		bypass := io.SetPrefix + "bypass_" + fam
		if (fam == "4" && len(pl.BypassV4) > 0) || (fam == "6" && len(pl.BypassV6) > 0) {
			fmt.Fprintf(&b, "%s -t mangle -A %s -m set --match-set %s dst -j RETURN\n", ipt, ch, bypass)
		}
		// Preserve the kept S86 RU-routing: a packet it already marked skips WR marking.
		if io.S86Mark != 0 {
			fmt.Fprintf(&b, "%s -t mangle -A %s -m mark --mark %s/0xffffffff -j RETURN\n", ipt, ch, hexMark(io.S86Mark))
		}
		// Restore an established connection's previously-chosen egress mark BEFORE the per-zone
		// match, so a long-lived flow keeps its tunnel even if its destination later leaves the
		// ipset — e.g. a DNS-populated domain entry expiring after its timeout — instead of
		// silently falling back to the WAN default mid-connection (a censored-traffic leak).
		fmt.Fprintf(&b, "%s -t mangle -A %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s\n", ipt, ch, mask, mask)
		for _, z := range pl.Zones {
			if z.SrcScoped {
				// Source-scoped zone: the bypass RETURN above already exited peer-dst traffic, so a
				// source-only line here can't loop a tunnel-peer packet (no nft-style re-assert
				// needed). Emit the cartesian iface/mac/proto rules, each with the per-family source
				// set (when the source carries IPs for this family) and the dest set (when present).
				// A DOMAIN-populated zone has a real (dnsmasq-fed) dest set in BOTH families —
				// RenderIpsetRestore creates <zone>_4/_6 and DnsmasqIpsetConfig fills them at query
				// time — so it must count as a destination here exactly like the non-source path
				// below. Without it, a device-scoped domain list either emits a dest-less mark
				// (ALL of the device's traffic tunneled, not just the listed domains) or, mixed
				// with v4 CIDRs, SKIPS the fam=6 rule entirely (the AAAA answers dnsmasq added
				// are never marked → the scoped device's IPv6 to those domains leaks to WAN).
				hasDest := (fam == "4" && (len(z.V4) > 0 || zoneHasDomains(z))) || (fam == "6" && (len(z.V6) > 0 || zoneHasDomains(z)))
				srcIPThisFam := (fam == "4" && len(z.SrcV4) > 0) || (fam == "6" && len(z.SrcV6) > 0)
				hasAnySrcIP := len(z.SrcV4) > 0 || len(z.SrcV6) > 0
				noDest := len(z.V4) == 0 && len(z.V6) == 0 && !zoneHasDomains(z)
				if z.SrcNegate {
					// "except" scope: mark the dest for EVERY source EXCEPT the scoped devices. By De
					// Morgan NOT(mac∈M OR ip∈S) = mac∉M AND ip∉S — ONE rule with every source term
					// NEGATED and AND-combined. The positive cartesian below is OR semantics and would
					// INVERT the routing (mark only the excepted devices), or — for a mixed MAC+IP group
					// — AND a positive MAC with a positive src set that no packet satisfies (route
					// nobody). Negated zones are only ever device-group excepts (MACs + a family-specific
					// src-IP set, never iface/port): the MAC negation is family-agnostic; the IP-set
					// negation applies only where THIS family has source IPs; and, unlike a positive
					// scope, the opposite family is NOT skipped (every packet there is trivially "not
					// from" the other family's IPs, so the dest is routed for all of it). iptables can't
					// negate an iface/port set as one rule, so guard that (never happens for a device
					// group) rather than emit a half-negated, wrong rule.
					if len(z.SrcIface) > 0 || len(z.SrcPort) > 0 {
						continue
					}
					// This family has no dest of its own while the zone has dests in the OTHER family
					// (a v4-only list rendered for v6, etc.) → nothing to route here; a dest-less rule
					// would mark ALL of this family's traffic. A genuinely source-only zone (noDest)
					// still emits its dest-less mark.
					if !(hasDest || noDest) {
						continue
					}
					var srcNeg strings.Builder
					for _, mac := range z.SrcMAC {
						srcNeg.WriteString(" -m mac ! --mac-source " + mac)
					}
					if srcIPThisFam {
						srcNeg.WriteString(" -m set ! --match-set " + io.srcSetName(z.Name, fam) + " src")
					}
					// No device identity in this family (e.g. an IP-only device on the other family) →
					// this "except" excepts nobody here, so route the dest for everyone; needs a dest to
					// bound it, else a source-less rule would mark ALL traffic — skip that.
					if srcNeg.Len() == 0 && !hasDest {
						continue
					}
					destMatch := ""
					if hasDest {
						destMatch = " -m set --match-set " + io.setName(z.Name, fam) + " dst"
					}
					fmt.Fprintf(&b, "%s -t mangle -A %s%s%s -j MARK --set-xmark %s/%s\n",
						ipt, ch, srcNeg.String(), destMatch, hexMark(z.Mark), mask)
					continue
				}
				// The IP source (if any) must be satisfiable in this family; otherwise an opposite-
				// family source-IP rule would match every dst here (an over-route) — skip it.
				srcConstraintOK := srcIPThisFam || !hasAnySrcIP
				if !srcConstraintOK || !(hasDest || noDest) {
					continue
				}
				srcMatch := ""
				if srcIPThisFam {
					srcMatch = " -m set --match-set " + io.srcSetName(z.Name, fam) + " src"
				}
				destMatch := ""
				if hasDest {
					destMatch = " -m set --match-set " + io.setName(z.Name, fam) + " dst"
				}
				for _, sm := range z.iptablesSourceMatchCombos() {
					fmt.Fprintf(&b, "%s -t mangle -A %s%s%s%s -j MARK --set-xmark %s/%s\n",
						ipt, ch, sm, srcMatch, destMatch, hexMark(z.Mark), mask)
				}
				continue
			}
			has := (fam == "4" && (len(z.V4) > 0 || zoneHasDomains(z))) || (fam == "6" && (len(z.V6) > 0 || zoneHasDomains(z)))
			if !has {
				continue
			}
			set := io.setName(z.Name, fam)
			fmt.Fprintf(&b, "%s -t mangle -A %s -m set --match-set %s dst -j MARK --set-xmark %s/%s\n",
				ipt, ch, set, hexMark(z.Mark), mask)
		}
		// Mirror the chosen egress mark into the connmark (conntrack attribution; routing-inert).
		fmt.Fprintf(&b, "%s -t mangle -A %s -j CONNMARK --save-mark --nfmask %s --ctmask %s\n", ipt, ch, mask, mask)
		// Ensure the jump from PREROUTING exists (appended → runs AFTER S86's pos-1 mark).
		fmt.Fprintf(&b, "%s -t mangle -C PREROUTING -j %s 2>/dev/null || %s -t mangle -A PREROUTING -j %s\n", ipt, ch, ipt, ch)
	}
	emit("iptables", "4")
	if len(pl.BypassV6) > 0 || pl.hasV6Zone() {
		emit("ip6tables", "6")
	}
	// WAN-fallback SNAT: when a failover table routes a WR-marked flow out the WAN uplink (all
	// VPN tiers down → direct, per the no-kill-switch policy), MASQUERADE it to the WAN source
	// IP (mirrors S86). Harmless when the flow egresses a tunnel instead (-o wan won't match).
	for _, e := range pl.nonWanEgresses() {
		if e.Kind != EgressInterface {
			continue
		}
		fmt.Fprintf(&b, "iptables -t nat -C POSTROUTING -o %s -m mark --mark %s/%s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -m mark --mark %s/%s -j MASQUERADE\n",
			io.WanIface, hexMark(e.Mark), mask, io.WanIface, hexMark(e.Mark), mask)
	}
	for _, dev := range io.masqDevices() {
		fmt.Fprintf(&b, "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", dev, dev)
	}
	// DNS interception: clients' plain DNS is answered by THIS router, whatever server they asked
	// for. REDIRECT (not DNAT) because the destination is the router itself — it rewrites to the
	// interface's own address without us having to know it, which matters on a box whose LAN address
	// the operator can change. Idempotent check→append, like every rule here, because the netfilter.d
	// hook re-runs this script after each NDM firewall rebuild.
	if io.DNSIntercept && io.DNSInterceptLAN != "" {
		for _, proto := range []string{"udp", "tcp"} {
			fmt.Fprintf(&b, "iptables -t nat -C PREROUTING -i %s -p %s --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || iptables -t nat -A PREROUTING -i %s -p %s --dport 53 -j REDIRECT --to-ports 53\n",
				io.DNSInterceptLAN, proto, io.DNSInterceptLAN, proto)
		}
		if io.DNSRejectEncrypted {
			// DoT has a port of its own, so it can be refused precisely.
			fmt.Fprintf(&b, "iptables -C FORWARD -i %s -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -I FORWARD -i %s -p tcp --dport 853 -j REJECT --reject-with tcp-reset\n",
				io.DNSInterceptLAN, io.DNSInterceptLAN)
			// DoH cannot be, except at the few addresses everyone hardcodes.
			for _, ip := range WellKnownDoHEndpoints {
				fmt.Fprintf(&b, "iptables -C FORWARD -i %s -p tcp -d %s --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -I FORWARD -i %s -p tcp -d %s --dport 443 -j REJECT --reject-with tcp-reset\n",
					io.DNSInterceptLAN, ip, io.DNSInterceptLAN, ip)
			}
		}
	}
	// TCP MSS clamping (QW1): iptables FORWARD mangle TCPMSS per kernel tunnel egress.
	// Mirrors the nft wr_mss chain: --clamp-mss-to-pmtu is the iptables equivalent of
	// `rt mtu` (dynamically tracks path MTU from ICMP frag-needed). Idempotent (check→append).
	// ip6tables mirrors it so AWG tunnels carrying IPv6 also clamp v6 TCP SYN.
	seenMSS := map[string]bool{}
	for _, e := range pl.nonWanEgresses() {
		if e.Kind != EgressInterface || e.Iface == "" || seenMSS[e.Iface] {
			continue
		}
		seenMSS[e.Iface] = true
		for _, ipt := range []string{"iptables", "ip6tables"} {
			fmt.Fprintf(&b, "%s -t mangle -C FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || %s -t mangle -A FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n",
				ipt, e.Iface, ipt, e.Iface)
		}
	}
	return b.String()
}

func (pl *Plan) hasV6Zone() bool {
	for _, z := range pl.Zones {
		if len(z.V6) > 0 || len(z.SrcV6) > 0 {
			return true
		}
		// A DOMAIN zone is dual-stack: dnsmasq populates both an inet and an inet6 set from the
		// A/AAAA answers, so the v6 datapath (ip6tables chain + v6 ip rules/default) must be
		// emitted for it too — else the AAAA-resolved addresses of a tunnel-routed domain are
		// never marked and IPv6 leaks direct to the WAN. (Domains are only collected on the
		// Keenetic ipset plane, so this is a no-op for the OpenWrt nft path.)
		if zoneHasDomains(z) {
			return true
		}
		// A source-only zone with only iface/mac/port (no source IP) applies to BOTH families,
		// so the v6 datapath (ip6tables chain + v6 ip rules) must be emitted for it too.
		if z.SrcScoped && len(z.V4) == 0 && len(z.V6) == 0 && len(z.SrcV4) == 0 && len(z.SrcV6) == 0 {
			return true
		}
	}
	return false
}

// RenderIPScript returns idempotent `ip rule`/`ip route` shell to install the fwmark→table→
// egress routing: each non-WAN egress gets a rule (del-then-add for idempotency) and an initial
// SEED default route in its table to Egress.Iface (the failover group's first member). The seed
// is add-not-replace so a hook re-assert can never clobber the cron's elected live egress — the
// 1-min failover cron owns the authoritative election (it uses `ip route replace`).
// WAN-marked/unmarked traffic falls through to the main table.
func (pl *Plan) RenderIPScript(opt Options) string {
	opt.withDefaults()
	mask := hexMark(pl.Mask)
	var b strings.Builder
	// LAN/private-dst replies must reach the bridge, not loop back out the tunnel (see
	// privateExcludes). These sit just below the fwmark rules so they win for LAN dsts.
	for _, x := range privateExcludes(opt) {
		fmt.Fprintf(&b, "ip rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
		fmt.Fprintf(&b, "ip rule add to %s lookup main priority %d\n", x.CIDR, x.Priority)
	}
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		fmt.Fprintf(&b, "ip rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, pref)
		fmt.Fprintf(&b, "ip rule add fwmark %s/%s table %d priority %d\n", hexMark(e.Mark), mask, e.Table, pref)
		switch e.Kind {
		case EgressInterface:
			// SEED only (add-not-replace): a re-assert after an NDM netfilter rebuild must NOT clobber
			// the cron's elected live egress back to this static first member — doing so black-holed
			// censored lists (Telegram) onto a possibly-dead primary until the next 1-min cron tick.
			fmt.Fprintf(&b, "ip route add default dev %s table %d 2>/dev/null || true\n", e.Iface, e.Table)
			if e.FailClosed {
				// Kill switch — mirror render.go RenderIP (this was MISSING on the ipset/Keenetic plane,
				// a WAN leak on tunnel-down): a fail-closed blackhole at a high metric in the SAME table.
				// While the iface is up its metric-0 `default dev` route wins; when it drops the kernel
				// flushes that route and this blackhole catches the fwmark'd traffic and DROPS it instead
				// of the lookup falling through to the main table (= WAN). The cron's elected dev route is
				// metric 0, so this distinct high-metric route never clobbers it (safe with the SEED idiom).
				// `|| true`: this is a shell-script plane (unlike RenderIP's Runner cmds); a device whose
				// iproute2 rejects the form must degrade to today's behavior (no enforcement), never break
				// the whole apply. On KeeneticOS the daemon's fwmark tables may be inert (NDM owns routing),
				// so this enforces on full-iproute2 Entware; the Keenetic-native kill-switch is separate.
				fmt.Fprintf(&b, "ip route replace blackhole default metric %d table %d 2>/dev/null || true\n", failClosedMetric, e.Table)
			}
		case EgressBlackhole:
			fmt.Fprintf(&b, "ip route replace blackhole default table %d\n", e.Table)
		}
	}
	// IPv6 datapath, symmetric with v4 — a MARKED v6 packet to a censored dst must route
	// THROUGH the tunnel table, not fall through to the main v6 table (which on a device
	// whose v6 default is the WAN egresses the WAN = a censorship leak). Emitted only when
	// the plan actually marks v6 (mirrors the ip6tables mangle chain). v6 forwarded-NAT
	// (MASQUERADE) is intentionally NOT wired — a v6 LAN is absent on the target — so a v6
	// forwarded flow fails CLOSED in the tunnel table rather than ever leaking to the WAN.
	if pl.hasV6Zone() || len(pl.BypassV6) > 0 {
		for _, x := range privateExcludesV6(opt) {
			fmt.Fprintf(&b, "ip -6 rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
			fmt.Fprintf(&b, "ip -6 rule add to %s lookup main priority %d\n", x.CIDR, x.Priority)
		}
		for i, e := range pl.nonWanEgresses() {
			pref := opt.RulePref + i
			fmt.Fprintf(&b, "ip -6 rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, pref)
			fmt.Fprintf(&b, "ip -6 rule add fwmark %s/%s table %d priority %d\n", hexMark(e.Mark), mask, e.Table, pref)
			switch e.Kind {
			case EgressInterface:
				fmt.Fprintf(&b, "ip -6 route add default dev %s table %d 2>/dev/null || true\n", e.Iface, e.Table)
				if e.FailClosed {
					// Kill switch (v6) — mirror the v4 fail-closed blackhole above + render.go (fail-safe).
					fmt.Fprintf(&b, "ip -6 route replace blackhole default metric %d table %d 2>/dev/null || true\n", failClosedMetric, e.Table)
				}
			case EgressBlackhole:
				fmt.Fprintf(&b, "ip -6 route replace blackhole default table %d\n", e.Table)
			}
		}
	}
	return b.String()
}

// RenderTeardownScript removes everything the Keenetic plane installed: the PREROUTING jump,
// our mangle chain, the ip rules + table routes, and the kernel sets.
func (pl *Plan) RenderTeardownScript(opt Options, io IpsetOptions) string {
	opt.withDefaults()
	io.withDefaults()
	mask := hexMark(pl.Mask)
	var b strings.Builder
	for _, ipt := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&b, "%s -t mangle -D PREROUTING -j %s 2>/dev/null || true\n", ipt, io.Chain)
		fmt.Fprintf(&b, "%s -t mangle -F %s 2>/dev/null || true\n", ipt, io.Chain)
		fmt.Fprintf(&b, "%s -t mangle -X %s 2>/dev/null || true\n", ipt, io.Chain)
	}
	for _, e := range pl.nonWanEgresses() {
		if e.Kind != EgressInterface {
			continue
		}
		fmt.Fprintf(&b, "iptables -t nat -D POSTROUTING -o %s -m mark --mark %s/%s -j MASQUERADE 2>/dev/null || true\n", io.WanIface, hexMark(e.Mark), mask)
	}
	for _, dev := range io.masqDevices() {
		fmt.Fprintf(&b, "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true\n", dev)
	}
	// TCP MSS clamping teardown (QW1): remove TCPMSS rules from the FORWARD chain.
	seenMSS := map[string]bool{}
	for _, e := range pl.nonWanEgresses() {
		if e.Kind != EgressInterface || e.Iface == "" || seenMSS[e.Iface] {
			continue
		}
		seenMSS[e.Iface] = true
		for _, ipt := range []string{"iptables", "ip6tables"} {
			fmt.Fprintf(&b, "%s -t mangle -D FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n",
				ipt, e.Iface)
		}
	}
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		fmt.Fprintf(&b, "ip rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, pref)
		fmt.Fprintf(&b, "ip route flush table %d 2>/dev/null || true\n", e.Table)
	}
	for _, x := range privateExcludes(opt) {
		fmt.Fprintf(&b, "ip rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
	}
	if pl.hasV6Zone() || len(pl.BypassV6) > 0 {
		for i, e := range pl.nonWanEgresses() {
			pref := opt.RulePref + i
			fmt.Fprintf(&b, "ip -6 rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, pref)
			fmt.Fprintf(&b, "ip -6 route flush table %d 2>/dev/null || true\n", e.Table)
		}
		for _, x := range privateExcludesV6(opt) {
			fmt.Fprintf(&b, "ip -6 rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
		}
	}
	for _, n := range pl.IpsetNames(io) {
		fmt.Fprintf(&b, "ipset destroy %s 2>/dev/null || true\n", n)
	}
	return b.String()
}

// DnsmasqIpsetConfig returns the dnsmasq `ipset=` directives that make dnsmasq populate each
// DNS zone's kernel set as it resolves the listed domains (and every subdomain). Domains are
// batched so no line exceeds maxLine bytes (~1024 keeps the line safe). The header comment marks the
// file as WayHop-owned. Returns "" if no zone has domains.
func (pl *Plan) DnsmasqIpsetConfig(io IpsetOptions, maxLine int) string {
	io.withDefaults()
	if maxLine <= 0 {
		maxLine = 1024
	}
	type dz struct {
		sets    string // comma-separated set names — v4,v6 so dnsmasq adds A→inet, AAAA→inet6
		domains []string
	}
	var zones []dz
	for _, z := range pl.Zones {
		if zoneHasDomains(z) {
			// Target BOTH the inet and inet6 sets: dnsmasq routes each resolved A record to the
			// matching-family (inet) set and each AAAA to the inet6 set, so a tunnel-routed
			// domain's IPv6 traffic is marked/routed instead of leaking direct to the WAN.
			zones = append(zones, dz{sets: io.setName(z.Name, "4") + "," + io.setName(z.Name, "6"), domains: z.Domains})
		}
	}
	if len(zones) == 0 {
		return ""
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].sets < zones[j].sets })
	var b strings.Builder
	b.WriteString("# Generated by WayHop (dnsmasq-ipset domain routing) — do not edit.\n")
	for _, z := range zones {
		// Build "ipset=/d1/d2/.../<set4>,<set6>" lines, each ≤ maxLine bytes.
		suffix := "/" + z.sets
		line := "ipset="
		for _, d := range z.domains {
			add := "/" + d
			if len(line)+len(add)+len(suffix) > maxLine && line != "ipset=" {
				b.WriteString(line + suffix + "\n")
				line = "ipset="
			}
			line += add
		}
		if line != "ipset=" {
			b.WriteString(line + suffix + "\n")
		}
	}
	return b.String()
}

// ListZoneName is the zone a routing list compiles into, and ZoneSetName is the kernel set that zone
// installs. Both are exported so a caller reading the LIVE kernel — per-list packet counters, set
// presence — names exactly what the renderer created instead of re-deriving the rule and drifting
// from it. fam is "4" or "6".
func ListZoneName(listID string) string { return "list_" + nftName(listID) }

func (io IpsetOptions) ZoneSetName(zone, fam string) string {
	io.withDefaults()
	return io.setName(zone, fam)
}
