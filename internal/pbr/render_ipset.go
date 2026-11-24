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
	// DynamicDomainSets splits new resolver answers into wd_ hash:ip sets. The wr_ sets and their
	// existing members stay in place until their own timeouts expire, which makes migration additive.
	DynamicDomainSets bool
	S86Mark           uint32 // skip-marking guard: a packet already carrying this exact mark RETURNs (S86 RU-routing 0x250); 0 = no guard

	// DNSIntercept redirects clients' plain DNS (udp/tcp 53) to the router's own resolver, so a
	// device with a hardcoded 8.8.8.8 is answered by the resolver this router actually manages.
	// Without it, a LAN device that resolves through 1.1.1.1 directly walks past every domain rule
	// the DNS page shows.
	DNSIntercept bool
	// DNSInterceptLAN is the interface clients arrive on (default br0 on KeeneticOS). Redirecting on
	// the WAN side would capture the router's own upstream queries and loop them back into itself.
	// The teardown deletes the redirect and the refusals on this interface whether or not the two
	// switches are on: the plane it replaces may have had them on, so a caller sets it on every plane.
	DNSInterceptLAN string
	// DNSRejectEncrypted additionally refuses DoT (tcp/853) and the well-known public DoH endpoints,
	// so a client that hardcodes an ENCRYPTED resolver falls back to plain 53 — which the redirect
	// above then catches. It cannot capture DoH to an arbitrary host: that is HTTPS to an address
	// nobody can distinguish without breaking TLS, and pretending otherwise would be a lie about
	// what this feature covers.
	DNSRejectEncrypted bool
	// FastDNSEnforce redirects plain DNS and refuses DoT on every captured LAN interface. Unlike the
	// legacy interception above, its redirect leaves packets addressed to the router itself untouched.
	FastDNSEnforce bool

	// MasqDevices are tunnel devices NDM does not own - the ones WayHop's userspace AmneziaWG
	// creates - that need forwarded-LAN MASQUERADE. NDM NATs its own interfaces; nobody NATs these,
	// and a forwarded LAN packet would leave with its private source, which the server's cryptokey
	// routing drops (the peer's allowed IPs are the tunnel address). The router's own tunnels are
	// deliberately not listed: their NAT stays NDM's. v4 only, like every MASQUERADE on this plane.
	MasqDevices []string

	// LANIfaces are the interfaces LAN clients arrive on, from the host facts. The kill switch
	// backstop's ip rules match them by `iif`, which is what keeps the router's own traffic out of
	// them. Empty: no backstop rules can be rendered (the caller refuses a kill switch then).
	LANIfaces []string
	// KillSwitchDNS is the sing-box DNS listener as dnsmasq names a server ("127.0.0.1#5353"). The
	// names of a kill-switched domain list are pinned to it with `server=/name/...`, so dnsmasq asks
	// that server alone for them and fails with it instead of moving on to a direct row of its chain.
	KillSwitchDNS string
	// HandoffIface is the sing-box hand-off TUN (handoff.go); "" when no core runs, and then an
	// overlap stays with the stronger list.
	HandoffIface string
	// BackstopPref is the priority of the kill switch backstop's rules, derived from the router's live
	// rule list (BackstopPrefFromRules); 0 = ahead of every WayHop rule.
	BackstopPref int
	// BootRestore is a file holding the plane's ipset restore stream: the program restores the sets
	// from it when one is missing (after a reboot, before the daemon runs). "" = none.
	BootRestore string
	// BackstopReady is the tmpfs stamp the daemon writes once it has filled the backstop table since
	// boot; while it is absent the program holds forwarded traffic in that table. "" = no hold.
	BackstopReady string
	// BootLearned is the daemon's file of learned members of kill-switched domain sets (ipset restore
	// format, remaining timeouts), restored with the sets at boot. "" = none.
	BootLearned string
	// FillTool is the WayHop binary the hook runs once per boot as `backstop-fill` to put the
	// kill-switched destinations into the backstop table before the daemon is up.
	FillTool string
	// BootHoldLift is how many seconds after boot the hook lifts the broad hold when no full fill or
	// daemon sync happened; 0 = never (strict).
	BootHoldLift int
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

// dnsRule is one rule of the DNS interception, in a chain NDM owns. The script and the teardown both
// render from dnsRedirectRules and dnsRejectRules, so every rule the script can add is one the
// teardown deletes.
type dnsRule struct {
	v6    bool   // ip6tables (fast mode's IPv6 refusals) instead of iptables
	table string // "nat" or "filter"
	chain string
	add   string // -A or -I
	spec  string
}

// dnsRedirectRules send clients' plain DNS arriving on lan to the router's own resolver.
func dnsRedirectRules(lan string) []dnsRule {
	var out []dnsRule
	for _, proto := range []string{"udp", "tcp"} {
		out = append(out, dnsRule{table: "nat", chain: "PREROUTING", add: "-A",
			spec: "-i " + lan + " -p " + proto + " --dport 53 -j REDIRECT --to-ports 53"})
	}
	return out
}

// dnsFastRedirectRules are the fast-mode redirects: the legacy interception's rules. No addrtype match:
// KeeneticOS does not load xt_addrtype (live 22.11, the rule never landed and every Apply's postcheck
// failed), and a redirect of a lookup already addressed to the router's own :53 is a no-op.
func dnsFastRedirectRules(lan string) []dnsRule {
	return dnsRedirectRules(lan)
}

func dnsDoTRejectRule(lan string) dnsRule {
	return dnsRule{table: "filter", chain: "FORWARD", add: "-I",
		spec: "-i " + lan + " -p tcp --dport 853 -j REJECT --reject-with tcp-reset"}
}

// dnsRejectRules refuse DoT and DoH to WellKnownDoHEndpoints for clients arriving on lan.
func dnsRejectRules(lan string) []dnsRule {
	// DoT has a port of its own, so it can be refused precisely.
	out := []dnsRule{dnsDoTRejectRule(lan)}
	// DoH cannot be, except at the few addresses everyone hardcodes.
	for _, ip := range WellKnownDoHEndpoints {
		out = append(out, dnsRule{table: "filter", chain: "FORWARD", add: "-I",
			spec: "-i " + lan + " -p tcp -d " + ip + " --dport 443 -j REJECT --reject-with tcp-reset"})
	}
	return out
}

// iptablesTableArg is the `-t` option for table, empty for filter: the script has never named the
// filter table, and its bytes stay what routers already run.
func iptablesTableArg(table string) string {
	if table == "" || table == "filter" {
		return ""
	}
	return "-t " + table + " "
}

// writeAdd renders the idempotent check-then-add the netfilter.d hook can re-run after every rebuild.
func (r dnsRule) writeAdd(b *strings.Builder) {
	t, tool := iptablesTableArg(r.table), r.tool()
	fmt.Fprintf(b, "%s %s-C %s %s 2>/dev/null || %s %s%s %s %s\n", tool, t, r.chain, r.spec, tool, t, r.add, r.chain, r.spec)
}

func (r dnsRule) tool() string {
	if r.v6 {
		return "ip6tables"
	}
	return "iptables"
}

// deleteEveryCopy is the rule's teardown line, in its own family.
func (r dnsRule) deleteEveryCopy() string {
	return DeleteEveryCopy(r.tool(), r.table, r.chain, r.spec)
}

// dnsV6RefuseRules refuse forwarded IPv6 DNS (53) and DoT (853) from clients on lan, in fast mode. Only
// forwarded traffic: the router's own resolver, reached by INPUT, stays reachable. A client set to an
// outside IPv6 resolver falls back to IPv4, which the redirect catches. No ip6tables REDIRECT: a
// KeeneticOS kernel need not have IPv6 NAT.
func dnsV6RefuseRules(lan string) []dnsRule {
	return []dnsRule{
		{v6: true, table: "filter", chain: "FORWARD", add: "-I", spec: "-i " + lan + " -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable"},
		{v6: true, table: "filter", chain: "FORWARD", add: "-I", spec: "-i " + lan + " -p tcp --dport 53 -j REJECT --reject-with tcp-reset"},
		{v6: true, table: "filter", chain: "FORWARD", add: "-I", spec: "-i " + lan + " -p tcp --dport 853 -j REJECT --reject-with tcp-reset"},
	}
}

// IptablesDeleteEveryCopy renders the teardown line that deletes one rule of a chain NDM owns, every
// copy of it: a lock race or an older build can have added the rule twice, and one -D would leave the
// other. The executor matches a teardown against it, so the two cannot spell the delete differently.
func IptablesDeleteEveryCopy(table, chain, spec string) string {
	return DeleteEveryCopy("iptables", table, chain, spec)
}

// DeleteEveryCopy is IptablesDeleteEveryCopy for tool (iptables or ip6tables).
func DeleteEveryCopy(tool, table, chain, spec string) string {
	return "while " + tool + " " + iptablesTableArg(table) + "-D " + chain + " " + spec + " 2>/dev/null; do :; done\n"
}

// fastDNSLANs is the validated, stable interface set for fast enforcement. An explicitly enabled
// legacy intercept keeps its interface in the set even if the host's LAN capture was incomplete.
func (o IpsetOptions) fastDNSLANs() []string {
	if !o.FastDNSEnforce {
		return nil
	}
	ifaces := append([]string(nil), o.LANIfaces...)
	if o.DNSIntercept && o.DNSInterceptLAN != "" {
		ifaces = append(ifaces, o.DNSInterceptLAN)
	}
	return lanIfaces(ifaces)
}

// FastDNSOpenFlag, when it exists, suspends fast mode's DNS enforcement: the daemon
// creates it in tmpfs when the router's dnsmasq has stopped answering, so the LAN's devices can use
// their own resolvers, and removes it when dnsmasq is back. The program and the netfilter.d hook skip
// the enforcement rules while it is there; a reboot clears it.
const FastDNSOpenFlag = "/tmp/wayhop-dns-open"

const (
	fastDNSOpenIf = "if [ ! -e " + FastDNSOpenFlag + " ]; then\n"
	fastDNSOpenFi = "fi\n"
)

// EnforcedLANs is the interfaces fast DNS enforcement is rendered on (none when it is off).
func (o IpsetOptions) EnforcedLANs() []string { return o.fastDNSLANs() }

// FilterSectionEnd closes the filter-table section RenderIptablesScript puts first when it refuses
// encrypted DNS. NDM rebuilds the filter table on its own and drops the FORWARD refusals with it, so
// the netfilter.d hook answers filter:iptables for a script carrying this line, and the script stops
// here on that event: the mangle flush and rebuild below would be work for a table that has none of
// it. Apply runs the script without $table, so it never stops here.
const FilterSectionEnd = "case \"$table:$type\" in filter:iptables) exit 0 ;; esac\n"

// FastFilterSectionEnd closes the filter section of a Keenetic fast-mode program, which also refuses
// IPv6 DNS in ip6tables' filter table: a filter rebuild of either family re-runs only that section.
const FastFilterSectionEnd = "case \"$table:$type\" in filter:iptables|filter:ip6tables) exit 0 ;; esac\n"

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

// DynamicDomainTimeout is the six-hour lifetime of a resolver-learned address. A new flow to an
// active address refreshes it through the xt_SET rule rendered beside the zone's mark rule.
const DynamicDomainTimeout = 21600

// prefixedSetName returns a kernel ipset name capped to ipset's 31-char limit. A long id is
// truncated and disambiguated with a short hash so two long ids never collide.
func prefixedSetName(prefix, zone, fam string) string {
	n := prefix + zone + "_" + fam
	if len(n) <= 31 {
		return n
	}
	h := sha1.Sum([]byte(zone))
	suf := "_" + hex.EncodeToString(h[:])[:6] + "_" + fam
	keep := 31 - len(suf)
	return (prefix + zone)[:keep] + suf
}

// setName returns the kernel ipset name for a zone+family.
func (io IpsetOptions) setName(zone, fam string) string {
	return prefixedSetName(io.SetPrefix, zone, fam)
}

// dynamicSetName returns the separate hash:ip set that receives new dnsmasq answers.
func (io IpsetOptions) dynamicSetName(zone, fam string) string {
	return prefixedSetName("wd_", zone, fam)
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
func zoneHasDomains(z Zone) bool { return len(z.Domains) > 0 || z.RemoteList != "" }

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
		if io.DynamicDomainSets && zoneHasDomains(z) {
			out = append(out, io.dynamicSetName(z.Name, "4"), io.dynamicSetName(z.Name, "6"))
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
		if io.DynamicDomainSets && dns {
			for _, fam := range []string{"4", "6"} {
				family := "inet"
				if fam == "6" {
					family = "inet6"
				}
				fmt.Fprintf(&b, "create %s hash:ip family %s hashsize 1024 maxelem %d timeout %d -exist\n",
					io.dynamicSetName(z.Name, fam), family, io.DomainMaxElem, DynamicDomainTimeout)
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
	var b strings.Builder
	pl.renderFilterSection(&b, io)
	pl.renderMangleAndNat(&b, io)
	return b.String()
}

// renderFilterSection writes the encrypted-DNS refusals. They are the plane's only filter-table rules,
// so they come first, as a section of their own that ends at FilterSectionEnd (see there).
func (pl *Plan) renderFilterSection(b *strings.Builder, io IpsetOptions) {
	legacy := io.DNSIntercept && io.DNSInterceptLAN != "" && io.DNSRejectEncrypted
	fastLANs := io.fastDNSLANs()
	if !legacy && len(fastLANs) == 0 {
		return
	}
	if legacy {
		b.WriteString("# filter: refuse DoT and the well-known DoH addresses. A filter rebuild re-runs only this part.\n")
		for _, r := range dnsRejectRules(io.DNSInterceptLAN) {
			r.writeAdd(b)
		}
	} else {
		b.WriteString("# filter: refuse DNS over TLS. A filter rebuild re-runs only this part.\n")
	}
	if len(fastLANs) > 0 {
		b.WriteString(fastDNSOpenIf)
	}
	for _, lan := range fastLANs {
		if legacy && lan == io.DNSInterceptLAN {
			continue
		}
		dnsDoTRejectRule(lan).writeAdd(b)
	}
	for _, lan := range fastLANs {
		for _, r := range dnsV6RefuseRules(lan) {
			r.writeAdd(b)
		}
	}
	if len(fastLANs) > 0 {
		b.WriteString(fastDNSOpenFi)
		b.WriteString(FastFilterSectionEnd)
		return
	}
	b.WriteString(FilterSectionEnd)
}

// MangleStageSuffix names the staging chain of the restore fallback (see writeMangleChain).
const MangleStageSuffix = "_S"

// iptablesRestoreDefault gives a script that has no pinned restore (the OpenWrt fw3 include) the
// PATH one. The Keenetic preamble always defines its own first, so this line never replaces it there.
const iptablesRestoreDefault = "command -v iptables_restore >/dev/null 2>&1 || iptables_restore() { iptables-restore \"$@\"; }\n" +
	"command -v ip6tables_restore >/dev/null 2>&1 || ip6tables_restore() { ip6tables-restore \"$@\"; }\n"

// writeMangleChain replaces the marking chain's rules without a moment in which it is empty.
//
// Flushing and refilling the chain rule by rule would leave a gap: between the -F and the last -A, a
// packet to a listed destination is not marked and goes by the main table, the WAN, kill switch or not.
// So the whole chain is one `iptables-restore --noflush` commit: the declared
// chain is flushed and refilled inside a single table replacement, so the kernel switches from the old
// rules to the new ones at once and every other chain of the table stays as it is. iptables 1.4.21
// (KeeneticOS) has the restore in xtables-multi; it takes no -w, and a table changed under it is
// refused by the kernel (EAGAIN) instead of being overwritten.
//
// When the restore is unavailable or refused, the fallback is still never empty: the new rules go into
// a staging chain first, jumped to right after the live chain, so while the live chain is flushed and
// refilled the staging chain marks every packet; then the staging jump and chain go.
//
// hook is the built-in chain that jumps to ch (PREROUTING, or OUTPUT for the hand-off's return traffic)
// and match the jump's match ("" for none); the staging chain is jumped to the same way.
func writeMangleChain(b *strings.Builder, ipt, hook, match, ch string, specs []string) {
	restore := strings.ReplaceAll(ipt, "-", "_") + "_restore"
	stage := ch + MangleStageSuffix
	jump := func(c string) string {
		if match == "" {
			return "-j " + c
		}
		return match + " -j " + c
	}
	fmt.Fprintf(b, "%s --noflush <<'WR_MANGLE' || {\n", restore)
	b.WriteString("*mangle\n")
	fmt.Fprintf(b, ":%s - [0:0]\n", ch)
	for _, s := range specs {
		fmt.Fprintf(b, "-A %s %s\n", ch, s)
	}
	b.WriteString("COMMIT\nWR_MANGLE\n")
	fmt.Fprintf(b, "%s -t mangle -N %s 2>/dev/null || %s -t mangle -F %s\n", ipt, stage, ipt, stage)
	for _, s := range specs {
		fmt.Fprintf(b, "%s -t mangle -A %s %s\n", ipt, stage, s)
	}
	fmt.Fprintf(b, "if %s -t mangle -C %s %s 2>/dev/null; then\n", ipt, hook, jump(ch))
	fmt.Fprintf(b, "%s -t mangle -C %s %s 2>/dev/null || %s -t mangle -A %s %s\n", ipt, hook, jump(stage), ipt, hook, jump(stage))
	b.WriteString("fi\n")
	fmt.Fprintf(b, "%s -t mangle -N %s 2>/dev/null || true\n", ipt, ch)
	fmt.Fprintf(b, "%s -t mangle -F %s\n", ipt, ch)
	for _, s := range specs {
		fmt.Fprintf(b, "%s -t mangle -A %s %s\n", ipt, ch, s)
	}
	fmt.Fprintf(b, "while %s -t mangle -D %s %s 2>/dev/null; do :; done\n", ipt, hook, jump(stage))
	fmt.Fprintf(b, "%s -t mangle -F %s 2>/dev/null || true\n", ipt, stage)
	fmt.Fprintf(b, "%s -t mangle -X %s 2>/dev/null || true\n", ipt, stage)
	b.WriteString("}\n")
}

// renderMangleAndNat writes the marking chains, the NAT and MSS rules and the DNS redirect.
func (pl *Plan) renderMangleAndNat(b *strings.Builder, io IpsetOptions) {
	mask := hexMark(pl.Mask)
	b.WriteString(iptablesRestoreDefault)
	emit := func(ipt, fam string) {
		ch := io.Chain
		var specs []string
		add := func(format string, args ...any) { specs = append(specs, fmt.Sprintf(format, args...)) }
		dynamicMark := func(z Zone, source string) {
			if !io.DynamicDomainSets || !zoneHasDomains(z) {
				return
			}
			set := io.dynamicSetName(z.Name, fam)
			add("%s", strings.TrimPrefix(fmt.Sprintf("%s -m set --match-set %s dst -j MARK --set-xmark %s/%s",
				source, set, hexMark(z.Mark), mask), " "))
		}
		dynamicRefresh := func(z Zone) {
			if !io.DynamicDomainSets || !zoneHasDomains(z) {
				return
			}
			set := io.dynamicSetName(z.Name, fam)
			add("-m set --match-set %s dst -m conntrack --ctstate NEW -j SET --add-set %s dst --exist --timeout %d",
				set, set, DynamicDomainTimeout)
		}
		// Anti-loop bypass first: tunnel server IPs RETURN (unmarked → main table → WAN).
		bypass := io.SetPrefix + "bypass_" + fam
		if (fam == "4" && len(pl.BypassV4) > 0) || (fam == "6" && len(pl.BypassV6) > 0) {
			add("-m set --match-set %s dst -j RETURN", bypass)
		}
		// Preserve the kept S86 RU-routing: a packet it already marked skips WR marking.
		if io.S86Mark != 0 {
			add("-m mark --mark %s/0xffffffff -j RETURN", hexMark(io.S86Mark))
		}
		// Restore an established connection's previously-chosen egress mark BEFORE the per-zone
		// match, so a long-lived flow keeps its tunnel even if its destination later leaves the
		// ipset — e.g. a DNS-populated domain entry expiring after its timeout — instead of
		// silently falling back to the WAN default mid-connection (a censored-traffic leak).
		add("-j CONNMARK --restore-mark --nfmask %s --ctmask %s", mask, mask)
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
					add("%s", strings.TrimPrefix(fmt.Sprintf("%s%s -j MARK --set-xmark %s/%s",
						srcNeg.String(), destMatch, hexMark(z.Mark), mask), " "))
					dynamicMark(z, srcNeg.String())
					dynamicRefresh(z)
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
					add("%s", strings.TrimPrefix(fmt.Sprintf("%s%s%s -j MARK --set-xmark %s/%s",
						sm, srcMatch, destMatch, hexMark(z.Mark), mask), " "))
					dynamicMark(z, sm+srcMatch)
				}
				dynamicRefresh(z)
				continue
			}
			has := (fam == "4" && (len(z.V4) > 0 || zoneHasDomains(z))) || (fam == "6" && (len(z.V6) > 0 || zoneHasDomains(z)))
			if !has {
				continue
			}
			set := io.setName(z.Name, fam)
			add("-m set --match-set %s dst -j MARK --set-xmark %s/%s", set, hexMark(z.Mark), mask)
			dynamicMark(z, "")
			dynamicRefresh(z)
		}
		// Mirror the chosen egress mark into the connmark (conntrack attribution; routing-inert).
		add("-j CONNMARK --save-mark --nfmask %s --ctmask %s", mask, mask)
		// A KeeneticOS access policy's slot becomes the policy's whole mark only now, after the save: the
		// connection keeps the slot, so a packet whose destination left the set is restored onto the slot
		// above and rewritten here like the first one. NDM's own rule then routes it, by the table and
		// ladder NDM keeps for that policy.
		for _, ps := range pl.NDMPolicySlots() {
			add("-m mark --mark %s/%s -j MARK --set-xmark %s/0xffffffff", hexMark(ps.Slot), mask, hexMark(ps.Mark))
		}
		if fam == "4" && pl.handoffOn(io) {
			specs = append(specs, pl.handoffChainSpecs(io)...)
		}
		if fam == "4" {
			b.WriteString(legacyOutputJumpDelete(ch))
		}
		writeMangleChain(b, ipt, "PREROUTING", "", ch, specs)
		// Ensure the jump from PREROUTING exists (appended → runs AFTER S86's pos-1 mark). The chain is
		// complete before the jump is first added.
		fmt.Fprintf(b, "%s -t mangle -C PREROUTING -j %s 2>/dev/null || %s -t mangle -A PREROUTING -j %s\n", ipt, ch, ipt, ch)
		if fam == "4" && pl.handoffOn(io) {
			// The hand-off's return traffic, classified by a chain OUTPUT can carry (no device match).
			out := HandoffOutputChain(io)
			match := strings.TrimSuffix(handoffOutputJump(""), " -j ")
			writeMangleChain(b, ipt, "OUTPUT", match, out, pl.handoffOutputSpecs(io))
			j := handoffOutputJump(out)
			fmt.Fprintf(b, "%s -t mangle -C OUTPUT %s 2>/dev/null || %s -t mangle -A OUTPUT %s\n", ipt, j, ipt, j)
		}
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
		fmt.Fprintf(b, "iptables -t nat -C POSTROUTING -o %s -m mark --mark %s/%s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -m mark --mark %s/%s -j MASQUERADE\n",
			io.WanIface, hexMark(e.Mark), mask, io.WanIface, hexMark(e.Mark), mask)
	}
	for _, dev := range io.masqDevices() {
		fmt.Fprintf(b, "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", dev, dev)
	}
	// DNS interception: clients' plain DNS is answered by THIS router, whatever server they asked
	// for. REDIRECT (not DNAT) because the destination is the router itself — it rewrites to the
	// interface's own address without us having to know it, which matters on a box whose LAN address
	// the operator can change. Idempotent check→append, like every rule here, because the netfilter.d
	// hook re-runs this script after each NDM firewall rebuild. The encrypted-DNS refusals that go
	// with it are at the top of the script, in the filter section.
	if fastLANs := io.fastDNSLANs(); len(fastLANs) > 0 {
		b.WriteString(fastDNSOpenIf)
		for _, lan := range fastLANs {
			for _, r := range dnsFastRedirectRules(lan) {
				r.writeAdd(b)
			}
		}
		b.WriteString(fastDNSOpenFi)
	} else if io.DNSIntercept && io.DNSInterceptLAN != "" {
		for _, r := range dnsRedirectRules(io.DNSInterceptLAN) {
			r.writeAdd(b)
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
			fmt.Fprintf(b, "%s -t mangle -C FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || %s -t mangle -A FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n",
				ipt, e.Iface, ipt, e.Iface)
		}
	}
}

func (pl *Plan) hasV6Zone() bool {
	for _, z := range pl.Zones {
		if len(z.V6) > 0 || len(z.SrcV6) > 0 || len(z.RouteV6) > 0 {
			return true
		}
		// A DOMAIN zone is dual-stack: dnsmasq populates both an inet and an inet6 set from the
		// A/AAAA answers, so the v6 datapath (ip6tables chain + v6 ip rules/default) must be
		// emitted for it too — else the AAAA-resolved addresses of a tunnel-routed domain are
		// never marked and IPv6 leaks direct to the WAN. (Domains are only collected on the
		// Keenetic ipset plane, so this is a no-op for the OpenWrt nft path.)
		if zoneHasDomains(z) && !z.DNSNoV6 {
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
		writeRule(&b, "ip", "to "+x.CIDR+" lookup main", x.Priority)
	}
	// Private destinations a zone names explicitly are carved out of that pin (unpin.go).
	b.WriteString(pl.unpinScript(opt, false))
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		if e.Kind == EgressInterface && e.FailClosed {
			// Kill switch, before the table's rule is (re)written: the table's own blackhole and the
			// mark's backstop rule exist first, so neither the del-then-add of the rule below nor an
			// empty table (link down, the elector's all-down clear, a reinstall) can send the marked
			// traffic on to the main table.
			fmt.Fprintf(&b, "ip route replace blackhole default metric %d table %d 2>/dev/null || true\n", failClosedMetric, e.Table)
			b.WriteString(failClosedBackstop(e, mask, opt, false))
		}
		writeTableRule(&b, "ip", fmt.Sprintf("fwmark %s/%s table %d", hexMark(e.Mark), mask, e.Table), pref, tableRuleStagePref(opt))
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
	// An access policy's own rule is NDM's (priority 100-109), and so is the blackhole
	// that follows it. This is the backstop for the hours between Applies: a policy deleted or renumbered
	// in NDM takes its rule with it, and a packet still carrying its mark would fall through every
	// WayHop rule to the main table - the WAN. While NDM's rule exists it matches first and this never
	// fires. BusyBox ip 1.37 on KeeneticOS accepts the rule type only as "type blackhole" (measured: a bare
	// "blackhole" is "invalid argument") and prints it as "lookup main blackhole".
	for _, ps := range pl.NDMPolicySlots() {
		writeRule(&b, "ip", "fwmark "+hexMark(ps.Mark)+" type blackhole", ndmPolicyBackstopPref(opt))
	}
	// IPv6 datapath, symmetric with v4 — a MARKED v6 packet to a censored dst must route
	// THROUGH the tunnel table, not fall through to the main v6 table (which on a device
	// whose v6 default is the WAN egresses the WAN = a censorship leak). Emitted only when
	// the plan actually marks v6 (mirrors the ip6tables mangle chain). v6 forwarded-NAT
	// (MASQUERADE) is intentionally NOT wired — a v6 LAN is absent on the target — so a v6
	// forwarded flow fails CLOSED in the tunnel table rather than ever leaking to the WAN.
	if pl.hasV6Zone() || len(pl.BypassV6) > 0 {
		for _, x := range privateExcludesV6(opt) {
			writeRule(&b, "ip -6", "to "+x.CIDR+" lookup main", x.Priority)
		}
		b.WriteString(pl.unpinScript(opt, true))
		for i, e := range pl.nonWanEgresses() {
			pref := opt.RulePref + i
			if e.Kind == EgressInterface && e.FailClosed {
				fmt.Fprintf(&b, "ip -6 route replace blackhole default metric %d table %d 2>/dev/null || true\n", failClosedMetricV6, e.Table)
				b.WriteString(failClosedBackstop(e, mask, opt, true))
			}
			writeTableRule(&b, "ip -6", fmt.Sprintf("fwmark %s/%s table %d", hexMark(e.Mark), mask, e.Table), pref, tableRuleStagePref(opt))
			switch e.Kind {
			case EgressInterface:
				fmt.Fprintf(&b, "ip -6 route add default dev %s table %d 2>/dev/null || true\n", e.Iface, e.Table)
				if e.FailClosed {
					// Kill switch (v6) — mirror the v4 fail-closed blackhole above + render.go (fail-safe).
					fmt.Fprintf(&b, "ip -6 route replace blackhole default metric %d table %d 2>/dev/null || true\n", failClosedMetricV6, e.Table)
				}
			case EgressBlackhole:
				fmt.Fprintf(&b, "ip -6 route replace blackhole default table %d\n", e.Table)
			}
		}
		// The v6 backstop matters more: on KeeneticOS some NDM policy marks have v4 rules only.
		for _, ps := range pl.NDMPolicySlots() {
			writeRule(&b, "ip -6", "fwmark "+hexMark(ps.Mark)+" type blackhole", ndmPolicyBackstopPref(opt))
		}
	}
	return b.String()
}

// failClosedRulePref is the priority of a kill-switched mark's backstop rule: after every table rule
// (RulePref + egress index; the mark space holds fewer than 256 egresses) and long before the main
// table's rule (32766). The table's own metric-1000 blackhole already drops the marked traffic when
// the tunnel's route is gone; the backstop also covers a table with no route at all, which the
// table-level blackhole cannot: a flush, a hand-deleted route, the window of a reinstall. A table
// lookup that finds nothing goes on to the next rule, and for this mark that is the backstop.
func failClosedRulePref(opt Options) int { return opt.RulePref + 300 }

// writeTableRule rewrites one egress's table rule make-before-break: a copy at the staging priority
// first, then the rule at its own priority deleted (every copy) and added, then the copy goes. The add
// at the own priority is not best-effort: MissingIPRules reads it back.
func writeTableRule(b *strings.Builder, ip, spec string, pref, stage int) {
	var body strings.Builder
	fmt.Fprintf(&body, "%s rule add %s priority %d 2>/dev/null || true\n", ip, spec, stage)
	fmt.Fprintf(&body, "while %s rule del %s priority %d 2>/dev/null; do :; done\n", ip, spec, pref)
	fmt.Fprintf(&body, "%s rule add %s priority %d\n", ip, spec, pref)
	fmt.Fprintf(&body, "while %s rule del %s priority %d 2>/dev/null; do :; done\n", ip, spec, stage)
	guardRule(b, ip, spec, pref, body.String())
}

// writeRule rewrites a rule whose short del-then-add gap is covered otherwise (a private exclude, a
// blackhole rule), only when it is missing.
func writeRule(b *strings.Builder, ip, spec string, pref int) {
	body := fmt.Sprintf("%s rule del %s priority %d 2>/dev/null || true\n%s rule add %s priority %d\n", ip, spec, pref, ip, spec, pref)
	guardRule(b, ip, spec, pref, body)
}

// tableRuleStagePref holds a copy of an egress's table rule while the rule at its own priority is
// rewritten, so a re-run of the program never has a moment without one. Marks are
// exclusive, so one shared priority serves every egress; it sits after every egress rule and before
// the fail-closed rules.
func tableRuleStagePref(opt Options) int { return opt.RulePref + 299 }

// failClosedBackstop installs a kill-switched egress's backstop rule. It runs right after the table's
// blackhole was written, so the short del-then-add here is covered by that route. The add is not
// best-effort: MissingIPRules reads it back, and a kill switch the kernel did not take fails the Apply.
func failClosedBackstop(e Egress, mask string, opt Options, v6 bool) string {
	ip := "ip"
	if v6 {
		ip = "ip -6"
	}
	var b strings.Builder
	writeRule(&b, ip, fmt.Sprintf("fwmark %s/%s type blackhole", hexMark(e.Mark), mask), failClosedRulePref(opt))
	return b.String()
}

// ndmPolicyBackstopPref sits just above the private-destination excludes (RulePref-3..-1), so a
// policy-marked packet NDM no longer routes is dropped before anything WayHop owns can route it.
func ndmPolicyBackstopPref(opt Options) int { return opt.RulePref - 4 }

// RenderTeardownScript removes everything the Keenetic plane installed: the PREROUTING jump,
// our mangle chain, the DNS redirect and the encrypted-DNS refusals, the ip rules + table routes,
// and the kernel sets.
func (pl *Plan) RenderTeardownScript(opt Options, io IpsetOptions) string {
	opt.withDefaults()
	io.withDefaults()
	mask := hexMark(pl.Mask)
	var b strings.Builder
	// Reverse of the install order: everything that sets a mark goes first, the jumps
	// from OUTPUT and PREROUTING and the chains, then the ip rules and tables that route the marks.
	pl.renderHandoffChainTeardown(&b, io)
	for _, ipt := range []string{"iptables", "ip6tables"} {
		// Delete every jump, not one: duplicates left by lock races in older versions kept the chain
		// referenced, so -X failed quietly and the extras outlived routing-off until a reboot.
		// The restore fallback's staging chain too: a script killed half-way leaves it jumped to.
		for _, ch := range []string{io.Chain, io.Chain + MangleStageSuffix} {
			fmt.Fprintf(&b, "while %s -t mangle -D PREROUTING -j %s 2>/dev/null; do :; done\n", ipt, ch)
			fmt.Fprintf(&b, "%s -t mangle -F %s 2>/dev/null || true\n", ipt, ch)
			fmt.Fprintf(&b, "%s -t mangle -X %s 2>/dev/null || true\n", ipt, ch)
		}
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
	// The DNS redirect and the refusals go whatever this plane's own switches say. This script runs
	// when the plane is replaced (a switch turned off), when the mode leaves the kernel plane and when
	// routing is turned off, and the plane it removes may have been rendered with them on. They sit in
	// chains NDM owns, so nothing else would take them out before NDM's next rebuild of those tables.
	if lan := io.DNSInterceptLAN; lan != "" {
		for _, r := range append(dnsRedirectRules(lan), dnsRejectRules(lan)...) {
			b.WriteString(IptablesDeleteEveryCopy(r.table, r.chain, r.spec))
		}
	}
	for _, lan := range io.fastDNSLANs() {
		rules := append(append(dnsFastRedirectRules(lan), dnsDoTRejectRule(lan)), dnsV6RefuseRules(lan)...)
		for _, r := range rules {
			b.WriteString(r.deleteEveryCopy())
		}
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
		fmt.Fprintf(&b, "ip rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, tableRuleStagePref(opt))
		fmt.Fprintf(&b, "ip route flush table %d 2>/dev/null || true\n", e.Table)
		if e.Kind == EgressInterface && e.FailClosed {
			fmt.Fprintf(&b, "ip rule del fwmark %s/%s type blackhole priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, failClosedRulePref(opt))
		}
	}
	b.WriteString(pl.unpinTeardownScript(opt, false))
	for _, x := range privateExcludes(opt) {
		fmt.Fprintf(&b, "ip rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
	}
	for _, ps := range pl.NDMPolicySlots() {
		fmt.Fprintf(&b, "ip rule del fwmark %s type blackhole priority %d 2>/dev/null || true\n", hexMark(ps.Mark), ndmPolicyBackstopPref(opt))
	}
	if pl.hasV6Zone() || len(pl.BypassV6) > 0 {
		for i, e := range pl.nonWanEgresses() {
			pref := opt.RulePref + i
			fmt.Fprintf(&b, "ip -6 rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, pref)
			fmt.Fprintf(&b, "ip -6 rule del fwmark %s/%s table %d priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, e.Table, tableRuleStagePref(opt))
			fmt.Fprintf(&b, "ip -6 route flush table %d 2>/dev/null || true\n", e.Table)
			if e.Kind == EgressInterface && e.FailClosed {
				fmt.Fprintf(&b, "ip -6 rule del fwmark %s/%s type blackhole priority %d 2>/dev/null || true\n", hexMark(e.Mark), mask, failClosedRulePref(opt))
			}
		}
		for _, ps := range pl.NDMPolicySlots() {
			fmt.Fprintf(&b, "ip -6 rule del fwmark %s type blackhole priority %d 2>/dev/null || true\n", hexMark(ps.Mark), ndmPolicyBackstopPref(opt))
		}
		b.WriteString(pl.unpinTeardownScript(opt, true))
		for _, x := range privateExcludesV6(opt) {
			fmt.Fprintf(&b, "ip -6 rule del to %s lookup main priority %d 2>/dev/null || true\n", x.CIDR, x.Priority)
		}
	}
	pl.renderHandoffTeardown(&b, opt, io)
	pl.renderBackstopTeardown(&b, opt, io)
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
		sets       string // comma-separated set names — v4,v6 so dnsmasq adds A→inet, AAAA→inet6
		domains    []string
		failClosed bool
	}
	failClosed := map[string]bool{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface && e.FailClosed {
			failClosed[e.Tag] = true
		}
	}
	var zones []dz
	for _, z := range pl.Zones {
		if zoneHasDomains(z) {
			// Target BOTH the inet and inet6 sets: dnsmasq routes each resolved A record to the
			// matching-family (inet) set and each AAAA to the inet6 set, so a tunnel-routed
			// domain's IPv6 traffic is marked/routed instead of leaking direct to the WAN.
			set4, set6 := io.setName(z.Name, "4"), io.setName(z.Name, "6")
			if io.DynamicDomainSets {
				set4, set6 = io.dynamicSetName(z.Name, "4"), io.dynamicSetName(z.Name, "6")
			}
			zones = append(zones, dz{sets: set4 + "," + set6, domains: z.Domains,
				failClosed: failClosed[z.EgressTag]})
		}
	}
	if len(zones) == 0 {
		return ""
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].sets < zones[j].sets })
	var b strings.Builder
	b.WriteString("# Generated by WayHop (dnsmasq-ipset domain routing) — do not edit.\n")
	if io.DynamicDomainSets {
		// Fast mode's canary (as in the nft snippet): only the resolver that loaded this file answers
		// it, so the restart guard and the watch prove the LAN's resolver took the file, not just that
		// some dnsmasq answers on 127.0.0.1:53 (HUNT-K #10, #11).
		b.WriteString("address=/" + FastCanaryName + "/" + FastCanaryAddr + "\n")
	}
	batch := func(directive string, domains []string, suffix string) {
		// Build "<directive>=/d1/d2/.../<suffix>" lines, each ≤ maxLine bytes.
		head := directive + "="
		line := head
		for _, d := range domains {
			add := "/" + d
			if len(line)+len(add)+len(suffix) > maxLine && line != head {
				b.WriteString(line + suffix + "\n")
				line = head
			}
			line += add
		}
		if line != head {
			b.WriteString(line + suffix + "\n")
		}
	}
	for _, z := range zones {
		batch("ipset", z.domains, "/"+z.sets)
	}
	// A kill-switched list's names are asked of the sing-box DNS listener alone. With a domain server
	// dnsmasq uses only the servers given for that domain, so when the tunnel is down the lookup fails
	// there instead of moving on to the next row of the chain, which may resolve by the provider.
	if io.KillSwitchDNS != "" {
		var pinned []string
		seen := map[string]bool{}
		for _, z := range zones {
			if !z.failClosed {
				continue
			}
			for _, d := range z.domains {
				if !seen[d] {
					seen[d] = true
					pinned = append(pinned, d)
				}
			}
		}
		if len(pinned) > 0 {
			sort.Strings(pinned)
			b.WriteString("# Kill switch: these names are resolved by the WayHop DNS listener only.\n")
			batch("server", pinned, "/"+io.KillSwitchDNS)
		}
	}
	return b.String()
}

// KillSwitchDomains reports whether a fail-closed zone carries domain names: their lookups need the
// sing-box DNS listener (IpsetOptions.KillSwitchDNS), and without it the plane must be refused.
func (pl *Plan) KillSwitchDomains() bool { return len(pl.KillSwitchDomainZones()) > 0 }

// KillSwitchDomainZones names the fail-closed zones that carry domain names.
func (pl *Plan) KillSwitchDomainZones() []string {
	failClosed := map[string]bool{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface && e.FailClosed {
			failClosed[e.Tag] = true
		}
	}
	var out []string
	for _, z := range pl.Zones {
		if zoneHasDomains(z) && failClosed[z.EgressTag] {
			out = append(out, z.Name)
		}
	}
	return out
}

// KillSwitchScopedZones names the fail-closed zones scoped to some devices: the backstop cannot cover
// them (an ip rule does not see MACs, and the other devices reach those destinations directly). Both
// routing lists and routing rules with a source matcher. The NDMPolicy clause cannot
// fire today (a policy zone has no egress, so no fail-closed one); it is kept so a
// future kill-switched policy egress is refused rather than silently uncovered.
func (pl *Plan) KillSwitchScopedZones() []string {
	failClosed := map[string]bool{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface && e.FailClosed {
			failClosed[e.Tag] = true
		}
	}
	var out []string
	for _, z := range pl.Zones {
		if (z.SrcScoped || z.NDMPolicy != "") && failClosed[z.EgressTag] { // A policy's list too
			out = append(out, z.Name)
		}
	}
	return out
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

// DynamicSetName names the resolver-fed hash:ip set for a zone and family.
func (io IpsetOptions) DynamicSetName(zone, fam string) string {
	return io.dynamicSetName(zone, fam)
}

// DynamicSets names the plan's wd_ sets (none unless io.DynamicDomainSets), and which of them belong
// to a zone that sends its addresses somewhere other than the WAN (a tunnel or block): a flow to such an
// address that a direct list had saved with the WAN mark is stale once the name takes it, like
// DlistSetsBeyondWAN on the nft plane. Access-policy zones are left out of beyondWAN, as there.
func (pl *Plan) DynamicSets(io IpsetOptions) (names []string, beyondWAN map[string]bool) {
	beyondWAN = map[string]bool{}
	if pl == nil || !io.DynamicDomainSets {
		return nil, beyondWAN
	}
	kind := map[string]EgressKind{}
	for _, e := range pl.Egresses {
		kind[e.Tag] = e.Kind
	}
	for _, z := range pl.Zones {
		if !zoneHasDomains(z) {
			continue
		}
		for _, fam := range []string{"4", "6"} {
			n := io.dynamicSetName(z.Name, fam)
			names = append(names, n)
			if z.NDMPolicy == "" && kind[z.EgressTag] != EgressWAN {
				beyondWAN[n] = true
			}
		}
	}
	return names, beyondWAN
}
