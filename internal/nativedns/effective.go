package nativedns

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// EffectivePath is the RUNTIME DNS datapath the router actually serves — distinct from the adopted
// CONFIG (NativeDNS). It answers the spec's DNS-leak questions that the config alone cannot: what
// process actually listens on :53, what the router's own upstreams are, whether LAN :53 is
// force-redirected through the router (anti-bypass hijack), and — critically — whether a LAN client
// can still ESCAPE the router DNS via public DoH/DoT (an unblocked bypass = a silent leak vector).
// Pure-parsed from captured device text so it is unit-testable; RunEffectivePath gathers the text.
type EffectivePath struct {
	Listeners []DNSListener `json:"listeners,omitempty"` // who serves DNS on :53
	// Upstreams are the router's own resolv.conf nameservers: where the router's programs look names
	// up, not where its forwarder sends LAN queries. On OpenWrt they are the stub pointing at the
	// local dnsmasq, so Loops is judged from dnsmasq's configuration instead (see forwarderLoops).
	Upstreams  []string `json:"upstreams,omitempty"`
	Hijack53   bool     `json:"hijack53"`              // a nat REDIRECT/DNAT forces LAN :53 to a local resolver
	Hijack53To string   `json:"hijack53_to,omitempty"` // the port/target the :53 redirect sends to
	// The two encrypted escape hatches, reported separately because only one of them is closable by
	// port number. A rule on :853 stops DoT. DoH rides ordinary HTTPS on :443, so constraining it
	// means naming the resolvers (an address set); a port rule cannot do it without breaking the web.
	//
	// These were one field, set from the :853 signal alone and named for DoH. On the test test router
	// that produced "plain and DoT bypass are both constrained" with LeakRisk cleared — correct there
	// only by luck, because that box also carries a resolver-set block the detector never read. The
	// :853 rules themselves come from the https-dns-proxy package, which every OpenWrt running it
	// installs, so the same verdict would have been printed on any such router with no DoH blocking
	// at all: a client using its own DoH resolver bypasses the router entirely and the page said
	// there was no leak risk.
	DoTBypassBlocked bool `json:"dot_bypass_blocked"` // a rule blocks/redirects :853
	DoHBypassBlocked bool `json:"doh_bypass_blocked"` // a rule constrains :443 to named resolver addresses
	// IPv6Gaps names the routes above that the IPv4 firewall shuts and IPv6 leaves open, on a router
	// whose LAN has a routable IPv6 address (GapPlain53, GapDoT, GapDoH). Hijack53 and the two
	// Bypass fields are read from `iptables` (or nft when there is no iptables), and the
	// intercept WayHop installs is iptables only. On a LAN with IPv6 a client reached a v6 resolver
	// on :53, :853 or :443 untouched while ip6tables was never read, the verdict was cleared and
	// the DNS page said clients could not route around it (QA-107).
	IPv6Gaps []string  `json:"ipv6_gaps,omitempty"`
	LeakRisk bool      `json:"leak_risk"`       // true when clients can bypass the router DNS unhindered
	Loops    []DNSLoop `json:"loops,omitempty"` // upstreams that resolve back into this router's own DNS path
	Notes    []string  `json:"notes,omitempty"` // human-readable findings for the diagnostics view

	// RulesUnknown reports that the firewall rules could not be READ, so Hijack53 and
	// DoHBypassBlocked are absences of evidence rather than evidence of absence.
	//
	// Both derive from `iptables -S`, whose error was discarded. On a router with no iptables binary
	// — a plausible fw4/nftables-only OpenWrt build — every probe returns empty and the detector
	// then stated as a finding that "LAN DNS is not forced through the router (no :53 redirect)".
	// The leak verdict errs safe (it flags a risk), but that NOTE asserts a measurement which never
	// happened: it sends someone chasing a problem that may not exist, and teaches them to distrust
	// the detector.
	RulesUnknown bool `json:"rules_unknown,omitempty"`
}

// DNSListener is one process listening on :53.
type DNSListener struct {
	Proto   string `json:"proto"`             // "udp" | "tcp"
	Addr    string `json:"addr"`              // e.g. "0.0.0.0:53" or ":::53"
	Process string `json:"process,omitempty"` // e.g. "dnsmasq" (may be empty if not captured)
}

var (
	// A :53 REDIRECT/DNAT (to a local resolver) in the nat table = LAN DNS forced through the router.
	reDport53   = regexp.MustCompile(`(?:--dport|dpt:?)\s*53\b`)
	reToPorts   = regexp.MustCompile(`--to-ports\s+(\S+)`)
	reToDestrgx = regexp.MustCompile(`--to-destination\s+(\S+)`)
	// :853 is DoT; a rule mentioning it (REJECT/DROP/DNAT) means the router actively handles DoT bypass.
	reDport853 = regexp.MustCompile(`(?:--dport|dpt:?)\s*853\b`)

	// The iptables spelling of a DoH constraint: :443 restricted to an ipset or a destination, and
	// dropped rather than merely counted. Same requirement as the nft side — the port alone is the
	// whole web, so a rule that does not name where it applies is not DoH handling.
	reDport443       = regexp.MustCompile(`(?:--dport|dpt:?)\s*443\b`)
	reMatchSetOrDest = regexp.MustCompile(`--match-set\s+\S+|\s-d\s+\S+|--destination\s+\S+`)
	reDropVerb       = regexp.MustCompile(`-j\s+(DROP|REJECT)\b`)

	// What the IPv6 comparison reads, stricter than the signals above. The verdict to jump to: a
	// chain whose name holds REDIRECT is not one, and KeeneticOS writes exactly that into ip6tables
	// (`-p udp --dport 53 -j _NDM_IC_REDIRECT`, an empty chain), so the loose read would have taken
	// it for an IPv6 :53 redirect on every Keenetic.
	reJumpRedirect = regexp.MustCompile(`(?:^|\s)-j\s+(?:REDIRECT|DNAT)(?:\s|$)`)
	reJumpStop     = regexp.MustCompile(`(?:^|\s)-j\s+(?:REJECT|DROP|REDIRECT|DNAT)(?:\s|$)`)
	// A match that leaves some of the interface's packets alone: a mark (KeeneticOS's hotspot DNS
	// redirects carry one, in both families), a source, a connection mark. reNarrowDest adds the
	// destination, which narrows a :53 or :853 rule but is the whole point of a DoH one.
	reNarrow     = regexp.MustCompile(`(?:^|\s)(?:-s|--source|--src-range|--mac-source|--mark|--ndmmark|--connmark|--ctmark|--uid-owner|--gid-owner)\s`)
	reNarrowDest = regexp.MustCompile(`(?:^|\s)(?:-d|--destination|--dst-range|--match-set)\s`)
	// The interface clause of a rule: `-i br0`, or `! -i eth3` for every interface but that one.
	reInIface = regexp.MustCompile(`(?:^|\s)(!\s+)?(?:-i|--in-interface)\s+(\S+)`)
	// A FORWARD rule that refuses everything arriving on an interface (or on every one): no port, no
	// protocol, no other match but a comment. It shuts all three routes at once, so an IPv6 LAN whose
	// forwarding is refused outright (`ip6tables -A FORWARD -i br0 -j REJECT`) leaves none open.
	reRefuseAll = regexp.MustCompile(`^-A FORWARD(?:\s+(?:!\s+)?(?:-i|--in-interface)\s+\S+)?` +
		`(?:\s+-m\s+comment\s+--comment\s+(?:"[^"]*"|\S+))?\s+-j\s+(?:REJECT|DROP)(?:\s+--reject-with\s+\S+)?\s*$`)
)

// The bypass routes IPv6Gaps can name.
const (
	GapPlain53 = "53"
	GapDoT     = "dot"
	GapDoH     = "doh"
)

// gapRoutes is the order routes are checked and named in, and gapNames how the note names them.
var (
	gapRoutes = []string{GapPlain53, GapDoT, GapDoH}
	gapNames  = map[string]string{
		GapPlain53: "the :53 redirect", GapDoT: "the DoT (:853) refusal", GapDoH: "the DoH resolver refusal",
	}
)

// ruleBinding is the interface clause of one rule. No clause binds it to every interface.
type ruleBinding struct {
	iface   string
	negated bool
}

func bindingOf(ln string) ruleBinding {
	if m := reInIface.FindStringSubmatch(ln); m != nil {
		return ruleBinding{iface: m[2], negated: m[1] != ""}
	}
	return ruleBinding{}
}

// matches reports whether a rule bound this way sees packets arriving on iface. iptables reads a
// trailing `+` as a prefix wildcard.
func (b ruleBinding) matches(iface string) bool {
	if b.iface == "" {
		return true
	}
	same := b.iface == iface
	if p, ok := strings.CutSuffix(b.iface, "+"); ok {
		same = strings.HasPrefix(iface, p)
	}
	return same != b.negated
}

// names reports whether the rule is bound to iface by name, which is what says iface is a LAN the
// rule guards. An unbound or negated rule says nothing about which interface faces the clients.
func (b ruleBinding) names(iface string) bool {
	return b.iface != "" && !b.negated && b.matches(iface)
}

// routeRules are the rules that shut one route, by the interfaces they are bound to. plain holds
// the ones that catch every packet there; all holds those and the conditional ones.
type routeRules struct{ plain, all []ruleBinding }

func (r routeRules) on(iface string) (shut, plain bool) {
	for _, b := range r.all {
		shut = shut || b.matches(iface)
	}
	for _, b := range r.plain {
		plain = plain || b.matches(iface)
	}
	return shut, plain
}

// bypassRules is what one address family's firewall says about the three ways round the router DNS.
type bypassRules struct {
	// The signals the verdict is read from, loose as they have always been: any :53 nat rule naming
	// REDIRECT or DNAT, any rule touching :853, any rule refusing :443 at named destinations.
	hijack53   bool
	hijack53To string
	dot, doh   bool
	// Per route (gapRoutes), the rules with a real verdict and where they apply. The IPv6 check
	// compares the two families with these, interface by interface.
	routes map[string]routeRules
	// refuseAll are the FORWARD rules that refuse every packet arriving where they apply. gapsOn
	// reads them on the IPv6 side only: there they shut every route, while the IPv4 verdict is still
	// read from the signals above.
	refuseAll []ruleBinding
}

// refusesAll reports whether a blanket FORWARD refusal covers packets arriving on iface.
func (r bypassRules) refusesAll(iface string) bool {
	for _, b := range r.refuseAll {
		if b.matches(iface) {
			return true
		}
	}
	return false
}

// readBypassRules parses `-S` output: natRules for the :53 redirect, allRules (nat + filter) for the
// :853 rule and the :443 rule that names destinations.
func readBypassRules(natRules, allRules string) bypassRules {
	r := bypassRules{routes: map[string]routeRules{}}
	record := func(route, ln string, narrowed bool) {
		rr, b := r.routes[route], bindingOf(ln)
		rr.all = append(rr.all, b)
		if !narrowed {
			rr.plain = append(rr.plain, b)
		}
		r.routes[route] = rr
	}
	// A :53 hijack (a nat REDIRECT/DNAT on --dport 53) = LAN DNS forced to a local resolver.
	for _, ln := range strings.Split(natRules, "\n") {
		if !reDport53.MatchString(ln) {
			continue
		}
		if reJumpRedirect.MatchString(ln) {
			record(GapPlain53, ln, reNarrow.MatchString(ln) || reNarrowDest.MatchString(ln))
		}
		if r.hijack53 {
			continue
		}
		if up := strings.ToUpper(ln); !strings.Contains(up, "REDIRECT") && !strings.Contains(up, "DNAT") {
			continue
		}
		r.hijack53 = true
		if m := reToPorts.FindStringSubmatch(ln); m != nil {
			r.hijack53To = m[1]
		} else if m := reToDestrgx.FindStringSubmatch(ln); m != nil {
			r.hijack53To = m[1]
		}
	}
	// One signal each. A rule touching :853 manages DoT. DoH needs a rule that names destinations,
	// since the port is shared with the entire web.
	for _, ln := range strings.Split(allRules, "\n") {
		if reDport853.MatchString(ln) {
			r.dot = true
			if reJumpStop.MatchString(ln) {
				record(GapDoT, ln, reNarrow.MatchString(ln) || reNarrowDest.MatchString(ln))
			}
		}
		if reDport443.MatchString(ln) && reMatchSetOrDest.MatchString(ln) && reDropVerb.MatchString(ln) {
			r.doh = true
			record(GapDoH, ln, reNarrow.MatchString(ln))
		}
		if reRefuseAll.MatchString(strings.TrimSpace(ln)) {
			r.refuseAll = append(r.refuseAll, bindingOf(ln))
		}
	}
	return r
}

// gapsOn lists the routes v4 shuts on iface that v6 leaves open there. Like is held to like: where
// IPv4 shuts a route for every packet, IPv6 must too, so KeeneticOS's own mark-conditioned :53
// redirects (present in both families) do not stand in for WayHop's unconditional IPv4 one; where
// IPv4's own rule is conditional, any IPv6 rule with a real verdict there matches it. IPv6 forwarding
// refused outright on iface shuts every route there.
func gapsOn(iface string, v4, v6 bypassRules) []string {
	if v6.refusesAll(iface) {
		return nil
	}
	var gaps []string
	for _, route := range gapRoutes {
		shut4, plain4 := v4.routes[route].on(iface)
		if !shut4 {
			continue
		}
		shut6, plain6 := v6.routes[route].on(iface)
		if !plain6 && (plain4 || !shut6) {
			gaps = append(gaps, route)
		}
	}
	return gaps
}

// guards reports whether any of the rules is bound to iface by name, and sees iface at all.
func (r bypassRules) guards(iface string) (named, seen bool) {
	for _, rr := range r.routes {
		for _, b := range rr.all {
			named = named || b.names(iface)
			seen = seen || b.matches(iface)
		}
	}
	return named, seen
}

// DetectEffectivePath parses captured device text into an EffectivePath. All inputs are best-effort:
// an empty string for any source simply contributes nothing (a non-router host yields a near-empty,
// low-signal result rather than an error). resolvConf is /etc/resolv.conf; listeners is
// `netstat -tulnp` (or ss) output; natRules is `iptables -t nat -S`; allRules is any firewall dump
// (nat + filter) scanned for a :853 bypass rule.
func DetectEffectivePath(resolvConf, listeners, natRules, allRules string) EffectivePath {
	var ep EffectivePath

	// 1) Router's own upstreams (nameserver lines).
	ep.Upstreams = resolvNameservers(resolvConf)

	// 2) :53 listeners (LAN DNS servers). netstat/ss lines: proto ... <localaddr:53> ... [pid/proc].
	for _, ln := range strings.Split(listeners, "\n") {
		if !strings.Contains(ln, ":53 ") && !strings.HasSuffix(strings.TrimSpace(ln), ":53") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToLower(f[0])
		if !strings.HasPrefix(proto, "udp") && !strings.HasPrefix(proto, "tcp") {
			continue
		}
		l := DNSListener{Proto: strings.TrimSuffix(strings.TrimSuffix(proto, "6"), "4")}
		for _, tok := range f {
			if strings.HasSuffix(tok, ":53") {
				l.Addr = tok
			}
			if i := strings.Index(tok, "/"); i > 0 && l.Process == "" { // "928/dnsmasq"
				l.Process = tok[i+1:]
			}
		}
		if l.Addr != "" {
			ep.Listeners = append(ep.Listeners, l)
		}
	}

	// 3) :53 hijack, 4) DoT and DoH handling.
	v4 := readBypassRules(natRules, allRules)
	ep.Hijack53, ep.Hijack53To = v4.hijack53, v4.hijack53To
	ep.DoTBypassBlocked, ep.DoHBypassBlocked = v4.dot, v4.doh

	// 5) Leak verdict + notes.
	applyLeakVerdict(&ep)

	// No Loops here: resolv.conf is not where the forwarder sends queries, and judging loops from it
	// reported the stock OpenWrt stub as two confirmed self-loops (QA-117). RunEffectivePath reads
	// dnsmasq's own upstreams for that.
	return ep
}

// RunEffectivePath gathers the runtime DNS state via the injected runner and returns the parsed
// EffectivePath. Every probe is best-effort (a failing command contributes an empty string), so this
// degrades to a low-signal result off a router rather than erroring.
func RunEffectivePath(run Runner) EffectivePath {
	resolvConf, _ := run("cat", "/etc/resolv.conf")
	listeners, _ := run("netstat", "-tulnp")
	natRules, natErr := run("iptables", "-t", "nat", "-S")
	filterRules, filErr := run("iptables", "-S")
	addrs, _ := run("ip", "-o", "addr")
	ep := DetectEffectivePath(resolvConf, listeners, natRules, natRules+"\n"+filterRules)
	// iptables told us nothing. Before declaring the firewall unreadable, try nftables: on an fw4
	// OpenWrt there may be no iptables binary at all, and the ruleset is perfectly readable the
	// other way. Only when BOTH fail is the firewall genuinely unknown.
	if rulesUnreadable(natRules, natErr, filterRules, filErr) {
		nftOut, nftErr := run("nft", "list", "ruleset")
		nf := NftFindings{}
		if nftErr == nil {
			nf = DetectFromNft(nftOut)
		}
		if nf.Parsed {
			ep.Hijack53 = nf.Hijack53
			if nf.Hijack53To != "" {
				ep.Hijack53To = nf.Hijack53To
			}
			ep.DoTBypassBlocked = nf.DoTHandled
			ep.DoHBypassBlocked = nf.DoHHandled
			// The leak verdict was computed from the empty iptables read; recompute it now that the
			// firewall has actually been seen, or the notes would describe a router nobody looked at.
			ep.Notes = nil
			ep.LeakRisk = false
			applyLeakVerdict(&ep)
		} else {
			markRulesUnknown(&ep)
		}
	} else {
		// IPv6 is judged on the iptables path only. nft's inet tables carry both families in one
		// rule, and that path is reached only when there is no iptables to read.
		checkIPv6(&ep, run, readBypassRules(natRules, natRules+"\n"+filterRules), addrs)
	}
	// Loops are judged from where dnsmasq forwards. Ownership comes from the live address list: a
	// listener bound to 0.0.0.0 proves the router serves DNS but not WHICH addresses it owns, so
	// without it an upstream pointing at the router's own LAN IP would go unnoticed.
	ep.Loops = forwarderLoops(run, ep.Listeners, parseOwnAddrs(addrs))
	return ep
}

// checkIPv6 holds the IPv4 verdict to IPv6 where the LAN can use it: on an interface with a
// routable IPv6 address, every route the IPv4 rules shut there must be shut in ip6tables too, or it
// is listed in IPv6Gaps and the verdict is a leak risk.
//
// The LAN is what the IPv4 rules are bound to by name (WayHop binds its intercept to the bridge it
// guards). A rule bound to no interface, or to all but one, cannot say which interface faces the
// clients, so there an interface an IPv6 default route leaves through, in any table, is taken for the
// uplink and skipped. Only a routable address counts: link-local and ULA (fc00::/7) reach no public resolver.
// ip6tables is read only then, so a router whose LAN has no IPv6 is judged exactly as before.
func checkIPv6(ep *EffectivePath, run Runner, v4 bypassRules, addrs string) {
	if !v4.hijack53 && !v4.dot && !v4.doh {
		return // nothing shut over IPv4 either: the verdict already says so
	}
	var uplinks map[string]bool
	var v6 *bypassRules
	unread := false
	v6Iface := ""
	var gaps []string
	for _, iface := range routableIPv6Interfaces(addrs) {
		named, seen := v4.guards(iface)
		if !seen {
			continue
		}
		if !named {
			if uplinks == nil {
				uplinks = ipv6DefaultRouteInterfaces(run)
			}
			if uplinks[iface] {
				continue
			}
		}
		if v6 == nil {
			nat6, natErr := run("ip6tables", "-t", "nat", "-S")
			filter6, filErr := run("ip6tables", "-S")
			v6 = &bypassRules{}
			if unread = rulesUnreadable(nat6, natErr, filter6, filErr); !unread {
				*v6 = readBypassRules(nat6, nat6+"\n"+filter6)
			}
		}
		if gaps = gapsOn(iface, v4, *v6); len(gaps) > 0 {
			v6Iface = iface
			break
		}
	}
	if len(gaps) == 0 {
		return
	}
	var named []string
	for _, g := range gaps {
		named = append(named, gapNames[g])
	}
	ep.IPv6Gaps = gaps
	verb := "cover"
	if len(named) == 1 {
		verb = "covers"
	}
	routes := joinAnd(named)
	routes = strings.ToUpper(routes[:1]) + routes[1:]
	// Plain sentences, one finding each: where IPv6 is, what covers IPv4 only, what that lets through.
	claim := fmt.Sprintf("%s %s IPv4 only: nothing in ip6tables does the same.", routes, verb)
	if unread {
		claim = fmt.Sprintf("%s %s IPv4. The IPv6 firewall (ip6tables) could not be read, so nothing "+
			"confirms the same for IPv6.", routes, verb)
	}
	ep.Notes = nil
	ep.LeakRisk = false
	applyLeakVerdict(ep)
	ep.Notes = append(ep.Notes, fmt.Sprintf("The LAN also has IPv6: %s holds a routable address. %s "+
		"A device using IPv6 can reach its own resolver past the router DNS.", v6Iface, claim))
}

// routableIPv6Interfaces lists, in order, the interfaces holding an IPv6 address a LAN client could
// use to reach a public resolver, from `ip -o addr` output.
func routableIPv6Interfaces(out string) []string {
	var ifaces []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		for i := 2; i+1 < len(f); i++ {
			if f[i] != "inet6" {
				continue
			}
			addr := f[i+1]
			if j := strings.IndexByte(addr, '/'); j >= 0 {
				addr = addr[:j]
			}
			ip := net.ParseIP(addr)
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			iface := f[1]
			if j := strings.IndexByte(iface, '@'); j >= 0 {
				iface = iface[:j]
			}
			if iface != "lo" && !seen[iface] {
				seen[iface] = true
				ifaces = append(ifaces, iface)
			}
		}
	}
	return ifaces
}

// ipv6DefaultRouteInterfaces lists the interfaces an IPv6 default route leaves through, in any
// routing table: the uplinks, which no client sits behind. Empty when it cannot be read.
//
// Every table, not main alone: an uplink routed by policy keeps its default in a table of its own,
// and read from main it passed for a LAN, so a router with fw3's unbound zone rules was told that
// pppoe-wan left :53, DoT and DoH open over IPv6. iproute2 and BusyBox both take `table all` and print
// one route per line as `[type] default [from P] [via G] dev D [table T] ...`; a typed route
// (unreachable, blackhole) leads with its type and is not an uplink. A build that refuses `table all`
// is read from main, as before.
func ipv6DefaultRouteInterfaces(run Runner) map[string]bool {
	out, err := run("ip", "-6", "route", "show", "table", "all", "default")
	if err != nil && strings.TrimSpace(out) == "" {
		out, _ = run("ip", "-6", "route", "show", "default")
	}
	devs := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "dev" {
				devs[f[i+1]] = true
			}
		}
	}
	return devs
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// applyLeakVerdict turns Hijack53 + DoHBypassBlocked into the leak verdict and its notes.
//
// A client can leak when the router does NOT force LAN :53 through itself AND does not block DoT —
// nothing constrains where DNS goes. Even with a :53 hijack an unblocked :853/DoH path is still an
// escape hatch, so that is flagged too.
//
// Split out because the firewall may be read TWICE: once through iptables and, when that binary is
// absent, again through nft. The second read has to recompute the verdict from scratch, or the
// notes would still describe the empty first attempt.
func applyLeakVerdict(ep *EffectivePath) {
	// Three ways out, and the verdict may only be cleared when all three are shut. The DoH case is
	// the one that used to be inferred rather than measured: a :853 rule says nothing about a client
	// resolving over ordinary HTTPS, so "no leak risk" was printed for routers where every browser
	// with its own DoH resolver walked straight past the router's DNS.
	switch {
	case !ep.Hijack53 && !ep.DoTBypassBlocked && !ep.DoHBypassBlocked:
		ep.LeakRisk = true
		ep.Notes = append(ep.Notes, "LAN DNS is not forced through the router (no :53 redirect) and neither DoT nor DoH is blocked — clients can use any resolver, bypassing routing/leak protection.")
	case !ep.Hijack53:
		ep.LeakRisk = true
		ep.Notes = append(ep.Notes, "Encrypted DNS is constrained but plain :53 is not force-redirected — clients pointed at a public plain resolver bypass the router DNS.")
	case !ep.DoTBypassBlocked && !ep.DoHBypassBlocked:
		ep.LeakRisk = true
		ep.Notes = append(ep.Notes, "LAN :53 is redirected to the router, but neither DoT (:853) nor DoH (:443 to a resolver list) is constrained — a client using its own encrypted resolver still bypasses the router DNS.")
	case !ep.DoHBypassBlocked:
		ep.LeakRisk = true
		ep.Notes = append(ep.Notes, "LAN :53 is redirected and DoT (:853) is handled, but DoH is not constrained — DoH rides ordinary HTTPS, so blocking it means restricting :443 to a list of known resolver addresses. Until that exists, any client with its own DoH resolver bypasses the router DNS.")
	case !ep.DoTBypassBlocked:
		ep.LeakRisk = true
		ep.Notes = append(ep.Notes, "LAN :53 is redirected and DoH resolvers are restricted, but nothing handles DoT on :853 — a client configured for DoT still bypasses the router DNS.")
	case len(ep.IPv6Gaps) > 0:
		// checkIPv6 adds the note on what IPv6 leaves open.
		ep.Notes = append(ep.Notes, "Over IPv4, LAN :53 is redirected to the router, DoT is refused on :853, and DoH is refused at the well-known resolver addresses.")
	default:
		// Not "all three routes are constrained": the DoH refusal names addresses, and a resolver
		// outside the list is ordinary HTTPS to the router. The verdict still clears, because that
		// is as far as a router can shut DoH, but the note must not claim more than that.
		ep.Notes = append(ep.Notes, "LAN :53 redirected to the router, DoT refused on :853, and DoH refused at the well-known resolver addresses. A DoH resolver outside that list looks like any other HTTPS and is not refused.")
	}
	if len(ep.IPv6Gaps) > 0 {
		ep.LeakRisk = true
	}
}

// rulesUnreadable reports that neither firewall read produced anything usable. A command that
// errored AND printed nothing told us nothing; one that printed rules told us something even if it
// also errored, and an empty ruleset read cleanly is a real (empty) ruleset.
func rulesUnreadable(natOut string, natErr error, filterOut string, filterErr error) bool {
	usable := func(out string, err error) bool {
		return err == nil || strings.TrimSpace(out) != ""
	}
	return !usable(natOut, natErr) && !usable(filterOut, filterErr)
}

// markRulesUnknown replaces the derived firewall findings with an honest "not measured". LeakRisk is
// deliberately LEFT set: erring toward flagging a risk is right when nothing is known. The note now
// separates which half of that is a measurement and which is an assumption.
func markRulesUnknown(ep *EffectivePath) {
	ep.RulesUnknown = true
	ep.LeakRisk = true
	ep.Notes = append([]string{
		"Could not read this router's firewall rules, so whether LAN :53 is redirected and whether " +
			"DoT/DoH is blocked are both UNKNOWN — not confirmed absent. Treated as a leak risk " +
			"because nothing here could be verified.",
	}, ep.Notes...)
}

// parseOwnAddrs pulls addresses out of `ip -o addr` output ("2: br-lan inet 192.168.50.1/24 ...").
// Best-effort: unparseable lines contribute nothing.
func parseOwnAddrs(out string) []string {
	var addrs []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" || f[i] == "inet6" {
				addrs = append(addrs, f[i+1])
			}
		}
	}
	return addrs
}
