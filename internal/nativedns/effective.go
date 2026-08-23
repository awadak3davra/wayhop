package nativedns

import (
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
	Listeners  []DNSListener `json:"listeners,omitempty"`   // who serves DNS on :53
	Upstreams  []string      `json:"upstreams,omitempty"`   // router's own resolv.conf nameservers
	Hijack53   bool          `json:"hijack53"`              // a nat REDIRECT/DNAT forces LAN :53 to a local resolver
	Hijack53To string        `json:"hijack53_to,omitempty"` // the port/target the :53 redirect sends to
	// The two encrypted escape hatches, reported separately because only one of them is closable by
	// port number. A rule on :853 stops DoT. DoH rides ordinary HTTPS on :443, so constraining it
	// means naming the resolvers (an address set); a port rule cannot do it without breaking the web.
	//
	// These were one field, set from the :853 signal alone and named for DoH. On the test AX3000T
	// that produced "plain and DoT bypass are both constrained" with LeakRisk cleared — correct there
	// only by luck, because that box also carries a resolver-set block the detector never read. The
	// :853 rules themselves come from the https-dns-proxy package, which every OpenWrt running it
	// installs, so the same verdict would have been printed on any such router with no DoH blocking
	// at all: a client using its own DoH resolver bypasses the router entirely and the page said
	// there was no leak risk.
	DoTBypassBlocked bool      `json:"dot_bypass_blocked"` // a rule blocks/redirects :853
	DoHBypassBlocked bool      `json:"doh_bypass_blocked"` // a rule constrains :443 to named resolver addresses
	LeakRisk         bool      `json:"leak_risk"`          // true when clients can bypass the router DNS unhindered
	Loops            []DNSLoop `json:"loops,omitempty"`    // upstreams that resolve back into this router's own DNS path
	Notes            []string  `json:"notes,omitempty"`    // human-readable findings for the diagnostics view

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
)

// DetectEffectivePath parses captured device text into an EffectivePath. All inputs are best-effort:
// an empty string for any source simply contributes nothing (a non-router host yields a near-empty,
// low-signal result rather than an error). resolvConf is /etc/resolv.conf; listeners is
// `netstat -tulnp` (or ss) output; natRules is `iptables -t nat -S`; allRules is any firewall dump
// (nat + filter) scanned for a :853 bypass rule.
func DetectEffectivePath(resolvConf, listeners, natRules, allRules string) EffectivePath {
	var ep EffectivePath

	// 1) Router's own upstreams (nameserver lines).
	for _, ln := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) >= 2 && f[0] == "nameserver" {
			ep.Upstreams = append(ep.Upstreams, f[1])
		}
	}

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

	// 3) :53 hijack (a nat REDIRECT/DNAT on --dport 53) = LAN DNS forced to a local resolver.
	for _, ln := range strings.Split(natRules, "\n") {
		if !reDport53.MatchString(ln) {
			continue
		}
		up := strings.ToUpper(ln)
		if !strings.Contains(up, "REDIRECT") && !strings.Contains(up, "DNAT") {
			continue
		}
		ep.Hijack53 = true
		if m := reToPorts.FindStringSubmatch(ln); m != nil {
			ep.Hijack53To = m[1]
		} else if m := reToDestrgx.FindStringSubmatch(ln); m != nil {
			ep.Hijack53To = m[1]
		}
		break
	}

	// 4) Bypass handling, one signal each. A rule touching :853 manages DoT. DoH needs a rule that
	// names destinations, since the port is shared with the entire web.
	ep.DoTBypassBlocked = reDport853.MatchString(allRules)
	for _, ln := range strings.Split(allRules, "\n") {
		if reDport443.MatchString(ln) && reMatchSetOrDest.MatchString(ln) && reDropVerb.MatchString(ln) {
			ep.DoHBypassBlocked = true
			break
		}
	}

	// 5) Leak verdict + notes.
	applyLeakVerdict(&ep)

	// Loops detectable from captured state alone (loopback upstreams, and upstreams equal to an
	// address a listener is explicitly bound to). RunEffectivePath enriches this with the router's
	// full address list when it can read one.
	ep.Loops = DetectDNSLoops(ep.Listeners, ep.Upstreams, nil)

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
	// Ownership from the live address list when available: a listener bound to 0.0.0.0 proves the
	// router serves DNS but not WHICH addresses it owns, so without this an upstream pointing at
	// the router's own LAN IP would go unnoticed.
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
	}
	if own := parseOwnAddrs(addrs); len(own) > 0 {
		ep.Loops = DetectDNSLoops(ep.Listeners, ep.Upstreams, own)
	}
	return ep
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
	default:
		ep.Notes = append(ep.Notes, "LAN :53 redirected to the router, DoT handled on :853, and DoH restricted to known resolver addresses — all three bypass routes are constrained.")
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
