package nativedns

import (
	"regexp"
	"strings"
)

// Reading the firewall through nftables, for routers that have no iptables binary.
//
// The effective-path detector derived Hijack53 and DoHBypassBlocked from `iptables -S` alone. On a
// modern OpenWrt running fw4 there may be no iptables at all — the test AX3000T is exactly that —
// so every probe came back empty and the detector reported the redirect as absent. AUD-43 made that
// honest (it now says the firewall could not be read); this makes it unnecessary in the common case.
//
// Parsing `nft list ruleset` is not the same job as scanning `iptables -t nat -S`. That command
// prints ONLY the nat table, so any matching line is by definition a nat rule. nft prints
// everything — filter, nat, mangle, every table — so a `dport 53` line means nothing until you know
// which chain it sits in. This tracks the chain and its hook, and only counts a redirect that is
// actually in a nat prerouting chain.

var (
	// `chain dstnat {` / `chain prerouting {`
	reNftChain = regexp.MustCompile(`^\s*chain\s+(\S+)\s*\{`)
	// `type nat hook prerouting priority dstnat; policy accept;`
	reNftHook = regexp.MustCompile(`type\s+(\w+)\s+hook\s+(\w+)`)
	// `udp dport 53`, `tcp dport { 53, 5353 }`, `dport 53-54` — the port may be a set or a range.
	reNftDport53  = regexp.MustCompile(`\bdport\s+(?:\{[^}]*\b53\b[^}]*\}|53\b)`)
	reNftDport853 = regexp.MustCompile(`\bdport\s+(?:\{[^}]*\b853\b[^}]*\}|853\b)`)
	// `redirect to :41100`, `redirect to 41100`
	reNftRedirect = regexp.MustCompile(`\bredirect\s+to\s+:?(\S+?)\b`)
	// `dnat to 192.168.50.1:5353`, `dnat ip to 10.0.0.1:53`
	reNftDnat = regexp.MustCompile(`\bdnat\s+(?:ip6?\s+)?to\s+(\S+)`)
	// A rule that stops traffic rather than steering it.
	//
	// The jump form is how fw4 actually writes a reject: the rule reads `tcp dport 853 counter jump
	// handle_reject`, and `\breject\b` does not match inside `handle_reject` because the underscore
	// is a word character. Measured on the test AX3000T, where every :853 rule the https-dns-proxy
	// package installs takes that shape — so DoT handling went undetected on the router family this
	// matters most for. That erred safe, which is why it survived; it still made the page say DoT was
	// unhandled on a router that rejects it.
	reNftDrop = regexp.MustCompile(`\b(drop|reject)\b|\bjump\s+handle_(reject|drop)\b`)

	// :443, including the `dport { 443, 853 }` set form fw4 and hand-written tables both use.
	reNftDport443 = regexp.MustCompile(`\bdport\s+(?:\{[^}]*\b443\b[^}]*\}|443\b)`)
	// A destination RESTRICTION: an address set (`ip daddr @doh_v4`) or a literal address. DoH rides
	// ordinary HTTPS, so the port alone says nothing — the only way to constrain it without breaking
	// the web is to name the resolvers. Requiring the restriction is also what keeps an unrelated
	// blanket :443 rule out: the test AX3000T rejects `udp dport 443` from the LAN to force TCP for
	// QUIC, which has nothing to do with DNS and would otherwise read as DoH blocking.
	reNftDaddrSet = regexp.MustCompile(`\bip6?\s+daddr\s+(?:@\S+|[0-9a-fA-F:.]+(?:/\d+)?)`)
)

// NftFindings is what a ruleset dump established about the DNS path.
type NftFindings struct {
	Hijack53   bool   // a nat prerouting rule forces LAN :53 somewhere local
	Hijack53To string // where it sends it (port or host:port), when the rule says
	DoTHandled bool   // some rule drops, rejects or redirects :853
	// DoHHandled reports a rule that constrains :443 TO NAMED DESTINATIONS — the resolver set form.
	// It is separate from DoTHandled because the two are different escape hatches and only one of
	// them is closable by port. A ruleset that rejects :853 says nothing about a client resolving
	// over ordinary HTTPS, and the https-dns-proxy package adds those :853 rules on every OpenWrt
	// that installs it, so treating them as DoH handling would clear the leak verdict by default.
	DoHHandled bool
	Parsed     bool // the dump looked like an nft ruleset at all
}

// reNftJump matches `jump <chain>` / `goto <chain>` — how fw4 reaches its per-zone rules.
var reNftJump = regexp.MustCompile(`\b(?:jump|goto)\s+([A-Za-z0-9_.-]+)`)

// nftChain is one parsed chain: what hooks it (if anything), what it jumps to, and its rules.
type nftChain struct {
	kind  string // nat | filter | route | "" when the chain is a regular one
	hook  string // prerouting | output | … ; "" for a regular chain
	jumps []string
	rules []string
}

// DetectFromNft reads `nft list ruleset` output.
//
// Parsed reports whether the input was recognisably a ruleset — an empty string, an error message
// or the output of a different command must not be read as "no rules exist", which is the same
// absence-as-evidence mistake the rest of this file exists to avoid.
//
// Reachability, not membership. The first version of this asked whether a :53 redirect sat IN a
// chain hooked to nat prerouting, which is not how fw4 is built: the base `dstnat` chain holds only
// `iifname "br-lan" jump dstnat_lan`, and the redirect lives in `dstnat_lan`, a regular chain with
// no hook of its own. On the test AX3000T that made the detector report hijack53=false while 309,402
// UDP packets had gone through that exact rule, and the DNS page told the user their clients could
// bypass the router's DNS — the precise opposite of what the firewall was doing. Every fixture had
// agreed with it, because every fixture shared the same wrong model of fw4.
//
// So the ruleset is parsed into chains first, the set reachable from a nat/prerouting base chain is
// computed by following jump and goto, and only then are the rules in that set examined. Following
// jumps from ANY chain would be the opposite error: a redirect reached only from the OUTPUT hook is
// the router redirecting its own traffic, not forcing the LAN through itself.
func DetectFromNft(ruleset string) NftFindings {
	var f NftFindings
	if !strings.Contains(ruleset, "table ") && !strings.Contains(ruleset, "chain ") {
		return f
	}
	f.Parsed = true

	chains := map[string]*nftChain{}
	var cur *nftChain

	for _, raw := range strings.Split(ruleset, "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" {
			continue
		}
		if m := reNftChain.FindStringSubmatch(raw); m != nil {
			c := &nftChain{}
			chains[m[1]] = c
			cur = c
			continue
		}
		if strings.HasPrefix(ln, "}") {
			cur = nil
			continue
		}
		if cur == nil {
			continue
		}
		if m := reNftHook.FindStringSubmatch(ln); m != nil {
			cur.kind, cur.hook = m[1], m[2]
			continue
		}
		if m := reNftJump.FindStringSubmatch(ln); m != nil {
			cur.jumps = append(cur.jumps, m[1])
		}
		cur.rules = append(cur.rules, ln)

		// DoT handling is chain-agnostic: dropping :853 in an input or forward chain counts, and so
		// does redirecting it in nat. Anything that touches the port is the router taking a position.
		if reNftDport853.MatchString(ln) &&
			(reNftDrop.MatchString(ln) || reNftRedirect.MatchString(ln) || reNftDnat.MatchString(ln)) {
			f.DoTHandled = true
		}
		// The destination restriction is required, not incidental: without it every blanket :443
		// rule on the box would read as DoH blocking.
		if reNftDport443.MatchString(ln) && reNftDaddrSet.MatchString(ln) &&
			(reNftDrop.MatchString(ln) || reNftRedirect.MatchString(ln) || reNftDnat.MatchString(ln)) {
			f.DoHHandled = true
		}
	}

	// Walk out from every base chain that hooks nat prerouting. The name fallback stays for dumps
	// that omit the hook declaration, but it is now only a seed — the jump graph does the rest.
	reach := map[string]bool{}
	var walk func(string, int)
	walk = func(name string, depth int) {
		if depth > 16 || reach[name] { // depth cap: a ruleset may contain a jump cycle
			return
		}
		c := chains[name]
		if c == nil {
			return
		}
		reach[name] = true
		for _, j := range c.jumps {
			walk(j, depth+1)
		}
	}
	for name, c := range chains {
		seed := (c.kind == "nat" && c.hook == "prerouting") ||
			(c.kind == "" && (name == "dstnat" || name == "prerouting"))
		if seed {
			walk(name, 0)
		}
	}

	for name := range reach {
		for _, ln := range chains[name].rules {
			if !reNftDport53.MatchString(ln) {
				continue
			}
			if m := reNftRedirect.FindStringSubmatch(ln); m != nil {
				f.Hijack53 = true
				if f.Hijack53To == "" {
					f.Hijack53To = strings.TrimPrefix(m[1], ":")
				}
				continue
			}
			if m := reNftDnat.FindStringSubmatch(ln); m != nil {
				f.Hijack53 = true
				if f.Hijack53To == "" {
					f.Hijack53To = m[1]
				}
			}
		}
	}
	return f
}
