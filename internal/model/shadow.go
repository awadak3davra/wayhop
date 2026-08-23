package model

import (
	"sort"
	"strconv"
	"strings"
)

// Rule order is semantic: sing-box evaluates routing and DNS rules top-down and the FIRST match
// wins, and the generator emits them in array order. A rule whose match criteria are already fully
// covered by an earlier enabled rule therefore never fires — it is dead configuration that reads
// like working configuration, which is the failure this package exists to prevent elsewhere too.
//
// The detection here is deliberately narrow: it reports a rule only when an earlier enabled rule
// has an IDENTICAL match specification. That is provably unreachable, so there are no false
// positives. Genuine subset-shadowing (an earlier `*.example.com` swallowing a later
// `mail.example.com`) needs per-matcher containment reasoning across domains, CIDRs, geo sets and
// remote rule-sets whose contents are not known locally; claiming it without that reasoning would
// produce warnings the user cannot trust, and an unreliable warning is worse than none.

// Shadowed reports one dead rule: the rule at Index is unreachable because the rule at ShadowedBy
// already matches everything it matches.
type Shadowed struct {
	Index      int    // position of the dead rule
	ID         string // its id, for addressing it in the UI
	ShadowedBy int    // position of the earlier rule that always wins
	ByID       string
	Match      string // the shared match specification, for the message
}

// ShadowedRules returns the routing rules that can never match, in order.
// Disabled rules neither shadow nor are reported, and the default (catch-all) rule is excluded:
// it is meant to be last-resort and matches everything by design.
func ShadowedRules(rules []Rule) []Shadowed {
	var out []Shadowed
	seen := map[string]int{} // match key -> index of the first enabled rule carrying it
	for i := range rules {
		r := &rules[i]
		if r.Disabled || r.Default {
			continue
		}
		key := routeMatchKey(r)
		if key == "" {
			continue // matches nothing in particular; not a shadowing question
		}
		if j, ok := seen[key]; ok {
			out = append(out, Shadowed{Index: i, ID: r.ID, ShadowedBy: j, ByID: rules[j].ID, Match: key})
			continue
		}
		seen[key] = i
	}
	return out
}

// ShadowedDNSRules is the same analysis for the DNS plane.
func ShadowedDNSRules(rules []DNSRule) []Shadowed {
	var out []Shadowed
	seen := map[string]int{}
	for i := range rules {
		r := &rules[i]
		if r.Disabled {
			continue
		}
		key := dnsMatchKey(r)
		if key == "" {
			continue
		}
		if j, ok := seen[key]; ok {
			out = append(out, Shadowed{Index: i, ID: r.ID, ShadowedBy: j, ByID: rules[j].ID, Match: key})
			continue
		}
		seen[key] = i
	}
	return out
}

// routeMatchKey canonicalises everything a routing rule matches ON — never what it does. Two rules
// with the same key are interchangeable as far as matching goes, so whichever comes first always wins
// even when they point at different outbounds (which is exactly the case worth reporting).
func routeMatchKey(r *Rule) string {
	parts := []string{
		field("domain", r.Domain),
		field("suffix", r.DomainSuffix),
		field("geosite", r.GeoSite),
		field("geoip", r.GeoIP),
		field("ip", r.IPCIDR),
		field("port", ints(r.Port)),
		field("src_ip", r.SourceIPCIDR),
		field("src_mac", r.SourceMAC),
		field("src_iface", r.SourceIface),
		field("src_port", ints(r.SourcePort)),
	}
	return joinNonEmpty(parts)
}

func dnsMatchKey(r *DNSRule) string {
	parts := []string{
		field("rule_set", r.RuleSets),
		field("domain", r.Domain),
		field("suffix", r.DomainSuffix),
		field("geosite", r.GeoSite),
		field("qtype", r.QueryType),
	}
	return joinNonEmpty(parts)
}

// field renders one matcher as a canonical, order-independent string. Entries within a matcher are
// OR'd by sing-box, so [a b] and [b a] are the same set and must produce the same key; duplicates
// inside one matcher are likewise irrelevant to what it matches.
func field(name string, vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	uniq := make([]string, 0, len(vals))
	seen := map[string]bool{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		uniq = append(uniq, v)
	}
	if len(uniq) == 0 {
		return ""
	}
	sort.Strings(uniq)
	return name + "=" + strings.Join(uniq, ",")
}

func ints(v []int) []string {
	if len(v) == 0 {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, n := range v {
		out = append(out, strconv.Itoa(n))
	}
	return out
}

func joinNonEmpty(parts []string) string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}
