// Package dnsaudit checks that a profile's DNS plane and its traffic plane agree about where a
// domain should go.
package dnsaudit

import (
	"fmt"
	"strings"

	"wayhop/internal/model"
)

// Asymmetry is one routing list whose traffic and DNS take different paths.
//
// The model already states the intent — DNS rules reuse RoutingList IDs "so DNS routing and traffic
// routing stay coherent: a domain routed to a tunnel resolves via that tunnel's server". Nothing
// enforced it, and the two planes are edited independently, so they drift apart silently.
//
// It matters because the DNS query is the part that names the destination in plain sight. Route a
// domain's traffic through a tunnel while its DNS still goes out direct, and the tunnel hides the
// traffic while the lookup announces exactly where you were going — to the ISP, to the resolver, and
// to anyone watching the WAN. Nothing in the UI looks wrong: the traffic really is tunnelled.
type Asymmetry struct {
	RoutingListID string `json:"routing_list_id"`
	ListName      string `json:"list_name,omitempty"`
	TrafficVia    string `json:"traffic_via"` // outbound the matched traffic uses
	DNSVia        string `json:"dns_via"`     // outbound the resolving DNS server detours through
	DNSServerTag  string `json:"dns_server_tag,omitempty"`
	Exposed       bool   `json:"exposed"`   // the resolver sees a lookup from a different exit than the traffic
	Encrypted     bool   `json:"encrypted"` // query contents are protected on the path to the resolver
	Detail        string `json:"detail"`
}

// directTags are the outbound values that mean "no tunnel".
func isDirect(outbound string) bool {
	s := strings.TrimSpace(outbound)
	return s == "" || strings.EqualFold(s, "direct")
}

func isEncryptedDNS(serverType string) bool {
	switch strings.ToLower(strings.TrimSpace(serverType)) {
	case "https", "tls", "quic", "h3":
		return true
	default:
		return false
	}
}

// DetectAsymmetric reports routing lists whose traffic egress and DNS egress disagree.
//
// Pure over the profile, so it can run before Apply rather than being inferred afterwards from a
// packet capture.
func DetectAsymmetric(p model.Profile) []Asymmetry {
	if p.DNS == nil || !p.DNS.Enabled {
		return nil // no DNS plane of our own: nothing to be inconsistent with
	}

	type resolver struct {
		tag, detour string
		encrypted   bool
	}
	resolverOf := map[string]resolver{}
	for _, sv := range p.DNS.Servers {
		if sv.Enabled {
			resolverOf[sv.Tag] = resolver{
				tag: sv.Tag, detour: sv.Detour, encrypted: isEncryptedDNS(sv.Type),
			}
		}
	}

	// Which DNS server resolves each routing list, via the shared rule-set IDs.
	byList := map[string]resolver{}
	for _, r := range p.DNS.Rules {
		if r.Disabled || r.Server == "" || strings.EqualFold(r.Server, "reject") {
			continue // a rejected domain is never resolved, so it cannot be asymmetric
		}
		res, known := resolverOf[r.Server]
		if !known {
			continue // dangling server reference: validation's problem, not this check's
		}
		for _, id := range r.RuleSets {
			if _, seen := byList[id]; !seen { // first matching rule wins, as in sing-box
				byList[id] = res
			}
		}
	}

	var out []Asymmetry
	for _, rl := range p.RoutingLists {
		if !rl.Enabled || strings.EqualFold(rl.Outbound, "block") {
			continue
		}
		res, covered := byList[rl.ID]
		if !covered {
			// No DNS rule for this list: queries follow `final`, which is a deliberate default rather
			// than a mismatch. Only report it when the traffic IS tunnelled and the default is not,
			// because that is the same exposure by another route.
			if isDirect(rl.Outbound) || p.DNS.Final == "" {
				continue
			}
			finalResolver, known := resolverOf[p.DNS.Final]
			if !known || !isDirect(finalResolver.detour) {
				continue
			}
			detail := fmt.Sprintf("traffic for %q goes through %q, but no DNS rule covers this list "+
				"so its lookups fall through to the default server %q, which resolves directly",
				rl.Name, rl.Outbound, p.DNS.Final)
			if finalResolver.encrypted {
				detail += "; the query stays encrypted on the WAN, but the resolver sees it from the WAN address instead of the tunnel exit"
			} else {
				detail += "; the lookup names the destination before the traffic enters the tunnel"
			}
			out = append(out, Asymmetry{
				RoutingListID: rl.ID, ListName: rl.Name,
				TrafficVia: rl.Outbound, DNSVia: "direct", DNSServerTag: p.DNS.Final,
				Exposed: true, Encrypted: finalResolver.encrypted, Detail: detail,
			})
			continue
		}
		if res.detour == rl.Outbound || (isDirect(res.detour) && isDirect(rl.Outbound)) {
			continue // coherent
		}

		a := Asymmetry{
			RoutingListID: rl.ID, ListName: rl.Name,
			TrafficVia: rl.Outbound, DNSVia: res.detour, DNSServerTag: res.tag, Encrypted: res.encrypted,
		}
		switch {
		case isDirect(res.detour):
			// The resolver sees a different source exit than the traffic. Encrypted transports protect
			// the query on the WAN path; plaintext transports expose it to that path as well.
			a.Exposed = true
			if res.encrypted {
				a.Detail = fmt.Sprintf("traffic for %q goes through %q, but its encrypted DNS lookup goes directly via %q; "+
					"the WAN path cannot read the query, while the resolver sees it from the WAN address instead of the tunnel exit",
					rl.Name, rl.Outbound, res.tag)
			} else {
				a.Detail = fmt.Sprintf("traffic for %q goes through %q, but its DNS lookup goes DIRECT via "+
					"%q; the name is asked for before anything enters the tunnel, so whoever answers that "+
					"lookup and anyone on the path to it learns the destination the tunnel then hides",
					rl.Name, rl.Outbound, res.tag)
			}
		case isDirect(rl.Outbound):
			a.Detail = fmt.Sprintf("DNS for %q resolves through %q while the traffic goes direct; the "+
				"answer may be tied to the tunnel's exit and not reachable (or not optimal) from here",
				rl.Name, res.detour)
		default:
			a.Detail = fmt.Sprintf("DNS for %q resolves through %q but the traffic goes through %q; a "+
				"geo-targeted answer from one exit may not match the other",
				rl.Name, res.detour, rl.Outbound)
		}
		out = append(out, a)
	}
	return out
}
