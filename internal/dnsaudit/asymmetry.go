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

// hasAny reports whether a matcher field holds a real entry; blank entries match nothing.
func hasAny(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func isEncryptedDNS(serverType string) bool {
	switch strings.ToLower(strings.TrimSpace(serverType)) {
	case "https", "tls", "quic", "h3":
		return true
	default:
		return false
	}
}

// Plane is the part of the generated core the audit has to know to read the DNS plane as it will run.
type Plane struct {
	// TUN is true when the core is generated with its TUN inbound. Only that plane keeps fakeip
	// servers; without it the generator drops them and every rule that targets them, so those
	// lookups fall through to the next matching rule or the default resolver.
	TUN bool
}

// DetectAsymmetric reports routing lists whose traffic egress and DNS egress disagree.
//
// Pure over the profile, so it can run before Apply rather than being inferred afterwards from a
// packet capture.
func DetectAsymmetric(p model.Profile, plane Plane) []Asymmetry {
	if p.DNS == nil || !p.DNS.Enabled {
		return nil // no DNS plane of our own: nothing to be inconsistent with
	}

	type resolver struct {
		tag, detour string
		encrypted   bool
		// noLookup: no query leaves the router, so there is no lookup to disagree with the traffic.
		// A fakeip server hands out an address from its pool and the name is resolved at the exit
		// the traffic takes; read as a resolver it had no detour ("direct") and no encryption, and
		// the catalog's FakeIP preset was refused as a plaintext leak (QA-106). A reject rule
		// answers with a refusal.
		noLookup bool
	}
	resolverOf := map[string]resolver{}
	droppedFakeIP := map[string]bool{}
	for _, sv := range p.DNS.Servers {
		if !sv.Enabled {
			continue
		}
		if sv.Type == "fakeip" && !plane.TUN {
			droppedFakeIP[sv.Tag] = true
			continue // dropped by the generator with its rules: they fall through, as they will run
		}
		if model.IsVPNDNSType(sv.Type) {
			// A VPN's pushed resolvers are reached through that connection's tunnel and nowhere else
			// (sing-box dials them through the endpoint; with the VPN down they answer NXDOMAIN rather
			// than fall back to the WAN), so the connection IS the exit the lookup leaves through, as a
			// detour is for any other server. The WAN sees only the tunnel; the query itself is
			// usually plain DNS from the VPN server on, which is not end-to-end encryption, so it is
			// not counted as encrypted - and since its exit is never direct, it is never "exposed".
			resolverOf[sv.Tag] = resolver{tag: sv.Tag, detour: strings.TrimSpace(sv.Endpoint)}
			continue
		}
		resolverOf[sv.Tag] = resolver{
			tag: sv.Tag, detour: sv.Detour, encrypted: isEncryptedDNS(sv.Type), noLookup: sv.Type == "fakeip",
		}
	}

	// Which DNS server resolves each routing list, via the shared rule-set IDs.
	byList := map[string]resolver{}
	// The FakeIP server a list's rule named before anything claimed the list, when the generator
	// drops that server and the rule with it. The DNS page still shows the rule, so a finding that
	// said "no DNS rule covers this list" contradicted the page; it names the rule and why it is gone.
	fakeIPRule := map[string]string{}
	for _, r := range p.DNS.Rules {
		if r.Disabled || r.Server == "" {
			continue
		}
		var res resolver
		if strings.EqualFold(r.Server, "reject") {
			// A rejected domain is never resolved. A reject rule that matches on the lists therefore
			// answers every lookup for them, and must claim them like any first-matching rule:
			// skipped, it let the lists "fall through" to the default resolver, which they never
			// reach. Only a matcher ANDed with the lists narrows the rule and leaves the rest of their
			// lookups to later rules. query_type is (sing-box keeps it with the rule's own items), and
			// so is geosite, which the generator wraps with the lists in a logical AND. domain and
			// domain_suffix are not: sing-box 1.12 ORs them with the rule_set's own domain matches
			// (route/rule/rule_abstract.go), so {lists, domain_suffix} rejects every name in the
			// lists plus that suffix, and claims the lists.
			if hasAny(r.QueryType) || hasAny(r.GeoSite) {
				continue
			}
			res = resolver{tag: "reject", noLookup: true}
		} else {
			known := false
			if res, known = resolverOf[r.Server]; !known {
				if droppedFakeIP[r.Server] {
					for _, id := range r.RuleSets {
						if _, seen := byList[id]; !seen && fakeIPRule[id] == "" {
							fakeIPRule[id] = r.Server
						}
					}
				}
				continue // dangling or dropped server: validation's or the generator's, not this check's
			}
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
			// No DNS rule for this list: queries follow the default resolver, which is a deliberate
			// choice rather than a mismatch. Only report it when the traffic IS tunnelled and the
			// default is not, because that is the same exposure by another route. The default is
			// the server sing-box will actually use, which with no `final` is the first one emitted:
			// skipping an empty final let a plaintext `local` first server answer tunnel lists with
			// no finding at all (QA-105).
			if isDirect(rl.Outbound) {
				continue
			}
			def := p.DNS.DefaultServer(plane.TUN)
			if def == nil {
				continue
			}
			finalResolver, known := resolverOf[def.Tag]
			if !known || finalResolver.noLookup || !isDirect(finalResolver.detour) {
				continue
			}
			// Who answers, as a noun phrase: the sentence below says once that it resolves directly.
			which := fmt.Sprintf("the default server %q", def.Tag)
			switch {
			case p.DNS.Final == "":
				which = fmt.Sprintf("the first server %q (no default is chosen)", def.Tag)
			case def.Tag != p.DNS.Final:
				// The generator leaves out a final that names a server it drops: a fakeip one without
				// TUN (validation refuses a disabled one).
				which = fmt.Sprintf("the first server %q (the default %q is FakeIP, left out because "+
					"FakeIP needs TUN)", def.Tag, p.DNS.Final)
			}
			why := "no DNS rule covers this list"
			if fake := fakeIPRule[rl.ID]; fake != "" {
				why = fmt.Sprintf("its DNS rule sends it to the FakeIP server %q, and FakeIP needs TUN: in "+
					"fast or mixed mode that rule is left out", fake)
			}
			detail := fmt.Sprintf("traffic for %q goes through %q, but %s, so its lookups fall through to %s "+
				"and are resolved directly", rl.Name, rl.Outbound, why, which)
			if finalResolver.encrypted {
				detail += "; the query stays encrypted on the WAN, but the resolver sees it from the WAN address instead of the tunnel exit"
			} else {
				detail += "; the lookup names the destination before the traffic enters the tunnel"
			}
			out = append(out, Asymmetry{
				RoutingListID: rl.ID, ListName: rl.Name,
				TrafficVia: rl.Outbound, DNSVia: "direct", DNSServerTag: def.Tag,
				Exposed: true, Encrypted: finalResolver.encrypted, Detail: detail,
			})
			continue
		}
		if res.noLookup || res.detour == rl.Outbound || (isDirect(res.detour) && isDirect(rl.Outbound)) {
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
