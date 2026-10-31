package model

import (
	"sort"
	"strings"
)

// NDMPolicyPrefix marks a routing list's outbound as one of the KeeneticOS router's own access
// policies ("ndm-policy:Policy1") instead of an endpoint or group of this profile.
//
// An access policy is NDM's own routing object: a firewall mark, a routing table holding the default
// of the first live connection the policy permits, and a blackhole behind it. Measured on a live
// Keenetic: Policy1 is mark 0xffffaab with `fwmark 0xffffaab lookup 4098` followed by
// `fwmark 0xffffaab lookup unspec blackhole`, so NDM fails over, fails back and drops by itself when
// nothing it permits is up. Pointing a list at one hands those decisions to the router rather than
// re-implementing them.
//
// Only the NAME is stored. The mark and table are NDM's numbering, which it may change when policies
// are added or removed, so they are read from the router at every Apply and never kept as truth here.
const NDMPolicyPrefix = "ndm-policy:"

// NDMPolicyName returns the NDM access policy a routing outbound names, and whether it names one.
func NDMPolicyName(outbound string) (string, bool) {
	return strings.CutPrefix(outbound, NDMPolicyPrefix)
}

// ValidNDMPolicyName reports whether name has the shape of an NDM policy name: letters, digits, '_'
// and '-'. NDM names its own "Policy0", "Policy1", …; the bound is about what can safely travel in a
// tag and a log line, not about which names exist - that is a property of the router, checked by the
// host-aware review.
func ValidNDMPolicyName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// NDMPoliciesInUse lists, sorted and once each, the access policies the enabled routing lists of p
// point at. Empty when none does, which is what lets a router whose profile uses no policy skip
// reading them altogether.
func NDMPoliciesInUse(p *Profile) []string {
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		if name, ok := NDMPolicyName(rl.Outbound); ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
