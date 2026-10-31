package keenetic

import (
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// Policy is one KeeneticOS access policy as `show ip policy` reports it: the name NDM addresses it
// by, the operator's description, and the firewall mark and IPv4 routing table NDM routes it with.
//
// Measured on a live Keenetic: NDM installs `fwmark <mark> lookup <table>` followed by
// `fwmark <mark> lookup unspec blackhole` at priorities 100-109, ahead of everything else, and keeps
// the table's default on the first live connection the policy permits. A packet carrying the exact
// mark is therefore routed by NDM's own failover, fail-back and kill switch.
type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Mark        uint32 `json:"mark"`
	Table       int    `json:"table,omitempty"`
}

// ParsePolicies reads the access policies out of `ndmc -c "show ip policy"`. The shape, from a live
// router (route listings elided):
//
//	policy, name = Policy0, description = Bypass:
//	      mark: ffffaaa
//	    table4: 4096
//	    route4: …
//	    table6: 4096
//	policy, name = Policy1, description = Freedom:
//	      mark: ffffaab
//	    table4: 4098
//
// The mark is bare hex. Only a policy with a non-zero mark and a name WayHop can address is returned:
// the mark is the whole point (a zero one would clear every mark it was meant to set), and a name
// that fails model.ValidNDMPolicyName could never be selected. The first occurrence of a name wins.
// A policy's own keys precede its route listings, so nothing read after a `route…:` line counts and
// no route entry can be mistaken for the policy's mark or table. Pure, no device I/O.
func ParsePolicies(out string) []Policy {
	var policies []Policy
	seen := map[string]bool{}
	var cur *Policy
	haveMark, haveTable, listing := false, false, false
	flush := func() {
		if cur != nil && haveMark && cur.Mark != 0 && !seen[cur.Name] {
			seen[cur.Name] = true
			policies = append(policies, *cur)
		}
		cur, haveMark, haveTable, listing = nil, false, false, false
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "policy, name = "); ok {
			flush()
			// The header ends in ':' - it opens the policy's block. A description is optional.
			rest = strings.TrimSuffix(rest, ":")
			name, desc, _ := strings.Cut(rest, ", description = ")
			name = strings.TrimSpace(name)
			if !model.ValidNDMPolicyName(name) {
				continue
			}
			cur = &Policy{Name: name, Description: strings.TrimSpace(desc)}
			continue
		}
		if cur == nil || listing {
			continue
		}
		if strings.HasPrefix(t, "route") {
			listing = true
			continue
		}
		if v, ok := strings.CutPrefix(t, "mark: "); ok && !haveMark {
			haveMark = true
			if m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 32); err == nil {
				cur.Mark = uint32(m)
			}
			continue
		}
		if v, ok := strings.CutPrefix(t, "table4: "); ok && !haveTable {
			haveTable = true
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				cur.Table = n
			}
		}
	}
	flush()
	return policies
}

// PolicyMarks is the name → mark view of policies the routing planes are compiled with.
func PolicyMarks(policies []Policy) map[string]uint32 {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]uint32, len(policies))
	for _, p := range policies {
		out[p.Name] = p.Mark
	}
	return out
}
