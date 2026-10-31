package generator

import (
	"fmt"

	"wayhop/internal/model"
)

// ndmPolicyOutbounds is one `direct` outbound per KeeneticOS access policy a routing list points at,
// tagged with the list's own outbound ("ndm-policy:Policy1") so the list's route rule needs no rewrite.
//
// Its sockets carry the policy's mark (`routing_mark`, SO_MARK on Linux), and NDM's rule for that mark
// sits ahead of everything else - measured on a live Keenetic, `fwmark 0xffffaab lookup 4098` at
// priority 102 with its blackhole at 103 - so what the core sends for the list is routed by the
// policy's own failover, fail-back and kill switch, exactly like the LAN traffic the kernel plane marks
// for the same list.
//
// A policy with no mark here is refused rather than emitted as a plain `direct`: that would send the
// list out of the WAN while the panel says it goes through the policy.
func ndmPolicyOutbounds(p *model.Profile, marks map[string]uint32) ([]map[string]any, error) {
	var out []map[string]any
	for _, name := range model.NDMPoliciesInUse(p) {
		mark, ok := marks[name]
		if !ok || mark == 0 {
			return nil, fmt.Errorf("routing list outbound %q: the router's access policy %q was not read for this config", model.NDMPolicyPrefix+name, name)
		}
		out = append(out, map[string]any{
			"type": "direct", "tag": model.NDMPolicyPrefix + name, "routing_mark": mark,
		})
	}
	return out, nil
}
