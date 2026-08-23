package server

import (
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// MissingTunnel is an endpoint that routes through a native interface which is no longer present on
// the router.
type MissingTunnel struct {
	EndpointID string `json:"endpoint_id"`
	Name       string `json:"name,omitempty"`
	Iface      string `json:"iface,omitempty"`
	Enabled    bool   `json:"enabled"` // an ENABLED endpoint pointing at a dead interface is the urgent case
	Reason     string `json:"reason"`
}

// missingAdoptedTunnels reports endpoints whose underlying native interface has disappeared.
//
// WayHop routes through native tunnels it does not own, so the router can delete one at any time
// without telling it. Today nothing notices: the endpoint keeps rendering as a normal egress while
// traffic routed through it goes nowhere. The user's visible symptom is "some things stopped
// working", with a panel that looks entirely healthy.
//
// It REPORTS ONLY, and that restraint is the point. The spec requires that an externally removed
// tunnel "becomes unavailable without deleting unrelated rules": auto-removing the endpoint would
// cascade into every rule and group referencing it, turning a temporary absence — a tunnel that is
// down for a reboot, a firmware upgrade mid-flight, a discovery probe that failed — into permanent
// destruction of the user's routing configuration. Absence is a fact to surface, never an
// instruction to delete.
//
// Pure, so the decision is unit-testable without a router.
func missingAdoptedTunnels(endpoints []model.Endpoint, discovered []netvpn.DiscoveredVPN, discoveryOK bool, ignored []string) []MissingTunnel {
	skip := map[string]bool{}
	for _, id := range ignored {
		skip[id] = true
	}
	// A failed discovery means "we do not know", not "everything is gone". Reporting every adopted
	// tunnel as missing because one probe failed would be worse than silence.
	if !discoveryOK {
		return nil
	}

	liveIfaces := map[string]bool{}
	liveKeys := map[string]bool{}
	for _, d := range discovered {
		if d.Iface != "" {
			liveIfaces[d.Iface] = true
		}
		if k := strings.TrimSpace(d.PublicKey); k != "" {
			liveKeys[k] = true
		}
	}

	var out []MissingTunnel
	for _, e := range endpoints {
		if e.Engine != model.EngineExternal || skip[e.ID] {
			continue // dismissed by the user as expected; see Config.IgnoredDrift
		}
		iface := endpointIface(e)
		key := adoptedPublicKey(e)
		if iface == "" && key == "" {
			continue // nothing to check it against
		}
		// Present under EITHER identity: the key survives a rename, and the name covers a tunnel
		// whose key was never captured. Matching on either avoids reporting a renamed tunnel as
		// missing, which would be a false alarm for something that is working fine.
		if (key != "" && liveKeys[key]) || (iface != "" && liveIfaces[iface]) {
			continue
		}
		out = append(out, MissingTunnel{
			EndpointID: e.ID, Name: e.Name, Iface: iface, Enabled: e.Enabled,
			Reason: "the native interface this endpoint routes through is not present on the router; " +
				"it may have been removed, renamed beyond recognition, or simply be down",
		})
	}
	return out
}

// endpointIface returns the interface an external endpoint routes through.
func endpointIface(e model.Endpoint) string {
	if e.Params == nil {
		return ""
	}
	s, _ := e.Params["interface"].(string)
	return strings.TrimSpace(s)
}
