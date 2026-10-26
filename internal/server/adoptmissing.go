package server

import (
	"reflect"
	"strings"

	"wayhop/internal/keenetic"
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
	// Deleted is set when the router's configuration listing (NDM, uci) was read and no longer has
	// the tunnel: it was removed, not merely down. Without it the tunnel may simply not be running.
	Deleted bool   `json:"deleted"`
	Reason  string `json:"reason"`
}

// missingAdoptedTunnels reports endpoints whose underlying native interface has disappeared.
//
// WayHop routes through native tunnels it does not own, so the router can delete one at any time
// without telling it. Today nothing notices: the endpoint keeps rendering as a normal egress while
// traffic routed through it goes nowhere. The user's visible symptom is "some things stopped
// working", with a panel that looks entirely healthy.
//
// It REPORTS ONLY. The spec requires that an externally removed tunnel "becomes unavailable without
// deleting unrelated rules": removing an endpoint that rules or groups use would cascade into them,
// turning a temporary absence — a tunnel that is down for a reboot, a firmware upgrade mid-flight,
// a discovery probe that failed — into permanent destruction of the user's routing configuration.
// syncAdoptedTunnels removes only what nothing uses (see prunableAdopted).
//
// An endpoint the router's configuration listing should hold (an NDM name on Keenetic, a uci
// tunnel on OpenWrt) is judged against that listing and reported Deleted when it is gone. When the
// listing could not be read it is not judged at all: the runtime alone cannot see a Keenetic
// tunnel. Pure, so the decision is unit-testable without a router.
func missingAdoptedTunnels(endpoints []model.Endpoint, d netvpn.Discovery, ignored []string) []MissingTunnel {
	skip := map[string]bool{}
	for _, id := range ignored {
		skip[id] = true
	}
	// A failed discovery means "we do not know", not "everything is gone". Reporting every adopted
	// tunnel as missing because one probe failed would be worse than silence.
	if d.Err != nil {
		return nil
	}

	var out []MissingTunnel
	for _, e := range endpoints {
		if e.Engine != model.EngineExternal || skip[e.ID] {
			continue // dismissed by the user as expected; see Config.IgnoredDrift
		}
		iface := endpointIface(e)
		_, ndm := keenetic.ResolveNDMName(e)
		if iface == "" && adoptedPublicKey(e) == "" && !ndm {
			continue // nothing to check it against
		}
		if presentTunnel(e, d.VPNs) {
			continue
		}
		deleted := false
		switch {
		case ndm || adoptedSource(e) == netvpn.SourceNDM:
			if !d.NDM {
				continue // only the NDM listing can see a Keenetic tunnel, and it was not read
			}
			deleted = true
		case adoptedSource(e) == netvpn.SourceUCI:
			deleted = d.UCI
		}
		reason := "the native interface this endpoint routes through is not present on the router; " +
			"it may have been removed, renamed beyond recognition, or simply be down"
		if deleted {
			reason = "the router no longer has this tunnel in its configuration: it was deleted there"
		}
		out = append(out, MissingTunnel{
			EndpointID: e.ID, Name: e.Name, Iface: iface, Enabled: e.Enabled, Deleted: deleted, Reason: reason,
		})
	}
	return out
}

// presentTunnel reports whether any discovered tunnel is the adopted endpoint.
func presentTunnel(e model.Endpoint, discovered []netvpn.DiscoveredVPN) bool {
	for _, d := range discovered {
		if adoptedMatches(e, d) {
			return true
		}
	}
	return false
}

// adoptedSource is where the endpoint's tunnel was last seen (netvpn.SourceNDM…), "" if never
// recorded.
func adoptedSource(e model.Endpoint) string {
	s, _ := e.Params["source"].(string)
	return s
}

// syncAdoptedTunnels brings the adopted endpoints in p up to date with what the router has now,
// and reports the ones whose tunnel is gone. It returns whether p changed.
//
//   - A tunnel that is still there refreshes its endpoint's identity in place: a new interface or
//     NDM name, its public key, its peer address (the anti-loop bypass reads it), its label while
//     the operator has not renamed it. Routing state is never touched (refreshAdoptedEndpoint).
//   - A tunnel the router deleted takes its endpoint with it only when nothing could miss it: the
//     endpoint is off and no rule, routing list, DNS server or group uses it. Anything else is
//     reported and kept, for the operator to repoint or delete.
//
// Without it an adopted endpoint was a snapshot of the day it was adopted: a tunnel deleted in the
// router's web UI stayed in the list as a normal exit, and a renamed one kept its old name.
func syncAdoptedTunnels(p *model.Profile, d netvpn.Discovery, ignored []string) (missing []MissingTunnel, pruned []MissingTunnel, changed bool) {
	for i, e := range p.Endpoints {
		if e.Engine != model.EngineExternal {
			continue
		}
		for _, v := range d.VPNs {
			if !adoptedMatches(e, v) {
				continue
			}
			fresh := refreshAdoptedEndpoint(e, endpointFromDiscovered(v))
			if !reflect.DeepEqual(fresh, e) {
				p.Endpoints[i] = fresh
				changed = true
			}
			break
		}
	}
	gone := map[string]bool{}
	for _, m := range missingAdoptedTunnels(p.Endpoints, d, ignored) {
		if m.Deleted && prunableAdopted(*p, m.EndpointID) {
			gone[m.EndpointID] = true
			pruned = append(pruned, m)
			continue
		}
		missing = append(missing, m)
	}
	if len(gone) > 0 {
		kept := make([]model.Endpoint, 0, len(p.Endpoints)-len(gone))
		for _, e := range p.Endpoints {
			if !gone[e.ID] {
				kept = append(kept, e)
			}
		}
		p.Endpoints = kept
		changed = true
	}
	return missing, pruned, changed
}

// prunableAdopted reports whether removing the endpoint can change nothing: it is off and nothing
// references it, not even as one member of a group with others.
func prunableAdopted(p model.Profile, id string) bool {
	for _, e := range p.Endpoints {
		if e.ID == id && e.Enabled {
			return false
		}
	}
	for _, r := range p.Rules {
		if r.Outbound == id {
			return false
		}
	}
	for _, g := range p.Groups {
		for _, m := range g.Members {
			if m == id {
				return false
			}
		}
	}
	for _, rl := range p.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			return false
		}
	}
	if p.DNS != nil {
		for _, ds := range p.DNS.Servers {
			if ds.Detour == id {
				return false
			}
		}
	}
	return true
}

// endpointIface returns the interface an external endpoint routes through.
func endpointIface(e model.Endpoint) string {
	if e.Params == nil {
		return ""
	}
	s, _ := e.Params["interface"].(string)
	return strings.TrimSpace(s)
}
