package server

import (
	"fmt"
	"strings"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// adoptedPublicKey returns the public key an adopted endpoint was created from, if any.
func adoptedPublicKey(e model.Endpoint) string {
	if e.Params == nil {
		return ""
	}
	k, _ := e.Params["public_key"].(string)
	return strings.TrimSpace(k)
}

// resolveAdoptedID picks the endpoint ID to use when adopting (or re-adopting) a discovered native
// tunnel.
//
// The default ID is "external-<iface>", which is derived from the interface NAME — and interface
// names are mutable. Rename a tunnel on the router (awg0 → awg1, or an NDM rename on Keenetic) and
// re-adopting it would mint a NEW record while the old one lingers pointing at an interface that no
// longer exists: one tunnel, two endpoints, one of them permanently broken. The spec's ownership
// model requires the opposite — "persist stable identifiers independently of mutable interface
// names".
//
// A WireGuard/AmneziaWG interface's public key IS stable across renames, so an existing endpoint
// carrying the same key is the same tunnel and its ID is reused. The record is then updated in place
// and simply learns its new interface name.
//
// Deliberately matched by key rather than migrated to key-derived IDs: existing installs already
// have "external-<iface>" records, and rewriting their IDs would orphan every rule and group that
// references them. Keeping the ID and fixing the LOOKUP is the change that costs a user nothing.
func resolveAdoptedID(existing []model.Endpoint, d netvpn.DiscoveredVPN) string {
	return resolveAdoptedIDAmong(existing, d, []netvpn.DiscoveredVPN{d})
}

// resolveAdoptedIDAmong is resolveAdoptedID knowing every tunnel the router has now, so an
// endpoint whose own interface is still there is never handed to another tunnel with its key.
func resolveAdoptedIDAmong(existing []model.Endpoint, d netvpn.DiscoveredVPN, vpns []netvpn.DiscoveredVPN) string {
	for _, e := range existing {
		if t, ok := adoptedTunnelFor(e, vpns); ok && t.Iface == d.Iface {
			return e.ID // same tunnel, whatever it is called today
		}
	}
	// A new tunnel can land on a name a deleted one left behind: KeeneticOS reuses a freed
	// WireguardN slot. When the old record still holds "external-<iface>" (rules route through it,
	// so it was kept), the new tunnel gets an ID of its own rather than silently taking over the old
	// tunnel's rules.
	taken := map[string]bool{}
	for _, e := range existing {
		taken[e.ID] = true
	}
	id := "external-" + d.Iface
	for n := 2; taken[id]; n++ {
		id = fmt.Sprintf("external-%s-%d", d.Iface, n)
	}
	return id
}

// adoptedTunnelFor picks, among the tunnels the router has now, the one an adopted endpoint is.
//
// The endpoint's own interface wins while a tunnel by that name is there and its key does not say
// it is another tunnel. The public key alone (a renamed tunnel) decides only when no tunnel carries
// the endpoint's name and exactly one carries its key. Two interfaces built from one private key
// share a public key: a live test router had awg1 to one exit and a second interface to another under
// one key, and matching by key first re-pointed the RU connection at the second one when a page
// listed the tunnels. The next Apply, made for a DNS change, sent every RU list into a firewall zone
// LAN traffic may not enter.
func adoptedTunnelFor(e model.Endpoint, vpns []netvpn.DiscoveredVPN) (netvpn.DiscoveredVPN, bool) {
	if e.Engine != model.EngineExternal {
		return netvpn.DiscoveredVPN{}, false
	}
	ek := adoptedPublicKey(e)
	if iface := endpointIface(e); iface != "" {
		for _, v := range vpns {
			if v.Iface != iface {
				continue
			}
			if dk := strings.TrimSpace(v.PublicKey); ek == "" || dk == "" || ek == dk {
				return v, true
			}
		}
	}
	var hit netvpn.DiscoveredVPN
	n := 0
	for _, v := range vpns {
		if adoptedMatches(e, v) {
			hit = v
			n++
		}
	}
	return hit, n == 1
}

// adoptedMatches reports whether an adopted endpoint is the discovered tunnel.
//
// The interface's public key decides whenever both sides carry one: it survives renames, and two
// different keys under one name are two tunnels (a deleted Keenetic tunnel whose slot a new one
// reused). Without a key on both sides the kernel name decides, then the NDM name. A missing key
// never matches another missing key.
func adoptedMatches(e model.Endpoint, d netvpn.DiscoveredVPN) bool {
	if e.Engine != model.EngineExternal {
		return false
	}
	if ek, dk := adoptedPublicKey(e), strings.TrimSpace(d.PublicKey); ek != "" && dk != "" {
		return ek == dk
	}
	if iface := endpointIface(e); iface != "" && iface == d.Iface {
		return true
	}
	name, known := keenetic.ResolveNDMName(e)
	return known && name == d.NDMName
}
