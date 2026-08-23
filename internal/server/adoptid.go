package server

import (
	"strings"

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
	fallback := "external-" + d.Iface

	key := strings.TrimSpace(d.PublicKey)
	if key == "" {
		// NDM discovery does not expose public keys. The exact live kernel interface is still enough
		// to refresh an existing record in place (not to infer a rename): this is how a pre-ownership
		// Keenetic endpoint learns its authoritative NDM name without duplicating itself.
		for _, e := range existing {
			iface, _ := e.Params["interface"].(string)
			if e.Engine == model.EngineExternal && iface == d.Iface {
				return e.ID
			}
		}
		return fallback
	}
	for _, e := range existing {
		if e.Engine != model.EngineExternal {
			continue
		}
		if adoptedPublicKey(e) == key {
			return e.ID // same tunnel, whatever it is called today
		}
	}
	return fallback
}
