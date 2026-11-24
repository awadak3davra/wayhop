package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// handleVPNDiscover lists native VPN tunnels (WireGuard / AmneziaWG) already configured on
// the router, so the UI can offer to route through them without re-importing keys. The discovery
// captures no secrets (no private keys, preshared keys, or obfuscation headers). full_tunnel /
// active are computed server-side so every client agrees on the verdict.
//
// It is also the moment WayHop learns the router's current truth, so it brings the adopted
// endpoints up to date with it (syncAdoptedTunnels): a renamed tunnel's endpoint follows it, a
// deleted one is reported under "missing", or under "removed" when nothing used it and it was
// dropped. The operator's routing is never changed by it.
func (s *Server) handleVPNDiscover(w http.ResponseWriter, r *http.Request) {
	type vpnRow struct {
		Iface       string        `json:"iface"`
		NDMName     string        `json:"ndm_name,omitempty"`
		Type        string        `json:"type"`
		Name        string        `json:"name,omitempty"`
		Source      string        `json:"source,omitempty"`
		PublicKey   string        `json:"public_key"`
		ListenPort  int           `json:"listen_port,omitempty"`
		Peers       []netvpn.Peer `json:"peers,omitempty"`
		FullTunnel  bool          `json:"full_tunnel"`
		Active      bool          `json:"active"`
		Adopted     bool          `json:"adopted,omitempty"`
		EndpointID  string        `json:"endpoint_id,omitempty"`
		NeedsRepair bool          `json:"needs_repair,omitempty"`
	}
	now := time.Now().Unix()
	disc := netvpn.DiscoverAll(r.Context())
	ignored := s.config().IgnoredDrift
	resp := map[string]any{}

	var missing, removed []MissingTunnel
	if err := s.store.Reconcile(func(p *model.Profile) bool {
		var changed bool
		missing, removed, changed = syncAdoptedTunnels(p, disc, ignored)
		return changed
	}); err != nil {
		// The listing is still worth returning; say why the endpoints were not brought up to date.
		resp["sync_error"] = err.Error()
		missing, removed = missingAdoptedTunnels(s.store.Profile().Endpoints, disc, ignored), nil
	}

	profile := s.store.Profile()
	out := make([]vpnRow, 0, len(disc.VPNs))
	for _, v := range disc.VPNs {
		id, needsRepair := nativeAdoptionAmong(profile.Endpoints, v, disc.VPNs)
		out = append(out, vpnRow{
			Iface: v.Iface, NDMName: v.NDMName, Type: v.Type, Name: v.Name, Source: v.Source,
			PublicKey: v.PublicKey, ListenPort: v.ListenPort, Peers: v.Peers,
			FullTunnel: v.FullTunnel(), Active: v.Active(now),
			Adopted: id != "", EndpointID: id, NeedsRepair: needsRepair,
		})
	}
	resp["vpns"] = out
	// Adopted endpoints whose interface has vanished. Reported, never auto-removed while anything
	// uses them: deleting one would cascade through every rule referencing it.
	if len(missing) > 0 {
		resp["missing"] = missing
	}
	if len(removed) > 0 {
		resp["removed"] = removed
	}
	if disc.Err != nil {
		// Non-fatal: still return whatever was found, but surface WHY discovery may be incomplete so
		// the UI can warn instead of showing an empty list that is indistinguishable from a real break.
		resp["discover_error"] = disc.Err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// nativeAdoption names the endpoint that adopted a discovered tunnel ("" if none), and whether that
// endpoint needs its ownership or NDM identity repaired. It matches as the sync does
// (adoptedMatches), so a new tunnel that reused a deleted one's interface name is offered for
// adoption instead of hiding behind the old record.
func nativeAdoption(endpoints []model.Endpoint, discovered netvpn.DiscoveredVPN) (string, bool) {
	return nativeAdoptionAmong(endpoints, discovered, []netvpn.DiscoveredVPN{discovered})
}

// nativeAdoptionAmong is nativeAdoption knowing every tunnel the router has now (adoptedTunnelFor),
// so two interfaces sharing a key are not both shown as adopted by the endpoint of one of them.
func nativeAdoptionAmong(endpoints []model.Endpoint, discovered netvpn.DiscoveredVPN, vpns []netvpn.DiscoveredVPN) (string, bool) {
	for _, endpoint := range endpoints {
		if t, ok := adoptedTunnelFor(endpoint, vpns); !ok || t.Iface != discovered.Iface {
			continue
		}
		if discovered.NDMName == "" { // OpenWrt has no NDM identity to repair.
			return endpoint.ID, false
		}
		ndmName, known := keenetic.ResolveNDMName(endpoint)
		return endpoint.ID, !endpoint.IsExternal() || !known || ndmName != discovered.NDMName
	}
	return "", false
}

// peerEndpointHost extracts the bare host of the FIRST peer carrying an endpoint,
// dropping the :port (and any [] around an IPv6 literal). This becomes the adopted
// endpoint's params["endpoint_ip"] so the anti-loop bypass (generator.endpointBypass /
// pbr plan.Bypass, which read params["endpoint_ip"]) can keep the tunnel's own peer
// IP off the tunnel — routing a full-tunnel exit's peer through itself recurses.
func peerEndpointHost(peers []netvpn.Peer) string {
	for _, p := range peers {
		ep := strings.TrimSpace(p.Endpoint)
		if ep == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(ep); err == nil {
			return host
		}
		// No port present: strip [] of a bare IPv6 literal, else use as-is.
		return strings.Trim(ep, "[]")
	}
	return ""
}

// endpointFromDiscovered maps a discovered native tunnel to an
// model.EngineExternal endpoint the user can then route through. It is pure (no I/O)
// so it is unit-tested directly. The OS owns the iface; WayHop only uses it as an
// egress, so no Server/Port/keys are created. Enabled follows whether the tunnel is up; adoption
// never auto-applies, and routing through it is the user's explicit next step.
//
// The ID is stable per iface ("external-<iface>"), so re-adopting the same tunnel
// updates the existing record (via store.UpsertEndpoint) rather than duplicating it.
func endpointFromDiscovered(d netvpn.DiscoveredVPN) model.Endpoint {
	params := map[string]any{
		"interface":  d.Iface,
		"discovered": true,
	}
	if host := peerEndpointHost(d.Peers); host != "" {
		params["endpoint_ip"] = host
	}
	if d.PublicKey != "" {
		params["public_key"] = d.PublicKey
	}
	// Capture the raw NDM interface name (Keenetic only) so the native managed-toggle can
	// target the right interface WITHOUT guessing it from the derived kernel name. Absent for
	// wg/awg-dump discovery (OpenWrt), where NDMName is empty — no key added.
	if d.NDMName != "" {
		params["ndm_name"] = d.NDMName
	}
	// Where the tunnel was seen decides whether its later absence means "deleted" (see
	// missingAdoptedTunnels); the label the name was made from tells a name WayHop wrote from one
	// the operator chose (see autoNamed).
	if d.Source != "" {
		params["source"] = d.Source
	}
	params["native_label"] = strings.TrimSpace(d.Name)
	return model.Endpoint{
		ID:       "external-" + d.Iface,
		Name:     nativeEndpointName(d.Name, d.Iface),
		Engine:   model.EngineExternal,
		Protocol: model.Protocol(d.Type), // descriptive only; validate skips protocol for external
		// The underlying tunnel is owned by the router/OS — WayHop routes through it but must never
		// stop/delete/rewrite it. OwnerExternal is the flag every destructive native op gates on.
		Owner:  model.OwnerExternal,
		Params: params,
		// On from the start when the router has the tunnel up, so adding a connection is not followed by
		// a second step to switch it on. A tunnel that is down stays off: enabled, it would stop every
		// Apply until it was brought up (the capture cannot bind a switched-off interface).
		Enabled: d.Active(time.Now().Unix()),
	}
}

// refreshAdoptedEndpoint repairs discovery metadata without changing an operator's routing state.
// Re-adoption is an ownership/identity refresh, not a hidden disable, rename, or health-policy reset.
// The name follows the router's label only while it is still the one WayHop made (autoNamed).
func refreshAdoptedEndpoint(existing, discovered model.Endpoint) model.Endpoint {
	discovered.ID = existing.ID
	discovered.Enabled = existing.Enabled
	discovered.Health = existing.Health
	discovered.MTU = existing.MTU
	discovered.PersistentKeepalive = existing.PersistentKeepalive
	if strings.TrimSpace(existing.Name) != "" && !autoNamed(existing) {
		discovered.Name = existing.Name
	}
	params := make(map[string]any, len(existing.Params)+len(discovered.Params))
	for key, value := range existing.Params {
		params[key] = value
	}
	for key, value := range discovered.Params {
		params[key] = value // the fresh interface/NDM identity is authoritative
	}
	discovered.Params = params
	return discovered
}

// nativeEndpointName is the name an adopted tunnel is given: the router's label, else the device.
func nativeEndpointName(label, iface string) string {
	if label = strings.TrimSpace(label); label != "" {
		return label + " (native)"
	}
	return iface + " (native)"
}

// autoNamed reports whether an adopted endpoint still carries the name WayHop made for it, so a
// label changed on the router may replace it. An endpoint adopted before the label was recorded
// counts as auto-named while it keeps the " (native)" suffix every such name had.
func autoNamed(e model.Endpoint) bool {
	if label, ok := e.Params["native_label"].(string); ok {
		return e.Name == nativeEndpointName(label, endpointIface(e))
	}
	return strings.HasSuffix(e.Name, " (native)")
}

// handleVPNAdopt turns an already-discovered native tunnel into an
// EngineExternal endpoint (switched on when the tunnel is up) the user can route through. It re-runs the SAME discovery
// handleVPNDiscover uses and adopts ONLY a tunnel that is currently present — never a
// phantom iface. It does NOT touch the OS tunnel or auto-apply.
func (s *Server) handleVPNAdopt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface string `json:"iface"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	iface := strings.TrimSpace(body.Iface)
	if iface == "" {
		writeErr(w, http.StatusBadRequest, "iface is required")
		return
	}
	vpns, derr := netvpn.Discover(r.Context())
	for _, v := range vpns {
		if v.Iface == iface {
			ep := endpointFromDiscovered(v)
			// Re-adopting a RENAMED tunnel must update the record that already exists rather than
			// minting a second one beside it (see resolveAdoptedID): the interface name changed, the
			// tunnel did not.
			profile := s.store.Profile()
			ep.ID = resolveAdoptedIDAmong(profile.Endpoints, v, vpns)
			for _, existing := range profile.Endpoints {
				if existing.ID == ep.ID {
					ep = refreshAdoptedEndpoint(existing, ep)
					break
				}
			}
			if err := s.store.UpsertEndpoint(ep); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, ep)
			return
		}
	}
	if derr != nil {
		// Discovery broke (not merely "iface absent") — report that, not a misleading 404.
		writeErr(w, http.StatusInternalServerError, "tunnel discovery failed: "+derr.Error())
		return
	}
	writeErr(w, http.StatusNotFound, "iface not currently discovered")
}

// replacedTunnelEndpoint is existing re-bound to the discovered tunnel d: the same record (ID, name,
// health policy, on or off), so everything that routes through it keeps doing so, with the new
// tunnel's identity in place of the old one's. The old parameters are NOT merged in, unlike
// refreshAdoptedEndpoint: a stale peer address or key belongs to the tunnel that died.
func replacedTunnelEndpoint(existing model.Endpoint, d netvpn.DiscoveredVPN, now int64) model.Endpoint {
	fresh := endpointFromDiscovered(d)
	fresh.ID = existing.ID
	fresh.Health = existing.Health
	fresh.MTU = existing.MTU
	fresh.PersistentKeepalive = existing.PersistentKeepalive
	// The operator's own name stays; a name WayHop made follows the new tunnel's label.
	if strings.TrimSpace(existing.Name) != "" && !autoNamed(existing) {
		fresh.Name = existing.Name
	}
	// A switched-on connection stays on. One that was off comes on when the new tunnel is up: replacing
	// a dead tunnel is asking for it to work.
	fresh.Enabled = existing.Enabled || d.Active(now)
	return fresh
}

// handleReplaceTunnel (POST /api/endpoints/{id}/replace-tunnel {"iface":"nwg0"}) points an adopted
// connection at another tunnel the router has now: the dead one was replaced by a new one, in the
// same slot or another. Rules, lists, groups and DNS detours stay as they are. A connection already
// adopted for that tunnel (made when it first appeared) is folded in: what used it moves to this
// record and it is removed.
func (s *Server) handleReplaceTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Iface string `json:"iface"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil || strings.TrimSpace(body.Iface) == "" {
		writeErr(w, http.StatusBadRequest, "iface is required")
		return
	}
	iface := strings.TrimSpace(body.Iface)
	profile := s.store.Profile()
	existing := profile.EndpointByID(id)
	if existing == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("connection %q does not exist", id))
		return
	}
	if existing.Engine != model.EngineExternal {
		writeErr(w, http.StatusBadRequest, "only a connection adopted from a router tunnel can be pointed at another tunnel")
		return
	}
	disc := netvpn.DiscoverAll(r.Context())
	var target *netvpn.DiscoveredVPN
	for i := range disc.VPNs {
		if disc.VPNs[i].Iface == iface {
			target = &disc.VPNs[i]
		}
	}
	if target == nil {
		if disc.Err != nil {
			writeErr(w, http.StatusInternalServerError, "tunnel discovery failed: "+disc.Err.Error())
			return
		}
		writeErr(w, http.StatusNotFound, "that tunnel is not on the router now")
		return
	}
	// Another record for the same tunnel, to fold in after this one is re-bound.
	var duplicate string
	for _, e := range profile.Endpoints {
		if e.ID == id || e.Engine != model.EngineExternal {
			continue
		}
		if t, ok := adoptedTunnelFor(e, disc.VPNs); ok && t.Iface == target.Iface {
			duplicate = e.ID
		}
	}
	fresh := replacedTunnelEndpoint(*existing, *target, time.Now().Unix())
	if err := s.store.UpsertEndpoint(fresh); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if duplicate != "" {
		if err := s.store.DeleteEndpointReplacing(duplicate, id); err != nil {
			writeErr(w, http.StatusConflict, "the connection was re-bound, but the duplicate record "+duplicate+" could not be folded into it: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "iface": target.Iface, "folded": duplicate})
}
