package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"velinx/internal/model"
	"velinx/internal/netvpn"
)

// handleVPNDiscover lists native VPN tunnels (WireGuard / AmneziaWG) already configured on
// the router, so the UI can offer to route through them without re-importing keys. Read-only;
// the discovery captures no secrets (no private keys, preshared keys, or obfuscation headers).
// full_tunnel / active are computed server-side so every client agrees on the verdict.
func (s *Server) handleVPNDiscover(w http.ResponseWriter, r *http.Request) {
	type vpnRow struct {
		Iface      string        `json:"iface"`
		Type       string        `json:"type"`
		Name       string        `json:"name,omitempty"`
		PublicKey  string        `json:"public_key"`
		ListenPort int           `json:"listen_port,omitempty"`
		Peers      []netvpn.Peer `json:"peers,omitempty"`
		FullTunnel bool          `json:"full_tunnel"`
		Active     bool          `json:"active"`
	}
	now := time.Now().Unix()
	vpns := netvpn.Discover(r.Context())
	out := make([]vpnRow, 0, len(vpns))
	for _, v := range vpns {
		out = append(out, vpnRow{
			Iface: v.Iface, Type: v.Type, Name: v.Name, PublicKey: v.PublicKey, ListenPort: v.ListenPort,
			Peers: v.Peers, FullTunnel: v.FullTunnel(), Active: v.Active(now),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vpns": out})
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

// endpointFromDiscovered maps a discovered native tunnel to a DISABLED
// model.EngineExternal endpoint the user can then route through. It is pure (no I/O)
// so it is unit-tested directly. The OS owns the iface; Velinx only uses it as an
// egress, so no Server/Port/keys are created. Enabled is false — adoption never
// auto-enables or auto-applies; enabling + routing is the user's explicit next step.
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
	name := d.Iface + " (native)"
	if strings.TrimSpace(d.Name) != "" {
		name = d.Name + " (native)"
	}
	return model.Endpoint{
		ID:       "external-" + d.Iface,
		Name:     name,
		Engine:   model.EngineExternal,
		Protocol: model.Protocol(d.Type), // descriptive only; validate skips protocol for external
		Params:   params,
		Enabled:  false,
	}
}

// handleVPNAdopt turns an already-discovered native tunnel into a DISABLED
// EngineExternal endpoint the user can route through. It re-runs the SAME discovery
// handleVPNDiscover uses and adopts ONLY a tunnel that is currently present — never a
// phantom iface. It does NOT touch the OS tunnel, auto-enable, or auto-apply.
func (s *Server) handleVPNAdopt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Iface string `json:"iface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	iface := strings.TrimSpace(body.Iface)
	if iface == "" {
		writeErr(w, http.StatusBadRequest, "iface is required")
		return
	}
	for _, v := range netvpn.Discover(r.Context()) {
		if v.Iface == iface {
			ep := endpointFromDiscovered(v)
			if err := s.store.UpsertEndpoint(ep); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, ep)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "iface not currently discovered")
}
