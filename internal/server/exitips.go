package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"wayhop/internal/model"
)

// exitTile is one per-egress descriptor for the Dashboard's exit-IP grid: the tunnel's
// display name, the public WAN IP its traffic egresses from (the real observed exit when a
// live per-egress probe succeeds, otherwise the connection's server address — for a single-hop
// VPN the two are the same), and the geolocation of that IP (country + provider).
type exitTile struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	CC      string `json:"cc,omitempty"`
	Country string `json:"country,omitempty"`
	ISP     string `json:"isp,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Hosting bool   `json:"hosting,omitempty"`
	Probed  bool   `json:"probed,omitempty"` // true when IP came from a live per-egress probe (else the server IP)
}

// exitTilesState caches the per-egress tiles so the Dashboard grid renders without a burst of
// geo lookups on every poll. Server IPs rarely change and the free geo providers rate-limit, so
// a generous TTL keeps the grid fresh while staying well under any provider cap.
type exitTilesState struct {
	mu    sync.Mutex
	tiles []exitTile
	at    time.Time
}

const exitTilesTTL = 5 * time.Minute

// handleExitIPs returns one exit descriptor per ENABLED endpoint (each is a network exit).
// For every endpoint it reports the connection's public WAN IP + geo: a live per-egress probe
// (bound to the endpoint's kernel interface — router/Linux only) supplies the REAL observed exit
// when available, otherwise the endpoint's own server address stands in (identical for a single-
// hop VPN). Geo is best-effort — a failed lookup leaves the country/provider blank but the tile
// and its IP still stand. Degrades to {available:false} in demo.
func (s *Server) handleExitIPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.config().Demo {
		// No real exits or geo off-router; serve the synthetic grid (documentation IPs only) so the
		// dashboard renders. Skips the live probe + geo network calls the real path would make.
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "exits": demoExitTiles()})
		return
	}
	s.exitTiles.mu.Lock()
	if len(s.exitTiles.tiles) > 0 && time.Since(s.exitTiles.at) < exitTilesTTL {
		tiles := append([]exitTile(nil), s.exitTiles.tiles...)
		s.exitTiles.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "exits": tiles})
		return
	}
	s.exitTiles.mu.Unlock()

	if s.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	p := s.store.Profile()
	// One bounded budget for the whole grid so a slow geo/probe can't hang the poll.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	tiles := make([]exitTile, 0, len(p.Endpoints))
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		ip, probed := s.resolveExitIP(ctx, e)
		if ip == "" {
			continue // nothing meaningful to show for this endpoint
		}
		t := exitTile{ID: e.ID, Name: exitName(e), IP: ip, Probed: probed}
		if g := geoForIP(ctx, ip); !g.empty() {
			t.CC, t.Country, t.ISP, t.ASN, t.Hosting = g.CC, g.Country, g.ISP, g.ASN, g.Hosting
		}
		tiles = append(tiles, t)
	}
	if len(tiles) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	s.exitTiles.mu.Lock()
	s.exitTiles.tiles, s.exitTiles.at = tiles, time.Now()
	s.exitTiles.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "exits": tiles})
}

// resolveExitIP returns the public WAN IP the endpoint egresses from, plus whether it came from a
// live probe. A live per-egress probe (bound to the endpoint's kernel interface) is attempted
// first so a multi-hop / NAT'd exit reports its REAL address; it is a no-op off-router (non-Linux,
// no kernel interface, or the probe fails), where the endpoint's server address is used instead.
func (s *Server) resolveExitIP(ctx context.Context, e *model.Endpoint) (string, bool) {
	if iface := kernelIfaceOf(e); iface != "" && s.coreUp() {
		if ip := probeExitIPViaIface(ctx, iface); ip != "" {
			return ip, true
		}
	}
	return endpointServerIP(e), false
}

// exitName is the human label for an endpoint's exit tile (its Name, or the id as a fallback).
func exitName(e *model.Endpoint) string {
	if n := strings.TrimSpace(e.Name); n != "" {
		return n
	}
	return e.ID
}

// endpointServerIP is the connection's public server address: the endpoint's Server, or — for an
// EngineExternal tunnel that binds an OS interface rather than dialing a server — the recorded
// peer endpoint_ip. Only a routable literal or host is returned ("" when nothing usable).
func endpointServerIP(e *model.Endpoint) string {
	if s := strings.TrimSpace(e.Server); s != "" {
		return s
	}
	if e.Params != nil {
		if v, ok := e.Params["endpoint_ip"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// kernelIfaceOf returns the OS interface an endpoint egresses through for a live per-egress probe:
// an EngineExternal endpoint's bound interface, or an AmneziaWG/WireGuard endpoint's plugin
// interface name. "" when the endpoint has no kernel interface (e.g. a sing-box VLESS outbound),
// in which case resolveExitIP falls back to the server IP.
func kernelIfaceOf(e *model.Endpoint) string {
	if e.Params != nil {
		if v, ok := e.Params["interface"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// validExitIP trims + validates an echo body into an IP (or "").
func validExitIP(body string) string {
	s := strings.TrimSpace(body)
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}
