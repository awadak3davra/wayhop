package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
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

	facts := s.newExitFacts()
	tiles := make([]exitTile, 0, len(p.Endpoints))
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		ip, probed := s.resolveExitIP(ctx, e, facts)
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

// engineBypassMark is the fwmark that exempts a socket from sing-box's transparent redirect. Its
// auto_redirect (which the generator turns on for gateway mode) installs a `nat` OUTPUT chain
// whose last rule REDIRECTs every locally generated IPv4 TCP connection into sing-box, so a probe
// socket bound to awg0 was DNAT'd to loopback and re-dialed by sing-box's own outbound: the socket
// kept the tunnel's source address, the tunnel's counters never moved, and the tile reported the
// router's WAN address as the tunnel's exit. The same chain's FIRST rule is `meta mark <this>
// return`, so a socket carrying the mark is left alone and really egresses out the interface it is
// bound to. Measured on an AX3000T (sing-box 1.13.21): unmarked, awg0 and awg1 both answered the
// WAN IP and `awg show <iface> transfer` did not move; marked, they answered their own exits and
// the counters moved.
//
// The value is sing-tun's default for `tun.auto_redirect_output_mark`, which WayHop never sets. A
// host using a different one is not a wrong answer, only a missed measurement: probeEgressIP
// discards any result equal to the router's own exit, so the grid falls back to the tunnel's
// server address instead of passing the WAN off as the tunnel's.
const engineBypassMark = 0x2024

// probeIface is the per-egress probe seam: SO_BINDTODEVICE (+ optional fwmark) on the router,
// a no-op stub off Linux. A variable so tests can drive resolveExitIP's decision logic on any
// platform.
var probeIface = probeExitIPViaIface

// exitFacts caches what every tile in ONE refresh shares, each read at most once and only when a
// kernel-interface endpoint actually needs it: the router's own uplink exit IP (the answer a
// per-egress probe must never return) and the live wg/awg peer addresses. The applied plan's
// interface bindings are read up front instead, so every tile names its device from one snapshot.
type exitFacts struct {
	native      map[string]string // endpoint id -> the interface the applied native plan gave it
	nativeKnown bool              // a native plan is applied; false leaves the name to the profile
	wanIP       string
	wanDone     bool
	peers       map[string]string // kernel iface -> tunnel peer host
	peersDone   bool
}

// newExitFacts starts one refresh from the applied native plan's interface bindings.
func (s *Server) newExitFacts() *exitFacts {
	native, known := s.currentNativeInterfaceBindings()
	return &exitFacts{native: native, nativeKnown: known}
}

// link is the kernel device an endpoint's exit is probed through, resolved as the health monitor and
// the speed test resolve it (tunnelLink): with a native plan applied, the device the plan bound, an
// empty binding meaning the endpoint has none of its own (the core carries it, or it is not in the
// applied snapshot); otherwise the adopted interface, or the name derived for an AmneziaWG endpoint.
// Read from the editable profile alone, it followed edits not yet applied and missed the names a
// strict plan assigns (wr_* on OpenWrt, WireguardN on a Keenetic, probed as nwgN). "" when there is
// none, and the tile shows the server address.
func (f *exitFacts) link(e *model.Endpoint) string {
	return tunnelLink(*e, f.native, f.nativeKnown)
}

// wan is the exit IP the router presents when nothing binds a tunnel — probed once per refresh,
// outside the engine's redirect so it is the real uplink answer and not whatever sing-box's rules
// would have chosen. "" when it could not be measured, which simply disables the guard.
func (f *exitFacts) wan(ctx context.Context) string {
	if !f.wanDone {
		f.wanDone = true
		f.wanIP = probeIface(ctx, "", engineBypassMark)
	}
	return f.wanIP
}

// peer is the tunnel peer's address for a kernel interface, read live from the wg/awg runtime.
// The last resort for an EngineExternal endpoint that carries neither a Server nor an
// endpoint_ip (hand-made rather than adopted by discovery): without it such a tile has no address
// at all and is dropped from the grid.
func (f *exitFacts) peer(ctx context.Context, iface string) string {
	if !f.peersDone {
		f.peersDone = true
		f.peers = discoveredPeerIPs(ctx)
	}
	return f.peers[iface]
}

// discoveredPeerIPs maps each live kernel tunnel to its first peer's host, from the wg/awg dump.
func discoveredPeerIPs(ctx context.Context) map[string]string {
	vpns, _ := netvpn.Discover(ctx) // absence of wg/awg is normal, never an error worth surfacing
	out := make(map[string]string, len(vpns))
	for _, v := range vpns {
		if host := peerEndpointHost(v.Peers); host != "" {
			out[v.Iface] = host
		}
	}
	return out
}

// resolveExitIP returns the public WAN IP the endpoint egresses from, plus whether it came from a
// live probe. A live per-egress probe (bound to the endpoint's kernel interface, see exitFacts.link)
// is attempted first so a multi-hop / NAT'd exit reports its REAL address; it is a no-op off-router
// (non-Linux, no kernel interface, or the probe fails), where the endpoint's server address — or,
// for a kernel tunnel that records none, its live peer address — is used instead.
func (s *Server) resolveExitIP(ctx context.Context, e *model.Endpoint, f *exitFacts) (string, bool) {
	iface := f.link(e)
	if iface != "" && s.coreUp() {
		if ip := probeEgressIP(ctx, iface, f.wan(ctx)); ip != "" {
			return ip, true
		}
	}
	if ip := endpointServerIP(e); ip != "" {
		return ip, false
	}
	// An empty applied binding stops the probe, not this lookup: a tunnel enabled after the last Apply
	// is live on the router all the same, and without its peer its tile would drop from the grid.
	if iface == "" {
		iface = tunnelLink(*e, nil, false)
	}
	if iface != "" {
		return f.peer(ctx, iface), false
	}
	return "", false
}

// probeEgressIP measures ONE tunnel's real public exit: an IP echo fetched through a socket bound
// to that tunnel's kernel interface. The bypass mark goes first because on a gateway router the
// engine's redirect is in the way (see engineBypassMark); the unmarked attempt follows for hosts
// where nothing redirects local traffic and the mark could only hit some other rule.
//
// A result is believed only when it differs from the router's own uplink exit: a probe that comes
// back with the WAN address never entered the tunnel, and showing it would label the address the
// tunnel exists to hide as the address it presents. Returning "" there leaves the caller with the
// endpoint's server address, which is the truth for a single-hop VPN.
func probeEgressIP(ctx context.Context, iface, wanIP string) string {
	for _, mark := range [...]int{engineBypassMark, 0} {
		ip := probeIface(ctx, iface, mark)
		if ip == "" || ip == wanIP {
			continue
		}
		return ip
	}
	return ""
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

// validExitIP trims + validates an echo body into an IP (or "").
func validExitIP(body string) string {
	s := strings.TrimSpace(body)
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}
