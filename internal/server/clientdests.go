package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"wakeroute/internal/clash"
)

// discoverDest is one external destination a LAN client has contacted (from conntrack), with the
// egress it took and aggregated traffic — the raw material for "what is this device requesting?
// add it as a routing rule" (backlog domain-discovery). Domain is the sniffed SNI/host (from the
// clash /connections view) when sing-box saw the connection AND the IP maps unambiguously to one
// host; blank for fast-mode kernel traffic or a shared CDN IP.
type discoverDest struct {
	Dst       string `json:"dst"`
	Domain    string `json:"domain,omitempty"`
	Exit      string `json:"exit,omitempty"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	Conns     int    `json:"conns"`
}

// unambiguousHosts maps a destination IP to its sniffed host from the clash /connections view,
// BUT only when every observed connection to that IP carried the SAME host — a shared CDN IP that
// served multiple SNIs is left out (no source IP is exposed in the metadata, so a guess could
// mis-attribute one client's domain to another). Pure for unit-testing.
func unambiguousHosts(conns []clash.Conn) map[string]string {
	sets := map[string]map[string]bool{}
	for _, c := range conns {
		ip, host := c.Metadata.DestinationIP, c.Metadata.Host
		if ip == "" || host == "" {
			continue
		}
		if sets[ip] == nil {
			sets[ip] = map[string]bool{}
		}
		sets[ip][host] = true
	}
	out := make(map[string]string, len(sets))
	for ip, hs := range sets {
		if len(hs) == 1 {
			for h := range hs {
				out[ip] = h
			}
		}
	}
	return out
}

// discoverClient is one LAN client and the external destinations it reached.
type discoverClient struct {
	IP    string         `json:"ip"`
	Name  string         `json:"name,omitempty"`
	Dests []discoverDest `json:"dests"`
}

// isPublicDest reports whether dst is a routable public address worth surfacing for routing — it
// drops LAN-internal noise (RFC1918 / ULA private, loopback, link-local, multicast) so the view
// shows only the external services a device actually reaches out to.
func isPublicDest(dst string) bool {
	ip := net.ParseIP(dst)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// aggregateClientDests groups conntrack rows per LAN client → distinct PUBLIC destination (its
// resolved exit + summed bytes/conns), each client's destinations sorted by traffic and capped,
// clients sorted by total traffic. Pure (deps passed in) for unit-testing.
func aggregateClientDests(conns []Conn, leases map[string]string, markExit func(uint32) string, hostByIP map[string]string, perClientCap int) []discoverClient {
	type acc struct {
		exit     string
		up, down int64
		conns    int
	}
	byClient := map[string]map[string]*acc{}
	names := map[string]string{}
	totals := map[string]int64{}
	for i := range conns {
		c := &conns[i]
		if !isPublicDest(c.Dst) {
			continue
		}
		m := byClient[c.Src]
		if m == nil {
			m = map[string]*acc{}
			byClient[c.Src] = m
			names[c.Src] = leases[c.Src]
		}
		a := m[c.Dst]
		if a == nil {
			a = &acc{exit: markExit(c.Mark)}
			m[c.Dst] = a
		}
		a.up += c.UpBytes
		a.down += c.DownBytes
		a.conns++
		totals[c.Src] += c.UpBytes + c.DownBytes
	}
	out := make([]discoverClient, 0, len(byClient))
	for client, m := range byClient {
		dc := discoverClient{IP: client, Name: names[client]}
		for dst, a := range m {
			dc.Dests = append(dc.Dests, discoverDest{Dst: dst, Domain: hostByIP[dst], Exit: a.exit, UpBytes: a.up, DownBytes: a.down, Conns: a.conns})
		}
		sort.Slice(dc.Dests, func(i, j int) bool {
			ti, tj := dc.Dests[i].UpBytes+dc.Dests[i].DownBytes, dc.Dests[j].UpBytes+dc.Dests[j].DownBytes
			if ti != tj {
				return ti > tj
			}
			return dc.Dests[i].Dst < dc.Dests[j].Dst
		})
		if perClientCap > 0 && len(dc.Dests) > perClientCap {
			dc.Dests = dc.Dests[:perClientCap]
		}
		out = append(out, dc)
	}
	sort.Slice(out, func(i, j int) bool {
		if ti, tj := totals[out[i].IP], totals[out[j].IP]; ti != tj {
			return ti > tj
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// handleClientDestinations reports, per LAN client, the external destinations it has recently
// contacted and via which exit — the backend for the "discover what a device requests, then add a
// rule" flow. Read-only; reuses the conntrack table + connmark→exit resolver + DHCP leases.
// GET /api/clients/destinations.
func (s *Server) handleClientDestinations(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	// Best-effort SNI/domain labels for the destination IPs sing-box saw (tun/hybrid). Optional:
	// a clash fetch failure or fast-mode (no LAN connections there) just leaves dests IP-only.
	var hostByIP map[string]string
	if s.clash != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if cs, err := s.clash.Connections(ctx); err == nil {
			hostByIP = unambiguousHosts(cs.Connections)
		}
	}
	out := aggregateClientDests(parseConntrack(string(data)), readLeases(), s.markExitResolver(), hostByIP, 50)
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "clients": out})
}
