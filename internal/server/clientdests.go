package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"wayhop/internal/clash"
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

// defaultRouteIfaces names the interfaces with a default route on them. Read from /proc/net/route so
// this needs no host capture and no platform branch; an unreadable table yields an empty set, which
// only means the WAN is not excluded - the same shape of degradation as an unreadable interface list.
func defaultRouteIfaces() map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		if f[1] == "00000000" { // destination 0.0.0.0 => the default route
			out[f[0]] = true
		}
	}
	return out
}

// lanPrefixes are the router's own directly-connected subnets, minus every interface the profile
// names as a tunnel. Those tunnel subnets are where the seven non-devices came from: the router does
// hold an address on each, so "directly connected" alone would keep letting the far end in.
//
// Returns nil when the interfaces cannot be read, which isLANSource treats as "no opinion" and shows
// everything, exactly as before this filter existed.
func (s *Server) lanPrefixes() ([]netip.Prefix, map[string]bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	// The router is not a device on its own network. Its ppp0 address showed up as one: a
	// point-to-point interface masks to /32, so the prefix contains exactly the router itself.
	self := map[string]bool{}
	// An interface carrying a default route is the way OUT, not part of the network inside. On the
	// operator's Keenetic that is eth3 (172.31.1.140/19, the ISP's own segment) and ppp0
	// (172.31.2.13): both are RFC1918, so privateness cannot tell them from a LAN, and both were
	// still contributing "devices" after the tunnels were excluded.
	tunnels := defaultRouteIfaces()
	if s != nil && s.store != nil {
		profile := s.store.Profile()
		for _, iface := range kernelIfaceByEndpoint(&profile) {
			if iface != "" {
				tunnels[iface] = true
			}
		}
	}
	var out []netip.Prefix
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || tunnels[ifc.Name] {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			self[n.IP.String()] = true
			if p, err := netip.ParsePrefix(n.String()); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out, self
}

// isLANSource reports whether src sits in one of the router's own LAN prefixes.
//
// The card is headed "per device on your network" and the aggregation filtered only DESTINATIONS, so
// every conntrack row with a public destination became a "device" - including rows whose SOURCE is
// the far side of a tunnel. Measured on a live Keenetic: 30 listed devices, of which 23 were
// on the LAN (192.168.0.0/24, the br0 subnet) and seven were tunnel-side addresses - 10.0.1.x,
// 10.50.1.x, 10.50.2.x, 10.50.3.x, 10.50.4.x, 172.31.1.x, 172.31.2.x. Nearly a quarter of a
// list someone reads to find which of THEIR devices is leaking.
//
// An empty prefix list means the router's own addresses could not be read. That returns true for
// everything, i.e. today's behaviour: showing a few rows too many beats emptying the card on a host
// whose interfaces this cannot enumerate.
func isLANSource(src string, lans []netip.Prefix, self map[string]bool) bool {
	if self[src] {
		return false
	}
	if len(lans) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(src)
	if err != nil {
		return false
	}
	for _, p := range lans {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func aggregateClientDests(conns []Conn, leases map[string]string, markExit func(uint32) string, hostByIP map[string]string, perClientCap int, lans []netip.Prefix, self map[string]bool) []discoverClient {
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
		if !isLANSource(c.Src, lans, self) {
			continue // the far end of a tunnel is not a device on this network
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
	lans, self := s.lanPrefixes()
	out := aggregateClientDests(parseConntrack(string(data)), readLeases(), s.markExitResolver(), hostByIP, 50,
		lans, self)
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "clients": out})
}
