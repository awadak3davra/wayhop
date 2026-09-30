package server

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"wayhop/internal/health"
	"wayhop/internal/model"
)

// speedHost is the host every speed test reaches (the speedtest package's Cloudflare endpoints).
const speedHost = "speed.cloudflare.com"

// tunnelLink is the kernel device an endpoint's traffic leaves by, resolved the way the health
// monitor resolves it (the applied native binding, else the adopted or derived name), with a
// Keenetic NDM name (Wireguard0) turned into its kernel link (nwg0): the name a socket binds to and
// the counters are kept under. "" for an endpoint that is no kernel tunnel.
func tunnelLink(e model.Endpoint, native map[string]string, known bool) string {
	iface := health.EndpointIface(e, native, known)
	if k := keeneticKernelName(iface); k != "" {
		return k
	}
	return iface
}

// dialLog keeps the local address of every connection a dialer made, so a leg can say afterwards
// which interface it left by: the kernel chose the source address with the route, and no one
// else's traffic moves it (the interface counters, tried first, did: a family member streaming
// through a tunnel during the test made the line leg read as that tunnel).
type dialLog struct {
	mu    sync.Mutex
	local []net.IP
}

// wrap logs dial's connections; a nil dial is the default dialer, on IPv4 like the rest. When a dial
// fails, route, if set, tells the address the connection would have left from, so a leg that never
// connected is still known by its way out.
func (l *dialLog) wrap(dial func(ctx context.Context, network, addr string) (net.Conn, error), route func(ctx context.Context, addr string) net.IP) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, over4(network), addr)
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		var ip net.IP
		switch {
		case err == nil:
			if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
				ip = a.IP
			}
		case route != nil:
			ip = route(ctx, addr)
		}
		if ip != nil {
			l.mu.Lock()
			l.local = append(l.local, ip)
			l.mu.Unlock()
		}
		return c, err
	}
}

// tunnelLeft is the tunnel one of the logged connections left by, or "": a local address on a link
// that is one of WayHop's tunnels, or a tunnel by what the kernel says it is.
func (l *dialLog) tunnelLeft(tunnels map[string]bool) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ip := range l.local {
		if link := linkOfAddr(ip); link != "" && (tunnels[link] || isTunnelDevice(link)) {
			return link
		}
	}
	return ""
}

// linkOfAddr is the interface that holds ip, "" when none does.
var linkOfAddr = func(ip net.IP) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return i.Name
			}
		}
	}
	return ""
}

// isTunnelDevice reports whether a kernel link is a tunnel by what the kernel says it is: a tun
// device (sing-box's TUN, amneziawg-go, OpenVPN) has tun_flags, and a kernel WireGuard or AmneziaWG
// link names its module in its uevent. The link type alone would not do: an LTE modem in raw-IP mode
// has the same type as a tunnel, and would be taken for one.
var isTunnelDevice = func(name string) bool {
	base := "/sys/class/net/" + name + "/"
	if _, err := os.Stat(base + "tun_flags"); err == nil {
		return true
	}
	data, err := os.ReadFile(base + "uevent")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "DEVTYPE="); ok {
			return v == "wireguard" || v == "amneziawg"
		}
	}
	return false
}

// speedRoute is where the speed test's host goes by the configured rules, as /route would answer:
// the first rule or list that names it, else the default route (a Default rule's outbound), else
// direct. named says a rule or list named the site, rather than the default route applying. A geo
// or remote list that may also catch it is not evaluated, as in /route.
func (s *Server) speedRoute(ctx context.Context, p *model.Profile) (route string, named bool) {
	if s.store != nil && namesAnything(p) {
		if res := s.traceDomain(ctx, speedHost); len(res.Configured) > 0 {
			return res.Configured[0].Outbound, true
		}
	}
	for _, r := range p.Rules {
		if r.Default && !r.Disabled {
			return r.Outbound, false
		}
	}
	return model.OutboundDirect, false
}

// namesAnything reports whether any rule or routing list could name a site; with none, the trace
// (and the lookup it starts with) has nothing to find.
func namesAnything(p *model.Profile) bool {
	for _, r := range p.Rules {
		if !r.Default && !r.Disabled {
			return true
		}
	}
	for _, rl := range p.RoutingLists {
		if rl.Enabled {
			return true
		}
	}
	return false
}

// over4 keeps a speed test on IPv4. The tunnels carry IPv4 only; the router's own IPv6 may leave by
// a different path than its IPv4; and a dual-stack dial that tries IPv6 first and falls back adds
// its wait to the latency figure.
func over4(network string) string {
	if network == "tcp" {
		return "tcp4"
	}
	return network
}
