package server

import (
	"net"
	"os"
	"sync"
	"time"
)

// Host allow-list decision for the DNS-rebinding guard.
//
// Threat model: the panel is unauthenticated and binds all interfaces. After a DNS rebind the
// attacker's page and the panel share an origin, so Origin==Host and the same-origin guard passes.
// Only pinning Host to names this router actually answers to stops it.
//
// The decision NEVER resolves the Host. Resolving it and accepting "it points at a local IP" is the
// rebinding attack restated as a rule.

// hostDecider answers whether a request Host may be served.
type hostDecider struct {
	configured func() []string // operator's allowed_hosts
	anyHost    func() bool     // explicit compatibility opt-out

	mu       sync.Mutex
	local    map[string]struct{} // literal IPs currently on this machine
	names    map[string]struct{} // locally-derived names (hostname, localhost)
	loadedAt time.Time
}

var (
	// Interface addresses change (DHCP lease, a tunnel coming up), so the snapshot expires.
	localAddrTTL = 5 * time.Second
	// A miss refreshes before denying, so a just-assigned address is not refused for a whole TTL.
	// Rate-limited: without it, unknown Hosts would drive an interface enumeration per request, which
	// is a cheap way to make the guard expensive. Variables so a test can exercise the refresh path
	// without sleeping through the real interval.
	localAddrMissRefresh = time.Second
)

func newHostDecider(configured func() []string, anyHost func() bool) *hostDecider {
	return &hostDecider{configured: configured, anyHost: anyHost}
}

// allow reports whether host (a raw Host header) may be served.
func (d *hostDecider) allow(host string) bool {
	if d.anyHost != nil && d.anyHost() {
		return true
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	for _, c := range d.configured() {
		if n := normalizeHost(c); n != "" && n == h {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() {
			return true
		}
		return d.isLocalAddr(h)
	}
	return d.isLocalName(h)
}

// isLocalAddr reports whether h is an IP literal currently assigned to an interface.
func (d *hostDecider) isLocalAddr(h string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshLocked(false)
	if _, ok := d.local[h]; ok {
		return true
	}
	if time.Since(d.loadedAt) >= localAddrMissRefresh {
		d.refreshLocked(true)
		_, ok := d.local[h]
		return ok
	}
	return false
}

func (d *hostDecider) isLocalName(h string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshLocked(false)
	_, ok := d.names[h]
	return ok
}

// refreshLocked reloads the local snapshot when it is stale (or when force is set).
func (d *hostDecider) refreshLocked(force bool) {
	if !force && d.local != nil && time.Since(d.loadedAt) < localAddrTTL {
		return
	}
	addrs := localAddrs()
	names := map[string]struct{}{"localhost": {}}
	if hn, err := os.Hostname(); err == nil {
		// The hostname is read from the OS, never from the request, so it cannot be attacker-chosen.
		if n := normalizeHost(hn); n != "" {
			names[n] = struct{}{}
			// Routers publish the same name under the LAN search domains; both are locally derived.
			names[n+".lan"] = struct{}{}
			names[n+".local"] = struct{}{}
		}
	}
	d.local, d.names, d.loadedAt = addrs, names, time.Now()
}

// localAddrs is a variable so tests can supply a fixed set instead of the host's real interfaces,
// which differ per machine and would make the matrix below untestable.
var localAddrs = func() map[string]struct{} {
	out := map[string]struct{}{}
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range ifaces {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		// Zone-qualified link-local (fe80::1%eth0) is stored unqualified: a Host header carries no zone.
		out[normalizeHost(ip.String())] = struct{}{}
	}
	return out
}
