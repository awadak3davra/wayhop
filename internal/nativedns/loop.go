package nativedns

import (
	"fmt"
	"net"
	"strings"
)

// DNSLoop is one detected (or suspected) DNS resolution loop.
//
// A loop is the failure where the router's resolver forwards a query to something that sends it
// straight back. It does not announce itself: queries hang until they time out, or a resolver
// answers SERVFAIL, and the visible symptom is "the internet is slow" or "some sites don't load".
// Nothing in a config file looks wrong, because each half of the loop is individually reasonable —
// which is exactly why this needs detecting rather than reviewing.
type DNSLoop struct {
	// Upstream is the configured resolver address that closes the loop.
	Upstream string `json:"upstream"`
	// Kind: "self" — the upstream is this router's own DNS listener, so it forwards to itself;
	// "lan" — the upstream is a LAN host, which loops if that host resolves via this router.
	Kind string `json:"kind"`
	// Confirmed distinguishes a loop proven from captured state ("self") from one that depends on a
	// peer's configuration this router cannot see ("lan"). Reporting a suspicion as a certainty
	// would make the check untrustworthy the first time someone ran a legitimate LAN resolver.
	Confirmed bool   `json:"confirmed"`
	Detail    string `json:"detail"`
}

// DetectDNSLoops reports upstreams that resolve back into this router's own DNS path.
//
// listeners are the router's :53 servers, upstreams where its forwarder sends queries (any spelling
// upstreamHostPort reads; no port means 53), and routerAddrs the router's own IP addresses (any form;
// host parts are compared). All inputs are best-effort — an
// empty set simply yields no findings, so a partial capture degrades to silence rather than to a
// false alarm.
//
// The two cases are deliberately weighted differently:
//
//   - self: the upstream is loopback, or an address this router owns, AND a listener serves DNS on
//     that address and port. That is a real loop provable from state captured on this box.
//   - lan: the upstream is a private address that is NOT this router. Whether it loops depends on
//     how that host resolves, which cannot be seen from here — so it is reported unconfirmed. A
//     dedicated LAN resolver (Pi-hole, AdGuard Home on another box) is a perfectly normal setup and
//     must not be flagged as broken.
func DetectDNSLoops(listeners []DNSListener, upstreams []string, routerAddrs []string) []DNSLoop {
	return detectLoops(listeners, upstreams, routerAddrs, "53")
}

// detectLoops is DetectDNSLoops for one forwarder answering on port, whose own sockets are
// listeners. An upstream is that forwarder only when it names the forwarder's port AND an address the
// forwarder listens on (or the wildcard of that address's family). Anything else local is another
// service: dnsmasq's `127.0.0.1#5053` is an https-dns-proxy, 127.0.0.1:53 may be a different resolver
// while dnsmasq is bound to the LAN address, and :53 is another dnsmasq instance for one on 5353.
// Listeners are captured on :53 only, so a forwarder on another port is never proven to loop.
func detectLoops(listeners []DNSListener, upstreams, routerAddrs []string, port string) []DNSLoop {
	if len(upstreams) == 0 {
		return nil
	}
	own := ownAddressSet(routerAddrs, listeners)

	var out []DNSLoop
	seen := map[string]bool{}
	for _, up := range upstreams {
		host, upPort := upstreamHostPort(up)
		if upPort == "" {
			upPort = "53"
		}
		if host == "" || seen[host+"#"+upPort] {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue // a hostname upstream cannot be judged without resolving it, which this must not do
		}
		seen[host+"#"+upPort] = true
		local := ip.IsLoopback() || own[host]
		itself := local && upPort == port && listensAt(listeners, ip, port)

		switch {
		case itself && ip.IsLoopback():
			out = append(out, DNSLoop{
				Upstream: up, Kind: "self", Confirmed: true,
				Detail: fmt.Sprintf("upstream %s is this router's own loopback and the router serves "+
					"DNS locally, so queries are forwarded back to the resolver that sent them", up),
			})
		case local && ip.IsLoopback() && upPort == port && port == "53" && len(listeners) == 0:
			// A loopback upstream with no local listener at all is a misconfiguration, but a different
			// one — say so accurately.
			out = append(out, DNSLoop{
				Upstream: up, Kind: "self", Confirmed: true,
				Detail: fmt.Sprintf("upstream %s points at loopback but nothing is listening for DNS "+
					"there, so resolution cannot succeed", up),
			})
		case local && !itself:
			continue
		case itself:
			out = append(out, DNSLoop{
				Upstream: up, Kind: "self", Confirmed: true,
				Detail: fmt.Sprintf("upstream %s is this router's own address, so its resolver forwards "+
					"queries to itself", up),
			})
		case ip.IsPrivate() || ip.IsLinkLocalUnicast():
			out = append(out, DNSLoop{
				Upstream: up, Kind: "lan", Confirmed: false,
				Detail: fmt.Sprintf("upstream %s is a LAN host; if that host resolves through this "+
					"router, DNS loops between the two. Normal for a dedicated LAN resolver that uses "+
					"its own upstreams", up),
			})
		}
	}
	return out
}

// ownAddressSet collects the router's own address host parts, including any concrete address it is
// listening on (a listener bound to a specific IP is proof the router owns that address; a wildcard
// bind proves nothing about which address it is).
func ownAddressSet(routerAddrs []string, listeners []DNSListener) map[string]bool {
	own := map[string]bool{}
	for _, a := range routerAddrs {
		if h := hostOf(a); h != "" && net.ParseIP(h) != nil {
			own[h] = true
		}
	}
	for _, l := range listeners {
		h, _ := listenerHostPort(l.Addr)
		if h == "" {
			continue
		}
		ip := net.ParseIP(h)
		if ip == nil || ip.IsUnspecified() {
			continue // 0.0.0.0 / :: is a wildcard, not an owned address
		}
		own[h] = true
	}
	return own
}

// upstreamHostPort splits a resolver reference into host and port ("" when none is given), in every
// spelling the readers produce: "ip", "ip:port", "[v6]:port", and dnsmasq's "ip#port", which may
// carry an "@interface" or "@source" suffix.
func upstreamHostPort(s string) (string, string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return strings.Trim(s[:i], "[]"), s[i+1:]
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return hostOf(s), ""
}

// listensAt reports whether a listener on port answers ip: bound to that address, or to the wildcard
// of its family. dnsmasq opens its IPv6 sockets IPv6-only, so 0.0.0.0 does not answer ::1.
func listensAt(listeners []DNSListener, ip net.IP, port string) bool {
	for _, l := range listeners {
		h, p := listenerHostPort(l.Addr)
		if p != port {
			continue
		}
		if h == "*" {
			return true
		}
		lip := net.ParseIP(h)
		switch {
		case lip == nil:
		case lip.Equal(ip):
			return true
		case lip.IsUnspecified() && (lip.To4() != nil) == (ip.To4() != nil):
			return true
		}
	}
	return false
}

// listenerHostPort splits a netstat/ss local address ("0.0.0.0:53", ":::53", "::1:53", "[::1]:53",
// "*:53") at its last colon.
func listenerHostPort(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return "", ""
	}
	return strings.Trim(addr[:i], "[]"), addr[i+1:]
}

// hostOf extracts the host part from "ip", "ip:port", "[v6]:port", or a bare CIDR.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "/"); i >= 0 { // CIDR → address
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(s, "[]")
}
