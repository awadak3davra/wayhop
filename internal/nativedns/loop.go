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
// listeners are the router's :53 servers, upstreams its configured resolvers, and routerAddrs the
// router's own IP addresses (any form; host parts are compared). All inputs are best-effort — an
// empty set simply yields no findings, so a partial capture degrades to silence rather than to a
// false alarm.
//
// The two cases are deliberately weighted differently:
//
//   - self: the upstream is loopback, or an address this router owns, AND the router serves DNS
//     there. That is a real loop provable from state captured on this box.
//   - lan: the upstream is a private address that is NOT this router. Whether it loops depends on
//     how that host resolves, which cannot be seen from here — so it is reported unconfirmed. A
//     dedicated LAN resolver (Pi-hole, AdGuard Home on another box) is a perfectly normal setup and
//     must not be flagged as broken.
func DetectDNSLoops(listeners []DNSListener, upstreams []string, routerAddrs []string) []DNSLoop {
	if len(upstreams) == 0 {
		return nil
	}
	own := ownAddressSet(routerAddrs, listeners)
	servesDNS := len(listeners) > 0

	var out []DNSLoop
	seen := map[string]bool{}
	for _, up := range upstreams {
		host := hostOf(up)
		if host == "" || seen[host] {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue // a hostname upstream cannot be judged without resolving it, which this must not do
		}
		seen[host] = true

		switch {
		case ip.IsLoopback():
			// Loopback is only a loop when this router actually answers DNS. A loopback upstream with
			// no local listener is a misconfiguration, but a different one — say so accurately.
			if servesDNS {
				out = append(out, DNSLoop{
					Upstream: up, Kind: "self", Confirmed: true,
					Detail: fmt.Sprintf("upstream %s is this router's own loopback and the router serves "+
						"DNS locally, so queries are forwarded back to the resolver that sent them", up),
				})
			} else {
				out = append(out, DNSLoop{
					Upstream: up, Kind: "self", Confirmed: true,
					Detail: fmt.Sprintf("upstream %s points at loopback but nothing is listening for DNS "+
						"there, so resolution cannot succeed", up),
				})
			}
		case own[host]:
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
		h := hostOf(l.Addr)
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
