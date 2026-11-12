package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/pbr"
)

// listfeedbind.go makes a routing list's CIDR and domain feeds leave the way the list says.
//
// RoutingList.DownloadVia only reached sing-box, as a rule set's download_detour. The two feeds the
// daemon fetches itself went out over the provider with no regard to it, so a router configured to
// download every list through a VPN announced "antifilter" to its provider on each refresh. Measured
// on a live Keenetic: at the 12 h refresh, the provider's address to peer.antifilter.download:443.
//
// Same mechanism as Updater.DownloadVia, and for the same reason it is not a routing change: the socket
// is bound to the chosen link (SO_BINDTODEVICE) for the fetch, with no mark, table or rule to undo.
//
// THE FALLBACK RULE, which is a different one from the updater's. A component download with no path
// leaves the router unable to install anything; a list feed with no path leaves the router with the
// list it already has. So a feed never quietly takes the provider's path:
//
//   - No via, or "direct": the ordinary path. That is what the operator asked for.
//   - A tunnel: the socket is bound to its link. A tunnel that is switched off or gone, or one that
//     does not answer, fails the refresh. The list keeps its last-good content, the failure is reported
//     on the Routing page, and the list is asked again on the next hourly tick.
//   - A group: the operator's order, first healthy member with a link. A member named "direct" counts
//     as a member, so a group ending in direct is how an operator asks for "tunnels, then the provider".
//     A group with no direct and no healthy member fails as a tunnel does.
//   - A proxy outbound (or a group of nothing else): carried by sing-box, with no link for a socket to
//     bind to. The feed stays on the ordinary path, as it always did, and the Routing page says so.
//     Refusing would stop feeds that work today, with no way for this socket to reach that outbound.
//
// sing-box applies the same rule to a rule set: a download_detour that is down keeps the cached set.

// errFeedPathDown marks a refresh that was not attempted, or could not finish, because the list's
// download path is down. It says nothing about the feed, so the auto-refresh asks again at the next
// tick instead of waiting out the list's whole interval.
var errFeedPathDown = errors.New("its download path is down, so the last-good list stays")

// feedVia is the outbound a list's feeds leave through: the list's own choice, else the profile-wide
// default its rule sets use. One knob for one question, as the generator reads it.
func (s *Server) feedVia(rl model.RoutingList) string {
	if rl.DownloadVia != "" {
		return rl.DownloadVia
	}
	return s.config().RuleSetDetour
}

// feedIface answers where a feed leaves right now under the rule above: the link to bind, "" for the
// ordinary path, or errFeedPathDown. It is called once per connection, so a failover between two
// requests of a multi-ASN feed moves to the live member.
func (s *Server) feedIface(via string) (string, error) {
	if via == "" || via == model.OutboundDirect {
		return "", nil
	}
	profile := s.store.Profile()
	if e := profile.EndpointByID(via); e != nil {
		iface := pbr.KernelIface(e)
		switch {
		case !e.Enabled:
			return "", fmt.Errorf("%w (%q is switched off)", errFeedPathDown, via)
		case iface == "":
			return "", nil // a proxy outbound: no link to bind to
		}
		// Health is not consulted for one tunnel. The dial is a better test than the last probe, and it
		// fails rather than escapes: a socket bound to a dead link reaches nothing.
		return iface, nil
	}
	if g := profile.GroupByID(via); g != nil {
		return s.groupFeedIface(&profile, g)
	}
	return "", fmt.Errorf("%w (%q is no longer in the profile)", errFeedPathDown, via)
}

func (s *Server) groupFeedIface(p *model.Profile, g *model.Group) (string, error) {
	alive := map[string]bool{}
	if s.monitor != nil {
		for _, h := range s.monitor.MemberHealth(g.Members) {
			alive[h.ID] = h.Alive
		}
	}
	return groupFeedPath(p, g, alive)
}

// groupFeedPath walks a group's members in order, kept apart from the monitor as electMember is. It also
// answers for direct members and for proxy-only groups, which the routing-list election has no need to.
func groupFeedPath(p *model.Profile, g *model.Group, alive map[string]bool) (string, error) {
	links := false
	for _, id := range g.Members {
		if id == model.OutboundDirect {
			return "", nil // the operator's own "then the provider"
		}
		e := p.EndpointByID(id)
		if e == nil || !e.Enabled {
			continue
		}
		iface := pbr.KernelIface(e)
		if iface == "" {
			continue
		}
		links = true
		if alive[id] {
			return iface, nil
		}
	}
	if !links {
		return "", nil // nothing in this group has a link to bind to
	}
	return "", fmt.Errorf("%w (no member of %q is healthy)", errFeedPathDown, g.ID)
}

// feedPathNote is what the Routing page states about a list's feeds, when the dropdown alone would
// mislead: the rule above is holding them back, or the outbound cannot carry them. A list on the path
// its dropdown names, or with no feed, has nothing to add.
func feedPathNote(s *Server, rl model.RoutingList) string {
	if rl.CIDRSource == "" && rl.DomainSource == "" {
		return ""
	}
	via := s.feedVia(rl)
	if via == "" || via == model.OutboundDirect {
		return ""
	}
	iface, err := s.feedIface(via)
	switch {
	case errors.Is(err, errFeedPathDown):
		return "The feed is waiting: " + err.Error() + "."
	case iface == "" && !s.feedEndsInDirect(via):
		return "This connection has no network link to bind to, so the feed leaves over your provider."
	}
	return ""
}

// feedEndsInDirect reports a group the rule above has just fallen through to its direct member, which
// is the operator's own choice and needs no note.
func (s *Server) feedEndsInDirect(via string) bool {
	profile := s.store.Profile()
	if g := profile.GroupByID(via); g != nil {
		return groupHasDirect(g)
	}
	return false
}

// listFetchClient is subscriptionFetchClient for one list's feeds: the same SSRF guard and capped
// redirects, with its sockets bound under the rule above. A direct list gets exactly the old client.
func (s *Server) listFetchClient(via string) *http.Client {
	if via == "" || via == model.OutboundDirect {
		return s.subscriptionFetchClient()
	}
	bind := func(network, address string, c syscall.RawConn) error {
		iface, err := s.feedIface(via)
		if err != nil {
			return err
		}
		return bindFeedSocket(iface, network, address, c)
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if !s.allowInternalFetch {
				if err := blockInternalDial(network, address, c); err != nil {
					return err
				}
			}
			return bind(network, address, c)
		},
		Resolver: s.feedResolver(via, bind),
	}
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: dialer.DialContext, IdleConnTimeout: 30 * time.Second},
		CheckRedirect: subscriptionRedirect,
	}
}

// feedFetchError names a bound fetch that never got an answer as the path being down, as opposed to the
// feed itself failing: a tunnel that does not answer says nothing about the feed. An HTTP error is the
// feed's own answer, so it stays what it is.
func feedFetchError(iface string, err error) error {
	var ne net.Error
	if iface != "" && errors.As(err, &ne) {
		return fmt.Errorf("%w: %v", errFeedPathDown, err)
	}
	return err
}

// bindFeedSocket applies the binding. Off Linux there is no such socket option and BindToDevice returns
// nil: the daemon only runs there as the local demo, where there are no tunnels to bind to.
func bindFeedSocket(iface, network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	if bind := netdiag.BindToDevice(iface); bind != nil {
		return bind(network, address, c)
	}
	return nil
}

// feedLookupResolvers answer a bound feed's name lookup when the router's resolv.conf names only
// something local, which a socket bound to a tunnel cannot reach.
var feedLookupResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// feedResolver keeps the feed's name lookup on the same path as the feed. A socket option on the dialer
// does not reach the resolver, which opens sockets of its own, and the name is the part a provider
// reads for free: peer.antifilter.download in plaintext says what the bound TLS connection hid.
//
// The servers stay the router's own resolv.conf where they can be reached through a tunnel. A local one
// (127.0.0.1, a LAN forwarder) is swapped for a public resolver only while the socket is really bound;
// on the ordinary path, which a group ending in direct can fall to, the lookup is left as it was.
func (s *Server) feedResolver(via string, bind func(network, address string, c syscall.RawConn) error) *net.Resolver {
	var next atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if iface, err := s.feedIface(via); err == nil && iface != "" && !publicResolverAddr(address) {
				address = feedLookupResolvers[int(next.Add(1)-1)%len(feedLookupResolvers)]
			}
			d := net.Dialer{Timeout: 5 * time.Second, Control: bind}
			return d.DialContext(ctx, network, address)
		},
	}
}

// publicResolverAddr reports whether a resolver address from resolv.conf can answer through a tunnel:
// not loopback, private or link-local. On a bound socket those would time out instead of answering.
func publicResolverAddr(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	return !isInternalDialIP(net.ParseIP(strings.Trim(host, "[]")))
}
