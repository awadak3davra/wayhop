package server

import (
	"errors"
	"log"
	"net/netip"
	"sync"

	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// ctflushLimit bounds how many conntrack entries one Apply may remove: a mistake in the plan must not
// become a reset of every connection on the router.
const ctflushLimit = 4096

// ctflushOpen is the conntrack table the flush works on; tests replace it.
var ctflushOpen = ctflush.Open

// ctflushNoModule says once per run that the kernel cannot list connections, rather than on every Apply.
var ctflushNoModule sync.Once

// ctflushLocal reports the router's own addresses, read when the flush runs; tests replace it.
var ctflushLocal = ownAddrs

// flushStaleFlows removes the conntrack entries a kernel-plane change left on the wrong exit. It never
// fails the caller: the routing change has landed either way, and a flow left behind still ends on its
// own (or, for UDP with keepalives, does not - which is why this runs on every path that changes the
// plane: Apply, rollback, routing off and on, boot after a restart). It runs once the new plane is
// live, and ctflush judges each flow by what that plane does with its next packet. Logged.
func (s *Server) flushStaleFlows(prev, cur *pbr.Plan) {
	if s.config().Demo || !ctflush.Changed(prev, cur) {
		return
	}
	t, err := ctflushOpen()
	if err != nil {
		if !errors.Is(err, ctflush.ErrUnsupported) {
			log.Printf("apply: connections on the old routes were left as they are (conntrack unavailable: %v)", err)
		}
		return
	}
	defer t.Close()
	cfg := s.config()
	opt := ctflush.Options{Limit: ctflushLimit, Local: ctflushLocal(), Hybrid: s.routingMode(cfg) == "hybrid"}
	if s.detectedPlatform() == platform.Keenetic {
		opt.Plane = ctflush.PlaneIpset // applykeeneticpbr.go renders the iptables + ipset plane there
	}
	res, err := ctflush.Flush(t, prev, cur, opt)
	switch {
	case errors.Is(err, ctflush.ErrNoModule):
		ctflushNoModule.Do(func() {
			log.Printf("apply: connections on the old routes are left to end on their own: %v (OpenWrt: install kmod-nf-conntrack-netlink)", err)
		})
	case err != nil:
		log.Printf("apply: moved %d connection(s) to their new route, then stopped: %v", res.Deleted, err)
	case res.Capped:
		log.Printf("apply: moved %d connection(s) to their new route and stopped at the limit; the rest move when they end", res.Deleted)
	case res.Deleted > 0:
		log.Printf("apply: moved %d connection(s) to their new route (%d examined)", res.Deleted, res.Seen)
	}
}

// ownAddrs reports whether an address is the router's own (routerAddrs, read now). An empty set means
// the interfaces could not be read - a router always has loopback - and then every address counts as
// the router's, so the flush touches nothing rather than guess.
func ownAddrs() func(netip.Addr) bool {
	own := routerAddrs()
	if len(own) == 0 {
		return func(netip.Addr) bool { return true }
	}
	return func(a netip.Addr) bool { return own[a.Unmap().String()] }
}
