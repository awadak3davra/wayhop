package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// killswitchlocal.go reads the router's own routes for the nft guard.
//
// A kill-switched list may name a private network behind its tunnel, and the routing plane sends
// that network by mark, except what the main table has a route of its own for (unpin.go: `lookup
// main suppress_prefixlength 0`): the router's segments inside the listed range stay reachable. The
// guard has no routing table to ask, so the daemon tells it: the main table's prefixes that are not
// a default route, each with its device and with the side that device is on.
//
// Sides (killswitchzones.go). The provider's side is the device with a default route,
// the other devices of its interface (the physical port under a PPPoE session has no default route,
// and it is the provider's) and the zones that face the provider. A tunnel is a device WayHop runs
// traffic through. The LAN side is every other device a firewall zone holds, whether that zone
// masquerades or not. A device no zone holds, or one in a zone it shares with the uplink, is on no
// known side. A private network a kill-switched list NAMES is accepted only by a route of the
// LAN side: the provider's segment with the same numbers is exactly where that list must not
// go; a device of unknown side gets its answers and nothing else. A range a list only SWEEPS
// (0.0.0.0/0, a bogon feed's supernet) is accepted by any of the router's routes, so the page of
// the modem or of the router upstream stays reachable, as it is on the routing plane.
//
// The guard binds each prefix to its device, so an entry that is no longer true accepts nothing that
// leaves by another device. That is what lets the LAN's routes only grow while the daemon runs: a
// segment that goes down and comes back costs no reload of the guard and no write of its boot copy.
// The routes of any other device are kept as they are read, not as they once were: a stale prefix
// there would accept, by the provider's device, addresses that are no longer its segment. While such
// a device has no route at all (it is down) its routes are kept, so an uplink that flaps costs nothing.
//
// Bounds. Only routes a rule can use are remembered: IPv4 inside private space (a
// judged prefix is always private), IPv6 as read. The guard is told at most ksLocalMax routes of the
// LAN side and ksLocalOtherMax of the rest, counted apart, so a tunnel's two hundred routes
// cannot push the LAN out. If the LAN side still does not fit, or the firewall's zones cannot be
// read at all, the guard is told so (NamesHold.LocalPartial) and lets answers through to the segment
// it was not told about; the log says it once and Diagnostics shows it.
//
// Read from /proc; the zones by `uci show`, at an Apply, when a device appears and every
// ksZoneRefresh. The guard renders an entry only when a rule needs it, so on a router whose
// kill-switched lists cover no private network nothing here changes the program.

const (
	// ksLocalMax bounds the routes of the LAN side the guard is told about, ksLocalOtherMax the
	// routes of every other device, ksLocalSeenMax what the daemon remembers of both.
	ksLocalMax      = 64
	ksLocalOtherMax = 64
	ksLocalSeenMax  = 512
	// ksProviderMax bounds the device names of the provider's side the guard is told.
	ksProviderMax = 16
	// ksZoneRefresh is how old the reading of the firewall's zones may get.
	ksZoneRefresh = 10 * time.Minute
)

// ksLocal is the routes seen since the daemon started and what the guard is told of them.
type ksLocal struct {
	// refresh serializes the readings; mu guards the fields.
	refresh sync.Mutex
	mu      sync.Mutex
	read    bool
	// seen is the remembered routes (House unset).
	seen map[pbr.GuardLocal]ksSeen
	// uplink is every device seen with a default route since the daemon started. Remembered: an
	// uplink whose default route is away for a moment (a lease being renewed) is still the provider's.
	uplink map[string]bool
	// sides is the last good reading of the firewall's zones, taken at sidesAt for the devices sidesFor.
	sides    ksSides
	sidesAt  time.Time
	sidesFor string
	sidesErr string
	// tunnels is the devices WayHop knows as tunnels, from the plan it last installed or renewed.
	tunnels map[string]bool
	// What the guard is told.
	told     []pbr.GuardLocal
	partial  bool
	provider []string
	// houseOver and otherOver are the routes the bounds left out.
	houseOver, otherOver int
	// sources is the operator's source routing remembered since the daemon started, read at
	// sourceAt, and toldSource what the guard is told of it (killswitchsource.go).
	sources    map[pbr.GuardSource]bool
	sourceAt   time.Time
	toldSource []pbr.GuardSource
	// sourceOver is how many pairs of the last reading the bound refused, and
	// sourceOverSaid whether the log has said so (once per daemon run: the set only grows).
	sourceOver     int
	sourceOverSaid bool
	// said is the state the log last described.
	said string
}

// ksSeen is what is remembered of one route: whether the latest reading had it, and whether it
// goes by a gateway (a connected segment is told before a network behind one).
type ksSeen struct{ now, via bool }

// ksReading is one reading of the main table.
type ksReading struct {
	// Routes is every prefix that is not a default route, with its device (House unset).
	Routes []pbr.GuardLocal
	// Via is the routes that go by a gateway.
	Via map[pbr.GuardLocal]bool
	// Uplink is the devices that carry a default route: the ways out.
	Uplink map[string]bool
}

// ksReadLocalRoutes reads the main table's routes; tests replace it.
var ksReadLocalRoutes = func() ksReading {
	v4, _ := os.ReadFile("/proc/net/route")
	v6, _ := os.ReadFile("/proc/net/ipv6_route")
	return localRoutesFrom(string(v4), string(v6), binary.NativeEndian)
}

// noteGuardTunnels tells the reading which devices are the tunnels of plan, the one being installed
// or kept: a tunnel is never the uplink and never the LAN side, whatever zone holds it.
func (s *Server) noteGuardTunnels(plan *pbr.Plan) {
	if s == nil || plan == nil {
		return
	}
	tunnels := planTunnels(plan)
	s.ksLocal.mu.Lock()
	s.ksLocal.tunnels = tunnels
	s.ksLocal.mu.Unlock()
}

// refreshGuardLocal reads the routes again and reports whether what the guard is told changed. The
// reconcile tick and an Apply call it; namesHold only reads what they left, so the install and its
// postcheck render the same program. zones asks for the firewall's zones to be read now (an Apply);
// otherwise they are read when they are unknown, old, or a device appeared.
func (s *Server) refreshGuardLocal(zones bool) bool {
	if s == nil {
		return false
	}
	l := &s.ksLocal
	l.refresh.Lock()
	defer l.refresh.Unlock()
	reading := ksReadLocalRoutes()
	routes, out := reading.Routes, reading.Uplink
	devs := routeDevices(routes, out)

	l.mu.Lock()
	need := zones || !l.sides.known || l.sidesFor != devs || time.Since(l.sidesAt) > ksZoneRefresh
	needSource := zones || time.Since(l.sourceAt) > ksSourceRefresh
	l.mu.Unlock()
	// The operator's own source routing, read no more than once a minute.
	var dump ksSourceDump
	sourceRead := false
	if needSource && s.cfg != nil && !s.config().Demo && s.detectedPlatform() == platform.OpenWrt {
		d, err := ksReadSourceRouting(context.Background(), s.tableIO().read)
		dump, sourceRead = d, err == nil
	}
	var fresh ksSides
	var freshErr error
	if need {
		read := s.uciReader
		if read == nil {
			read = readUCI
		}
		network, firewall, err := read()
		if err == nil {
			fresh = parseSides(network, firewall)
			if !fresh.known {
				err = fmt.Errorf("the firewall configuration names no zone")
			}
		}
		freshErr = err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.read = true
	if need {
		// A reading that failed leaves the last good one in place: the program, and its copy on
		// flash, do not flip with a uci that was busy for a moment.
		if freshErr == nil {
			l.sides, l.sidesErr = fresh, ""
		} else {
			l.sidesErr = freshErr.Error()
		}
		l.sidesAt, l.sidesFor = time.Now(), devs
	}
	if l.seen == nil {
		l.seen = map[pbr.GuardLocal]ksSeen{}
	}
	if l.uplink == nil {
		l.uplink = map[string]bool{}
	}
	for dev := range out {
		if len(l.uplink) < ksLocalSeenMax {
			l.uplink[dev] = true
		}
	}
	judge := l.sides.judge(l.uplink, l.tunnels)
	house := judge.house
	if needSource {
		l.sourceAt = time.Now()
	}
	toldSource := l.noteSourcesLocked(sourceRoutes(dump, judge), sourceRead, judge)

	now := map[pbr.GuardLocal]ksSeen{}
	up := map[string]bool{} // the devices that have a route in this reading
	for _, r := range routes {
		up[r.Dev] = true
		// What no rule can use is not remembered: a judged IPv4 prefix is always private.
		if r.Prefix.Addr().Is4() && !pbr.OverlapsUnpinnable(r.Prefix) {
			continue
		}
		k := pbr.GuardLocal{Dev: r.Dev, Prefix: r.Prefix}
		now[k] = ksSeen{now: true, via: reading.Via[k]}
	}
	for r, was := range l.seen {
		switch {
		case now[r].now:
		case house(r.Dev) || !up[r.Dev] && !out[r.Dev]:
			now[r] = ksSeen{via: was.via} // remembered: the LAN's own, or a device that is down
		}
	}
	l.seen = boundSeen(now, house)

	var hs, others []pbr.GuardLocal
	for r := range l.seen {
		switch {
		case house(r.Dev):
			hs = append(hs, pbr.GuardLocal{Dev: r.Dev, Prefix: r.Prefix, House: true, Via: l.seen[r].via})
		case pbr.OverlapsUnpinnable(r.Prefix):
			// Of the other devices only private space: their public routes are the provider's own
			// segment and the tunnels' servers, nothing the guard should pass by them.
			// A device of unknown side is told as such, unless nothing was read at all: then the
			// guard is told so once, for every device (partial).
			r.Candidate = l.sides.known && judge.side(r.Dev) == sideUnsure
			others = append(others, r)
		}
	}
	l.houseOver, l.otherOver = 0, 0
	if sortLocal(hs, l.seen); len(hs) > ksLocalMax {
		l.houseOver, hs = len(hs)-ksLocalMax, hs[:ksLocalMax]
	}
	// Of the rest, a device that may be the LAN's comes before a tunnel's or the provider's routes.
	sortLocal(others, l.seen)
	sort.SliceStable(others, func(i, j int) bool { return others[i].Candidate && !others[j].Candidate })
	if len(others) > ksLocalOtherMax {
		l.otherOver, others = len(others)-ksLocalOtherMax, others[:ksLocalOtherMax]
	}
	told := append(hs, others...)
	sort.Slice(told, func(i, j int) bool { return lessLocal(told[i], told[j]) })

	var provider []string
	for dev := range judge.up {
		provider = append(provider, dev)
	}
	for r := range l.seen {
		if judge.provider(r.Dev) {
			provider = append(provider, r.Dev)
		}
	}
	provider = sortedUniqueStrings(provider)
	if len(provider) > ksProviderMax {
		provider = provider[:ksProviderMax]
	}
	partial := l.houseOver > 0 || !l.sides.known
	if !partial {
		provider = nil // only the partial guard reads it
	}

	changed := !reflect.DeepEqual(told, l.told) || partial != l.partial || !reflect.DeepEqual(provider, l.provider) ||
		!reflect.DeepEqual(toldSource, l.toldSource)
	l.told, l.partial, l.provider, l.toldSource = told, partial, provider, toldSource
	l.sayLocked()
	return changed
}

// sayLocked logs what the guard was not told, once per state.
func (l *ksLocal) sayLocked() {
	var parts []string
	if !l.sides.known {
		parts = append(parts, "the firewall's zones could not be read ("+l.sidesErr+"), so no device is known to be the LAN's side")
	}
	if l.houseOver > 0 {
		parts = append(parts, fmt.Sprintf("the LAN's side has %d more routes than the %d the guard is told", l.houseOver, ksLocalMax))
	}
	state := strings.Join(parts, "; ")
	if l.otherOver > 0 {
		state += fmt.Sprintf(" [%d routes of other devices left out]", l.otherOver)
	}
	if state == l.said {
		return
	}
	l.said = state
	switch {
	case len(parts) > 0:
		log.Printf("kill switch: %s. Where a kill-switched list covers private addresses, answers to the segments the guard was not told about "+
			"still pass; new connections to them from another segment are held", strings.Join(parts, "; "))
	case l.otherOver > 0:
		log.Printf("kill switch: %d routes of devices that are not the LAN's side are more than the %d the guard is told; where a "+
			"kill-switched list covers all of private space, those networks are held", l.otherOver, ksLocalOtherMax)
	default:
		log.Printf("kill switch: the guard is told all of the router's own routes again")
	}
}

// boundSeen keeps at most ksLocalSeenMax routes: the LAN's before the others, read now before
// remembered.
func boundSeen(now map[pbr.GuardLocal]ksSeen, house func(string) bool) map[pbr.GuardLocal]ksSeen {
	if len(now) <= ksLocalSeenMax {
		return now
	}
	all := make([]pbr.GuardLocal, 0, len(now))
	for r := range now {
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		if hi, hj := house(all[i].Dev), house(all[j].Dev); hi != hj {
			return hi
		}
		if now[all[i]].now != now[all[j]].now {
			return now[all[i]].now
		}
		return lessLocal(all[i], all[j])
	})
	kept := make(map[pbr.GuardLocal]ksSeen, ksLocalSeenMax)
	for _, r := range all[:ksLocalSeenMax] {
		kept[r] = now[r]
	}
	return kept
}

// sortLocal orders routes for a bound: read now before remembered, a connected segment before a
// network behind a gateway (the LAN itself before a routing daemon's feed), IPv4 before IPv6, then
// by prefix and device.
func sortLocal(rs []pbr.GuardLocal, seen map[pbr.GuardLocal]ksSeen) {
	of := func(r pbr.GuardLocal) ksSeen { return seen[pbr.GuardLocal{Dev: r.Dev, Prefix: r.Prefix}] }
	sort.Slice(rs, func(i, j int) bool {
		si, sj := of(rs[i]), of(rs[j])
		if si.now != sj.now {
			return si.now
		}
		if si.via != sj.via {
			return sj.via
		}
		if a, b := rs[i].Prefix.Addr().Is4(), rs[j].Prefix.Addr().Is4(); a != b {
			return a
		}
		if c := rs[i].Prefix.Addr().Compare(rs[j].Prefix.Addr()); c != 0 {
			return c < 0
		}
		if rs[i].Prefix.Bits() != rs[j].Prefix.Bits() {
			return rs[i].Prefix.Bits() < rs[j].Prefix.Bits()
		}
		return rs[i].Dev < rs[j].Dev
	})
}

func lessLocal(a, b pbr.GuardLocal) bool {
	if a.Dev != b.Dev {
		return a.Dev < b.Dev
	}
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	return a.Prefix.Bits() < b.Prefix.Bits()
}

// routeDevices names the devices of a reading, for telling when one appeared.
func routeDevices(routes []pbr.GuardLocal, out map[string]bool) string {
	var devs []string
	for _, r := range routes {
		devs = append(devs, r.Dev)
	}
	for d := range out {
		devs = append(devs, d)
	}
	return strings.Join(sortedUniqueStrings(devs), " ")
}

func sortedUniqueStrings(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if s != "" && (i == 0 || s != in[i-1]) {
			out = append(out, s)
		}
	}
	return out
}

// guardLocalState is what the guard is told about the router's own routes: the routes in a stable
// order, whether they are not all of the LAN side, and the provider's devices for that case.
func (s *Server) guardLocalState() (local []pbr.GuardLocal, partial bool, provider []string) {
	if s == nil {
		return nil, false, nil
	}
	l := &s.ksLocal
	l.mu.Lock()
	read := l.read
	l.mu.Unlock()
	if !read {
		s.refreshGuardLocal(false)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]pbr.GuardLocal(nil), l.told...), l.partial, append([]string(nil), l.provider...)
}

// everUplink is uplink with every device the daemon has seen carry a default route.
func (s *Server) everUplink(uplink map[string]bool) map[string]bool {
	out := map[string]bool{}
	for d := range uplink {
		out[d] = true
	}
	s.ksLocal.mu.Lock()
	defer s.ksLocal.mu.Unlock()
	for d := range s.ksLocal.uplink {
		out[d] = true
	}
	return out
}

// guardLocal is the routes the guard is told about.
func (s *Server) guardLocal() []pbr.GuardLocal {
	local, _, _ := s.guardLocalState()
	return local
}

// localRoutesFrom reads /proc/net/route and /proc/net/ipv6_route. order is the byte order the
// kernel printed the IPv4 fields in: its own.
//
//	Iface   Destination Gateway  Flags RefCnt Use Metric Mask     MTU Window IRTT
//	br-lan  0001A8C0    00000000 0001  0      0   0      00FFFFFF 0   0      0
//
//	fd00000000000000 0000000000000000 40 00000000000000000000000000000000 00 <nexthop> 00000400 00000001 00000000 00000001 br-lan
//
// (the IPv6 file prints each address as 32 digits; it is abbreviated above). Left out: default
// routes, and routes so broad that they are a default route in halves (shorter than /8, or /16 for
// IPv6); loopback; reject routes; host routes of the router's own IPv6 addresses; link-local and
// multicast. Which of the routes the guard can use, and by which side, is the caller's to say.
func localRoutesFrom(route4, route6 string, order binary.ByteOrder) ksReading {
	const (
		rtfUp      = 0x1
		rtfGateway = 0x2
		rtfReject  = 0x200
	)
	out := map[string]bool{} // the devices that are a way out
	via := map[pbr.GuardLocal]bool{}
	var routes []pbr.GuardLocal
	lines := strings.Split(route4, "\n")
	if len(lines) > 0 {
		lines = lines[1:] // the header
	}
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		mask, err2 := strconv.ParseUint(f[7], 16, 32)
		flags, err3 := strconv.ParseUint(f[3], 16, 32)
		if err1 != nil || err2 != nil || err3 != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		var a, m [4]byte
		order.PutUint32(a[:], uint32(dst))
		order.PutUint32(m[:], uint32(mask))
		ones := bits.OnesCount32(binary.BigEndian.Uint32(m[:]))
		if bits.LeadingZeros32(^binary.BigEndian.Uint32(m[:])) != ones {
			continue // not a prefix mask
		}
		addr := netip.AddrFrom4(a)
		if addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		if ones < 8 {
			out[f[0]] = true
			continue
		}
		r := pbr.GuardLocal{Dev: f[0], Prefix: netip.PrefixFrom(addr, ones).Masked()}
		routes = append(routes, r)
		if flags&rtfGateway != 0 {
			via[r] = true
		}
	}
	for _, ln := range strings.Split(route6, "\n") {
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		raw, err1 := hex.DecodeString(f[0])
		plen, err2 := strconv.ParseUint(f[1], 16, 8)
		flags, err3 := strconv.ParseUint(f[8], 16, 32)
		dev := f[9]
		if err1 != nil || err2 != nil || err3 != nil || len(raw) != 16 || plen > 128 || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		addr := netip.AddrFrom16([16]byte(raw))
		if addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() || addr.Is4In6() {
			continue
		}
		if plen < 16 {
			out[dev] = true
			continue
		}
		if plen == 128 {
			continue
		}
		r := pbr.GuardLocal{Dev: dev, Prefix: netip.PrefixFrom(addr, int(plen)).Masked()}
		routes = append(routes, r)
		if flags&rtfGateway != 0 {
			via[r] = true
		}
	}
	kept := routes[:0]
	for _, r := range routes {
		if r.Dev != "lo" {
			kept = append(kept, r)
		}
	}
	return ksReading{Routes: kept, Via: via, Uplink: out}
}
