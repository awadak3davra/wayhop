package server

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// killswitchzones.go says which side of the router a device is on, and what Review
// and Diagnostics say about it.
//
// Three sides, and one answer for "not known":
//
//   - The provider's: a device that carries a default route in the main table (IPv4 or IPv6), every
//     device of the interface that route belongs to (the port under a PPPoE session, wan6 beside
//     wan, a second interface on the same port), and every device of a firewall zone that faces the
//     provider. A zone faces the provider when it does not accept input and either holds the uplink,
//     or is only ever the destination of a forwarding and all its interfaces are configured as
//     clients of another network (a WAN whose default route lives in another table: mwan3, ip4table).
//   - A tunnel: a device WayHop itself runs traffic through, the kernel links of its endpoints and
//     the core's TUN. Whatever zone it is in, and whatever routes it carries.
//   - The LAN's: any other device a firewall zone holds. The LAN, a guest or IoT network, the
//     clients of a WireGuard server.
//   - Not known: a device no zone holds, or one that shares a zone with the uplink while that zone
//     accepts input (a tunnel with a default route put into the LAN zone, or the reverse). Such a
//     device gets its answers and no new connection to a network a list names.
//
// Masquerading says nothing: OpenWrt ships it on the wan zone only, and routers in the field have it
// on lan and on the tunnels' zone as well. No name is assumed either: not "wan", not "lan". "No
// default route" alone does not make a device the LAN's: the physical port under a PPPoE or L2TP
// session has none, and it is the provider's.
//
// A zone names interfaces (`network`), which uci maps to devices, and devices as they are (`device`,
// a trailing + for "any with this prefix"):
//
//	firewall.@zone[1].name='wan'
//	firewall.@zone[1].network='wan' 'wan6'
//	firewall.@zone[1].input='REJECT'
//	firewall.@forwarding[0].src='lan'
//	firewall.@forwarding[0].dest='wan'
//	network.wan.device='eth1'
//	network.wan.proto='pppoe'            (its session is the device pppoe-wan)
//	network.lan.device='br-lan'
//
// netifd names an interface's own device <kind>-<interface> (pppoe-wan, l2tp-wan, 6in4-wan6, and
// br-lan for a bridge declared the old way), and a tunnel's device after the interface itself, so a
// device with such a name belongs to that interface whatever uci says its lower device is. That is
// the configuration's own naming, read against the interfaces it declares, not a guess from a name.

// ksSide is the side of the router a device is on.
type ksSide int

const (
	sideUnsure ksSide = iota
	sideHouse
	sideProvider
	sideTunnel
)

// ksSides is one reading of the network and firewall configuration.
type ksSides struct {
	// known is false when nothing was read: then no device is the LAN's.
	known bool
	zones []ksZone
	// ifaces is the interfaces the network configuration declares or a zone names, sorted.
	ifaces []string
	// devs is the devices uci gives each interface; an entry "@x" is the interface x's.
	devs map[string][]string
	// client is the interfaces configured to take their address or their gateway from another
	// network: a protocol that asks for one, or a gateway stated by hand.
	client map[string]bool
	// proto is each interface's protocol as the network configuration states it.
	proto map[string]string
}

type ksZone struct {
	name     string
	networks []string
	devices  []string
	// acceptsInput is the zone's input policy (the firewall's default when the zone states none).
	acceptsInput bool
	// src and dest say whether any forwarding leaves the zone or enters it.
	src, dest bool
}

// ksClientProtos are the interface protocols by which the router is a client of another network.
// wireguard and the like are not among them: the same protocol is a server for the LAN's own
// clients.
var ksClientProtos = map[string]bool{
	"dhcp": true, "dhcpv6": true, "pppoe": true, "pppoa": true, "pptp": true, "l2tp": true,
	"3g": true, "qmi": true, "ncm": true, "mbim": true, "modemmanager": true, "wwan": true,
	"dslite": true, "map": true, "464xlat": true, "6in4": true, "6rd": true, "6to4": true,
}

// uciSection is one section of `uci show`: its name (cfg0123ab, @zone[0], lan), type and options.
type uciSection struct {
	name, typ string
	opt       map[string][]string
}

// uciSections reads `uci show <config>` in the order the sections appear.
func uciSections(config, text string) []*uciSection {
	byName := map[string]*uciSection{}
	var out []*uciSection
	for _, ln := range strings.Split(text, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(ln), "=")
		parts := strings.SplitN(key, ".", 3)
		if !ok || len(parts) < 2 || parts[0] != config {
			continue
		}
		s := byName[parts[1]]
		if s == nil {
			s = &uciSection{name: parts[1], opt: map[string][]string{}}
			// An anonymous section carries its type in its name: @zone[0].
			if anon, ok := strings.CutPrefix(parts[1], "@"); ok {
				s.typ, _, _ = strings.Cut(anon, "[")
			}
			byName[parts[1]] = s
			out = append(out, s)
		}
		if len(parts) == 2 {
			s.typ = strings.Join(uciWords(val), "")
			continue
		}
		s.opt[parts[2]] = append(s.opt[parts[2]], uciWords(val)...)
	}
	return out
}

func (s *uciSection) first(opt string) string {
	if v := s.opt[opt]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// parseSides reads `uci show network` and `uci show firewall`.
func parseSides(network, firewall string) ksSides {
	sd := ksSides{devs: map[string][]string{}, client: map[string]bool{}, proto: map[string]string{}}
	ifaces := map[string]bool{}
	for _, s := range uciSections("network", network) {
		if s.typ != "interface" {
			continue
		}
		ifaces[s.name] = true
		if p := s.first("proto"); p != "" {
			sd.proto[s.name] = p
		}
		if devs := append(append([]string(nil), s.opt["device"]...), s.opt["ifname"]...); len(devs) > 0 {
			sd.devs[s.name] = devs
		}
		if ksClientProtos[s.first("proto")] || s.first("gateway") != "" || s.first("ip6gw") != "" {
			sd.client[s.name] = true
		}
	}
	sections := uciSections("firewall", firewall)
	accepts := func(policy string) bool { return strings.EqualFold(policy, "ACCEPT") }
	// fw4 drops input where neither the zone nor the defaults say otherwise.
	defaultInput := false
	src, dest := map[string]bool{}, map[string]bool{}
	for _, s := range sections {
		switch s.typ {
		case "defaults":
			defaultInput = accepts(s.first("input"))
		case "forwarding":
			src[s.first("src")], dest[s.first("dest")] = true, true
		}
	}
	for _, s := range sections {
		if s.typ != "zone" {
			continue
		}
		z := ksZone{name: s.first("name"), networks: s.opt["network"], devices: s.opt["device"], acceptsInput: defaultInput}
		if in := s.first("input"); in != "" {
			z.acceptsInput = accepts(in)
		}
		if len(z.networks)+len(z.devices)+len(s.opt["subnet"]) == 0 && z.name != "" {
			z.networks = []string{z.name} // fw4: a zone that names nothing holds the interface of its own name
		}
		z.src, z.dest = src[z.name], dest[z.name]
		for _, n := range z.networks {
			ifaces[n] = true
		}
		sd.zones = append(sd.zones, z)
	}
	for n := range ifaces {
		sd.ifaces = append(sd.ifaces, n)
	}
	sort.Strings(sd.ifaces)
	sd.known = len(sd.zones) > 0
	return sd
}

// uciWords splits a uci value: 'a' 'b', or the older 'a b'.
func uciWords(val string) []string {
	return strings.Fields(strings.NewReplacer("'", " ", "\"", " ").Replace(val))
}

// ifaceHolds reports whether dev is a device of the interface n.
func (sd ksSides) ifaceHolds(n, dev string, depth int) bool {
	if dev == n || strings.HasSuffix(dev, "-"+n) {
		return true
	}
	for _, d := range sd.devs[n] {
		if d == dev {
			return true
		}
		if alias, ok := strings.CutPrefix(d, "@"); ok && depth < 2 && sd.ifaceHolds(alias, dev, depth+1) {
			return true
		}
	}
	return false
}

// sameUplink reports whether the interfaces a and b are one way out: one is an alias of the other
// (wan6 on @wan), or both are configured on the same device (PPPoE and the provider's own network on
// one port).
func (sd ksSides) sameUplink(a, b string) bool {
	for _, d := range sd.devs[a] {
		if d == "@"+b {
			return true
		}
		for _, e := range sd.devs[b] {
			if e == "@"+a || d == e && !strings.HasPrefix(d, "@") {
				return true
			}
		}
	}
	for _, e := range sd.devs[b] {
		if e == "@"+a {
			return true
		}
	}
	return false
}

func (sd ksSides) zoneHolds(z ksZone, dev string) bool {
	for _, n := range z.networks {
		if sd.ifaceHolds(n, dev, 0) {
			return true
		}
	}
	for _, d := range z.devices {
		// fw4 takes a trailing + as "any device with this prefix".
		if d == dev || strings.HasSuffix(d, "+") && strings.HasPrefix(dev, strings.TrimSuffix(d, "+")) {
			return true
		}
	}
	return false
}

// Zone kinds, by what the routes and the firewall say together.
const (
	zoneInward  = iota // the LAN's
	zoneOutward        // faces the provider
	zoneMixed          // holds the uplink and accepts input: says nothing about its other devices
)

// ksJudge is a reading of the configuration set against the routes: which devices are a way out,
// and which are WayHop's tunnels.
type ksJudge struct {
	sd     ksSides
	up     map[string]bool // devices with a default route that are not tunnels
	upIf   map[string]bool // the interfaces those devices belong to
	tunnel map[string]bool
	kind   []int // per zone of sd.zones
}

// judge sets the reading against uplink, the devices that carry a default route, and tunnel, the
// devices WayHop knows as tunnels. A tunnel is never the uplink: the kernel lists the IPv6 routes of
// every table in one file, WayHop's own default route by a tunnel among them.
func (sd ksSides) judge(uplink, tunnel map[string]bool) ksJudge {
	j := ksJudge{sd: sd, up: map[string]bool{}, upIf: map[string]bool{}, tunnel: tunnel}
	for dev := range uplink {
		if !tunnel[dev] {
			j.up[dev] = true
		}
	}
	for _, n := range sd.ifaces {
		for dev := range j.up {
			if sd.ifaceHolds(n, dev, 0) {
				j.upIf[n] = true
			}
		}
	}
	for grown := true; grown; {
		grown = false
		for _, n := range sd.ifaces {
			if j.upIf[n] {
				continue
			}
			for _, m := range sd.ifaces {
				if j.upIf[m] && sd.sameUplink(n, m) {
					j.upIf[n], grown = true, true
					break
				}
			}
		}
	}
	for _, z := range sd.zones {
		j.kind = append(j.kind, j.zoneKind(z))
	}
	return j
}

func (j ksJudge) zoneKind(z ksZone) int {
	holdsUp := false
	for _, n := range z.networks {
		holdsUp = holdsUp || j.upIf[n]
	}
	for dev := range j.up {
		holdsUp = holdsUp || j.sd.zoneHolds(z, dev)
	}
	switch {
	case holdsUp && z.acceptsInput:
		return zoneMixed
	case holdsUp:
		return zoneOutward
	case z.acceptsInput || !z.dest || z.src || len(z.devices) > 0 || len(z.networks) == 0:
		return zoneInward
	}
	// No route says this zone is a way out. The firewall does, when nothing else can be meant:
	// input is not accepted, traffic is only ever forwarded into it, and every interface it holds
	// is a client of another network. An isolated IoT zone fails the last test (the router is that
	// network's own gateway), a tunnels' zone too (a server's clients look the same).
	for _, n := range z.networks {
		if !j.sd.client[n] {
			return zoneInward
		}
	}
	return zoneOutward
}

// side says which side dev is on.
func (j ksJudge) side(dev string) ksSide {
	if j.tunnel[dev] {
		return sideTunnel
	}
	if j.up[dev] {
		return sideProvider
	}
	for n := range j.upIf {
		if j.sd.ifaceHolds(n, dev, 0) {
			return sideProvider
		}
	}
	if !j.sd.known {
		return sideUnsure
	}
	side := sideUnsure
	for i, z := range j.sd.zones {
		if !j.sd.zoneHolds(z, dev) {
			continue
		}
		switch j.kind[i] {
		case zoneOutward:
			return sideProvider
		case zoneMixed:
			return sideUnsure
		}
		side = sideHouse
	}
	return side
}

func (j ksJudge) house(dev string) bool    { return j.side(dev) == sideHouse }
func (j ksJudge) provider(dev string) bool { return j.side(dev) == sideProvider }

// planTunnels is the devices WayHop knows as tunnels for plan: the kernel links of its endpoints and
// the core's TUN.
func planTunnels(plan *pbr.Plan) map[string]bool {
	out := map[string]bool{}
	if plan == nil {
		return out
	}
	for _, d := range plan.TunnelDevices() {
		out[d] = true
	}
	if plan.CoreTun != "" {
		out[plan.CoreTun] = true
	} else {
		out[ksLegacyCoreTun] = true
	}
	return out
}

const (
	findingNamedOnProvider = "kill_switch.named_on_provider"
	findingSweptUplinkDNS  = "kill_switch.swept_uplink_resolver"
	findingNamedOnHouse    = "kill_switch.named_on_house"
)

// providerSideFindings says what the router's own routes mean for a kill switch over private
// addresses. routes and uplink are the main table as killswitchlocal.go
// reads it.
//
// A network a kill-switched list names that a device outside the LAN side has a route into: the
// routing plane would answer from that route, the provider's segment; the guard holds it instead, so
// that part of the list is out of reach whenever its tunnel does not carry it, and Review says why.
//
// A range a list only sweeps, with the uplink's own private segment inside: that segment stays
// reachable, the provider's box with it, and a device set by hand to use that box as its resolver
// has its lookups answered by the provider.
func providerSideFindings(plan *pbr.Plan, sd ksSides, routes []pbr.GuardLocal, uplink map[string]bool) []PlanFinding {
	named, swept := plan.GuardJudgedPrivate()
	if len(named)+len(swept) == 0 || !sd.known {
		return nil
	}
	j := sd.judge(uplink, planTunnels(plan))
	sort.Slice(routes, func(a, b int) bool { return lessLocal(routes[a], routes[b]) })
	var out []PlanFinding
	seen := map[string]bool{}
	for _, p := range named {
		for _, r := range routes {
			side := j.side(r.Dev)
			if !r.Prefix.Overlaps(p) || side == sideTunnel || seen[p.String()+r.Dev] {
				continue
			}
			seen[p.String()+r.Dev] = true
			if side == sideHouse && !j.tunnelDevice(r.Dev) {
				continue // the LAN's own segment inside a listed range: nothing to say
			}
			if side == sideHouse {
				// A tunnel WayHop does not run has a route into the named network, and
				// the router's own route wins over the list's tunnel in every state; nothing said so.
				// Never the provider's device; it is "this list by its tunnels" that is given up.
				owner := "a kill-switched list or rule"
				if o := namedOwner(plan, p); o != "" {
					owner = o
				}
				part := p.String()
				if r.Prefix.Bits() > p.Bits() {
					part = r.Prefix.String()
				}
				out = append(out, PlanFinding{
					ID: findingNamedOnHouse, Setting: "kill switch", Item: p.String() + " on " + r.Dev,
					Requested: p.String() + " by its tunnel only", Effective: part + " reached by " + r.Dev,
					Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
					Detail: fmt.Sprintf("%s names the private network %s, and the router has a route of its own into the same addresses (%s) by %s: "+
						"%s is reached by %s, a network of this router's own, not by the list's tunnel, whether the tunnel is up or not. "+
						"Never by the provider", owner, p, r.Prefix, r.Dev, part, r.Dev),
					Remedy: "Nothing is required if " + r.Dev + " is where those addresses live. If the list means another network with the same numbers, " +
						"one of the two has to be renumbered: the router's own route is always preferred.",
				})
				continue
			}
			what := "is on no side WayHop can tell: no firewall zone holds it, or its zone also holds the uplink"
			effect := "new connections to those addresses are held there (answers still pass)"
			remedy := "If " + r.Dev + " is a network of the LAN, put its interface in a firewall zone that the uplink is not in " +
				"(LuCI: Network, Firewall). If it is the provider's, nothing is required."
			if side == sideProvider {
				what = "is the provider's side (it carries a default route, belongs to the interface that does, or its firewall zone faces the provider)"
				effect = "the kill switch holds those addresses there"
				remedy = "Nothing is required if " + r.Dev + " is the provider's. If it is a network of the LAN, give it an interface and a firewall zone of " +
					"its own, apart from the uplink's (LuCI: Network, Firewall). To reach the provider's own " + r.Prefix.String() +
					", take it out of the kill-switched list."
			}
			owner := "a kill-switched list or rule"
			if o := namedOwner(plan, p); o != "" {
				owner = o
			}
			out = append(out, PlanFinding{
				ID: findingNamedOnProvider, Setting: "kill switch", Item: p.String() + " on " + r.Dev,
				Requested: p.String() + " by its tunnel only", Effective: "held on " + r.Dev,
				Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
				Detail: fmt.Sprintf("%s names the private network %s, and the router has a route into the same addresses (%s) by %s, which %s. "+
					"That may be another network with the same numbers, not the one the list means: %s, "+
					"and they are reached by the list's tunnel or not at all", owner, p, r.Prefix, r.Dev, what, effect),
				Remedy: remedy,
			})
		}
	}
	for _, r := range routes {
		if !j.provider(r.Dev) || r.Prefix.Addr().Is6() {
			continue
		}
		for _, p := range swept {
			if !r.Prefix.Overlaps(p) {
				continue
			}
			out = append(out, PlanFinding{
				ID: findingSweptUplinkDNS, Setting: "kill switch", Item: r.Prefix.String() + " on " + r.Dev,
				Requested: "everything by the tunnel", Effective: "the provider's own segment stays reachable",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
				Detail: fmt.Sprintf("a kill-switched list covers all of %s, and the router's uplink %s is itself connected to %s. That segment stays "+
					"reachable by the uplink, so the page of the provider's box opens; a device set by hand to use that box as its DNS resolver "+
					"has its lookups answered by the provider, kill-switched names included. Devices that take their settings from this router ask this router",
					p, r.Dev, r.Prefix),
				Remedy: "Nothing is required. To hold that segment too, add " + r.Prefix.String() + " to the kill-switched list by name.",
			})
			break
		}
	}
	return out
}

// namedOwner names the kill-switched list or rule whose zone states p.
func namedOwner(plan *pbr.Plan, p netip.Prefix) string {
	for _, z := range plan.Zones {
		for _, c := range append(append([]string(nil), z.V4...), z.V6...) {
			q, err := netip.ParsePrefix(c)
			if err != nil {
				a, aerr := netip.ParseAddr(c)
				if aerr != nil {
					continue
				}
				q = netip.PrefixFrom(a, a.BitLen())
			}
			if q.Masked() != p {
				continue
			}
			if o, ok := plan.ZoneOrigin(z.Name); ok {
				if o.Kind == pbr.ZoneFromRule {
					return fmt.Sprintf("the routing rule %q", o.ID)
				}
				return fmt.Sprintf("the list %q", o.ID)
			}
			if id, ok := model.ListEgressID(z.EgressTag); ok {
				return fmt.Sprintf("the list %q", id)
			}
		}
	}
	return ""
}

// killSwitchRoutesCheck is the Diagnostics row for what the nft guard is told about the router's
// own routes.
func (s *Server) killSwitchRoutesCheck(context.Context) healthRow {
	return s.killSwitchRoutesRow(s.installedKernelPlan())
}

// killSwitchRoutesRow is the row for the installed plan.
func (s *Server) killSwitchRoutesRow(plan *pbr.Plan) healthRow {
	row := healthRow{ID: "killswitch_routes", Label: "Kill switch and the router's own networks"}
	if s.config().Demo || s.detectedPlatform() != platform.OpenWrt || plan == nil || !plan.HasNftGuard() {
		row.Status, row.Summary = "na", "no kill switch on the nft plane"
		return row
	}
	l := &s.ksLocal
	l.mu.Lock()
	sourceOver := l.sourceOver
	l.mu.Unlock()
	sourceBound := func() healthRow {
		row.Status, row.Summary, row.Detail = "warn", sourceBoundSummary(sourceOver), sourceBoundDetail
		row.Fix = "Restart WayHop after removing old source-routing rules, or route those networks with fewer rules."
		return row
	}
	named, swept := plan.GuardJudgedPrivate()
	if len(named)+len(swept) == 0 {
		if sourceOver > 0 {
			return sourceBound()
		}
		row.Status, row.Summary = "na", "no kill-switched list covers private addresses"
		return row
	}
	local, _, _ := s.guardLocalState()
	l.mu.Lock()
	known, sidesErr, houseOver, otherOver := l.sides.known, l.sidesErr, l.houseOver, l.otherOver
	l.mu.Unlock()
	tunnel := planTunnels(plan)
	house, other := 0, 0
	var unsure []string // devices of unknown side with a route into what a list names
	for _, r := range local {
		switch {
		case tunnel[r.Dev]:
			other++
		case r.House:
			house++
		case r.Candidate:
			other++
			for _, p := range named {
				if p.Overlaps(r.Prefix) {
					unsure = append(unsure, r.Dev)
					break
				}
			}
		default:
			other++
		}
	}
	unsure = sortedUniqueStrings(unsure)
	const answers = "Answers to the networks the kill switch was not told about still pass; new connections to them from another network " +
		"of the LAN (a port forward, LAN to guest, a server tunnel's clients) are held where a kill-switched list covers their addresses."
	switch {
	case !known:
		row.Status, row.Summary = "warn", "the firewall's zones could not be read: no network is known to be the LAN's own"
		row.Detail = "Reading them failed: " + sidesErr + ". " + answers
		row.Fix = "Check that `uci show firewall` works on the router and names the zones; WayHop reads it again within half a minute."
	case houseOver > 0:
		row.Status = "warn"
		row.Summary = fmt.Sprintf("the LAN has %d more networks than the %d the kill switch is told about", houseOver, ksLocalMax)
		row.Detail = answers
		row.Fix = "Aggregate the routes on the LAN's side (one route for a range instead of one per subnet)."
	case len(unsure) > 0:
		row.Status = "warn"
		row.Summary = "the side of " + strings.Join(unsure, ", ") + " is not known, and a kill-switched list names addresses it has a route into"
		row.Detail = "A device is the LAN's when a firewall zone holds it and the uplink is not in that zone; the provider's when it carries a " +
			"default route, belongs to the interface that does, or its zone faces the provider. Neither is true of these. Answers to their " +
			"segments pass; new connections to the listed addresses there are held."
		row.Fix = "Put the device's interface in a firewall zone of the LAN (LuCI: Network, Firewall), apart from the uplink."
	case sourceOver > 0:
		return sourceBound()
	case otherOver > 0:
		row.Status = "warn"
		row.Summary = fmt.Sprintf("%d routes of devices outside the LAN's side are more than the %d the kill switch is told about", otherOver, ksLocalOtherMax)
		row.Detail = "Where a kill-switched list covers all of private space, the networks left out are held: reached by the list's tunnel or not at all."
	default:
		row.Status = "pass"
		row.Summary = fmt.Sprintf("%d of the LAN's own networks and %d other routes told to the kill switch", house, other)
	}
	return row
}
