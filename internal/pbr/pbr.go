// Package pbr compiles the protocol-agnostic model into a kernel policy-based-routing
// plan (nftables fwmark + `ip rule`/`ip route`) for the native-first "hybrid" routing
// mode — see docs/ARCHITECTURE_NATIVE_FIRST.md (development repository). The kernel-routing brain
// is WayHop's own code: nothing external supplies the marking or the tables.
//
// Phase 1 (this file): a pure, testable compiler + nftables/ip renderers for IP-CIDR
// routing (manual IP lists, geoip-by-IP, the VoWiFi/ePDG carve-out). Domain/GeoSite/
// GeoIP-by-rule-set zones and live Apply/teardown + kernel failover are Phase 2; the
// compiler surfaces them as Warnings rather than mis-routing them.
package pbr

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// validOffloadDev matches a real Linux interface name: leading alnum then alnum/dot/underscore/
// hyphen, 1-15 chars. RenderNft emits the offload device list UNQUOTED as
// `devices = { … }`, and Apply feeds that ruleset to `nft -f -` as root — so a name carrying
// nft/shell metacharacters (whitespace, ';' '{' '}' ',' '#' '"' '$' '\' or a newline) would
// inject arbitrary root-level nft. Compile drops anything that fails this before it can reach
// the Flowtable, and config.Validate rejects it earlier still with a user-facing error.
var validOffloadDev = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

// ValidIfaceName is the one interface-name check every layer uses: a name the server
// accepted and the renderer dropped produced an empty program that was then reported as applied.
func ValidIfaceName(name string) bool { return validOffloadDev.MatchString(name) }

// EgressKind classifies a kernel routing destination.
type EgressKind string

const (
	EgressWAN       EgressKind = "wan"       // the system default route (main table)
	EgressInterface EgressKind = "interface" // route out a kernel netdev (awg0/awg1/wr-xxxx)
	EgressBlackhole EgressKind = "blackhole" // drop (block list)
	// EgressNDMPolicy is a destination one of KeeneticOS's own access policies routes. It classifies
	// a routing list's outbound and never appears in Plan.Egresses: the zone carries the policy's
	// whole mark and NDM's own rule, table and blackhole route it, so WayHop installs no table, ip rule
	// or failover entry for it, and no WayHop egress is renumbered by its presence.
	EgressNDMPolicy EgressKind = "ndm_policy"
)

// Egress is one kernel routing destination with its assigned fwmark + routing table.
type Egress struct {
	Tag   string     `json:"tag"` // model outbound tag (endpoint id, group id, "direct", "block")
	Kind  EgressKind `json:"kind"`
	Iface string     `json:"iface,omitempty"` // kernel ifname when Kind==EgressInterface
	Mark  uint32     `json:"mark"`            // fwmark (masked by Plan.Mask)
	Table int        `json:"table"`           // routing table number
	// FailClosed marks a kill-switched tunnel egress: RenderIP adds a high-metric `blackhole
	// default` fallback in this egress's table so that if the tunnel iface goes down (its metric-0
	// `default dev <iface>` route is flushed) the fwmark'd traffic is DROPPED instead of falling
	// through to the main table (WAN). Set from a Group's opt-in KillSwitch; only meaningful for
	// EgressInterface. Zero value = no fallback = byte-identical render for existing profiles.
	FailClosed bool `json:"fail_closed,omitempty"`
	// Ifaces is every device the runtime elector may point this egress's table at: a group's
	// members and a fastest list's candidates that have a kernel device, Iface (the compile-time
	// seed) included. Empty for a single tunnel. The MSS clamp and the kill-switch guard read it; a
	// plan stored before the field existed has none and renders byte for byte as it did.
	Ifaces []string `json:"ifaces,omitempty"`
}

// Devices is every device this egress's table may hold: Iface and Ifaces, in a stable order.
func (e Egress) Devices() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range append([]string{e.Iface}, e.Ifaces...) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// Zone is an IP-CIDR set whose matching destination traffic is marked for an egress.
type Zone struct {
	Name      string   `json:"name"`         // stable, nft-safe set name
	EgressTag string   `json:"egress_tag"`   // which Egress this zone routes to
	Mark      uint32   `json:"mark"`         // == the egress mark (denormalized for rendering)
	V4        []string `json:"v4,omitempty"` // IPv4 CIDRs (normalized, sorted)
	V6        []string `json:"v6,omitempty"` // IPv6 CIDRs
	// Domains is populated only when Options.CollectDomainZones is set (the Keenetic ipset+
	// dnsmasq plane): the list's domain entries, which dnsmasq resolves into the zone's kernel
	// ipset at query-time (so an 81k-domain list costs ~0 standing RAM — never pre-resolved).
	// Empty on the OpenWrt nft path (domains there are warned and handled by sing-box).
	Domains []string `json:"domains,omitempty"`
	// Source predicates (Phase C): a zone is SOURCE-SCOPED when any of these is set — it marks
	// only traffic FROM the matching source, in addition to its dest set (if any). SrcV4/SrcV6
	// render as `ip/ip6 saddr @<name>_s4/_s6` (their own nft sets); SrcMAC/SrcIface/SrcPort are
	// family-agnostic match prefixes. SrcScoped flags the zone so the hybrid TUN-exclude (§6.4)
	// does NOT drop its dest CIDR from the TUN — a source-scoped dest must still reach the
	// non-matching clients via the tunnel default. See docs/SPEC_SOURCE_BASED_ROUTING.md (development repository) §5 in the
	// development repository.
	SrcV4     []string `json:"src_v4,omitempty"`
	SrcV6     []string `json:"src_v6,omitempty"`
	SrcMAC    []string `json:"src_mac,omitempty"`
	SrcIface  []string `json:"src_iface,omitempty"`
	SrcPort   []int    `json:"src_port,omitempty"`
	SrcScoped bool     `json:"src_scoped,omitempty"`
	// SrcNegate inverts the source match — the zone marks traffic NOT from the source predicates
	// (renders `ether/ip saddr != …`). Used for a RoutingList's "except" scope: mark for EVERY device
	// except the group's members (AND of negations = the De Morgan of the group's any-member OR).
	SrcNegate bool `json:"src_negate,omitempty"`
	// NDMPolicy names the KeeneticOS access policy that routes this zone ("" for every other zone).
	// Mark is then a WayHop slot in the plan's own bits, set, saved and restored like any egress mark,
	// and NDMMark is the policy's whole mark as NDM reported it at capture. After the CONNMARK save the
	// chain rewrites the slot into NDMMark (NDM's rule matches it exactly: `fwmark 0xffffaab`, no mask).
	// The slot is what the connection remembers: NDM's marks fill the mask's bits with 0xff, so saving
	// the policy mark itself restored only 0x00ff0000 on a later packet whose destination had left the
	// set - a mark no rule matches, routed by the main table to the WAN (gap 6 review).
	NDMPolicy string `json:"ndm_policy,omitempty"`
	NDMMark   uint32 `json:"ndm_mark,omitempty"`
	// RemoteList names the remote rule-set list whose content this zone also carries (fast DNS plane).
	// The content itself (names and prefixes) is never part of the plan: the plan is persisted with
	// the applied state on flash, and the decompiled lists live in RAM only. The zone's rlist sets are
	// declared empty and filled from the daemon's copy at install and whenever it reloads them
	// (RenderRemoteElements); the snippet takes the names from the same copy.
	RemoteList string `json:"remote_list,omitempty"`
	// RemoteSource is the remote list's source URL this plan was reviewed with: the
	// daemon fills the zone only from content of that source, so an edited, unapplied source never
	// reaches the installed plane.
	RemoteSource string `json:"remote_source,omitempty"`
	// Routed: a large list of the fast DNS plane routed by a table of its own instead of nft sets
	// (routed.go). Its static prefixes move from V4/V6 to RouteV4/RouteV6; RemoteRouted says its remote
	// prefixes are routes too (no rlist sets). A direct one is routed by the main table: dropped.
	Routed       bool     `json:"routed,omitempty"`
	RouteV4      []string `json:"route_v4,omitempty"`
	RouteV6      []string `json:"route_v6,omitempty"`
	RemoteRouted bool     `json:"remote_routed,omitempty"`
	// RouteList is the routing list a Routed zone is (the generator lets the core carry it while the
	// TUN waits).
	RouteList string `json:"route_list,omitempty"`
	// DNSNoV6 keeps a domain zone of the fast DNS plane IPv4-only: its egress is a tunnel the v4-only
	// posture covers (egressV4OnlyPosture), so the resolver must not put AAAA answers into a set that
	// would mark them into a tunnel that cannot carry them. No IPv6 marking line and no ip -6 rule; an
	// all-device zone keeps a _6 set and nftset target whose addresses wd_v6only refuses instead
	// (Zone.V6Refused), so they do not leave by the provider.
	DNSNoV6 bool `json:"dns_no_v6,omitempty"`
	// origin is the model item the zone was compiled from: set by Compile only, never
	// serialized, so a plan read back from an artifact has none (ZoneOrigin reports false).
	origin ZoneOrigin
}

// ZoneOrigin is the model item a zone was compiled from: a routing list or a routing rule.
type ZoneOrigin struct {
	Kind string // ZoneFromList or ZoneFromRule
	ID   string
}

// The kinds of ZoneOrigin.
const (
	ZoneFromList = "list"
	ZoneFromRule = "rule"
)

// ZoneOrigin reports the model item zone name was compiled from, false for an unknown zone or a plan
// not produced by Compile in this process.
func (pl *Plan) ZoneOrigin(name string) (ZoneOrigin, bool) {
	for _, z := range pl.Zones {
		if z.Name == name && z.origin.ID != "" {
			return z.origin, true
		}
	}
	return ZoneOrigin{}, false
}

// Warning flags model content the IP-based Phase-1 compiler does not kernel-route.
type Warning struct {
	Scope string `json:"scope"` // rule/list id
	Msg   string `json:"msg"`
}

// Flowtable is the optional Phase-1b flow-offload datapath: general (UNmarked) LAN↔WAN
// flows are offloaded to the kernel/HW fast-path, while carve-out flows (any plan mark
// set) are deliberately EXCLUDED so their per-packet fwmark/PBR (and thus the UDP calls
// it carries) keep working. Lives in this plan's OWN nft table, so the existing
// RenderNft/RenderTeardown snapshot/restore it under the fail-safe for free — we never
// touch fw4's uci flow_offloading. See docs/ARCHITECTURE_NATIVE_FIRST.md (development repository) "Phase 1a/1b".
type Flowtable struct {
	Devices []string `json:"devices,omitempty"` // netdevs to offload (WAN uplink + LAN bridge); awg* tunnels excluded
	HW      bool     `json:"hw,omitempty"`      // emit `flags offload` for hardware PPE offload (vs software only)
}

// Plan is the compiled kernel-routing plan for hybrid mode.
type Plan struct {
	Table      string     `json:"table"`               // nft table name (own table, coexists with fw4)
	Mask       uint32     `json:"mask"`                // fwmark mask owned by this plan
	Egresses   []Egress   `json:"egresses"`            // sorted: wan first, then the rest by tag
	Zones      []Zone     `json:"zones"`               // sorted by name
	BypassV4   []string   `json:"bypass_v4,omitempty"` // kernel endpoints' own server IPs → main table (anti-loop)
	BypassV6   []string   `json:"bypass_v6,omitempty"`
	Flowtable  *Flowtable `json:"flowtable,omitempty"`   // optional Phase-1b flow-offload (nil = no offload, the default)
	MasqIfaces []string   `json:"masq_ifaces,omitempty"` // kernel tunnel ifaces needing forwarded-LAN MASQUERADE (de-duped, stable order)
	// GuardV6 is the IPv6 part of the fail-closed lists and rules that the plane does not carry:
	// their tunnel is IPv4-only (egressV4OnlyPosture), so the prefixes are in no zone, and in hybrid
	// mode the core's TUN is IPv4-only too. Nothing would mark them and they would leave by the
	// provider. The nft guard (RenderNftGuard) drops them. All-device lists and rules only.
	GuardV6 []string `json:"guard_v6,omitempty"`
	// GuardNames says a kill switch covers something this plane does not carry by address: a list's
	// domain names, a remote rule-set not fetched yet, a rule that matches names, geo sets or ports.
	// The core routes those, so only the core holds them, and while it is not running nothing does.
	// The nft guard's names hold reads this. Never set on the plane that collects domains itself
	// (KeeneticOS, where dnsmasq feeds the names into the kernel sets).
	GuardNames bool `json:"guard_names,omitempty"`
	// GuardNameSets is what GuardNames covers, one entry per kill-switched list or rule that matches
	// names. The nft guard gives each a pair of address sets with timeouts; the daemon
	// puts the addresses those names were reached at into them, and the guard lets such an address
	// leave only by the core's TUN or a tunnel. Empty on a plan stored before the field existed.
	GuardNameSets []GuardNameSet `json:"guard_name_sets,omitempty"`
	// CoreTun is the device name of the core's TUN as the generated config states it, and CoreTunV6
	// whether that TUN carries IPv6. Written by the server once the config for
	// this plan is generated; empty on a plan stored before that, and on a plane without a TUN.
	CoreTun   string `json:"core_tun,omitempty"`
	CoreTunV6 bool   `json:"core_tun_v6,omitempty"`
	// The fast DNS plane (routing mode "fast", Phase 2; docs/ARCHITECTURE_NATIVE_FIRST.md (development repository)). Every
	// field is empty on a plan without domain lists or core-egress lists, which then renders byte for
	// byte as before.
	//
	// CoreZones are the lists and rules whose outbound only the core can carry (a proxy endpoint, a
	// plugin, a group with no kernel member). They mark nothing: their addresses (static sets) and the
	// addresses the resolver gives for their names (dlist sets) are the only destinations wr_corepin
	// lets through to the core's redirect. Every other LAN flow is pinned past it.
	CoreZones []Zone `json:"core_zones,omitempty"`
	// FastDNS records that the plan was compiled for the fast DNS plane (Options.FastDNS): the core
	// config generated beside it drops the lists the kernel carries (generator Options.FastDNS).
	FastDNS bool `json:"fast_dns,omitempty"`
	// CorePin renders wr_corepin: set when CoreZones is not empty.
	CorePin bool `json:"core_pin,omitempty"`
	// DNSEnforce renders the LAN DNS redirect to the router's resolver and the DoT reject: set when a
	// zone of the plan carries names and the operator did not turn fast_dns_enforce off.
	DNSEnforce bool `json:"dns_enforce,omitempty"`
	// LANIfaces are the LAN's devices (the LAN side the kill-switch guard computes), the only input
	// devices wr_corepin and the DNS enforcement act on. Empty: neither renders.
	LANIfaces []string `json:"lan_ifaces,omitempty"`
}

// GuardNameSet is one kill-switched list or rule whose names only the core can match.
type GuardNameSet struct {
	// Set is the base name of its two nft sets (Set+"_4", Set+"_6") in the guard's table.
	Set string `json:"set"`
	// Kind is ZoneFromList or ZoneFromRule, and ID the list's or rule's id.
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Outbounds is where the core sends what the list or rule matches: the outbound its route rule
	// names. One tag: the core knows nothing of a list's candidates (the kernel elects among those),
	// it sends the list's names to the list's Outbound. A connection the core routed
	// to it is that list's traffic, whatever matched it (a name, a geo set, a port), and its address
	// is learned. A plan stored before that review also lists the candidates here.
	Outbounds []string `json:"outbounds,omitempty"`
	// Direct says the outbound is a tunnel itself, not a group: the core then reports a connection
	// routed to it with that one tag, and the same tag at the end of a longer chain is a group's
	// member at work, another route's traffic.
	Direct bool `json:"direct,omitempty"`
	// Shared says a route no kill switch covers sends its traffic to the same outbound (another
	// list, a rule, the default route). The outbound alone then does not tell whose a connection is,
	// and RuleSets does: the tags of the list's rule-sets in the core's config, which the core names
	// in the rule it reports for a connection. Without that name the address is not learned: holding
	// it would stop traffic the operator allowed by the provider.
	Shared   bool     `json:"shared,omitempty"`
	RuleSets []string `json:"rule_sets,omitempty"`
}

// Options tune the marking/table scheme. The defaults keep the table window well clear of what
// other routing software on a router claims (mwan3 ~1001+, the pbr package ~40000+).
type Options struct {
	Table     string // default "wayhop_pbr"
	MarkMask  uint32 // default 0x00ff0000
	MarkStep  uint32 // default 0x00010000 (egress N gets N*MarkStep)
	TableBase int    // default 151 (first non-main routing table)
	WANTable  int    // default 254 (main)
	RulePref  int    // default 150 (base ip-rule priority)

	// Phase 1b flow-offload (default off). Offload "" / "off" → no flowtable (current
	// behaviour, byte-identical output). "sw" → software flowtable; "hw" → also `flags
	// offload` (hardware PPE). Honored only when OffloadDevices is non-empty; the caller
	// (server) supplies the WAN+LAN devices since the pure compiler must not probe the host.
	Offload        string
	OffloadDevices []string

	// CollectDomainZones, when true, makes Compile gather a list/rule's domain entries into
	// Zone.Domains (for the Keenetic dnsmasq-ipset plane) instead of warning-and-dropping them.
	// Default false → the OpenWrt nft path is byte-identical (domains stay warnings).
	CollectDomainZones bool

	// FastDNS turns on the fast DNS plane on the nft plane (routing mode "fast", Phase 2): domain
	// entries of lists and rules become Zone.Domains, which dnsmasq resolves into `dlist_<zone>` sets
	// (RenderFastDnsmasq), lists and rules at an outbound only the core carries become CoreZones, and
	// a rule's Domain/DomainSuffix literals are routed as a list's names are. Off: byte-identical.
	FastDNS bool
	// RemoteSets is the content of remote rule-set lists (RoutingList.Source), keyed by list id, as
	// the daemon fetched and decompiled it (RAM only). Read only with FastDNS; a list whose content is
	// absent, or was fetched for another source URL, is warned about as before.
	RemoteSets map[string]RemoteSet
	// LANIfaces are the LAN's devices, for wr_corepin and the DNS enforcement (FastDNS only).
	LANIfaces []string
	// DNSEnforce asks for the LAN DNS redirect and the DoT reject when a zone carries names (FastDNS).
	DNSEnforce bool

	// NDMPolicies is KeeneticOS's access policies by name → mark, as `show ip policy` read them for
	// this compile. A routing list sent to "ndm-policy:<name>" becomes a zone carrying that mark; a
	// name absent here is warned about and not kernel-routed. Empty off KeeneticOS, so no other plane
	// can produce such a zone.
	NDMPolicies map[string]uint32

	// Devices names, per endpoint ID, the kernel device the router really carries an endpoint on
	// when that is not the name KernelIface derives. KeeneticOS is the case: an AmneziaWG endpoint
	// NDM creates as `interface WireguardN` lives on device nwgN, and the wr_* name derived from its
	// id is a device only WayHop's own AmneziaWG engine creates: a table seeded with it stays empty.
	// Nil (OpenWrt, whose native interfaces carry the derived wr_* name on purpose) leaves every
	// device as derived, so the plan is byte-identical.
	//
	// It only RENAMES a device (see KernelDevice): an endpoint KernelIface does not route stays
	// unrouted, so the kernel/proxy partition the generator shares with Compile does not move.
	Devices map[string]string

	// ListEgresses gives every routing list in "fastest" mode (model.FastestActive, two or more
	// candidates the kernel can route) an egress of its OWN, tagged model.ListEgressTag(id): its own
	// mark and table, which the runtime elector re-points at the list's fastest candidate. These
	// egresses are numbered AFTER every other one, so a profile without such lists, or a caller that
	// leaves this off, keeps every mark and table it had. Both planes render it: the ipset plane
	// (KeeneticOS) and the nft plane (OpenWrt). At most model.MaxFastestLists;
	// the rest share their outbound's egress as before, with a warning (the review blocks on it).
	ListEgresses bool

	// Slots keeps marks and tables where the applied plan has them: egress tag ->
	// slot, the slot being the index that gives mark (slot+2)*MarkStep and table TableBase+slot. A
	// tag found here keeps its slot; a new egress takes the lowest free one. Without it egresses are
	// numbered by sorted tag, so one list going into fastest mode, or one outbound no list uses any
	// more, moved every later egress to another mark and table: established IPv6 flows stayed on
	// the old mark, and anything outside WayHop that names a mark or a table (an operator's
	// `ip rule ... fwmark 0x30000/0xff0000 lookup 153`) then steered another list. Nil numbers as
	// before. See SlotsOf.
	Slots map[string]int
}

// SlotsOf reads a plan's egress slots for Options.Slots: the applied plan's, so that the next
// compile leaves every egress both plans have on its mark and table.
func SlotsOf(pl *Plan, opt Options) map[string]int {
	if pl == nil {
		return nil
	}
	opt.withDefaults()
	out := map[string]int{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressWAN || e.Table < opt.TableBase {
			continue
		}
		slot := e.Table - opt.TableBase
		if e.Mark == uint32(slot+2)*opt.MarkStep {
			out[e.Tag] = slot
		}
	}
	return out
}

// MaxTableID bounds every routing table WayHop allocates (TableBase..HandoffReturnTable). KeeneticOS's
// BusyBox ip refuses large table ids (measured on BusyBox 1.37: `table 59999` is "invalid argument",
// while ids up to 16389 are in use by NDM); the exact BusyBox bound is not settled, so WayHop keeps its
// window below 4096, where NDM's own policy tables start.
const MaxTableID = 4095

// checkTables refuses a table window BusyBox's ip could reject or that would reach NDM's tables.
func (o *Options) checkTables() error {
	if o.TableBase < 1 || HandoffReturnTable(*o) > MaxTableID {
		return fmt.Errorf("routing table window %d..%d is outside 1..%d", o.TableBase, HandoffReturnTable(*o), MaxTableID)
	}
	return nil
}

func (o *Options) withDefaults() {
	if o.Table == "" {
		o.Table = "wayhop_pbr"
	}
	if o.MarkMask == 0 {
		o.MarkMask = 0x00ff0000
	}
	if o.MarkStep == 0 {
		o.MarkStep = 0x00010000
	}
	if o.TableBase == 0 {
		o.TableBase = 151
	}
	if o.WANTable == 0 {
		o.WANTable = 254
	}
	if o.RulePref == 0 {
		o.RulePref = 150
	}
}

// KernelIface returns the kernel interface name an endpoint routes out through, or ""
// if the endpoint is not a kernel-plane (interface-backed) engine. Exported so the
// generator's hybrid-split classifier uses the IDENTICAL kernel/proxy test as Compile
// (no drift: the two planes must partition the same set of outbounds).
func KernelIface(e *model.Endpoint) string { return kernelIface(e) }

// KernelDevice is KernelIface with the router's own device names applied (see Options.Devices):
// the device an endpoint's kernel-routed traffic actually leaves through. It is "" exactly when
// KernelIface is "", so it can rename a device but never make a proxy endpoint kernel-routed.
func KernelDevice(e *model.Endpoint, devices map[string]string) string {
	derived := kernelIface(e)
	if derived == "" {
		return ""
	}
	if device := devices[e.ID]; device != "" {
		return device
	}
	return derived
}

// kernelIface returns the kernel interface name an endpoint routes out through, or ""
// if the endpoint is not a kernel-plane (interface-backed) engine.
func kernelIface(e *model.Endpoint) string {
	switch e.Engine {
	case model.EngineExternal:
		s, _ := e.Params["interface"].(string)
		return s
	case model.EngineAmneziaWG:
		// DERIVED, never stored — and the uci writer derives it from this same function, because the
		// two must name the same device or the plane installs `ip route … dev <something absent>`
		// for a tunnel that looks perfectly configured in LuCI. They did diverge once; see
		// defaultIfaceName in internal/server/netvpnplan.go.
		//
		// An earlier attempt at this preferred a recorded params["interface"] here. Two things
		// killed it: nothing writes that key for an AmneziaWG endpoint (adoption produces
		// EngineExternal, which the case above already handles), so the branch was unreachable; and
		// recording it WOULD change the profile, hence the canonical applied-hash, hence light
		// "unapplied changes" the instant a native apply succeeded.
		return util.AWGIface(e.ID)
	default:
		return ""
	}
}

// isExternalEndpoint reports whether the outbound tag refers to an EngineExternal endpoint
// (an adopted OS-owned tunnel like awg0). Both EngineExternal and EngineAmneziaWG resolve to
// EgressInterface, but only EngineExternal gets the v4-only fail-closed posture — AWG endpoints
// can carry IPv6 CIDRs normally.
func isExternalEndpoint(p *model.Profile, tag string) bool {
	e := p.EndpointByID(tag)
	return e != nil && e.Engine == model.EngineExternal
}

// localAddrDeclaresV6 reports (known, hasV6) for an endpoint's recorded interface addresses.
// known=false means the model carries no local_address at all (nothing to judge from). The
// value may be []string (fresh import) or []any (after a JSON store round-trip), so both are
// handled. A v6 literal is the only address form containing a colon, which is a cheap, exact test.
func localAddrDeclaresV6(e *model.Endpoint) (known, hasV6 bool) {
	raw, ok := e.Params["local_address"]
	if !ok {
		return false, false
	}
	var addrs []string
	switch v := raw.(type) {
	case []string:
		addrs = v
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				addrs = append(addrs, s)
			}
		}
	}
	if len(addrs) == 0 {
		return false, false
	}
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			return true, true
		}
	}
	return true, false
}

// egressV4OnlyPosture reports whether v6 destination CIDRs routed to this egress should be
// stripped (kept out of the fwmark plane so a v6 dest can't blackhole inside a v4-only tunnel).
//   - EngineExternal (adopted OS tunnel): always v4-only fail-closed — its v6 capability isn't
//     modeled, so we never fwmark-route v6 into it (unchanged behavior).
//   - EngineAmneziaWG: v4-only ONLY when it POSITIVELY declares a v4-only local_address (present,
//     no v6). A dual-stack AWG keeps v6, and an AWG whose address we don't know keeps v6 too
//     (fail-open: no existing config regresses; the strip kicks in only with positive evidence
//     the tunnel cannot carry v6 — otherwise a v6 dest fwmark-routed into a v4-only AWG black-holes).
func egressV4OnlyPosture(p *model.Profile, tag string) bool {
	if isExternalEndpoint(p, tag) {
		return true
	}
	e := p.EndpointByID(tag)
	if e == nil || e.Engine != model.EngineAmneziaWG {
		return false
	}
	known, hasV6 := localAddrDeclaresV6(e)
	return known && !hasV6
}

// Compile turns the profile into a kernel-routing Plan plus warnings for anything the
// IP-based Phase-1 compiler cannot kernel-route (domains, geoip/geosite rule-sets,
// group failover, proxy-engine targets).
func Compile(p *model.Profile, opt Options) (*Plan, []Warning, error) {
	opt.withDefaults()
	if p == nil {
		return nil, nil, fmt.Errorf("nil profile")
	}
	if err := opt.checkTables(); err != nil {
		return nil, nil, err
	}
	// A device name is rendered unquoted into shell (`ip route add default dev <name>`, run by the
	// Keenetic plane's sh) and into nft, so it gets the same real-interface-name test as the offload
	// devices. Refused, not skipped: dropping a name would fall back to the derived device, which is
	// the empty table this option exists to prevent.
	deviceIDs := make([]string, 0, len(opt.Devices))
	for id := range opt.Devices {
		deviceIDs = append(deviceIDs, id)
	}
	sort.Strings(deviceIDs)
	for _, id := range deviceIDs {
		if !validOffloadDev.MatchString(opt.Devices[id]) {
			return nil, nil, fmt.Errorf("endpoint %q: kernel device %q is not an interface name", id, opt.Devices[id])
		}
	}
	device := func(e *model.Endpoint) string { return KernelDevice(e, opt.Devices) }
	plan := &Plan{Table: opt.Table, Mask: opt.MarkMask, Zones: []Zone{}}
	var warns []Warning
	warn := func(scope, msg string) { warns = append(warns, Warning{Scope: scope, Msg: msg}) }
	// collect: a list's or rule's names become Zone.Domains (the Keenetic ipset plane, or the fast DNS
	// plane on nft) instead of a warning.
	collect := opt.CollectDomainZones || opt.FastDNS
	usedNames := map[string]bool{}
	// dnsNoV6 is read by addZone for the zone it is adding (see Zone.DNSNoV6).
	dnsNoV6 := false
	// remoteFor is read by addZone and addCoreZone: the remote list whose content the zone carries.
	remoteFor := ""
	// remoteSrc is that list's source URL, recorded with it (Zone.RemoteSource).
	remoteSrc := ""
	// coreOutbound reports an outbound only the core can carry (fast DNS plane): a proxy endpoint or
	// plugin, or a group none of whose members, nested groups included, has a kernel device.
	coreOutbound := func(tag string) bool {
		if !opt.FastDNS {
			return false
		}
		if _, ok := model.ListEgressID(tag); ok {
			return false
		}
		switch tag {
		case model.OutboundDirect, model.OutboundBlock, "":
			return false
		}
		if _, ok := model.NDMPolicyName(tag); ok {
			return false
		}
		if e := p.EndpointByID(tag); e != nil {
			return device(e) == ""
		}
		if g := p.GroupByID(tag); g != nil {
			return len(groupDevices(p, g, device, map[string]bool{})) == 0
		}
		return false
	}
	// addCoreZone records a list's or rule's destinations for wr_corepin (Plan.CoreZones).
	addCoreZone := func(name, egTag string, entries []string, kind, scope string) {
		v4, v6, names := classifyCIDRs(entries)
		domains := normalizeDomains(names)
		if len(v4)+len(v6)+len(domains) == 0 && remoteFor == "" {
			return
		}
		if usedNames[name] {
			base := name
			for i := 2; usedNames[name]; i++ {
				name = fmt.Sprintf("%s_%d", base, i)
			}
			warn(scope, "kernel set name collided with another id → renamed to "+name)
		}
		usedNames[name] = true
		plan.CoreZones = append(plan.CoreZones, Zone{Name: name, EgressTag: egTag, V4: v4, V6: v6, Domains: domains,
			RemoteList: remoteFor, RemoteSource: remoteSrc, origin: ZoneOrigin{Kind: kind, ID: scope}})
	}

	// listEgress is, per fastest list given its own egress, the candidates the kernel can route
	// (endpoint id -> device), and the compile-time device: the first of them.
	listEgress := map[string]string{}
	listDevices := map[string][]string{}
	listFailClosed := map[string]bool{}
	// strippedV6 is, per egress tag, the IPv6 prefixes the v4-only posture kept out of the plane.
	strippedV6 := map[string][]string{}
	if opt.ListEgresses {
		n := 0
		for i := range p.RoutingLists {
			rl := p.RoutingLists[i]
			if !model.FastestActive(p, rl) {
				continue
			}
			var first string
			var devs []string
			kernel := 0
			for _, id := range model.ListCandidates(p, rl) {
				if e := p.EndpointByID(id); e != nil && e.Enabled {
					if ifc := device(e); ifc != "" {
						kernel++
						devs = append(devs, ifc)
						if first == "" {
							first = ifc
						}
					}
				}
			}
			if kernel < 2 {
				warn(rl.ID, "fastest tunnel needs two or more tunnels the kernel routes; the list keeps its first tunnel")
				continue
			}
			if n >= model.MaxFastestLists {
				warn(rl.ID, fmt.Sprintf("more than %d lists in fastest mode; this one shares its first tunnel's table", model.MaxFastestLists))
				continue
			}
			n++
			listEgress[rl.ID] = first
			listDevices[rl.ID] = devs
			// The list's own egress fails closed when the list asks to block, and whenever a kill switch
			// covers its tunnels (review F3): the group's KillSwitch is keyed by the group's tag, and this
			// egress's tag is the list's, so it has to be carried over here or the list leaks to the WAN
			// when the elected tunnel's link goes down.
			listFailClosed[rl.ID] = model.EffectiveAllDown(p, rl) == model.OnAllDownBlock || model.ListKillSwitch(p, rl)
		}
	}

	// resolveEgress maps a model outbound tag to a kernel egress kind+iface.
	resolveEgress := func(scope, tag string) (EgressKind, string, bool) {
		if id, ok := model.ListEgressID(tag); ok {
			if ifc := listEgress[id]; ifc != "" {
				return EgressInterface, ifc, true
			}
			warn(scope, "unknown list egress "+tag)
			return "", "", false
		}
		switch tag {
		case model.OutboundDirect, "":
			return EgressWAN, "", true
		case model.OutboundBlock:
			return EgressBlackhole, "", true
		}
		if name, ok := model.NDMPolicyName(tag); ok {
			if _, known := opt.NDMPolicies[name]; known {
				return EgressNDMPolicy, "", true
			}
			warn(scope, "access policy "+name+" is not among this router's access policies — not kernel-routed")
			return "", "", false
		}
		if e := p.EndpointByID(tag); e != nil {
			if ifc := device(e); ifc != "" {
				return EgressInterface, ifc, true
			}
			warn(scope, "outbound "+tag+" is a proxy endpoint (userspace plane) — not kernel-routed")
			return "", "", false
		}
		if g := p.GroupByID(tag); g != nil {
			// Walk members in preference order, DESCENDING into nested groups — a group member may
			// itself be a group (a validated, first-class feature), so a kernel endpoint reachable
			// only through a nested group must still be found. Without the recursion the nested
			// member resolves to nil and is skipped, so the kernel primary is mis-selected (a later
			// direct member wins over the preferred nested one) or the whole list drops from kernel
			// routing. Visited-set for cycle safety (Validate rejects cycles, but be defensive).
			var walk func(grp *model.Group, seen map[string]bool) string
			walk = func(grp *model.Group, seen map[string]bool) string {
				if grp == nil || seen[grp.ID] {
					return ""
				}
				seen[grp.ID] = true
				for _, m := range grp.Members {
					if me := p.EndpointByID(m); me != nil {
						if ifc := device(me); ifc != "" {
							return ifc
						}
						continue
					}
					if ifc := walk(p.GroupByID(m), seen); ifc != "" {
						return ifc
					}
				}
				return ""
			}
			if ifc := walk(g, map[string]bool{}); ifc != "" {
				// Resolved: this list IS kernel-routed, through the group's current member. No warning
				// belongs on this path — a warn here is read by the review as "the kernel will not
				// carry this", and in fast mode it printed "effective: not routed at all" about a list
				// the plane routes perfectly well. What is genuinely incomplete (the plane re-electing
				// that member by itself) is a property of the GROUP, reported on the failover page,
				// not a defect of every list pointing at it.
				return EgressInterface, ifc, true
			}
			warn(scope, "group "+tag+" has no kernel-plane member — not kernel-routed")
			return "", "", false
		}
		warn(scope, "unknown outbound "+tag)
		return "", "", false
	}

	// Collect zones from IP-based rules + routing lists; track which egress tags are used.
	usedEgress := map[string]struct{}{}
	// srcSpec carries a rule's source matchers into addZone (nil for non-source rules + routing
	// lists). cidrs is classified into SrcV4/SrcV6; mac/iface/port pass through as family-agnostic
	// nft match prefixes. A non-nil spec with any populated field makes the zone SrcScoped.
	type srcSpec struct {
		cidrs []string
		mac   []string
		iface []string
		port  []int
	}
	addZone := func(name, egTag string, cidrs []string, src *srcSpec, negate bool, scope string) {
		kind := ZoneFromList // a rule's zone is "rule_<id>", a list's ListZoneName (read before any rename)
		if strings.HasPrefix(name, "rule_") {
			kind = ZoneFromRule
		}
		v4, v6, bad := classifyCIDRs(cidrs)
		// Classify the source CIDRs up front so the no-matcher early-return can keep a source-only
		// zone (no dest) when the rule still carries a source matcher (ip/mac/iface/port).
		var sv4, sv6 []string
		srcScoped := false
		if src != nil {
			sv4, sv6, _ = classifyCIDRs(src.cidrs)
			srcScoped = len(sv4) > 0 || len(sv6) > 0 || len(src.mac) > 0 || len(src.iface) > 0 || len(src.port) > 0
		}
		var domains []string
		if collect {
			domains = normalizeDomains(bad) // the non-IP entries are domains for dnsmasq
		} else {
			for _, b := range bad {
				warn(scope, "skipped non-IP entry "+b+" (domain matching is Phase 2)")
			}
		}
		// A caller that NAMED a destination which classification then emptied - every entry a
		// non-IP name on a plane that does not collect domains - must not degrade into a
		// destination-less source-only zone: a scoped domain-only list would compile into "route
		// EVERYTHING for these devices". The unscoped case already dropped here; the scoped one
		// slipped past on srcScoped alone.
		if len(cidrs) > 0 && len(v4) == 0 && len(v6) == 0 && len(domains) == 0 && remoteFor == "" {
			return
		}
		if len(v4) == 0 && len(v6) == 0 && len(domains) == 0 && !srcScoped && remoteFor == "" {
			return
		}
		// Disambiguate set names that collide after nftName() squashes non-alnum to '_'
		// (e.g. routing-list ids "list-services" and "list_services" both → "list_list_services").
		// model.Validate only rejects EXACT-duplicate ids, so without this the rendered nft
		// ruleset would declare the same set twice → `nft -f` rejects the whole load → Apply
		// fails cryptically. Suffix the later collision so BOTH lists still kernel-route.
		if usedNames[name] {
			base := name
			for i := 2; usedNames[name]; i++ {
				name = fmt.Sprintf("%s_%d", base, i)
			}
			warn(scope, "kernel set name collided with another id → renamed to "+name)
		}
		usedNames[name] = true
		z := Zone{Name: name, EgressTag: egTag, V4: v4, V6: v6, Domains: domains, RemoteList: remoteFor, RemoteSource: remoteSrc,
			origin: ZoneOrigin{Kind: kind, ID: scope}}
		if opt.FastDNS && (len(domains) > 0 || remoteFor != "") && dnsNoV6 {
			z.DNSNoV6 = true
		}
		if policy, ok := model.NDMPolicyName(egTag); ok {
			z.NDMPolicy = policy // routed by NDM: no WayHop egress, mark or table is allocated for it
		} else {
			usedEgress[egTag] = struct{}{}
		}
		// Source-scoped zone (Phase C): the source matchers narrow this zone so its mark is set
		// ONLY for the matching source. source_ip_cidr → SrcV4/SrcV6; mac/iface/port pass through
		// as family-agnostic nft prefixes. With a dest the dest set bounds it; source-only (no
		// dest) the renderer emits a destination-less line + a bypass re-assert. §6.4 keeps any
		// dest in the TUN so non-matching clients still reach it.
		if srcScoped {
			z.SrcV4, z.SrcV6 = sv4, sv6
			z.SrcMAC, z.SrcIface, z.SrcPort = canonicalMACs(src.mac), src.iface, src.port
			z.SrcScoped = true
			z.SrcNegate = negate
		}
		plan.Zones = append(plan.Zones, z)
	}

	for i := range p.Rules {
		r := &p.Rules[i]
		// A disabled rule is honored on BOTH planes: the sing-box generator skips it (Phase B),
		// so the kernel plane must not route it either — otherwise "disabled" would silently
		// still apply in fast/hybrid.
		if r.Disabled {
			continue
		}
		// A default rule is sing-box's catch-all (route.final): its matcher fields are
		// meaningless (sing-box ignores them), so a stale IPCIDR on it must NOT become a
		// zone — that would TUN-exclude the CIDR and silently shadow an earlier proxy
		// rule for the same IP. Unmatched traffic falls through to WAN (the main table)
		// on its own; the generator's route.final handles the in-TUN default.
		if r.Default {
			continue
		}
		// Only a routing list may be sent to an access policy; model.Validate refuses it on a rule.
		if _, ok := model.NDMPolicyName(r.Outbound); ok {
			warn(r.ID, "an access policy can carry a routing list only — rule not kernel-routed")
			continue
		}
		// Source matchers (source_ip_cidr/mac/iface/port) build a source-scoped zone on BOTH
		// kernel planes — nft (RenderNft) and iptables/ipset (RenderIptablesScript). A source+dest
		// rule is bounded by its dest set; a source-only rule (no dest) is allowed through by the
		// dest check below and routes every dest from the source. addZone marks the zone SrcScoped;
		// §6.4 keeps any dest in the TUN so non-matching clients still reach it.
		// A rule's matchers are ANDed. A zone can express only the IP and source parts, so a rule that
		// also names a domain, geosite, geoip or destination port must route NOTHING on the kernel
		// plane and stay whole in the userspace one. Building the zone from its CIDRs alone
		// sent all traffic to those addresses through the egress whatever its domain or port, and a
		// rule with no CIDR would have become a destination-less source zone: "block youtube.com for
		// this MAC" compiled into "block this MAC".
		// dest is the rule's destination entries: its CIDRs, and on the fast DNS plane its Domain and
		// DomainSuffix literals too (sing-box ORs them inside a rule; dnsmasq matches a name and every
		// name under it, so an exact Domain is widened to a suffix there - Review says so).
		dest := r.IPCIDR
		if opt.FastDNS && len(r.GeoSite) == 0 && len(r.Domain)+len(r.DomainSuffix) > 0 {
			dest = append(append(append([]string(nil), r.IPCIDR...), r.Domain...), r.DomainSuffix...)
		} else if len(r.Domain)+len(r.DomainSuffix)+len(r.GeoSite) > 0 {
			warn(r.ID, "domain/geosite matching not kernel-routed in Phase 1 - rule not kernel-routed")
			continue
		}
		if len(r.GeoIP) > 0 {
			warn(r.ID, "geoip rule-set not kernel-routed in Phase 1 (expand to a CIDR set in Phase 2) - rule not kernel-routed")
			continue
		}
		// A rule at an outbound only the core carries: the core matches it whole (ports and sources
		// included), so the kernel needs only its destinations, to let them through to the core.
		if coreOutbound(r.Outbound) {
			if len(dest) == 0 {
				warn(r.ID, "a rule with no destination cannot let only its own traffic through to the proxy core - rule not routed")
				continue
			}
			addCoreZone("core_rule_"+nftName(r.ID), r.Outbound, dest, ZoneFromRule, r.ID)
			continue
		}
		if len(r.Port) > 0 {
			warn(r.ID, "destination port matching not kernel-routed - rule not kernel-routed")
			continue
		}
		// A rule with no dest AND no source matcher has nothing to kernel-route — skip. A
		// source-only rule (no dest, has source) proceeds: it builds a destination-less zone.
		if len(dest) == 0 && !r.HasSourceMatcher() {
			continue
		}
		if k, _, ok := resolveEgress(r.ID, r.Outbound); ok && k != "" {
			cidrsForZone := dest
			srcForZone := r.SourceIPCIDR // empty for non-source rules → no source-scoping
			dnsNoV6 = false
			if k == EgressInterface && egressV4OnlyPosture(p, r.Outbound) {
				// v4-only fail-closed posture: v6 flows stay in the tunnel's own routing table
				// rather than be fwmark-routed into a tunnel that cannot carry them. Applies to an
				// adopted EngineExternal tunnel (capability unmodeled) AND to an EngineAmneziaWG
				// egress that POSITIVELY declares a v4-only local_address; a dual-stack/unknown AWG
				// keeps v6 (see egressV4OnlyPosture).
				var dropped6, names []string
				cidrsForZone, dropped6, names = classifyCIDRs(cidrsForZone)
				srcForZone, _, _ = classifyCIDRs(srcForZone) // align source families with the v4-only dest
				if !r.HasSourceMatcher() {
					strippedV6[r.Outbound] = append(strippedV6[r.Outbound], dropped6...)
				}
				// The fast DNS plane: names are not addresses (see the list path below); they stay, and
				// their zone takes A answers only.
				if opt.FastDNS && len(names) > 0 {
					cidrsForZone = append(cidrsForZone, names...)
					dnsNoV6 = true
				}
			}
			// A rule that ORIGINALLY named a dest but had it emptied by the v4-only posture stripping
			// (its only dests were a family this egress cannot carry) must route NOTHING on the kernel
			// plane — exactly as the routing-list path does (see `if len(cidrList) == 0 { continue }`
			// below). Otherwise its source matcher would build a destination-less source-only zone that
			// OVER-CAPTURES all traffic from the source into the tunnel, a mis-route the rule never named.
			if len(dest) > 0 && len(cidrsForZone) == 0 {
				continue
			}
			var src *srcSpec
			if r.HasSourceMatcher() {
				src = &srcSpec{cidrs: srcForZone, mac: r.SourceMAC, iface: r.SourceIface, port: r.SourcePort}
			}
			// Build a zone when there is a dest OR a source matcher (source-only zone). addZone's
			// early-return drops a zone that ends up with neither after classification.
			if len(cidrsForZone) > 0 || src != nil {
				addZone("rule_"+nftName(r.ID), r.Outbound, cidrsForZone, src, false, r.ID)
			}
		}
	}
	// Device-scope resolver: a RoutingList's ScopeGroups → the member MACs + IPs of its groups.
	// "only" narrows the list to those devices. MAC-identified and IP-identified members are emitted
	// as SEPARATE source-scoped zones so they OR (a device matches by MAC OR by IP), matching the
	// group's any-member semantics — the engine ANDs SrcMAC with SrcV4 within ONE zone, so they can't
	// share a zone. "except" is not kernel-negated yet (P8) → applies to all + a warning.
	devGroupByID := make(map[string]*model.DeviceGroup, len(p.DeviceGroups))
	for i := range p.DeviceGroups {
		devGroupByID[p.DeviceGroups[i].ID] = &p.DeviceGroups[i]
	}
	scopeMembers := func(rl *model.RoutingList) (macs, ips []string) {
		for _, gid := range rl.ScopeGroups {
			g := devGroupByID[gid]
			if g == nil {
				continue
			}
			for _, m := range g.Members {
				if mac := strings.TrimSpace(m.MAC); mac != "" {
					macs = append(macs, mac)
				}
				if ip := strings.TrimSpace(m.IP); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		return
	}

	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		// The fast DNS plane carries a remote rule-set's names and prefixes as the daemon decompiled them.
		remote, haveRemote := RemoteSet{}, false
		if rl.Source != "" && opt.FastDNS {
			remote, haveRemote = opt.RemoteSets[rl.ID]
			haveRemote = haveRemote && remote.Source == rl.Source && len(remote.Unrepresentable) == 0
		}
		if rl.Source != "" && !haveRemote {
			warn(rl.ID, "remote rule-set ("+rl.Source+") not kernel-routed in Phase 1 (set population is Phase 2)")
		}
		// Kernel zone CIDRs = Manual ∪ CIDRCache (the last-good auto-refresh fetch). Both
		// optional; classifyCIDRs in addZone dedups + collapses the union. CIDRCache is
		// empty until the refresh loop (auto-refresh phase 4) populates it, so this is inert
		// for hand-curated lists.
		cidrs := rl.Manual
		// DomainCache rides in the same union: classifyCIDRs sorts addresses from names, so a fetched
		// domain feed reaches Zone.Domains by exactly the path a typed domain already takes — no
		// second datapath, and a list may hold both kinds at once.
		if len(rl.CIDRCache) > 0 || len(rl.DomainCache) > 0 {
			cidrs = append(make([]string, 0, len(rl.Manual)+len(rl.CIDRCache)+len(rl.DomainCache)), rl.Manual...)
			cidrs = append(cidrs, rl.CIDRCache...)
			cidrs = append(cidrs, rl.DomainCache...)
		}
		// The remote content stays out of the plan (Zone.RemoteList): only the list's id goes in.
		remoteFor, remoteSrc = "", ""
		if haveRemote && len(remote.Domains)+len(remote.CIDRs) > 0 {
			remoteFor, remoteSrc = rl.ID, rl.Source
		}
		if len(cidrs) == 0 && remoteFor == "" {
			continue
		}
		// A list at an outbound only the core carries: the core matches it, the kernel lets its
		// destinations through to the core (Plan.CoreZones). Its device scope is the core's to apply.
		if coreOutbound(rl.Outbound) && listEgress[rl.ID] == "" {
			addCoreZone("core_"+nftName(rl.ID), rl.Outbound, cidrs, ZoneFromList, rl.ID)
			continue
		}
		// Resolve device scope. "only" routes just for the group members (as MAC + IP zones); an
		// "only" scope that resolves to no device routes for nobody. "all"/"" (and "except", for now)
		// route for everyone.
		var scopeMAC, scopeIP []string
		scopeKind := "" // "" (all clients), "only", or "except"
		switch rl.ScopeMode {
		case "only":
			scopeMAC, scopeIP = scopeMembers(rl)
			if len(scopeMAC) == 0 && len(scopeIP) == 0 {
				warn(rl.ID, "device scope resolves to no MAC/IP — list not kernel-routed")
				continue
			}
			scopeKind = "only"
		case "except":
			scopeMAC, scopeIP = scopeMembers(rl)
			if len(scopeMAC) > 0 || len(scopeIP) > 0 {
				scopeKind = "except"
			} // "except nobody" (no members) resolves to everyone ⇒ leave unscoped (route all)
		}
		egTag := rl.Outbound
		if listEgress[rl.ID] != "" {
			egTag = model.ListEgressTag(rl.ID)
		}
		if k, _, ok := resolveEgress(rl.ID, egTag); ok && k != "" {
			cidrList := cidrs
			dnsNoV6 = false
			if k == EgressInterface && egressV4OnlyPosture(p, rl.Outbound) {
				// v4-only fail-closed posture (EngineExternal, or a positively-v4-only AmneziaWG).
				v4only, dropped6, names := classifyCIDRs(cidrList)
				if scopeKind != "only" && scopeKind != "except" {
					strippedV6[egTag] = append(strippedV6[egTag], dropped6...)
				}
				// A name is not an address. The resolver decides which family it resolves to and
				// populates the matching set, so a v4-only egress has nothing to fail closed about
				// yet — dropping names here left a domain-only list with an empty CIDR set, and the
				// `continue` below then removed it from the plane silently, with no warning and no
				// zone. Observed as a domain list that applied cleanly and routed nothing.
				if collect {
					v4only = append(v4only, names...)
					dnsNoV6 = opt.FastDNS && (len(names) > 0 || remoteFor != "")
				}
				cidrList = v4only
			}
			if len(cidrList) == 0 && remoteFor == "" {
				continue
			}
			base := "list_" + nftName(rl.ID)
			switch scopeKind {
			case "only":
				// Separate MAC / IP source zones so they OR (see the scopeMembers comment).
				if len(scopeMAC) > 0 {
					addZone(base+"_dm", egTag, cidrList, &srcSpec{mac: scopeMAC}, false, rl.ID)
				}
				if len(scopeIP) > 0 {
					addZone(base+"_di", egTag, cidrList, &srcSpec{cidrs: scopeIP}, false, rl.ID)
				}
			case "except":
				// ONE NEGATED zone: mark for every source NOT in the group (ether saddr != macs AND ip
				// saddr != ips = De Morgan of the members' OR). Kernel-enforced; on a pure sing-box
				// egress in tun-only mode the excluded group can't be negated in sing-box (documented
				// limit — use an AmneziaWG/kernel egress for reliable except).
				addZone(base, egTag, cidrList, &srcSpec{mac: scopeMAC, cidrs: scopeIP}, true, rl.ID)
			default:
				addZone(base, egTag, cidrList, nil, false, rl.ID)
			}
		}
	}

	// Anti-loop bypass: every kernel endpoint's own server IP must egress via WAN, not
	// back into a tunnel (mirrors generator.endpointBypass).
	var bypass []string
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		// Only ENABLED kernel endpoints (a disabled one is never emitted/used, and
		// generator.endpointBypass also skips it — keep the two in sync).
		if !e.Enabled || kernelIface(e) == "" {
			continue
		}
		if e.Server != "" {
			bypass = append(bypass, e.Server)
		}
		// External endpoints carry the peer IP in params["endpoint_ip"], not in Server.
		// Mirror generator.endpointBypass so the two bypass sets never diverge.
		if eip, ok := e.Params["endpoint_ip"].(string); ok && eip != "" {
			bypass = append(bypass, eip)
		}
	}
	plan.BypassV4, plan.BypassV6, _ = classifyCIDRs(bypass)

	// MasqIfaces: every enabled KERNEL-routed endpoint's iface needs a forwarded-LAN
	// MASQUERADE regardless of whether it has active zones (an endpoint may be the egress
	// for a v4-only routing list that was already filtered above, or may not be in usedEgress
	// at all — e.g. all its CIDRs were IPv6). This covers BOTH EngineExternal (an adopted OS
	// tunnel, iface in Params) AND EngineAmneziaWG (WR's own wr-* device): forwarded LAN
	// packets leave with their RFC1918 source, so without a MASQUERADE the tunnel peer has no
	// return route and every LAN client on that zone is black-holed. Drive the masq set off
	// the SAME device() resolution that builds the egress zones so the two never diverge.
	{
		seen := map[string]bool{}
		for i := range p.Endpoints {
			e := &p.Endpoints[i]
			if !e.Enabled {
				continue
			}
			if ifc := device(e); ifc != "" && !seen[ifc] {
				seen[ifc] = true
				plan.MasqIfaces = append(plan.MasqIfaces, ifc)
			}
		}
	}

	// Assign marks + tables. WAN is always present (the bypass + any "direct" zone use it);
	// then each other used egress, in stable order.
	plan.Egresses = append(plan.Egresses, Egress{Tag: model.OutboundDirect, Kind: EgressWAN, Mark: opt.MarkStep, Table: opt.WANTable})
	var others, lists []string
	for tag := range usedEgress {
		switch _, isList := model.ListEgressID(tag); {
		case tag == model.OutboundDirect:
		case isList:
			lists = append(lists, tag)
		default:
			others = append(others, tag)
		}
	}
	sort.Strings(others)
	sort.Strings(lists)
	others = append(others, lists...) // list egresses last: every other mark and table stays put
	slots := assignSlots(others, opt.Slots, int(opt.MarkMask/opt.MarkStep)-2)
	for _, tag := range others {
		k, ifc, _ := resolveEgress(tag, tag) // already validated above; re-resolve for kind/iface
		i := slots[tag]
		eg := Egress{
			Tag: tag, Kind: k, Iface: ifc,
			Mark:  uint32(i+2) * opt.MarkStep,
			Table: opt.TableBase + i,
		}
		if k == EgressInterface {
			var devs []string
			if id, ok := model.ListEgressID(tag); ok {
				devs = listDevices[id]
			} else if g := p.GroupByID(tag); g != nil {
				devs = groupDevices(p, g, device, map[string]bool{})
			}
			if eg.Ifaces = (Egress{Ifaces: devs}).Devices(); len(eg.Ifaces) == 1 && eg.Ifaces[0] == ifc {
				eg.Ifaces = nil
			}
		}
		// A kill-switched GROUP makes its tunnel table fail closed. Each outbound tag gets its own
		// table, so this is per-group: rules routing to this same group share the table and its
		// fail-closed fate; rules routing elsewhere (even out the same iface via another tag) are
		// unaffected. Only a kernel tunnel egress can fail closed.
		if k == EgressInterface {
			if g := p.GroupByID(tag); g != nil && g.KillSwitch {
				eg.FailClosed = true
			}
			if id, ok := model.ListEgressID(tag); ok && listFailClosed[id] {
				eg.FailClosed = true // on_all_down "block": an emptied table drops instead of leaking
			}
		}
		plan.Egresses = append(plan.Egresses, eg)
	}
	// Egresses stay in mark order whatever slots they hold: both renders walk them in this order.
	sort.SliceStable(plan.Egresses, func(i, j int) bool { return plan.Egresses[i].Mark < plan.Egresses[j].Mark })
	// The IPv6 prefixes the v4-only posture took out of a fail-closed list or rule. The tag may have
	// no egress at all (every prefix of the list was IPv6), so the kill switch is read from the model.
	{
		var held []string
		for tag, cidrs := range strippedV6 {
			closed := false
			if g := p.GroupByID(tag); g != nil && g.KillSwitch {
				closed = true
			}
			if id, ok := model.ListEgressID(tag); ok && listFailClosed[id] {
				closed = true
			}
			if closed {
				held = append(held, cidrs...)
			}
		}
		_, plan.GuardV6, _ = classifyCIDRs(held)
	}
	if !opt.CollectDomainZones {
		plan.GuardNameSets = killSwitchedNameSets(p, listFailClosed)
		plan.GuardNames = len(plan.GuardNameSets) > 0
	}

	// Denormalize each zone's mark from its egress, and sort for stable output.
	markByTag := map[string]uint32{}
	kindByTag := map[string]EgressKind{}
	for _, e := range plan.Egresses {
		markByTag[e.Tag] = e.Mark
		kindByTag[e.Tag] = e.Kind
	}
	// A policy's slot continues WayHop's own numbering after the last egress, one per policy in name
	// order, so a plan without policy lists keeps every mark it had.
	slotOf := map[string]uint32{}
	var policies []string
	for _, z := range plan.Zones {
		if z.NDMPolicy != "" && slotOf[z.NDMPolicy] == 0 {
			slotOf[z.NDMPolicy] = 1
			policies = append(policies, z.NDMPolicy)
		}
	}
	sort.Strings(policies)
	for i, name := range policies {
		slotOf[name] = uint32(len(plan.Egresses)+1+i) * opt.MarkStep
	}
	for i := range plan.Zones {
		if policy := plan.Zones[i].NDMPolicy; policy != "" {
			plan.Zones[i].Mark = slotOf[policy]
			plan.Zones[i].NDMMark = opt.NDMPolicies[policy]
			continue
		}
		plan.Zones[i].Mark = markByTag[plan.Zones[i].EgressTag]
	}
	// Both render planes emit ONE non-terminating mark per zone, so for OVERLAPPING destination CIDRs
	// the LAST-emitted zone wins. The emit order is the precedence (see orderZonesForEmit): direct
	// first, then tunnels, then kill-switched tunnels, then blocks.
	failClosedTag := map[string]bool{}
	for _, e := range plan.Egresses {
		if e.FailClosed {
			failClosedTag[e.Tag] = true
		}
	}
	plan.Zones = orderZonesForEmit(plan.Zones, kindByTag, failClosedTag)

	// The fast DNS plane's own parts. Nothing here is set without FastDNS, and with it nothing is set
	// for a profile that has neither names nor a core-only list, so such a plan renders as before.
	if opt.FastDNS {
		plan.FastDNS = true
		sort.SliceStable(plan.CoreZones, func(i, j int) bool { return plan.CoreZones[i].Name < plan.CoreZones[j].Name })
		named := false
		for _, z := range append(append([]Zone(nil), plan.Zones...), plan.CoreZones...) {
			// A remote list's names live in RAM, not in the zone, so the zone counts as named when its
			// content has names, or is not known yet: without the DNS redirect a device resolving
			// elsewhere never fills its sets. A list known to hold only prefixes needs no
			// enforcement.
			remoteNamed := false
			if z.RemoteList != "" {
				set, known := opt.RemoteSets[z.RemoteList]
				remoteNamed = !known || len(set.Domains) > 0
			}
			named = named || len(z.Domains) > 0 || remoteNamed
		}
		// A remote list keeps the TUN too: its content lives in RAM only, so
		// after a reboot the kernel holds none of it until the daemon fetched it again, and until then
		// the core, which keeps every list by name while the TUN exists, has to carry it unpinned.
		remoteZone := false
		for _, z := range append(append([]Zone(nil), plan.Zones...), plan.CoreZones...) {
			remoteZone = remoteZone || z.RemoteList != ""
		}
		plan.CorePin = len(plan.CoreZones) > 0 || remoteZone
		for _, e := range plan.Egresses {
			if e.Mark == CoreMark&opt.MarkMask || e.Mark == ScopedDirectMark&opt.MarkMask {
				return nil, nil, fmt.Errorf("egress %q holds mark %s, which the fast DNS plane reserves", e.Tag, hexMark(e.Mark))
			}
		}
		plan.DNSEnforce = named && opt.DNSEnforce
		if plan.CorePin || plan.DNSEnforce {
			for _, d := range opt.LANIfaces {
				if validOffloadDev.MatchString(d) {
					plan.LANIfaces = append(plan.LANIfaces, d)
				}
			}
			plan.LANIfaces = sortedUnique(plan.LANIfaces)
		}
		// Large lists leave nftables: libnftables pays for every interval set on each resolver add
		// (routed.go, live 22.11).
		var lan []string
		for _, d := range opt.LANIfaces {
			if validOffloadDev.MatchString(d) {
				lan = append(lan, d)
			}
		}
		plan.routeLarge(p, sortedUnique(lan), opt.RemoteSets)
	}

	// Phase 1b: opt-in flow-offload for general (unmarked) traffic. Requires the caller to
	// supply the offload devices (WAN+LAN) — the pure compiler never probes the host. Off
	// by default → Flowtable stays nil → RenderNft output is unchanged.
	switch opt.Offload {
	case "sw", "hw":
		if len(opt.OffloadDevices) == 0 {
			warn("offload", "flow-offload requested but no devices supplied — skipped")
			break
		}
		// Reject any name that is not a real interface (see validOffloadDev): the list is
		// rendered UNQUOTED into the root `nft -f -` ruleset, so a crafted name must never
		// reach it. Drop + warn rather than fail the whole compile — a bad device shouldn't
		// brick routing, and config.Validate already blocks it at save/import time.
		devs := make([]string, 0, len(opt.OffloadDevices))
		for _, d := range opt.OffloadDevices {
			if validOffloadDev.MatchString(d) {
				devs = append(devs, d)
			} else {
				warn("offload", fmt.Sprintf("ignoring invalid offload device name %q", d))
			}
		}
		if len(devs) == 0 {
			warn("offload", "flow-offload requested but no valid device names — skipped")
			break
		}
		sort.Strings(devs)
		plan.Flowtable = &Flowtable{Devices: devs, HW: opt.Offload == "hw"}
	case "", "off":
		// no offload
	default:
		warn("offload", "unknown offload mode "+opt.Offload+" (want off|sw|hw) — skipped")
	}
	return plan, warns, nil
}

// classifyCIDRs normalizes IP/CIDR strings into sorted, OVERLAP-FREE v4 + v6 CIDR lists;
// non-IP entries (e.g. domains) are returned in `bad`. Overlapping/contained prefixes are
// collapsed (see collapsePrefixes): the nft `flags interval` sets RenderNft emits have NO
// auto-merge, so two overlapping elements (e.g. a copy-pasted ASN dump with 77.88.0.0/16
// AND 77.88.55.0/24) would make `nft -f` reject the WHOLE ruleset and fail Apply.
func classifyCIDRs(in []string) (v4, v6, bad []string) {
	var p4, p6 []netip.Prefix
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var pfx netip.Prefix
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				bad = append(bad, s)
				continue
			}
			pfx = p.Masked()
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				bad = append(bad, s)
				continue
			}
			bits := 32
			if a.Is6() {
				bits = 128
			}
			pfx = netip.PrefixFrom(a, bits)
		}
		// A v4-mapped IPv6 literal (::ffff:1.2.3.4, or ::ffff:192.0.2.0/120) represents an IPv4
		// address; the real packet travels the v4 datapath, so it must classify + emit into the v4
		// set — not the inet6 set where it could never match (a block that fails to block, a route
		// that leaks). Fold it to its v4 form, mirroring keenetic/kernel.go's `Is6() && !Is4In6()`.
		if pfx.Addr().Is4In6() {
			b := pfx.Bits() - 96
			if b < 0 {
				b = 0
			}
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), b).Masked()
		}
		if pfx.Addr().Is6() {
			if !seen6[pfx.String()] {
				seen6[pfx.String()] = true
				p6 = append(p6, pfx)
			}
		} else {
			if !seen4[pfx.String()] {
				seen4[pfx.String()] = true
				p4 = append(p4, pfx)
			}
		}
	}
	for _, p := range collapsePrefixes(p4) {
		v4 = append(v4, p.String())
	}
	for _, p := range collapsePrefixes(p6) {
		v6 = append(v6, p.String())
	}
	return v4, v6, bad
}

// collapsePrefixes drops every prefix wholly contained in another and returns the minimal
// disjoint set, sorted by address. CIDR prefixes are hierarchical (any two are either
// disjoint or one contains the other — they never partially overlap), so removing the
// contained ones leaves a set with no overlaps, which is exactly what an nft `flags
// interval` set (without auto-merge) requires. Behaviour-preserving: the union of matched
// addresses is unchanged, only redundant overlapping entries are removed. O(n²) but n is
// small (a routing list, not a full geoip table).
// collapsePrefixes drops every prefix already covered by a broader one, in ONE pass.
//
// Comparing each prefix against every prefix kept so far is nothing on a hand-written list and the
// whole cost of the page on an open feed: on a 15 866-prefix list, the ordinary size of
// `antifilter/allyouneed`, a quadratic scan runs ~125M containment checks and takes seconds on a
// router, and both GET /api/pbr/status and the Apply review recompile from scratch on every call.
//
// The sweep works because of the sort: ascending address, broadest first on a tie. Any prefix that
// could cover p starts at or before p, and the kept set is disjoint by construction, so only the
// most recently kept prefix can possibly contain p — the rest are strictly to its left. That turns
// the inner scan into a single comparison.
func collapsePrefixes(in []netip.Prefix) []netip.Prefix {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Addr() != in[j].Addr() {
			return in[i].Addr().Less(in[j].Addr())
		}
		return in[i].Bits() < in[j].Bits()
	})
	kept := in[:0]
	var last netip.Prefix
	haveLast := false
	for _, p := range in {
		if haveLast && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
			continue
		}
		kept = append(kept, p)
		last, haveLast = p, true
	}
	return kept
}

// normalizeDomains lowercases, trims, de-dups, and drops obvious non-domain noise (comments,
// entries with spaces, leading wildcards) from the non-IP entries of a list, producing the
// domain set for a dnsmasq `ipset=` directive. dnsmasq matches a domain and every subdomain,
// so a leading "*." / "." is stripped (youtube.com already covers www.youtube.com).
func normalizeDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimPrefix(s, ".")
		if s == "" || strings.ContainsAny(s, " \t#!/") || !strings.Contains(s, ".") {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// SingleLabelNames are the entries normalizeDomains leaves out for having no dot ("intranet"), as it
// would read them otherwise: lowercased, a leading "*." or "." taken off, comments and IP literals
// aside. Review names them instead of letting them vanish.
func SingleLabelNames(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimPrefix(s, ".")
		if s == "" || strings.ContainsAny(s, " \t#!/.:") || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// canonicalMACs rewrites each source MAC to the lowercase colon form (net.HardwareAddr.String()).
// model.Validate accepts a MAC in dash ("aa-bb-cc-dd-ee-ff") or dotted ("0123.4567.89ab") form as
// well as colon form (net.ParseMAC) and only CHECKS — it never rewrites. But BOTH routing planes
// render the stored string into a colon-only grammar — nft `ether saddr { <mac> }` (render.go) and
// iptables `-m mac --mac-source <mac>` (render_ipset.go) — so a non-colon MAC yields an INVALID
// ruleset and the whole apply fails (device-wide, not just that zone). Canonicalizing here — the
// single point z.SrcMAC is assigned — fixes both planes at once. A never-parseable entry (shouldn't
// occur post-Validate) passes through trimmed, unchanged (fail-safe, no worse than before).
func canonicalMACs(macs []string) []string {
	if len(macs) == 0 {
		return macs
	}
	out := make([]string, len(macs))
	for i, m := range macs {
		m = strings.TrimSpace(m)
		if hw, err := net.ParseMAC(m); err == nil {
			out[i] = hw.String()
		} else {
			out[i] = m
		}
	}
	return out
}

// nftName makes an id safe to embed in an nft identifier.
func nftName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// NDMPolicySlot is one KeeneticOS access policy a plan routes to: the WayHop slot its zones set and
// save, and the policy's own mark the slot is rewritten into.
type NDMPolicySlot struct {
	Name string
	Slot uint32
	Mark uint32
}

// NDMPolicySlots lists the plan's access policies once each, in slot order.
func (pl *Plan) NDMPolicySlots() []NDMPolicySlot {
	var out []NDMPolicySlot
	seen := map[string]bool{}
	for _, z := range pl.Zones {
		if z.NDMPolicy == "" || seen[z.NDMPolicy] {
			continue
		}
		seen[z.NDMPolicy] = true
		out = append(out, NDMPolicySlot{Name: z.NDMPolicy, Slot: z.Mark, Mark: z.NDMMark})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Slot < out[b].Slot })
	return out
}

// orderZonesForEmit is the precedence the kernel plane really applies, extracted so it can be
// asserted directly: the Routing page describes this order to the operator, and the two must not
// drift apart.
//
// The last mark wins an overlap, so zones are emitted weakest first, in five ranks:
//
//  0. direct (the WAN egress): a direct list never takes an address from a tunnel list. A direct
//     DOMAIN list (IP checks, api.ipify.org & co.) gets shared Cloudflare anycast addresses in its
//     set from dnsmasq; emitted after a tunnel list, it would send every site on those addresses
//     out the provider.
//  1. tunnels without a kill switch, and KeeneticOS access policies;
//  2. device-scoped direct zones: a device's own exemption wins over the tunnel lists;
//  3. kill-switched tunnels (fail-closed egresses): nothing but a block takes their addresses;
//  4. blocks: a block always wins.
//
// Within a rank, by NAME. That is NOT the order the operator arranged in the panel: on the operator's
// Keenetic the panel reads Telegram, Antifilter, Meta, Twitter, Re:filter, TeamViewer, GitHub while
// the mangle chain emits them alphabetically — invisible there only because all seven carry the
// same mark. A domain list's own names can still leave by its egress on an overlapping address: see
// Handoff.
//
// Returns a new slice: the caller's Zones may be shared with a plan the caller still holds.
func orderZonesForEmit(zones []Zone, kindByTag map[string]EgressKind, failClosed map[string]bool) []Zone {
	out := append([]Zone(nil), zones...)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := zoneRank(out[i], kindByTag, failClosed), zoneRank(out[j], kindByTag, failClosed); ri != rj {
			return ri < rj
		}
		// Inside a rank a list of names is the weaker claim on an address: dnsmasq put it there for
		// one name, which the hand-off still gives back; a CIDR list names the address itself.
		if di, dj := zoneHasDomains(out[i]), zoneHasDomains(out[j]); di != dj {
			return di
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// zoneRank is a zone's precedence class (orderZonesForEmit). A device-scoped direct zone (a rule or
// list that sends one device direct) is an explicit exemption of that device, not a list of shared
// addresses: it ranks after the tunnels, so the device's own traffic to a listed destination keeps
// going direct, and before the kill-switched lists, so the kill switch stays absolute.
func zoneRank(z Zone, kindByTag map[string]EgressKind, failClosed map[string]bool) int {
	switch {
	case z.NDMPolicy != "":
		return 2
	case kindByTag[z.EgressTag] == EgressBlackhole:
		return 5
	case failClosed[z.EgressTag]:
		return 4
	case kindByTag[z.EgressTag] == EgressWAN && z.SrcScoped:
		return 3
	case kindByTag[z.EgressTag] == EgressWAN:
		return 0
	}
	return 2
}

// assignSlots gives every tag its slot: the one prev holds for it when that is free and inside the
// mark space, else the lowest free one, in the order given. max is the highest usable slot.
func assignSlots(tags []string, prev map[string]int, max int) map[string]int {
	out := make(map[string]int, len(tags))
	taken := map[int]bool{}
	for _, tag := range tags {
		if slot, ok := prev[tag]; ok && slot >= 0 && slot <= max && !taken[slot] {
			out[tag] = slot
			taken[slot] = true
		}
	}
	next := 0
	for _, tag := range tags {
		if _, ok := out[tag]; ok {
			continue
		}
		for taken[next] {
			next++
		}
		out[tag] = next
		taken[next] = true
	}
	return out
}

// groupDevices is every kernel device a group's table may be pointed at: its members', nested
// groups included.
func groupDevices(p *model.Profile, g *model.Group, device func(*model.Endpoint) string, seen map[string]bool) []string {
	if g == nil || seen[g.ID] {
		return nil
	}
	seen[g.ID] = true
	var out []string
	for _, m := range g.Members {
		if e := p.EndpointByID(m); e != nil {
			if ifc := device(e); ifc != "" {
				out = append(out, ifc)
			}
			continue
		}
		out = append(out, groupDevices(p, p.GroupByID(m), device, seen)...)
	}
	return out
}

// killSwitchedNameSets lists what a kill switch covers that only the core can match
// (Plan.GuardNameSets): lists with names or a rule-set nobody has fetched, rules with name, geo or
// port matchers. In the profile's order.
//
// A list counts when its traffic must not leave by the provider: a kill switch covers its tunnels,
// or its own egress fails closed (listFailClosed: "block when every tunnel is down"). The same two
// conditions close the list's egress by address, so names and addresses are held alike.
func killSwitchedNameSets(p *model.Profile, listFailClosed map[string]bool) []GuardNameSet {
	closed := func(rl model.RoutingList) bool {
		return rl.Enabled && (model.ListKillSwitch(p, rl) || listFailClosed[rl.ID])
	}
	// open is the outbounds a route outside every kill switch names.
	open := map[string]bool{}
	for _, rl := range p.RoutingLists {
		if rl.Enabled && !closed(rl) {
			open[rl.Outbound] = true
		}
	}
	for _, r := range p.Rules {
		if g := p.GroupByID(r.Outbound); g == nil || !g.KillSwitch {
			open[r.Outbound] = true
		}
	}
	var out []GuardNameSet
	for _, rl := range p.RoutingLists {
		if !closed(rl) {
			continue
		}
		named := rl.Source != "" && len(rl.CIDRCache)+len(rl.DomainCache) == 0 // unfetched: whatever it holds, the core matches it
		if !named {
			all := append(append(append([]string(nil), rl.Manual...), rl.CIDRCache...), rl.DomainCache...)
			_, _, names := classifyCIDRs(all)
			named = len(normalizeDomains(names)) > 0
		}
		if named {
			ns := GuardNameSet{Set: "kn_" + nftName(rl.ID), Kind: ZoneFromList, ID: rl.ID, Outbounds: []string{rl.Outbound},
				Direct: p.GroupByID(rl.Outbound) == nil, Shared: open[rl.Outbound]}
			if ns.Shared {
				// The tags generator.routingFrom gives the list's rule-sets.
				ns.RuleSets = []string{"rs-" + rl.ID, "rsm-" + rl.ID}
			}
			out = append(out, ns)
		}
	}
	for _, r := range p.Rules {
		g := p.GroupByID(r.Outbound)
		if g == nil || !g.KillSwitch {
			continue
		}
		if len(r.Domain)+len(r.DomainSuffix)+len(r.GeoSite)+len(r.GeoIP)+len(r.Port) > 0 {
			out = append(out, GuardNameSet{Set: "kn_rule_" + nftName(r.ID), Kind: ZoneFromRule, ID: r.ID, Outbounds: []string{r.Outbound}})
		}
	}
	return out
}
