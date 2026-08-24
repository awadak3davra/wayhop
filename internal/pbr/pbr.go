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
// hyphen, 1-15 chars (IFNAMSIZ-1). RenderNft emits the offload device list UNQUOTED as
// `devices = { … }`, and Apply feeds that ruleset to `nft -f -` as root — so a name carrying
// nft/shell metacharacters (whitespace, ';' '{' '}' ',' '#' '"' '$' '\' or a newline) would
// inject arbitrary root-level nft. Compile drops anything that fails this before it can reach
// the Flowtable, and config.Validate rejects it earlier still with a user-facing error.
var validOffloadDev = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

// EgressKind classifies a kernel routing destination.
type EgressKind string

const (
	EgressWAN       EgressKind = "wan"       // the system default route (main table)
	EgressInterface EgressKind = "interface" // route out a kernel netdev (awg0/awg1/wr-xxxx)
	EgressBlackhole EgressKind = "blackhole" // drop (block list)
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
	plan := &Plan{Table: opt.Table, Mask: opt.MarkMask, Zones: []Zone{}}
	var warns []Warning
	warn := func(scope, msg string) { warns = append(warns, Warning{Scope: scope, Msg: msg}) }

	// resolveEgress maps a model outbound tag to a kernel egress kind+iface.
	resolveEgress := func(scope, tag string) (EgressKind, string, bool) {
		switch tag {
		case model.OutboundDirect, "":
			return EgressWAN, "", true
		case model.OutboundBlock:
			return EgressBlackhole, "", true
		}
		if e := p.EndpointByID(tag); e != nil {
			if ifc := kernelIface(e); ifc != "" {
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
						if ifc := kernelIface(me); ifc != "" {
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
	usedNames := map[string]bool{}
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
		if opt.CollectDomainZones {
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
		if len(cidrs) > 0 && len(v4) == 0 && len(v6) == 0 && len(domains) == 0 {
			return
		}
		if len(v4) == 0 && len(v6) == 0 && len(domains) == 0 && !srcScoped {
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
		usedEgress[egTag] = struct{}{}
		z := Zone{Name: name, EgressTag: egTag, V4: v4, V6: v6, Domains: domains}
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
		// Source matchers (source_ip_cidr/mac/iface/port) build a source-scoped zone on BOTH
		// kernel planes — nft (RenderNft) and iptables/ipset (RenderIptablesScript). A source+dest
		// rule is bounded by its dest set; a source-only rule (no dest) is allowed through by the
		// dest check below and routes every dest from the source. addZone marks the zone SrcScoped;
		// §6.4 keeps any dest in the TUN so non-matching clients still reach it.
		if len(r.Domain)+len(r.DomainSuffix)+len(r.GeoSite) > 0 {
			warn(r.ID, "domain/geosite matching not kernel-routed in Phase 1")
		}
		if len(r.GeoIP) > 0 {
			warn(r.ID, "geoip rule-set not kernel-routed in Phase 1 (expand to a CIDR set in Phase 2)")
		}
		// The predicates warned away above were this rule's DESTINATION. A rule whose only dest
		// was domain/geosite/geoip must route NOTHING on the kernel plane - the same contract the
		// v4-posture guard below enforces when stripping empties r.IPCIDR. Falling through would
		// build a destination-less source-only zone, and "block youtube.com for this MAC" would
		// compile into "block this MAC": the panel shows a domain rule, the kernel enforces a
		// device-wide one.
		if len(r.IPCIDR) == 0 && len(r.Domain)+len(r.DomainSuffix)+len(r.GeoSite)+len(r.GeoIP) > 0 {
			continue
		}
		// A rule with no dest AND no source matcher has nothing to kernel-route — skip. A
		// source-only rule (no dest, has source) proceeds: it builds a destination-less zone.
		if len(r.IPCIDR) == 0 && !r.HasSourceMatcher() {
			continue
		}
		if k, _, ok := resolveEgress(r.ID, r.Outbound); ok && k != "" {
			cidrsForZone := r.IPCIDR
			srcForZone := r.SourceIPCIDR // empty for non-source rules → no source-scoping
			if k == EgressInterface && egressV4OnlyPosture(p, r.Outbound) {
				// v4-only fail-closed posture: v6 flows stay in the tunnel's own routing table
				// rather than be fwmark-routed into a tunnel that cannot carry them. Applies to an
				// adopted EngineExternal tunnel (capability unmodeled) AND to an EngineAmneziaWG
				// egress that POSITIVELY declares a v4-only local_address; a dual-stack/unknown AWG
				// keeps v6 (see egressV4OnlyPosture).
				cidrsForZone, _, _ = classifyCIDRs(cidrsForZone)
				srcForZone, _, _ = classifyCIDRs(srcForZone) // align source families with the v4-only dest
			}
			// A rule that ORIGINALLY named a dest but had it emptied by the v4-only posture stripping
			// (its only dests were a family this egress cannot carry) must route NOTHING on the kernel
			// plane — exactly as the routing-list path does (see `if len(cidrList) == 0 { continue }`
			// below). Otherwise its source matcher would build a destination-less source-only zone that
			// OVER-CAPTURES all traffic from the source into the tunnel, a mis-route the rule never named.
			if len(r.IPCIDR) > 0 && len(cidrsForZone) == 0 {
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
		if rl.Source != "" {
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
		if len(cidrs) == 0 {
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
		if k, _, ok := resolveEgress(rl.ID, rl.Outbound); ok && k != "" {
			cidrList := cidrs
			if k == EgressInterface && egressV4OnlyPosture(p, rl.Outbound) {
				// v4-only fail-closed posture (EngineExternal, or a positively-v4-only AmneziaWG).
				v4only, _, names := classifyCIDRs(cidrList)
				// A name is not an address. The resolver decides which family it resolves to and
				// populates the matching set, so a v4-only egress has nothing to fail closed about
				// yet — dropping names here left a domain-only list with an empty CIDR set, and the
				// `continue` below then removed it from the plane silently, with no warning and no
				// zone. Observed as a domain list that applied cleanly and routed nothing.
				if opt.CollectDomainZones {
					v4only = append(v4only, names...)
				}
				cidrList = v4only
			}
			if len(cidrList) == 0 {
				continue
			}
			base := "list_" + nftName(rl.ID)
			switch scopeKind {
			case "only":
				// Separate MAC / IP source zones so they OR (see the scopeMembers comment).
				if len(scopeMAC) > 0 {
					addZone(base+"_dm", rl.Outbound, cidrList, &srcSpec{mac: scopeMAC}, false, rl.ID)
				}
				if len(scopeIP) > 0 {
					addZone(base+"_di", rl.Outbound, cidrList, &srcSpec{cidrs: scopeIP}, false, rl.ID)
				}
			case "except":
				// ONE NEGATED zone: mark for every source NOT in the group (ether saddr != macs AND ip
				// saddr != ips = De Morgan of the members' OR). Kernel-enforced; on a pure sing-box
				// egress in tun-only mode the excluded group can't be negated in sing-box (documented
				// limit — use an AmneziaWG/kernel egress for reliable except).
				addZone(base, rl.Outbound, cidrList, &srcSpec{mac: scopeMAC, cidrs: scopeIP}, true, rl.ID)
			default:
				addZone(base, rl.Outbound, cidrList, nil, false, rl.ID)
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
	// the SAME kernelIface() test that builds the egress zones so the two never diverge.
	{
		seen := map[string]bool{}
		for i := range p.Endpoints {
			e := &p.Endpoints[i]
			if !e.Enabled {
				continue
			}
			if ifc := kernelIface(e); ifc != "" && !seen[ifc] {
				seen[ifc] = true
				plan.MasqIfaces = append(plan.MasqIfaces, ifc)
			}
		}
	}

	// Assign marks + tables. WAN is always present (the bypass + any "direct" zone use it);
	// then each other used egress, in stable order.
	plan.Egresses = append(plan.Egresses, Egress{Tag: model.OutboundDirect, Kind: EgressWAN, Mark: opt.MarkStep, Table: opt.WANTable})
	var others []string
	for tag := range usedEgress {
		if tag != model.OutboundDirect {
			others = append(others, tag)
		}
	}
	sort.Strings(others)
	for i, tag := range others {
		k, ifc, _ := resolveEgress(tag, tag) // already validated above; re-resolve for kind/iface
		eg := Egress{
			Tag: tag, Kind: k, Iface: ifc,
			Mark:  uint32(i+2) * opt.MarkStep,
			Table: opt.TableBase + i,
		}
		// A kill-switched GROUP makes its tunnel table fail closed. Each outbound tag gets its own
		// table, so this is per-group: rules routing to this same group share the table and its
		// fail-closed fate; rules routing elsewhere (even out the same iface via another tag) are
		// unaffected. Only a kernel tunnel egress can fail closed.
		if k == EgressInterface {
			if g := p.GroupByID(tag); g != nil && g.KillSwitch {
				eg.FailClosed = true
			}
		}
		plan.Egresses = append(plan.Egresses, eg)
	}

	// Denormalize each zone's mark from its egress, and sort for stable output.
	markByTag := map[string]uint32{}
	kindByTag := map[string]EgressKind{}
	for _, e := range plan.Egresses {
		markByTag[e.Tag] = e.Mark
		kindByTag[e.Tag] = e.Kind
	}
	for i := range plan.Zones {
		plan.Zones[i].Mark = markByTag[plan.Zones[i].EgressTag]
	}
	// Both render planes emit ONE non-terminating mark per zone, so for OVERLAPPING destination CIDRs
	// the LAST-emitted zone wins. Order blackhole (block-list) zones LAST so a block always wins over an
	// overlapping tunnel/route zone — otherwise an alphabetically-earlier block set is silently
	// overwritten by a later tunnel mark and the blocked traffic leaks out the tunnel. Within each
	// class keep Name order for stable, reproducible output.
	plan.Zones = orderZonesForEmit(plan.Zones, kindByTag)

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
// It used to compare each prefix against every prefix kept so far. On a hand-written list that is
// nothing; on an open feed it is the whole cost of the page. Measured on this router with a
// 15 866-prefix list — the ordinary size of `antifilter/allyouneed` — the quadratic scan ran ~125M
// containment checks and took EIGHT SECONDS, and both GET /api/pbr/status and the Apply review
// recompile from scratch on every call, so the panel spent most of its life waiting on it.
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

// orderZonesForEmit is the precedence the kernel plane really applies, extracted so it can be
// asserted directly — the Routing page describes this order to the operator, and the two used to be
// able to drift with nothing to catch it.
//
// Blocks last (their mark then wins an overlap), and among ordinary zones by NAME. That second half
// is the one worth stating out loud: it is NOT the order the operator arranged in the panel. On the
// operator's Keenetic the panel reads Telegram, Antifilter, Meta, Twitter, Re:filter, TeamViewer,
// GitHub while the mangle chain emits them alphabetically — invisible there only because all seven
// zones carry the same mark.
//
// Returns a new slice: the caller's Zones may be shared with a plan the caller still holds.
func orderZonesForEmit(zones []Zone, kindByTag map[string]EgressKind) []Zone {
	out := append([]Zone(nil), zones...)
	isBlock := func(z Zone) bool { return kindByTag[z.EgressTag] == EgressBlackhole }
	sort.Slice(out, func(i, j int) bool {
		if bi, bj := isBlock(out[i]), isBlock(out[j]); bi != bj {
			return !bi // non-block zones first; block/blackhole zones emitted last so their mark wins
		}
		return out[i].Name < out[j].Name
	})
	return out
}
