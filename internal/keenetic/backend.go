package keenetic

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// Plan is the full KeeneticOS config WayHop would apply for a profile: one NDM command
// block per native VPN interface, an optional sing-box config for the non-native endpoints
// (each behind its own TUN device), and the `ip route` commands that steer traffic to either
// kind of interface. Compile refuses any active object it cannot represent; it never returns a
// partial plan that silently drops routing semantics. Produced by Compile (pure); the apply layer (future,
// user-gated) submits the NDM commands over RCI and writes Singbox to /opt/etc/sing-box.
type Plan struct {
	Interfaces [][]string        // per-interface NDM command blocks (interface WireguardN … up)
	Routes     []string          // `ip route …` commands
	Warnings   []string          // non-lossy informational notices only; never silently dropped semantics
	IfaceFor   map[string]string // endpoint ID → assigned iface ("WireguardN" native, "wrtunN" fallback)
	Singbox    map[string]any    // sing-box config for the non-native endpoints (nil if none) → /opt/etc/sing-box

	// GlobalPriority is the `ip global` ladder this plan wants: NDM interface name → priority. It is
	// how a default route is expressed natively — KeeneticOS routes everything through the highest
	// global connection — and it is kept OUT of Interfaces on purpose: those blocks describe
	// interfaces this plan owns and teardown removes, while these are edits to interfaces the router
	// owns. GlobalPriorityWas carries what each of them read before, so a rollback can put it back.
	GlobalPriority    map[string]int
	GlobalPriorityWas map[string]int

	// GroupMember records which member each failover group was compiled onto: the routes carrying
	// that group's traffic point at THIS member's interface. A group has no interface of its own on
	// the kernel plane — failover here is re-pointing these routes when the elected member changes,
	// so the caller has to be told what the current plan committed to in order to notice the change.
	GroupMember map[string]string

	// CompatibilityRouting means KeeneticOS cannot express the complete profile routing plane
	// losslessly (for example groups, domain rules, scoped lists, or custom DNS). Native VPN
	// interfaces remain owned by NDM, but one sing-box TUN named wrtun0 becomes the sole routing
	// authority. Routes must be empty in this mode so two routing planes can never disagree.
	CompatibilityRouting bool

	// RunningConfigRev is the SHA-256 of the exact NDM running-config observation used to
	// allocate interfaces and compile this plan. It binds the private materialization to the
	// transaction's final capture without persisting the credential-bearing router config.
	RunningConfigRev string
}

// CompileOptions tune slot/metric assignment + the sing-box fallback.
type CompileOptions struct {
	BaseIndex  int             // first WireguardN slot to assign (default 10 — avoid clobbering existing 0-9)
	BaseMetric int             // `ip global` for the first endpoint; each next +25 (lower priority). Default 100.
	Fallback   FallbackOptions // sing-box fallback knobs for non-native endpoints (defaults apply)

	// ListsViaIpset says the kernel policy plane (ipset + the MARK rules) is present and is what
	// carries routing lists on this router. Then a list's CIDRs must NOT also be emitted as NDM
	// static routes: the same destinations would be expressed twice, on two planes, and the static
	// form does not scale — measured, a single open feed is 15 866 prefixes against a 4096-command
	// ceiling on the NDM batch, so the whole Apply was rejected as an invalid plan. An ipset holds
	// those 15 866 entries as a hash set and does not care.
	//
	// The interfaces, the anti-loop bypass and the default-route ladder are still this plane's job;
	// only the per-list destinations move.
	ListsViaIpset bool

	// GlobalPriorityNow is what each interface's `ip global` currently reads, from the running
	// config (see GlobalPriorities). Compile needs it to place a default route ABOVE whatever holds
	// it today — the WAN — without guessing that router's numbers, and to record the previous value
	// for rollback. Absent map ⇒ no observation ⇒ Compile refuses to express a native default route
	// rather than inventing a ladder.
	GlobalPriorityNow map[string]int

	// GroupElection names, per failover group, the member that should carry its traffic right now.
	//
	// Compile is pure and probes nothing, so the choice would have to come from whoever holds the
	// health snapshot (the daemon's monitor). NOTHING sets it today — see the note at "1c) Failover
	// groups" for why that is a seam rather than an oversight — so in practice every group takes the
	// documented fallback: the first enabled, routable member in the operator's own order. An entry
	// naming a member this plan cannot route is ignored rather than obeyed.
	GroupElection map[string]string

	// AdoptInterfaces maps an endpoint ID to an ALREADY-LIVE interface name (the kernel/NDM
	// name routes should target, e.g. "nwg5" / "Wireguard5"). An adopted endpoint is NOT
	// (re)created — Compile records it in IfaceFor and routes target it, but emits no
	// `interface …` block (so Teardown never removes it either). This is mandatory for the
	// live cutover: a live router's AmneziaWG tunnels (nwg0/1/3/5) already exist and must be reused, not
	// bounced. See keenetic-backend.md (DEPLOY phase, Phase 1).
	AdoptInterfaces map[string]string

	// AdoptNDMNames maps an adopted endpoint ID to the NDM interface name (`Wireguard0`) that owns
	// the kernel link in AdoptInterfaces (`nwg0`).
	//
	// The two are different namespaces and only one of them is a routing target: `ip route … nwg0`
	// is answered by NDM with "argument parse error", because a Linux netdev name is not an NDM
	// interface. Routes to a WayHop-created tunnel were always correct — Compile assigns them
	// `WireguardN` — and only the adopted path put a kernel name into IfaceFor, which is why an
	// otherwise valid Apply died at native_commit on a router whose tunnels were adopted.
	//
	// The mapping cannot be derived: a hand-configured router may bind `Wireguard3` to `nwg5`, so
	// discovery reads it from NDM and the capture proves it before it is trusted here.
	AdoptNDMNames map[string]string

	// DomainsViaDNSMasq says the kernel policy plane is wired AND a resolver that can populate its
	// ipsets is present. Domains then stop forcing the compatibility core: dnsmasq adds each answer's
	// address to the zone's set at query time and the existing MARK rule routes it — the same trick
	// keen-pbr used, and the only way a name reaches a plane that matches addresses.
	//
	// Off by default so a router without that resolver keeps the conservative behaviour: a domain it
	// cannot populate must still pull in the core rather than silently routing nothing.
	DomainsViaDNSMasq bool

	// OccupiedInterfaces is captured from the same reviewed NDM running-config observation.
	// Managed endpoints are allocated only into slots that are not already owned by firmware,
	// another service, or an adopted tunnel.
	OccupiedInterfaces map[string]bool
}

func (o *CompileOptions) defaults() {
	if o.BaseIndex == 0 {
		o.BaseIndex = 10
	}
	if o.BaseMetric == 0 {
		o.BaseMetric = 100
	}
}

// nativeIface reports whether an endpoint maps to a KeeneticOS-native kernel interface
// (AmneziaWG or plain WireGuard) — the native-first path. Everything else (VLESS/Reality/
// Hysteria2/TUIC) needs the sing-box fallback.
func nativeIface(e *model.Endpoint) bool {
	return e.Engine == model.EngineAmneziaWG ||
		(e.Engine == model.EngineSingBox && e.Protocol == model.ProtoWireGuard)
}

// Compile turns a WayHop profile into a Keenetic Plan. Enabled AmneziaWG/WireGuard
// endpoints become native `interface WireguardN` (kernel + HW crypto); enabled non-native
// endpoints (VLESS/Reality/Hysteria2/TUIC) become sing-box TUN devices (`wrtunN`) via the
// fallback. Either kind is then a routable interface: routing-list IP-CIDRs become `ip route`
// to the chosen interface (or ISP/reject), and each endpoint's own server IP gets an
// anti-loop route via ISP. Any active rule/list semantics this backend cannot reproduce exactly are
// refused before a Plan is returned. Pure — no device I/O.
func Compile(p *model.Profile, opt CompileOptions) (*Plan, error) {
	if p == nil {
		return nil, fmt.Errorf("nil profile")
	}
	opt.defaults()
	compatibilityRouting := needsCompatibilityRouting(p, opt.DomainsViaDNSMasq)
	plan := &Plan{
		IfaceFor:             map[string]string{},
		CompatibilityRouting: compatibilityRouting,
	}
	idx, metric := opt.BaseIndex, opt.BaseMetric
	occupied := make(map[string]bool, len(opt.OccupiedInterfaces)+len(opt.AdoptInterfaces))
	for iface, present := range opt.OccupiedInterfaces {
		if present {
			occupied[iface] = true
		}
	}
	for _, iface := range opt.AdoptInterfaces {
		if strings.HasPrefix(iface, "Wireguard") {
			occupied[iface] = true
		} else if strings.HasPrefix(iface, "nwg") {
			occupied["Wireguard"+strings.TrimPrefix(iface, "nwg")] = true
		}
	}

	// 1) Native VPN endpoints → interface command blocks; non-native ones are collected for
	// the sing-box fallback below.
	var bypass []string
	var nonNative []*model.Endpoint
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		// Adopt an already-live interface (any engine): record it so routes can target it,
		// but never (re)create or tear it down. Must precede the native/fallback branches.
		if adopted, ok := opt.AdoptInterfaces[e.ID]; ok && adopted != "" {
			// IfaceFor is the ROUTE TARGET namespace — "WireguardN"/"wrtunN", per its own doc and
			// RouteTarget.Iface's. The adopted kernel name belongs to the link, not to NDM's
			// routing table, so it must be translated here or every route to an adopted tunnel is
			// rejected. Fail closed rather than emitting the kernel name: a route NDM refuses is a
			// failed Apply, but a route it silently accepts against the wrong interface would be a
			// datapath pointing somewhere nobody chose.
			target := opt.AdoptNDMNames[e.ID]
			if target == "" {
				return nil, fmt.Errorf("adopted endpoint %q has no NDM interface name for its routes", e.ID)
			}
			plan.IfaceFor[e.ID] = target
			if ip, err := netip.ParseAddr(e.Server); err == nil { // anti-loop (External may have no Server → ExtraBypass covers it)
				bypass = append(bypass, ip.String())
			}
			continue
		}
		if !nativeIface(e) {
			nonNative = append(nonNative, e)
			continue
		}
		for idx < 4096 && occupied[fmt.Sprintf("Wireguard%d", idx)] {
			idx++
		}
		if idx >= 4096 {
			return nil, fmt.Errorf("native endpoint %q: no free reviewed Wireguard slot", e.ID)
		}
		cmds, err := WireguardCommands(*e, WireguardOpts{Index: idx, Metric: metric})
		if err != nil {
			return nil, fmt.Errorf("native endpoint %q: %w", e.ID, err)
		}
		plan.IfaceFor[e.ID] = fmt.Sprintf("Wireguard%d", idx)
		occupied[plan.IfaceFor[e.ID]] = true
		plan.Interfaces = append(plan.Interfaces, cmds)
		if ip, err := netip.ParseAddr(e.Server); err == nil { // anti-loop: peer endpoint IP → ISP
			bypass = append(bypass, ip.String())
		}
		idx++
		metric += 25
	}

	// In compatibility-routing mode sing-box must see the complete profile at materialization
	// time, after native endpoints have been converted to exact external-interface bindings. This
	// marker is deliberately not an executable config. Every non-native endpoint shares the one
	// captured TUN; NDM routes are omitted below so that TUN is the sole routing authority.
	if compatibilityRouting {
		plan.Singbox = map[string]any{"wayhop_compatibility_routing": true}
		for _, e := range nonNative {
			plan.IfaceFor[e.ID] = "wrtun0"
		}
		return plan, nil
	}

	// 1b) Non-native endpoints → sing-box fallback (one TUN device each). NDM routes lists to
	// those TUNs exactly like a native interface; sing-box owns only the device, not the
	// routing/metric tiers. Each proxy server IP also gets an anti-loop ISP route.
	if len(nonNative) > 0 {
		fb, err := SingboxFallback(nonNative, opt.Fallback)
		if err != nil {
			return nil, fmt.Errorf("sing-box fallback: %w", err)
		}
		plan.Singbox = fb.Config
		plan.Warnings = append(plan.Warnings, fb.Warnings...)
		for _, e := range nonNative {
			iface, ok := fb.IfaceFor[e.ID]
			if !ok {
				return nil, fmt.Errorf("sing-box compatibility addon omitted active endpoint %q", e.ID)
			}
			plan.IfaceFor[e.ID] = iface
			if ip, err := netip.ParseAddr(e.Server); err == nil {
				bypass = append(bypass, ip.String())
			}
		}
	}

	// 1c) Failover groups → the interface of their elected member.
	//
	// A group is not a device: on the kernel plane it is a NAME for whichever member currently
	// carries its traffic, and failing over is re-pointing that name's routes at another interface.
	// Compile pins it to one member here. This is the whole reason a native group needs no proxy core
	// — the core's contribution was picking the member, which is a decision, not a datapath.
	//
	// WHO picks, today: nobody. GroupElection is the seam for a health-driven choice and NOTHING in
	// the daemon writes it (checked across the tree), so every group takes the branch below — the
	// first enabled, routable member in the operator's own order. That is fallback semantics for
	// every group type, including urltest, and it is what the panel now says on a native group
	// instead of promising a latency contest nobody runs.
	//
	// The earlier wording here said the daemon "supplies the choice through GroupElection and
	// recompiles when health moves it", which described an intention as a behaviour. Wiring it is not
	// free either: this plan is authenticated between review and execution, so an election that moves
	// with health would change the plan under its own signature — which is why it is a seam and not
	// yet a feature.
	plan.GroupMember = map[string]string{}
	groupIface := map[string]string{}
	for gi := range p.Groups {
		g := &p.Groups[gi]
		elected := opt.GroupElection[g.ID]
		if _, routable := plan.IfaceFor[elected]; !routable {
			elected = "" // an election naming a member this plan cannot route is not usable
		}
		if elected == "" {
			for _, m := range g.Members {
				if _, ok := plan.IfaceFor[m]; ok {
					elected = m
					break
				}
			}
		}
		if elected == "" {
			continue // no routable member; targetFor's existing refusal below names the group
		}
		plan.GroupMember[g.ID] = elected
		groupIface[g.ID] = plan.IfaceFor[elected]
	}

	// 1d) A default rule → the global-connection ladder (see defaultRouteLadder).
	if err := defaultRouteLadder(p, plan, opt, groupIface); err != nil {
		return nil, err
	}

	// 2) Routing lists → static routes (IP-CIDR entries only; domains aren't native routes).
	var routes []Route
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		tgt, ok := targetFor(rl.Outbound, plan.IfaceFor, groupIface)
		if !ok {
			if p.GroupByID(rl.Outbound) != nil {
				return nil, fmt.Errorf("list %q: outbound %q is a failover group with no member this backend can route to", rl.ID, rl.Outbound)
			}
			return nil, fmt.Errorf("list %q: outbound %q is not an executable native or compatibility interface", rl.ID, rl.Outbound)
		}
		// Device scope has NO native static-route equivalent (a static route can't match by source
		// device), so a scoped list applied here would route/block ALL clients, not just its device
		// group — a correctness/privacy regression. Refuse rather than widening it to all clients.
		if m := rl.ScopeMode; m == "only" || m == "except" {
			return nil, fmt.Errorf("list %q: device scope %q cannot be represented natively without widening it to all clients", rl.ID, m)
		}
		if rl.Source != "" {
			return nil, fmt.Errorf("list %q: remote/domain source cannot be represented by the native static-route backend", rl.ID)
		}
		if rl.CIDRSource != "" && len(rl.CIDRCache) == 0 {
			return nil, fmt.Errorf("list %q: CIDR source has no reviewed CIDR cache; refresh it before Apply", rl.ID)
		}
		// The outbound was resolved above, which is the part that must be checked on every plane; the
		// destinations themselves belong to whichever plane carries them. With the ipset plane present
		// that is not this one.
		if opt.ListsViaIpset {
			continue
		}
		entries := make([]string, 0, len(rl.Manual)+len(rl.CIDRCache))
		entries = append(entries, rl.Manual...)
		entries = append(entries, rl.CIDRCache...)
		seenEntries := make(map[string]bool, len(entries))
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if seenEntries[entry] {
				continue
			}
			if _, err := cidrToAddrMask(entry); err != nil {
				// A name has no static route: its addresses are not known until something resolves
				// it. With the resolver wired those entries become ipset members at query time, so
				// they are skipped here rather than failing the plan; without it they are genuinely
				// unrepresentable and the compatibility check above has already pulled in the core.
				if opt.DomainsViaDNSMasq {
					continue
				}
				return nil, fmt.Errorf("list %q: entry %q is not an IP/CIDR and cannot be represented by the native static-route backend", rl.ID, entry)
			}
			seenEntries[entry] = true
			routes = append(routes, Route{CIDR: entry, Target: tgt, Comment: rl.ID})
		}
	}

	// 3) Anti-loop bypass routes: a tunnel's own server IP must egress via ISP, never back
	// into the tunnel (mirrors the OpenWrt pbr bypass).
	for _, ip := range bypass {
		routes = append(routes, Route{CIDR: ip, Target: RouteTarget{Iface: "ISP"}, Comment: "wr_bypass"})
	}

	cmds, err := RouteCommands(routes)
	if err != nil {
		return nil, err
	}
	// The NDM batch has a hard command ceiling, and a plan over it is rejected wholesale with
	// "invalid plan" — a message that says nothing about the feed that caused it. Say it here, where
	// the number and the name are still in hand.
	if len(cmds) > MaxNativeRouteCommands {
		return nil, fmt.Errorf("this profile needs %d native static routes, over the %d this router accepts in one batch — the kernel policy plane (ipset) carries lists of that size; install it, or shorten the lists",
			len(cmds), MaxNativeRouteCommands)
	}
	plan.Routes = cmds
	return plan, nil
}

// MaxNativeRouteCommands mirrors the executor's per-batch command ceiling, minus room for the
// interface blocks and the priority ladder that share it.
const MaxNativeRouteCommands = 3500

// needsCompatibilityRouting reports when native NDM static routes cannot represent every active
// routing/DNS semantic. It is intentionally conservative: false means the native plan is complete;
// true keeps native connections but moves the complete routing policy into one compatibility TUN.
// needsCompatibilityRouting is the decision; compatibilityReason is the same walk, returning WHY.
// One function, so the sentence the panel shows can never drift from the branch Apply takes.
func needsCompatibilityRouting(p *model.Profile, domainsViaDNSMasq bool) bool {
	return len(compatibilityReasons(p, domainsViaDNSMasq)) > 0
}

func compatibilityReasons(p *model.Profile, domainsViaDNSMasq bool) []string {
	var reasons []string
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled {
			continue
		}
		// A default rule with no matchers says "everything goes here", and KeeneticOS says that with
		// the global-connection ladder (defaultRouteLadder) — no core involved, provided what it
		// points at is something this backend can route to.
		if ruleIsPlainDefault(r) && outboundIsNativelyRoutable(p, r.Outbound) {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("rule %q is not a plain default to a natively routable exit", r.ID))
	}
	// A group used to pull in the core unconditionally, on the reading that "the fastest of five" is
	// not a static route. Only the CHOICE is not static: at any instant the group is one member, and
	// failing over is re-pointing its routes — which is Compile plus the daemon's election, not a
	// proxy core. So only a group this backend cannot resolve on its own still needs one.
	for gi := range p.Groups {
		if !groupIsNativelyRoutable(p, &p.Groups[gi]) {
			reasons = append(reasons, fmt.Sprintf("group %q holds a member this router cannot route to natively", p.Groups[gi].ID))
		}
	}
	reasons = append(reasons, dnsPlaneCoreReasons(p)...)
	for i := range p.RoutingLists {
		list := &p.RoutingLists[i]
		if !list.Enabled {
			continue
		}
		if list.Source != "" || list.ScopeMode == "only" || list.ScopeMode == "except" {
			reasons = append(reasons, fmt.Sprintf("routing list %q ships as a sing-box rule-set or is scoped to specific devices", list.ID))
		}
		// Pointing a list at a group is only unrepresentable when the GROUP is: a natively routable
		// one resolves to a member's interface, which is an ordinary static route (see targetFor).
		if g := p.GroupByID(list.Outbound); g != nil && !groupIsNativelyRoutable(p, g) {
			reasons = append(reasons, fmt.Sprintf("routing list %q points at a group this router cannot route to natively", list.ID))
		}
		// A fetched domain feed is carried by the resolver plane, exactly like a typed name — and it
		// needs that plane present for the same reason. Without it the list would route nothing and
		// say nothing, so the core takes the whole policy instead.
		if (list.DomainSource != "" || len(list.DomainCache) > 0) && !domainsViaDNSMasq {
			reasons = append(reasons, fmt.Sprintf("routing list %q carries a domain feed and no resolver plane is wired", list.ID))
		}
		for _, entry := range list.Manual {
			entry = strings.TrimSpace(entry)
			if _, err := netip.ParseAddr(entry); err == nil {
				continue
			}
			if _, err := netip.ParsePrefix(entry); err != nil {
				// A name. The kernel plane carries it through the resolver when one is wired;
				// otherwise it is unroutable here and the core has to take the whole policy.
				if !domainsViaDNSMasq {
					// One sentence per list, not per name: the walk used to return here, and a list of
					// forty typed names would otherwise repeat the same reason forty times.
					reasons = append(reasons, fmt.Sprintf("routing list %q carries a domain name and no resolver plane is wired", list.ID))
					break
				}
			}
		}
	}
	return reasons
}

// GlobalPriorityStep spaces the ladder. Wide enough that the router's own numbers (which land on
// fractions of 65535) never collide with ours, small enough that several members still fit above the
// WAN.
//
// Exported because anything that RE-POINTS a ladder Compile laid out has to use the same spacing, or
// the two produce different numbers for the same intent and start fighting over which member is on
// top. internal/server/failovernative.go carried its own copy of the value with a comment claiming
// the two "can never drift into fighting each other" — two independent constants are exactly a thing
// that can drift, and a claim a compiler does not check is a wish.
const GlobalPriorityStep = 512

// ruleIsPlainDefault reports a rule that says only "everything goes here". Any matcher — destination,
// source, port — is a selection the static plane cannot make, and belongs to the core or the ipset
// plane; this is the one rule shape that is just a default route.
func ruleIsPlainDefault(r *model.Rule) bool {
	return r.Default &&
		len(r.Domain) == 0 && len(r.DomainSuffix) == 0 && len(r.GeoSite) == 0 && len(r.GeoIP) == 0 &&
		len(r.IPCIDR) == 0 && len(r.Port) == 0 && len(r.SourceIPCIDR) == 0 &&
		len(r.SourceMAC) == 0 && len(r.SourceIface) == 0 && len(r.SourcePort) == 0
}

// outboundIsNativelyRoutable answers, for a default rule's target, whether KeeneticOS can carry it
// without a proxy core. `direct` already is the default route. `block` is not a ladder — dropping
// everything is a firewall statement, not a connection priority — and neither is a group with a kill
// switch, whose whole point is that traffic must NOT fall back to the open WAN when its members die.
func outboundIsNativelyRoutable(p *model.Profile, tag string) bool {
	switch tag {
	case model.OutboundDirect, "":
		return true
	case model.OutboundBlock:
		return false
	}
	if e := p.EndpointByID(tag); e != nil {
		return e.Enabled && (e.IsExternal() || nativeIface(e))
	}
	if g := p.GroupByID(tag); g != nil {
		return !g.KillSwitch && groupIsNativelyRoutable(p, g)
	}
	return false
}

// defaultRouteLadder expresses an enabled, matcher-less default rule the way KeeneticOS expresses
// one: by raising the interfaces that should carry everything above the connection carrying it now.
//
// This is why a native default route needs no static 0.0.0.0/0 and no anti-loop bypass. NDM owns the
// default route and keeps each tunnel's own peer traffic on the underlying WAN — which matters here
// because an adopted tunnel's peer is often a HOSTNAME (measured: `cy.…online:9987`), so there is no
// address to write a bypass route to in the first place.
//
// The whole group goes on the ladder, elected member on top, in the operator's order: when the top
// one drops, the router's own connection failover walks to the next member instead of falling to the
// WAN. Every value we overwrite is recorded in GlobalPriorityWas so a rollback restores the router's
// own ordering rather than leaving ours behind.
func defaultRouteLadder(p *model.Profile, plan *Plan, opt CompileOptions, groupIface map[string]string) error {
	var rule *model.Rule
	for i := range p.Rules {
		if !p.Rules[i].Disabled && ruleIsPlainDefault(&p.Rules[i]) {
			rule = &p.Rules[i]
			break
		}
	}
	if rule == nil || rule.Outbound == model.OutboundDirect || rule.Outbound == "" {
		return nil // nothing to raise: the WAN already holds the default route
	}

	// Targets, best first. A group brings its whole membership so the ladder has depth.
	var targets []string
	if g := p.GroupByID(rule.Outbound); g != nil {
		if elected := plan.GroupMember[g.ID]; elected != "" {
			targets = append(targets, elected)
		}
		for _, m := range g.Members {
			if m != plan.GroupMember[g.ID] {
				targets = append(targets, m)
			}
		}
	} else {
		targets = append(targets, rule.Outbound)
	}
	var ifaces []string
	for _, id := range targets {
		if iface, ok := plan.IfaceFor[id]; ok {
			ifaces = append(ifaces, iface)
		}
	}
	if len(ifaces) == 0 {
		if iface, ok := groupIface[rule.Outbound]; ok {
			ifaces = []string{iface}
		} else {
			return fmt.Errorf("default rule %q: outbound %q has no interface this backend can route to", rule.ID, rule.Outbound)
		}
	}

	// Without the router's own numbers there is nothing to be higher THAN, and a guessed ladder is a
	// guessed default route. Refuse instead: the caller falls back to the core path.
	if len(opt.GlobalPriorityNow) == 0 {
		return fmt.Errorf("default rule %q: no observed `ip global` priorities; cannot place a native default route", rule.ID)
	}
	ours := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		ours[iface] = true
	}
	ceiling := 0
	for iface, prio := range opt.GlobalPriorityNow {
		if !ours[iface] && prio > ceiling {
			ceiling = prio
		}
	}
	top := ceiling + GlobalPriorityStep*len(ifaces)
	if top > 65535 {
		return fmt.Errorf("default rule %q: no room above the current global priorities (ceiling %d)", rule.ID, ceiling)
	}
	plan.GlobalPriority = map[string]int{}
	plan.GlobalPriorityWas = map[string]int{}
	for i, iface := range ifaces {
		plan.GlobalPriority[iface] = top - GlobalPriorityStep*i
		plan.GlobalPriorityWas[iface] = opt.GlobalPriorityNow[iface]
	}
	return nil
}

// dnsPlaneNeedsCore reports whether the DNS block asks for something only the proxy core can do.
//
// Having a DNS block used to be the whole test, which made "manage DNS" mean "install sing-box" even
// when every resolver in it goes out DIRECT and there are no rules — a configuration this router
// carries with its own dnsmasq and DoH. Two things genuinely need the core: a resolver whose queries
// must leave through a TUNNEL (the kernel plane routes packets by destination, and a resolver's
// detour is a statement about which exit its own traffic takes), and FakeIP, which is synthetic
// addressing that only the core can hand out and then match on.
func dnsPlaneNeedsCore(p *model.Profile) bool {
	return len(dnsPlaneCoreReasons(p)) > 0
}

// dnsPlaneCoreReasons names WHICH part of the DNS block asks for the core. The decision used to be a
// bare yes, so the panel could only recite the four things that might have caused it - and on the
// operator's router, where the DNS plane is the single reason sing-box runs at all, "an encrypted
// resolver, a fakeip plane, a detour, or a per-name rule" is a list to work through rather than an
// answer. Same walk as the decision, so the two cannot disagree.
func dnsPlaneCoreReasons(p *model.Profile) []string {
	if p.DNS == nil || !p.DNS.Enabled {
		return nil
	}
	var reasons []string
	if p.DNS.FakeIP {
		reasons = append(reasons, "the DNS plane uses fakeip, which only the core can synthesise")
	}
	for i := range p.DNS.Servers {
		s := &p.DNS.Servers[i]
		if !s.Enabled {
			continue
		}
		// An ENCRYPTED resolver needs the core whatever its detour: dnsmasq speaks plain UDP/TCP and
		// nothing else, so DoH/DoT/DoQ exists on this router only if sing-box is running. Leaving this
		// out is what made the plan read "native only" on a box whose profile asked for DoH — measured
		// on a live router: two DoH resolvers configured, the core installed and idle, and
		// dnsmasq answering in plaintext while the panel said the lookups were encrypted.
		tag := s.Tag
		if tag == "" {
			tag = s.Type
		}
		if model.IsEncryptedDNSType(s.Type) {
			reasons = append(reasons, fmt.Sprintf(
				"resolver %q is encrypted (%s) and dnsmasq speaks only plain UDP/TCP", tag, s.Type))
			continue
		}
		switch strings.TrimSpace(s.Detour) {
		case "", model.OutboundDirect:
		default:
			reasons = append(reasons, fmt.Sprintf(
				"resolver %q resolves through %q rather than direct", tag, strings.TrimSpace(s.Detour)))
		}
	}
	for i := range p.DNS.Rules {
		if !p.DNS.Rules[i].Disabled {
			// One sentence for the class: a per-name rule is resolver policy the core owns, and
			// twenty of them are still the same requirement.
			reasons = append(reasons, "a per-name DNS rule is resolver policy the core owns")
			break
		}
	}
	return reasons
}

// groupIsNativelyRoutable reports whether every member of g is something this backend turns into an
// interface by itself — an adopted tunnel or a kernel-native one. A group of those needs no core:
// its routes are the member's routes. One member that is neither (a VLESS endpoint, a nested group)
// is enough to need the core, and it is that MEMBER that requires it, not the group.
func groupIsNativelyRoutable(p *model.Profile, g *model.Group) bool {
	if g == nil || len(g.Members) == 0 {
		return false
	}
	for _, m := range g.Members {
		e := p.EndpointByID(m)
		if e == nil || !e.Enabled {
			return false
		}
		// External = an interface the router already runs; Compile adopts it ahead of the native
		// branch and hands it to no core. Same exemption gateEndpoint and PlanRequiresCore make.
		if e.IsExternal() {
			continue
		}
		if !nativeIface(e) {
			return false
		}
	}
	return true
}

// targetFor maps a model outbound tag to a route target: block→reject, direct/""→ISP, a native
// endpoint→its WireguardN, a failover group→the interface of the member it was compiled onto; a
// non-native/unknown outbound → (_, false).
func targetFor(outbound string, ifaceFor, groupIface map[string]string) (RouteTarget, bool) {
	switch outbound {
	case model.OutboundBlock:
		return RouteTarget{Reject: true}, true
	case model.OutboundDirect, "":
		return RouteTarget{Iface: "ISP"}, true
	}
	if iface, ok := ifaceFor[outbound]; ok {
		return RouteTarget{Iface: iface}, true
	}
	if iface, ok := groupIface[outbound]; ok {
		return RouteTarget{Iface: iface}, true
	}
	return RouteTarget{}, false
}

// Commands flattens the plan into the full ordered NDM command list (all interface blocks, the
// priority ladder, then the routes) — for preview/diff. The apply layer submits these over RCI
// /rci/parse.
func (p *Plan) Commands() []string {
	var out []string
	for _, block := range p.Interfaces {
		out = append(out, block...)
	}
	for _, block := range p.GlobalPriorityBlocks() {
		out = append(out, block...)
	}
	out = append(out, p.Routes...)
	return out
}

// GlobalPriorityBlocks renders the ladder as NDM command blocks — the same shape as Interfaces, and
// deliberately NOT stored there: an entry here edits one setting on an interface the ROUTER owns,
// while an Interfaces block describes an interface this plan owns and teardown removes with `no
// interface`. Filing a priority edit under the latter would make a rollback delete an adopted tunnel.
//
// Sorted by interface name so the batch, the diff and the verification are reproducible.
func (p *Plan) GlobalPriorityBlocks() [][]string { return priorityBlocks(p.GlobalPriority) }

// GlobalPriorityRestoreBlocks puts the router's own numbers back. This is what a rollback submits;
// without it an aborted apply would leave our ladder in place, silently owning the default route.
func (p *Plan) GlobalPriorityRestoreBlocks() [][]string { return priorityBlocks(p.GlobalPriorityWas) }

// StaleGlobalPriorityBlocks restores the interfaces the PREVIOUS plan raised and this one no longer
// does. It is the ladder's half of reconciliation, and it was missing.
//
// The ladder is not a resource with a `no` command: raising an interface overwrites a number the
// ROUTER owns, so nothing in TeardownCommands can undo it, and the rollback path only runs when an
// apply fails. A successful apply that stopped pointing the default rule at a tunnel therefore left
// the tunnel sitting on top of the ladder. Measured on a live Keenetic: the default rule was
// switched to `direct`, the apply reported success, and every client kept egressing through Yerevan
// until the five priorities were restored by hand — the panel said one thing and the router did
// another, which is the failure this whole apply path exists to prevent.
//
// An interface the target raises again is NOT restored: the target's own ladder block overwrites it
// in the same batch, and restoring it first would be a pointless write and a moment of ambiguity
// about which interface holds the default.
func StaleGlobalPriorityBlocks(previous, target *Plan) [][]string {
	if previous == nil || len(previous.GlobalPriority) == 0 {
		return nil
	}
	stale := map[string]int{}
	for iface := range previous.GlobalPriority {
		if target != nil {
			if _, stillOurs := target.GlobalPriority[iface]; stillOurs {
				continue
			}
		}
		// Only what we actually observed before raising it. Without a recorded previous value there is
		// no number to write, and inventing one would be a guessed default route — the same refusal
		// defaultRouteLadder makes when it cannot see the router's own priorities.
		if was, known := previous.GlobalPriorityWas[iface]; known {
			stale[iface] = was
		}
	}
	return priorityBlocks(stale)
}

func priorityBlocks(ladder map[string]int) [][]string {
	if len(ladder) == 0 {
		return nil
	}
	ifaces := make([]string, 0, len(ladder))
	for iface := range ladder {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)
	out := make([][]string, 0, len(ifaces))
	for _, iface := range ifaces {
		out = append(out, []string{"interface " + iface, "ip global " + strconv.Itoa(ladder[iface])})
	}
	return out
}

// PlanRequiresCore reports whether Compile would populate Plan.Singbox for this profile — that is,
// whether a Keenetic native apply materializes a sing-box core at all. It exists so the Apply review
// can ask the same question the executor answers instead of a differently-shaped one: the executor
// sets coreAction=ensure_absent exactly when Plan.Singbox is nil, while the review used to demand
// the core capability whenever generator.DatapathNativeOnly was false. That predicate hard-requires
// routing mode "fast", which is SeverityBlocked on a router without nftables, so on KeeneticOS it
// could never be true and every Apply was blocked for want of a core the executor would never start.
//
// It deliberately lives beside needsCompatibilityRouting and nativeIface: the two branches below
// mirror Compile's own classification, and keeping them in one file is what stops them drifting.
func PlanRequiresCore(p *model.Profile, domainsViaDNSMasq bool) bool {
	return len(CoreReasons(p, domainsViaDNSMasq)) > 0
}

// CoreReasons is PlanRequiresCore with its answer in words: every condition in this profile that
// pulls sing-box in, or nothing when the datapath is native end to end.
//
// The panel could say THAT the core is part of the datapath and never which part of the profile put
// it there, which leaves "run this router without sing-box" as a goal nobody can act on. Measured on
// a live Keenetic: five IP lists, two domain lists, a five-member native group and a plain
// default rule are all carried natively, and the single thing keeping sing-box alive is the DNS
// plane. That sentence is the whole difference between a fact and a next step.
//
// Derived from the same walk the decision uses, never a second opinion about it.
func CoreReasons(p *model.Profile, domainsViaDNSMasq bool) []string {
	if p == nil {
		return nil
	}
	// Compatibility routing folds the complete policy into one sing-box TUN.
	reasons := compatibilityReasons(p, domainsViaDNSMasq)
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		// Disabled endpoints are skipped by Compile's first statement and materialize nothing.
		if !e.Enabled {
			continue
		}
		// Compile adopts an already-live external interface ahead of the native/fallback branches
		// and never hands it to sing-box. Review cannot see the live AdoptInterfaces map, but an
		// enabled external endpoint whose NDM identity does not resolve is already refused by the
		// review.endpoint.external.keenetic_identity finding, so treating external as core-free here
		// cannot let an unrealizable plan through.
		if e.IsExternal() {
			continue
		}
		// Everything Compile does not recognise as kernel-native becomes a sing-box TUN.
		if !nativeIface(e) {
			name := e.Name
			if name == "" {
				name = e.ID
			}
			reasons = append(reasons, fmt.Sprintf("connection %q is not a kernel-native tunnel", name))
		}
	}
	return reasons
}
