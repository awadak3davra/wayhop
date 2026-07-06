package keenetic

import (
	"fmt"
	"net/netip"

	"wayhop/internal/model"
)

// Plan is the full KeeneticOS config WayHop would apply for a profile: one NDM command
// block per native VPN interface, an optional sing-box config for the non-native endpoints
// (each behind its own TUN device), the `ip route` commands that steer traffic to either
// kind of interface, and warnings for the residue that is still not representable (domain
// entries, remote rule-set sources). Produced by Compile (pure); the apply layer (future,
// user-gated) submits the NDM commands over RCI and writes Singbox to /opt/etc/sing-box.
type Plan struct {
	Interfaces [][]string        // per-interface NDM command blocks (interface WireguardN … up)
	Routes     []string          // `ip route …` commands
	Warnings   []string          // residue still not representable (domain entries, remote sources)
	IfaceFor   map[string]string // endpoint ID → assigned iface ("WireguardN" native, "wrtunN" fallback)
	Singbox    map[string]any    // sing-box config for the non-native endpoints (nil if none) → /opt/etc/sing-box
}

// CompileOptions tune slot/metric assignment + the sing-box fallback.
type CompileOptions struct {
	BaseIndex  int             // first WireguardN slot to assign (default 10 — avoid clobbering existing 0-9)
	BaseMetric int             // `ip global` for the first endpoint; each next +25 (lower priority). Default 100.
	Fallback   FallbackOptions // sing-box fallback knobs for non-native endpoints (defaults apply)

	// AdoptInterfaces maps an endpoint ID to an ALREADY-LIVE interface name (the kernel/NDM
	// name routes should target, e.g. "nwg5" / "Wireguard5"). An adopted endpoint is NOT
	// (re)created — Compile records it in IfaceFor and routes target it, but emits no
	// `interface …` block (so Teardown never removes it either). This is mandatory for the
	// live cutover: mama's AmneziaWG tunnels (nwg0/1/3/5) already exist and must be reused, not
	// bounced. See keenetic-backend.md (DEPLOY phase, Phase 1).
	AdoptInterfaces map[string]string
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
// anti-loop route via ISP. Domain entries + remote rule-set sources are recorded as
// warnings (not natively routable as static routes). Pure — no device I/O.
func Compile(p *model.Profile, opt CompileOptions) (*Plan, error) {
	opt.defaults()
	plan := &Plan{IfaceFor: map[string]string{}}
	idx, metric := opt.BaseIndex, opt.BaseMetric

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
			plan.IfaceFor[e.ID] = adopted
			if ip, err := netip.ParseAddr(e.Server); err == nil { // anti-loop (External may have no Server → ExtraBypass covers it)
				bypass = append(bypass, ip.String())
			}
			continue
		}
		if !nativeIface(e) {
			nonNative = append(nonNative, e)
			continue
		}
		cmds, err := WireguardCommands(*e, WireguardOpts{Index: idx, Metric: metric})
		if err != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("endpoint %q: %v", e.ID, err))
			continue
		}
		plan.IfaceFor[e.ID] = fmt.Sprintf("Wireguard%d", idx)
		plan.Interfaces = append(plan.Interfaces, cmds)
		if ip, err := netip.ParseAddr(e.Server); err == nil { // anti-loop: peer endpoint IP → ISP
			bypass = append(bypass, ip.String())
		}
		idx++
		metric += 25
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
				continue // OutboundFor rejected it (already warned by the fallback)
			}
			plan.IfaceFor[e.ID] = iface
			if ip, err := netip.ParseAddr(e.Server); err == nil {
				bypass = append(bypass, ip.String())
			}
		}
	}

	// 2) Routing lists → static routes (IP-CIDR entries only; domains aren't native routes).
	var routes []Route
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		tgt, ok := targetFor(rl.Outbound, plan.IfaceFor)
		if !ok {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("list %q: outbound %q is not a native interface — skipped", rl.ID, rl.Outbound))
			continue
		}
		if rl.Source != "" {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("list %q: remote/domain rule-set source not natively routable (NDM app-routing or sing-box)", rl.ID))
		}
		domains := 0
		for _, entry := range rl.Manual {
			if _, err := cidrToAddrMask(entry); err != nil {
				domains++ // a domain, not an IP/CIDR — can't be a static route
				continue
			}
			routes = append(routes, Route{CIDR: entry, Target: tgt, Comment: rl.ID})
		}
		if domains > 0 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("list %q: %d domain entries skipped (not natively routable as ip route)", rl.ID, domains))
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
	plan.Routes = cmds
	return plan, nil
}

// targetFor maps a model outbound tag to a route target: block→reject, direct/""→ISP, a
// native endpoint→its WireguardN; a non-native/unknown outbound → (_, false).
func targetFor(outbound string, ifaceFor map[string]string) (RouteTarget, bool) {
	switch outbound {
	case model.OutboundBlock:
		return RouteTarget{Reject: true}, true
	case model.OutboundDirect, "":
		return RouteTarget{Iface: "ISP"}, true
	}
	if iface, ok := ifaceFor[outbound]; ok {
		return RouteTarget{Iface: iface}, true
	}
	return RouteTarget{}, false
}

// Commands flattens the plan into the full ordered NDM command list (all interface blocks,
// then the routes) — for preview/diff. The apply layer submits these over RCI /rci/parse.
func (p *Plan) Commands() []string {
	var out []string
	for _, block := range p.Interfaces {
		out = append(out, block...)
	}
	out = append(out, p.Routes...)
	return out
}
