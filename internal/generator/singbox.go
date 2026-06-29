// Package generator translates the protocol-agnostic model into a core-native
// config. singbox.go targets sing-box: endpoints become outbounds, groups
// become urltest/selector, rules become the route. Non-sing-box engines
// (AmneziaWG, OpenVPN) are emitted as chained SOCKS outbounds plus a Plugin
// record the daemon uses to spawn the engine. See docs/ARCHITECTURE.md.
package generator

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"velinx/internal/model"
	"velinx/internal/pbr"
	"velinx/internal/util"
)

// isBlock reports whether a rule outbound names the builtin block target,
// case-insensitively (validation accepts "Block"/"BLOCK" too).
func isBlock(o string) bool { return strings.EqualFold(o, model.OutboundBlock) }

// canonicalOutbound lowercases the builtin direct/block tags to their canonical
// form (the generator only emits lowercase "direct"); endpoint/group IDs, which
// are case-sensitive, pass through unchanged.
func canonicalOutbound(o string) string {
	switch strings.ToLower(o) {
	case model.OutboundDirect:
		return model.OutboundDirect
	case model.OutboundBlock:
		return model.OutboundBlock
	}
	return o
}

const (
	defaultHealthURL = "http://cp.cloudflare.com/generate_204"
	basePluginPort   = 17900 // local SOCKS port block for engine plugins
)

// kernelEgress reports whether an outbound tag resolves to a kernel-plane egress in
// hybrid mode — an AmneziaWG/External endpoint, or a group with at least one such
// member. It uses pbr.KernelIface so the classification is BYTE-IDENTICAL to
// pbr.Compile (the two planes must partition the same outbound set; any drift would
// either dangle a sing-box reference or leave a CIDR routed by neither plane). direct/
// block/"" are never kernel (they stay in sing-box / become reject).
func kernelEgress(p *model.Profile, tag string) bool {
	switch tag {
	case model.OutboundDirect, model.OutboundBlock, "":
		return false
	}
	if e := p.EndpointByID(tag); e != nil {
		return pbr.KernelIface(e) != ""
	}
	if g := p.GroupByID(tag); g != nil {
		for _, m := range g.Members {
			if me := p.EndpointByID(m); me != nil && pbr.KernelIface(me) != "" {
				return true
			}
		}
	}
	return false
}

// ipOnlyKernelRule reports whether a rule is routed IDENTICALLY by pbr, so it can be
// dropped from sing-box in hybrid mode: a pure IP-CIDR matcher with NO domain/geosite/
// geoip and NO port matcher. pbr routes a rule's whole IPCIDR set to its kernel egress
// verbatim; a domain/geo matcher (pbr ignores it → over-routes the whole IP set) or a
// port matcher (pbr has no port concept) would make pbr's routing diverge from sing-
// box's AND semantics, so such a rule is KEPT in sing-box (and its kernel outbound
// preserved). The caller checks the outbound is kernel-class via kernelEgress. A rule
// carrying ANY source matcher is likewise KEPT in sing-box — pbr has no source concept
// until taught one (Phase C), and a source rule's semantics differ from a pure kernel
// zone — so source rules are never dropped to the kernel plane by this predicate.
func ipOnlyKernelRule(r *model.Rule) bool {
	return len(r.IPCIDR) > 0 &&
		len(r.Domain) == 0 && len(r.DomainSuffix) == 0 &&
		len(r.GeoSite) == 0 && len(r.GeoIP) == 0 && len(r.Port) == 0 &&
		len(r.SourceIPCIDR) == 0 && len(r.SourceMAC) == 0 &&
		len(r.SourceIface) == 0 && len(r.SourcePort) == 0
}

// hybridReachable returns the set of outbound tags reachable from the route references
// that SURVIVE into sing-box in hybrid mode — non-default rules pbr can't kernel-route,
// kept routing lists, and every rule's outbound that becomes route.final — following
// group membership TRANSITIVELY (so a kept group's members, including kernel endpoints
// and nested groups, are reached too). A kernel-class outbound (endpoint or group) is
// safe to OMIT only when it is NOT reachable: otherwise a surviving rule, the final, or
// a kept group's member list would reference a tag that no longer exists, and a dangling
// reference fails `sing-box check`, taking ALL routing down on apply. Keeping a still-
// referenced kernel outbound is always safe — it just routes via sing-box (bound to its
// interface) exactly as in non-hybrid mode. The set of DROPPED rules/lists here mirrors
// routeFrom/routingFrom's skip predicate exactly, so reachability and rule emission agree.
func hybridReachable(p *model.Profile) map[string]bool {
	roots := map[string]bool{}
	addRoot := func(tag string) {
		switch canonicalOutbound(tag) {
		case model.OutboundDirect, model.OutboundBlock, "":
			return // builtins are always present / become reject; never omitted
		}
		roots[tag] = true
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled {
			continue // mirrors routeFrom: a disabled rule is never emitted, references nothing
		}
		// A non-default pure-IP rule pointed at a kernel egress is dropped from sing-box
		// (pbr routes it); its outbound is therefore not referenced by it. Every other
		// rule — including a default (its outbound becomes route.final) — keeps its ref.
		if !r.Default && kernelEgress(p, r.Outbound) && ipOnlyKernelRule(r) {
			continue
		}
		addRoot(r.Outbound)
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		// A pure-IP manual list (no remote Source, no domains) to a kernel egress is
		// dropped (pbr routes it); any other list stays and keeps its outbound referenced.
		if kernelEgress(p, rl.Outbound) && rl.Source == "" {
			if domains, ips := splitDomainsIPs(rl.Manual); len(domains) == 0 && len(ips) > 0 {
				continue
			}
		}
		addRoot(rl.Outbound)
	}
	reach := map[string]bool{}
	var visit func(tag string)
	visit = func(tag string) {
		if reach[tag] {
			return
		}
		reach[tag] = true
		if g := p.GroupByID(tag); g != nil {
			for _, m := range g.Members {
				visit(m)
			}
		}
	}
	for tag := range roots {
		visit(tag)
	}
	return reach
}

// Options carries generation knobs that originate from the daemon config.
type Options struct {
	MixedPort   int    // local mixed (socks+http) inbound port
	ClashAddr   string // experimental.clash_api external_controller, e.g. 127.0.0.1:9090
	ClashSecret string
	TunEnabled  bool
	TunMTU      int    // TUN device MTU in gateway mode; 0 → 1500 default
	TunAddr     string // TUN host address/CIDR in gateway mode; "" → 172.19.0.1/30 default
	CacheFile   string // experimental.cache_file path (caches remote rule-sets); "" = sing-box default

	// Hybrid (RoutingMode=="hybrid", docs/ARCHITECTURE_NATIVE_FIRST.md): kernel PBR
	// handles WG/AmneziaWG/WAN/block + carve-outs, sing-box keeps only the obfuscation
	// (proxy) plane. When set, kernel-class outbounds + their pure-IP rules are dropped
	// and the kernel CIDRs are route_exclude'd from the TUN so they fall through to the
	// kernel where pbr's fwmark rules steer them. The exclude lists are the union of
	// pbr.Plan.Zones[].V4/V6 + Plan.Bypass{V4,V6} — the Plan is the SINGLE source of
	// truth, computed by the caller (server.genOptions) so generator and pbr never drift.
	Hybrid          bool
	KernelExcludeV4 []string
	KernelExcludeV6 []string
}

// Plugin is an endpoint a non-sing-box engine must realize, plus the local
// SOCKS port sing-box chains into.
type Plugin struct {
	Endpoint  model.Endpoint
	SOCKSPort int
}

// Result is the generated config plus any external engine plugins required.
type Result struct {
	Config  map[string]any
	Plugins []Plugin
}

// Generate builds a sing-box config from the profile.
func Generate(p *model.Profile, opts Options) (*Result, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Hybrid plane partition (computed once so every emission point agrees). In hybrid
	// mode pbr owns the kernel plane: a kernel-class outbound/group is OMITTED only when
	// it is unreachable from the route references that survive into sing-box. Omitting a
	// still-reachable one would dangle and fail `sing-box check`, taking all routing down.
	hybrid := opts.Hybrid
	var reachable map[string]bool
	if hybrid {
		reachable = hybridReachable(p)
	}
	omitKernelOutbound := func(id string) bool { return hybrid && !reachable[id] }

	res := &Result{Config: map[string]any{}}
	// sing-box >=1.12 removed the legacy `block`/`dns` special outbounds; blocking
	// is now a route-rule action ("reject"). Keep only `direct` (still a valid
	// outbound) and translate any block-targeted rule into a reject action below.
	outbounds := []map[string]any{
		{"type": "direct", "tag": model.OutboundDirect},
	}
	// Native WireGuard is no longer an outbound. sing-box deprecated the
	// `wireguard` outbound in 1.11 and REMOVED it in 1.13; the replacement is a
	// top-level `endpoints` entry (see endpointFor). The endpoint form is the
	// only one that `sing-box check` accepts on BOTH the deployed 1.12.17 and
	// 1.13.x: 1.12.17 already rejects the legacy outbound as a FATAL deprecation
	// (it needs ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true to load), and 1.13.x
	// rejects it as an unknown field. Emitting endpoints is thus required today
	// and survives a sing-box upgrade. Endpoint tags are referenceable by route
	// rules/groups exactly like outbound tags, so no rule/group rewrite is needed.
	var endpoints []map[string]any

	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		if e.Engine == model.EngineAmneziaWG {
			// AmneziaWG: the plugin brings up a kernel awg interface (ip link +
			// awg setconf — no awg-quick, no AllowedIPs default-route that would
			// hijack the host). sing-box egresses through it via bind_interface.
			// The ifname is derived from the endpoint ID; the plugin uses the same
			// util.AWGIface, so generator and plugin agree on one name.
			res.Plugins = append(res.Plugins, Plugin{Endpoint: *e})
			// Hybrid: pbr kernel-routes this interface via fwmark, so its sing-box
			// outbound is dead weight — drop it UNLESS a rule that stays in sing-box
			// (a domain/geo/port-matched rule pbr can't kernel-route) still references
			// it. The Plugin record is kept regardless so the daemon brings the awg
			// device up; pbr routes THROUGH that device.
			if !omitKernelOutbound(e.ID) {
				outbounds = append(outbounds, map[string]any{
					"type": "direct", "tag": e.ID, "bind_interface": util.AWGIface(e.ID),
				})
			}
			continue
		}
		if e.Engine == model.EngineExternal {
			// Route through an existing OS interface Velinx does NOT manage
			// (UCI/netifd owns it) — a direct outbound bound to it. No Plugin entry:
			// the daemon must not try to bring this interface up or tear it down.
			// Hybrid: same as AmneziaWG above, but there's no Plugin (netifd owns the
			// interface), so the kernel-omitted endpoint vanishes from sing-box entirely.
			if !omitKernelOutbound(e.ID) {
				iface, _ := e.Params["interface"].(string)
				outbounds = append(outbounds, map[string]any{
					"type": "direct", "tag": e.ID, "bind_interface": iface,
				})
			}
			continue
		}
		if e.Engine != model.EngineSingBox {
			// Other external engines (olcRTC): sing-box reaches them through a local
			// SOCKS the plugin exposes. The daemon brings up the engine on this port.
			port := basePluginPort + len(res.Plugins)
			res.Plugins = append(res.Plugins, Plugin{Endpoint: *e, SOCKSPort: port})
			outbounds = append(outbounds, map[string]any{
				"type": "socks", "tag": e.ID, "server": "127.0.0.1",
				"server_port": port, "version": "5",
			})
			continue
		}
		if e.Protocol == model.ProtoWireGuard {
			// Native sing-box WireGuard → top-level endpoint, not an outbound.
			ep, err := endpointFor(e)
			if err != nil {
				return nil, fmt.Errorf("endpoint %s: %w", e.ID, err)
			}
			endpoints = append(endpoints, ep)
			continue
		}
		ob, err := outboundFor(e)
		if err != nil {
			return nil, fmt.Errorf("endpoint %s: %w", e.ID, err)
		}
		outbounds = append(outbounds, ob)
	}

	groupsEmitted := false
	for i := range p.Groups {
		g := &p.Groups[i]
		// Hybrid: a kernel-bearing group is routed by pbr (kernel primary — pbr picks
		// the first kernel member and warns that per-member failover is Phase 2), so drop
		// it from sing-box — BUT only when it is unreachable (referenced solely by the
		// pure-IP rules pbr now handles). A kernel group still reachable from a surviving
		// rule/final (e.g. a domain rule targets it) is KEPT, together with its members
		// (reachability includes them), so neither the reference nor a member dangles.
		if hybrid && kernelEgress(p, g.ID) && !reachable[g.ID] {
			continue
		}
		outbounds = append(outbounds, groupOutbound(g))
		groupsEmitted = true
	}

	res.Config["outbounds"] = outbounds
	if len(endpoints) > 0 {
		res.Config["endpoints"] = endpoints
	}

	inbounds := []map[string]any{
		{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": opts.MixedPort},
	}
	if opts.TunEnabled {
		// Gateway mode: capture LAN traffic. `address` gives the tun device its IP;
		// auto_route installs the route + auto_redirect the (eBPF/nftables) redirect
		// so LAN traffic enters sing-box's route engine. address/mtu are config-driven
		// (Config.GatewayMTU/GatewayAddr) so nothing arbitrary is hardcoded — the
		// defaults below are a /30 host net (NOT the LAN subnet, which auto_route
		// excludes) and a standard MTU; lower the MTU for a constrained tunnel exit.
		mtu := opts.TunMTU
		if mtu <= 0 {
			mtu = 1500
		}
		addr := opts.TunAddr
		if addr == "" {
			addr = "172.19.0.1/30"
		}
		tun := map[string]any{
			"type": "tun", "tag": "tun-in",
			"address": []string{addr}, "mtu": mtu,
			"auto_route": true, "auto_redirect": true, "stack": "system",
		}
		if hybrid {
			// Exclude the kernel-routed CIDRs so they fall through to kernel routing,
			// where pbr's fwmark rules steer them out the right interface (or blackhole
			// them). With auto_redirect ON the exclude lands in nftables (NOT the kernel
			// route aggregator), which sidesteps sing-box #3858. strict_route stays OFF
			// (it would redirect SO_BINDTODEVICE kernel-plane sockets and break the
			// return path). The set is pbr.Plan.Zones ∪ Plan.Bypass — single source of
			// truth, so it can never disagree with what pbr actually routes.
			ex := append(append([]string{}, opts.KernelExcludeV4...), opts.KernelExcludeV6...)
			if len(ex) > 0 {
				tun["route_exclude_address"] = ex
			}
		}
		inbounds = append(inbounds, tun)
	}
	res.Config["inbounds"] = inbounds

	route, geoSets, blockDefault := routeFrom(p, hybrid)
	// Routing lists ("Routing" page) become route.rule_set entries (remote URL or
	// inline manual) plus referencing rules (reject lists first). Compose the final
	// rule order: user rules, then list rules, then — only now — the block-by-default
	// catch-all, so a block default never shadows the list rules.
	sets, listRules := routingFrom(p, hybrid)
	// Prepend the rule-sets synthesised from geosite/geoip rule matchers (empty for a
	// profile without such rules, so the rule_set / cache_file below are unchanged).
	sets = append(geoSets, sets...)
	if len(sets) > 0 {
		route["rule_set"] = sets
	}
	rules, _ := route["rules"].([]map[string]any)
	if bp := endpointBypass(p); len(bp) > 0 {
		// A tunnel's own endpoint must never route through a tunnel (a geoip/ip
		// rule can match it → recursion). Bypass to direct, ahead of everything.
		rules = append([]map[string]any{{"ip_cidr": bp, "action": "route", "outbound": "direct"}}, rules...)
	}
	if opts.TunEnabled {
		// TUN captures raw IP packets, so the destination domain is unknown — sniff
		// TLS-SNI/HTTP-Host/QUIC first, or the domain-based rule_sets can't match
		// (in mixed mode the domain comes from the proxy CONNECT, so it isn't needed
		// there). Must be the very first rule: sniff, then fall through to routing.
		rules = append([]map[string]any{{"action": "sniff"}}, rules...)
	}
	rules = append(rules, listRules...)
	if blockDefault {
		rules = append(rules, blockAllRule())
	}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	res.Config["route"] = route

	// `warn`, not `info`: on a router sing-box stdout is piped into the system log
	// (logread); info-level logs every connection and bloats it (a known incident
	// on the Keenetic). Warnings/errors still reach the diagnostics knowledgebase.
	res.Config["log"] = map[string]any{"level": "warn", "timestamp": true}

	exp := map[string]any{}
	if opts.ClashAddr != "" {
		exp["clash_api"] = map[string]any{"external_controller": opts.ClashAddr, "secret": opts.ClashSecret}
	}
	// cache_file persists sing-box state across reboots: remote rule-sets (so 10-40 lists don't
	// re-download every boot, auto-refreshing on their update_interval) AND the chosen member of each
	// selector/urltest group — so a manual exit pick (or the last-good failover choice) survives an
	// Apply/reboot instead of snapping back to the first member. Modern sing-box persists the
	// selection automatically whenever the cache is enabled; the old `store_selected` flag was
	// removed and is REJECTED by 1.12.x ("unknown field"), which would take ALL routing down on
	// apply — so it must NOT be emitted (verified on-device). Enabled when there are rule-sets OR
	// groups.
	if len(sets) > 0 || groupsEmitted {
		cf := map[string]any{"enabled": true}
		if opts.CacheFile != "" {
			cf["path"] = opts.CacheFile
		}
		exp["cache_file"] = cf
	}
	if len(exp) > 0 {
		res.Config["experimental"] = exp
	}
	return res, nil
}

// routingFrom turns the profile's RoutingLists into sing-box route.rule_set
// entries and the route rules that reference them. Reject (block) lists are
// emitted before route lists so a block always wins. A list contributes a remote
// rule-set (its URL, fetched via download_detour) and/or an inline rule-set (its
// manual domains/IPs).
func routingFrom(p *model.Profile, hybrid bool) (sets []map[string]any, rules []map[string]any) {
	var rejects, routes []map[string]any
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		// Hybrid: a manual IP list pointed at a kernel egress is kernel-routed by pbr
		// (same CIDRs, same egress) — drop it from sing-box. Only when it is PURELY IPs
		// with no remote Source and no domain entries: pbr can't route a remote rule-set
		// or domains (Phase 2), so a list carrying either STAYS in sing-box (and keeps
		// the kernel outbound it references alive, see hybridKeptKernelRefs).
		if hybrid && kernelEgress(p, rl.Outbound) && rl.Source == "" {
			if domains, ips := splitDomainsIPs(rl.Manual); len(domains) == 0 && len(ips) > 0 {
				continue
			}
		}
		var tags []string
		if rl.Source != "" {
			tag := "rs-" + rl.ID
			set := map[string]any{"tag": tag, "type": "remote", "url": rl.Source, "format": ruleSetFormat(rl)}
			// A remote rule-set is fetched over its download_detour. Honor an explicit
			// DownloadVia; otherwise default to direct so the list downloads over the WAN
			// even before any tunnel route exists AND can't be blocked from refreshing by
			// a down proxy that the list itself might route around (a chicken-and-egg
			// fetch-through-the-thing-being-configured trap). This mirrors the geosite/
			// geoip remote sets (geoRuleSets), which also fetch direct + cache via
			// cache_file. An empty DownloadVia previously omitted the field (sing-box then
			// fetches via the route's default outbound) — defaulting it to direct is the
			// safer, always-reachable choice and keeps the auto-update self-healing.
			if rl.DownloadVia != "" {
				set["download_detour"] = canonicalOutbound(rl.DownloadVia)
			} else {
				set["download_detour"] = model.OutboundDirect
			}
			set["update_interval"] = refreshInterval(rl.RefreshHours)
			sets = append(sets, set)
			tags = append(tags, tag)
		}
		if domains, ips := splitDomainsIPs(rl.Manual); len(domains) > 0 || len(ips) > 0 {
			// "rsm-" (not "rs-"+id+"-manual"): a manual tag can never collide with a
			// remote tag "rs-"+id, since "rs-…" and "rsm-…" differ at the 3rd char.
			// The old scheme collided when one list's id was "X-manual" and another's
			// was "X" — duplicate rule_set tags that sing-box rejects.
			tag := "rsm-" + rl.ID
			matcher := map[string]any{}
			if len(domains) > 0 {
				matcher["domain_suffix"] = domains
			}
			if len(ips) > 0 {
				matcher["ip_cidr"] = ips
			}
			sets = append(sets, map[string]any{"tag": tag, "type": "inline", "rules": []map[string]any{matcher}})
			tags = append(tags, tag)
		}
		if len(tags) == 0 {
			continue
		}
		rule := map[string]any{"rule_set": tags}
		if isBlock(rl.Outbound) {
			rule["action"] = "reject"
			rejects = append(rejects, rule)
		} else {
			rule["action"] = "route"
			rule["outbound"] = canonicalOutbound(rl.Outbound)
			routes = append(routes, rule)
		}
	}
	return sets, append(rejects, routes...)
}

// ruleSetFormat picks the rule-set format: explicit Format, else inferred from
// the URL (.json -> source, else binary .srs). The ?query / #fragment is stripped
// before the extension check — a token/versioned URL like "list.json?token=X" is
// still a JSON source, but a naive HasSuffix(".json") would miss it and mis-tag it
// binary, so sing-box would fail to parse the downloaded list at runtime.
func ruleSetFormat(rl *model.RoutingList) string {
	if rl.Format == "binary" || rl.Format == "source" {
		return rl.Format
	}
	path := rl.Source
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if strings.HasSuffix(path, ".json") {
		return "source"
	}
	return "binary"
}

func refreshInterval(hours int) string {
	if hours <= 0 {
		return "1d"
	}
	return strconv.Itoa(hours) + "h"
}

// splitDomainsIPs partitions manual entries into domain_suffix vs ip_cidr,
// skipping blanks/comments and normalising a bare IP to a /32 or /128 CIDR.
func splitDomainsIPs(entries []string) (domains, ips []string) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err == nil {
				ips = append(ips, e)
				continue
			}
		}
		if ip := net.ParseIP(e); ip != nil {
			if ip.To4() != nil {
				ips = append(ips, e+"/32")
			} else {
				ips = append(ips, e+"/128")
			}
			continue
		}
		domains = append(domains, e)
	}
	return domains, ips
}

// endpointBypass returns /32|/128 CIDRs for every enabled endpoint's own server
// address (and an external endpoint's declared "endpoint_ip" param). Routing a
// tunnel's own endpoint THROUGH a tunnel recurses — a geoip/ip rule can match the
// endpoint, which lives at that IP — so these are routed straight to direct, ahead
// of all other rules. Only IP literals contribute (a hostname resolves at runtime).
func endpointBypass(p *model.Profile) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return
		}
		c := ip.String() + "/32"
		if ip.To4() == nil {
			c = ip.String() + "/128"
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		add(e.Server)
		if eip, ok := e.Params["endpoint_ip"].(string); ok {
			add(eip)
		}
	}
	return out
}

func groupOutbound(g *model.Group) map[string]any {
	ob := map[string]any{"tag": g.ID, "outbounds": g.Members}
	switch g.Type {
	case model.GroupURLTest, model.GroupFallback:
		ob["type"] = "urltest"
		url, interval, tol := defaultHealthURL, "1m", 50
		if g.Test != nil {
			if g.Test.URL != "" {
				url = g.Test.URL
			}
			if iv := g.Test.Interval; iv > 0 {
				// Floor the urltest interval: sub-5s probing re-handshakes the test URL
				// through EVERY member that often — a CPU/socket/log storm on a weak router.
				// A pathological value can arrive via the API, a hand-edited profile, or a
				// subscription, so bound it here (mirrors the WG-MTU clamp). The 60s default
				// and any deliberate >=5s choice are untouched.
				if iv < 5 {
					iv = 5
				}
				interval = fmt.Sprintf("%ds", iv)
			}
			if g.Test.Tolerance > 0 {
				tol = g.Test.Tolerance
			}
		}
		ob["url"], ob["interval"], ob["tolerance"] = url, interval, tol
	default:
		ob["type"] = "selector"
	}
	if g.InterruptOnSwitch {
		// Drop in-flight connections when this group switches members, so a failover (or a manual
		// selector change) actually moves existing connections off the old/dead exit onto the new
		// one rather than leaving them pinned to whatever was selected when they opened. sing-box
		// honors this on both urltest and selector outbounds; default-off elsewhere keeps the
		// long-lived-transfer-survives-a-switch behavior.
		ob["interrupt_exist_connections"] = true
	}
	return ob
}

// sing-box hard-rejects an unknown value for these enum fields ("unsupported
// flow" / "unknown congestion control algorithm" / "unknown obfs type" /
// "unknown uTLS fingerprint"), which fails the whole shared singbox.json and
// takes ALL routing down on apply. So an unknown value is DROPPED (degraded) at
// emission rather than passed through: the one endpoint loses an optional knob
// (falls back to sing-box's default) instead of bricking the router. The sets
// track sing-box 1.12.x; a stale entry (a NEW valid value not yet listed) only
// causes a graceful default, never a brick — the safe direction to err.
var (
	knownFlows     = map[string]bool{"xtls-rprx-vision": true}
	knownSSPlugins = map[string]bool{"obfs-local": true, "v2ray-plugin": true}
	knownTUICCC    = map[string]bool{"cubic": true, "new_reno": true, "bbr": true}
	knownTUICRelay = map[string]bool{"native": true, "quic": true}
	knownHy2Obfs   = map[string]bool{"salamander": true}
	knownVMessSec  = map[string]bool{"auto": true, "none": true, "zero": true, "aes-128-gcm": true, "chacha20-poly1305": true}
	knownPacketEnc = map[string]bool{"xudp": true, "packetaddr": true}
	// Only values sing-box's uTLS actually accepts. NOT Xray's "randomizedalpn" /
	// "randomizednoalpn" — sing-box REJECTS those ("unknown uTLS fingerprint"), and
	// since one bad outbound fails the shared singbox.json, letting them through would
	// brick all routing. They are normalized to "randomized" via utlsFingerAlias first.
	knownUTLSFinger = map[string]bool{
		"chrome": true, "firefox": true, "edge": true, "safari": true, "ios": true,
		"android": true, "360": true, "qq": true, "random": true, "randomized": true,
	}
	// Xray/v2rayN fingerprint names that sing-box doesn't have, mapped to the nearest
	// sing-box equivalent so an imported link keeps its anti-fingerprint intent (a
	// randomized uTLS hello) instead of degrading to Go's default TLS fingerprint.
	utlsFingerAlias = map[string]string{
		"randomizedalpn":   "randomized",
		"randomizednoalpn": "randomized",
	}
)

// safeEnum returns v only if it is an accepted sing-box value, else "" (drop).
func safeEnum(v string, allowed map[string]bool) string {
	if allowed[v] {
		return v
	}
	return ""
}

// normalizeUTLSFinger maps an Xray-only uTLS fingerprint name to its nearest
// sing-box equivalent (others pass through unchanged for safeEnum to validate).
func normalizeUTLSFinger(v string) string {
	if a, ok := utlsFingerAlias[v]; ok {
		return a
	}
	return v
}

// singBoxPortRange converts one hop-port entry to the sing-box server_ports form:
// "start-end" -> "start:end", a bare "443" -> "443", or "" if it isn't a valid
// port / port range (so a malformed mport is dropped, not emitted as a config
// sing-box rejects with "bad port range"). A reversed range ("50000-20000") is
// normalized to ascending so the intended span actually hops, regardless of how
// sing-box treats a descending range.
func singBoxPortRange(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	parts := strings.SplitN(r, "-", 2)
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		nums[i] = n
	}
	if len(parts) == 2 {
		lo, hi := nums[0], nums[1]
		if lo > hi {
			lo, hi = hi, lo
		}
		return strconv.Itoa(lo) + ":" + strconv.Itoa(hi)
	}
	// sing-box server_ports entries must be ranges; a single port "443" is rejected
	// ("bad port range") and has to be expressed as the one-port range "443:443".
	p := strings.TrimSpace(parts[0])
	return p + ":" + p
}

// proxyAuth attaches upstream-proxy credentials to a socks/http outbound when the
// endpoint carries them. sing-box authenticates to the upstream proxy with these;
// the UI collects a username/password for socks/http endpoints, so dropping them
// here makes an authenticated proxy reject the connection (auth required).
func proxyAuth(ob map[string]any, e *model.Endpoint) {
	if u := str(e.Params, "username"); u != "" {
		ob["username"] = u
	}
	if pw := str(e.Params, "password"); pw != "" {
		ob["password"] = pw
	}
}

func outboundFor(e *model.Endpoint) (map[string]any, error) {
	ob := map[string]any{"tag": e.ID, "server": e.Server, "server_port": e.Port}
	switch e.Protocol {
	case model.ProtoVLESS:
		ob["type"] = "vless"
		ob["uuid"] = str(e.Params, "uuid")
		// xtls-rprx-vision operates on the raw TLS stream, so it works ONLY with a
		// TLS/reality layer AND no stream transport. sing-box accepts other pairings at
		// check time but then fails EVERY connection at runtime with "vision: not a
		// valid supported TLS connection" — over a transport the conn is a
		// *v2raywebsocket.WebsocketConn, and with no TLS it is a bare *net.TCPConn.
		// Both are plausible misconfigs (a reality flow copy-pasted onto a ws link, or
		// onto a plaintext one), so emit flow only when TLS is on and no transport is
		// set — the endpoint then works as plain vless instead of being silently dead.
		// (Reality/TLS-over-tcp endpoints keep their flow; the live config relies on it.)
		tlsOn := e.TLS != nil && e.TLS.Enabled
		hasTransport := e.Transport != nil && e.Transport.Type != ""
		if f := safeEnum(str(e.Params, "flow"), knownFlows); f != "" && tlsOn && !hasTransport {
			ob["flow"] = f
		}
		// Only emit a KNOWN packet_encoding — sing-box PANICS on an unknown value
		// ("unknown value"), which would take down the whole config; an unknown one
		// is dropped (UDP-over-VLESS falls back to the default).
		if pe := safeEnum(str(e.Params, "packet_encoding"), knownPacketEnc); pe != "" {
			ob["packet_encoding"] = pe
		}
	case model.ProtoVMess:
		ob["type"] = "vmess"
		ob["uuid"] = str(e.Params, "uuid")
		ob["alter_id"] = intp(e.Params, "alter_id")
		// vmess security has a default ("auto"); an UNKNOWN value bricks the whole
		// config ("unsupported security type"), so drop it back to auto rather than
		// pass it through (same optional-enum degrade as flow/cc/obfs/fp).
		if sec := safeEnum(str(e.Params, "security"), knownVMessSec); sec != "" {
			ob["security"] = sec
		} else {
			ob["security"] = "auto"
		}
	case model.ProtoTrojan:
		ob["type"] = "trojan"
		ob["password"] = str(e.Params, "password")
	case model.ProtoAnyTLS:
		// AnyTLS (sing-box 1.12+): a TLS-session-multiplexing anti-traffic-analysis protocol. Like
		// Trojan it is just password + TLS (the tls block comes from tlsCapable below); the optional
		// session-pool knobs (idle_session_*/min_idle_session) keep their sing-box defaults.
		ob["type"] = "anytls"
		ob["password"] = str(e.Params, "password")
	case model.ProtoShadowsocks:
		ob["type"] = "shadowsocks"
		ob["method"] = str(e.Params, "method")
		ob["password"] = str(e.Params, "password")
		if boolp(e.Params, "udp_over_tcp") {
			ob["udp_over_tcp"] = true
		}
		// sing-box implements obfs-local and v2ray-plugin natively. Emit only a KNOWN
		// plugin — an unknown name would make sing-box fail the (shared) config load,
		// so it is dropped (degrades to plain SS) rather than bricking all routing.
		if pl := safeEnum(str(e.Params, "plugin"), knownSSPlugins); pl != "" {
			ob["plugin"] = pl
			if po := str(e.Params, "plugin_opts"); po != "" {
				ob["plugin_opts"] = po
			}
		}
	case model.ProtoHysteria2:
		ob["type"] = "hysteria2"
		ob["password"] = str(e.Params, "password")
		// Salamander obfs needs a password — sing-box rejects an obfs block without
		// one ("missing obfs password"), which fails the WHOLE config load (every
		// endpoint shares one singbox.json), so a partial/garbled obfs import would
		// take the router's routing down on apply. Emit obfs only when both are set;
		// a lone obfs type degrades to plain hysteria2 (valid) instead of breaking all.
		if o, pw := safeEnum(str(e.Params, "obfs"), knownHy2Obfs), str(e.Params, "obfs_password"); o != "" && pw != "" {
			ob["obfs"] = map[string]any{"type": o, "password": pw}
		}
		// Port hopping: convert the imported hop range ("20000-50000" / a comma list)
		// to sing-box server_ports ("20000:50000"). Skip any malformed range — sing-box
		// rejects a bad one ("bad port range") and would brick the whole config.
		if hp := str(e.Params, "hop_ports"); hp != "" {
			var ports []string
			for _, r := range strings.Split(hp, ",") {
				if sp := singBoxPortRange(r); sp != "" {
					ports = append(ports, sp)
				}
			}
			if len(ports) > 0 {
				ob["server_ports"] = ports
			}
		}
	case model.ProtoTUIC:
		ob["type"] = "tuic"
		ob["uuid"] = str(e.Params, "uuid")
		ob["password"] = str(e.Params, "password")
		if cc := safeEnum(str(e.Params, "congestion_control"), knownTUICCC); cc != "" {
			ob["congestion_control"] = cc
		}
		// udp_over_stream (UDP tunneled over a QUIC stream) and udp_relay_mode (native|quic) are
		// MUTUALLY EXCLUSIVE in sing-box — emitting BOTH is a FATAL "udp_over_stream is conflict with
		// udp_relay_mode" at config decode, which bricks the whole shared singbox.json. Emit exactly
		// one: udp_over_stream wins when set; otherwise honor udp_relay_mode, gated through safeEnum so
		// an unknown value (a typo or a hostile ?udp_relay_mode=foo) is dropped (drop-don't-brick).
		if boolp(e.Params, "udp_over_stream") {
			ob["udp_over_stream"] = true
		} else if m := safeEnum(str(e.Params, "udp_relay_mode"), knownTUICRelay); m != "" {
			ob["udp_relay_mode"] = m
		}
		// heartbeat is a duration STRING ("10s") — a bare number or garbage makes
		// sing-box fail config decode, so only emit a value that parses as a
		// duration (a malformed one is dropped rather than bricking the config).
		// ParseDuration also ACCEPTS non-positive durations ("0s", "-5s"), but
		// sing-box rejects "heartbeat must be > 0" at decode, so require >0 too
		// (drop-don't-brick rather than failing the whole apply).
		if hb := str(e.Params, "heartbeat"); hb != "" {
			if d, err := time.ParseDuration(hb); err == nil && d > 0 {
				ob["heartbeat"] = hb
			}
		}
		if boolp(e.Params, "zero_rtt_handshake") {
			ob["zero_rtt_handshake"] = true
		}
	// NOTE: native WireGuard is NOT handled here. It is no longer a sing-box
	// outbound (deprecated 1.11, removed 1.13); Generate routes ProtoWireGuard
	// to endpointFor instead. A WG endpoint never reaches this switch.
	case model.ProtoSOCKS:
		ob["type"] = "socks"
		ob["version"] = "5"
		proxyAuth(ob, e)
	case model.ProtoHTTP:
		ob["type"] = "http"
		proxyAuth(ob, e)
	default:
		return nil, fmt.Errorf("protocol %q not supported by the sing-box generator", e.Protocol)
	}
	// A v2ray-style transport (ws/grpc/http/httpupgrade) is valid ONLY on the
	// VLESS/VMess/Trojan outbounds. sing-box REJECTS a `transport` field on any
	// other protocol (hysteria2/tuic/shadowsocks/socks/http) as a FATAL config
	// decode error ("json: unknown field transport"), and because every endpoint
	// shares one singbox.json that failure takes ALL routing down on the next
	// apply. The importer and UI manual form only attach a transport to those
	// three, but a raw POST /api/endpoints carries an arbitrary endpoint and
	// model.Validate is protocol-agnostic, so a hand-crafted hysteria2+transport
	// would otherwise brick Apply. Drop the stray transport (degrade to a valid
	// plain outbound) rather than brick — same drop-don't-brick discipline as the
	// obfs / hop_ports / heartbeat / reality-key guards above.
	if t := transportJSON(e.Transport); t != nil && transportCapable(e.Protocol) {
		ob["transport"] = t
	}
	// A `tls` block is valid only on the outbounds that actually carry one in
	// sing-box 1.12.x: VLESS/VMess/Trojan (TCP+TLS) and Hysteria2/TUIC/HTTP. A
	// shadowsocks or socks outbound has NO tls container, so emitting one is a
	// FATAL decode error ("json: unknown field tls") that bricks the shared
	// singbox.json on the next apply — the exact twin of the transport guard
	// above. The importer attaches TLS only to the capable protocols and the UI
	// gates the TLS form, but a raw POST /api/endpoints carries an arbitrary
	// endpoint and model.Validate never inspects e.TLS, so a hand-crafted
	// shadowsocks/socks + tls.enabled would otherwise brick Apply. Drop the stray
	// tls (degrade to a valid plain outbound) rather than brick.
	if tl := tlsJSON(e.TLS); tl != nil && tlsCapable(e.Protocol) {
		ob["tls"] = tl
		// TUIC runs over QUIC, so only the h3 ALPN family is valid. sing-box does
		// NOT override tuic's alpn (unlike hysteria2, which forces h3 internally), so
		// a non-h3 alpn — e.g. a subscription that blanket-applies alpn=h2,http/1.1
		// to every endpoint, or a copy-paste from a TCP link — passes `sing-box
		// check` but fails every connection at runtime ("tls: no application
		// protocol"). Keep only the h3 family; default to ["h3"] when none was given
		// OR none survives (this subsumes the old default-when-absent).
		if e.Protocol == model.ProtoTUIC {
			var kept []string
			if a, ok := tl["alpn"].([]string); ok {
				for _, p := range a {
					if p == "h3" || strings.HasPrefix(p, "h3-") {
						kept = append(kept, p)
					}
				}
			}
			if len(kept) == 0 {
				kept = []string{"h3"}
			}
			tl["alpn"] = kept
		}
		// WebSocket and httpupgrade are HTTP/1.1 upgrade mechanisms; they CANNOT run
		// over an h2-negotiated TLS connection. A link carrying alpn=h2 on a ws/
		// httpupgrade endpoint (subscription generators often blanket-apply the same
		// alpn to every endpoint) passes sing-box check but fails EVERY connection at
		// runtime — the server negotiates h2 and the upgrade never completes. Strip h2
		// so the handshake settles on http/1.1; drop alpn entirely if nothing remains
		// (sing-box then defaults correctly).
		if e.Transport != nil && (e.Transport.Type == "ws" || e.Transport.Type == "httpupgrade") {
			if a, ok := tl["alpn"].([]string); ok {
				var kept []string
				for _, p := range a {
					if p != "h2" {
						kept = append(kept, p)
					}
				}
				if len(kept) > 0 {
					tl["alpn"] = kept
				} else {
					delete(tl, "alpn")
				}
			}
		}
		// The mirror of the ws case: grpc and the http/h2 transport REQUIRE an
		// h2-negotiated TLS connection. A non-h2 alpn (e.g. the blanket alpn=http/1.1)
		// makes the server settle on http/1.1 and the gRPC/h2 stream never establishes
		// — passes sing-box check, fails every connection at runtime. Keep only h2;
		// delete alpn if none remains, so sing-box defaults h2 for these transports.
		if e.Transport != nil && (e.Transport.Type == "grpc" || e.Transport.Type == "http") {
			if a, ok := tl["alpn"].([]string); ok {
				var kept []string
				for _, p := range a {
					if p == "h2" {
						kept = append(kept, p)
					}
				}
				if len(kept) > 0 {
					tl["alpn"] = kept
				} else {
					delete(tl, "alpn")
				}
			}
		}
		// h3 (HTTP/3) runs ONLY over QUIC (UDP), so it is a valid ALPN only for the
		// QUIC-native protocols (tuic / hysteria2). On any TCP-based TLS endpoint
		// (vless/vmess/trojan over tcp/ws/grpc/http/httpupgrade) an alpn of "h3" is
		// invalid — it reaches here from a blanket subscription alpn or a copy-paste
		// from a tuic/hy2 link — and an ALPN-enforcing server rejects the handshake
		// ("tls: no application protocol") at runtime while `sing-box check` passes.
		// Completes the ALPN<->transport matrix (ws/httpupgrade=http/1.1 c40,
		// grpc/http=h2 c43): strip h3 for non-QUIC protocols; drop alpn if nothing
		// remains (sing-box then negotiates h2/http-1.1). tuic keeps the h3 it
		// defaults/carries above; hysteria2 (QUIC) is left untouched.
		if e.Protocol != model.ProtoTUIC && e.Protocol != model.ProtoHysteria2 {
			if a, ok := tl["alpn"].([]string); ok {
				var kept []string
				for _, p := range a {
					if p != "h3" {
						kept = append(kept, p)
					}
				}
				if len(kept) > 0 {
					tl["alpn"] = kept
				} else {
					delete(tl, "alpn")
				}
			}
		}
	}
	return ob, nil
}

// validWGKey reports whether s is a valid WireGuard base64 key (32 bytes,
// padded or raw). WireGuard keys are 32-byte values; standard base64 encodes
// them as 44 chars with one trailing '=' pad, raw (no-pad) base64 gives 43
// chars. Both encodings are accepted so a link-imported key (often padded) and
// a .conf key (often raw) are treated identically. An empty string or a string
// that does not decode to exactly 32 bytes returns false so callers can apply
// drop-don't-brick rather than passing garbage to sing-box.
func validWGKey(s string) bool {
	if s == "" {
		return false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return len(b) == 32
		}
	}
	return false
}

// normalizeWGKey re-encodes a WireGuard key (any base64 variant validWGKey accepts)
// as standard base64 WITH padding — the only form sing-box's WireGuard key decoder
// accepts (it rejects url-safe `-`/`_` AND unpadded keys: "decode private/public key:
// illegal base64 data"). validWGKey deliberately accepts std/raw/url so a link-imported
// (padded) and a .conf (sometimes raw/url-safe) key both validate, but emitting either
// non-std form verbatim fatally fails the whole shared config on apply — so canonicalize
// here. A string that does not decode to 32 bytes (e.g. an unvalidated optional
// pre_shared_key) is returned unchanged.
func normalizeWGKey(s string) string {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return s
}

// endpointFor renders a native WireGuard endpoint in sing-box's top-level
// `endpoints` schema (1.11+), the replacement for the removed `wireguard`
// outbound. The endpoint carries the interface address + private key; the single
// peer carries the server/port (peer address/port), public key, optional PSK and
// reserved bytes, and a full-tunnel allowed_ips so it routes everything sent to
// it — matching the old outbound, which had no allowed_ips and routed all traffic.
// The tag equals the endpoint id, so existing route rules/groups that reference
// it by tag keep working unchanged. AmneziaWG (EngineAmneziaWG) does NOT come
// here — it is a chained-SOCKS plugin, handled in Generate's external-engine path.
//
// Returns an error if the private key or the peer public key is not valid
// WireGuard base64 (32-byte key) — sing-box fatals on "decode private key" for
// an invalid key, which would block the whole config. Generate propagates this
// error, so handleApply aborts the apply (HTTP error, the offending endpoint
// named) with the live config left untouched by the apply-gate; the user corrects
// that endpoint. NB: this is fail-fast at the endpoint level, not endpoint-level
// drop-don't-brick — a bad peer WITHIN a multi-[Peer] config IS dropped (wgPeers),
// but one bad endpoint fails the apply rather than silently vanishing from it.
func endpointFor(e *model.Endpoint) (map[string]any, error) {
	privKey := str(e.Params, "private_key")
	if !validWGKey(privKey) {
		return nil, fmt.Errorf("wireguard endpoint %q: private_key is not valid 32-byte base64 (%q)", e.ID, privKey)
	}
	peerPubKey := str(e.Params, "peer_public_key")
	if !validWGKey(peerPubKey) {
		return nil, fmt.Errorf("wireguard endpoint %q: peer_public_key is not valid 32-byte base64 (%q)", e.ID, peerPubKey)
	}
	peer := map[string]any{
		"address":     e.Server,
		"port":        e.Port,
		"public_key":  normalizeWGKey(peerPubKey),
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if psk := str(e.Params, "pre_shared_key"); psk != "" {
		peer["pre_shared_key"] = normalizeWGKey(psk)
	}
	// `reserved` (the 3 WARP reserved bytes) is a documented param; pass it
	// through so a WARP-style peer isn't silently stripped of it. sing-box
	// accepts a 3-element number array (now on the peer, not the outbound).
	if r, ok := e.Params["reserved"]; ok {
		peer["reserved"] = r
	}
	// Keep the NAT mapping alive on an idle tunnel (seconds). Without it sing-box
	// never sends keepalives and a peer behind NAT goes silent after the mapping
	// expires — emit it when the imported config/link carried one. The typed
	// per-tunnel control Endpoint.PersistentKeepalive (the Tunnels-page knob) wins
	// when set (>0); a legacy import that only populated Params["persistent_keepalive"]
	// still works as the fallback, so existing profiles are byte-identical.
	if ka := e.PersistentKeepalive; ka > 0 {
		peer["persistent_keepalive_interval"] = ka
	} else if ka := intp(e.Params, "persistent_keepalive"); ka > 0 {
		peer["persistent_keepalive_interval"] = ka
	}
	// A multi-[Peer] .conf (wg-quick mesh) is parsed into Params["peers"] — emit
	// EVERY peer when that list holds MORE than one. A single-peer (or absent) list
	// falls back to the single-peer entry built above, so the existing single-peer
	// emission (including its catch-all allowed_ips and WARP reserved) is unchanged.
	peerEntries := []map[string]any{peer}
	if multi := wgPeers(e.Params); len(multi) > 1 {
		peerEntries = multi
	}
	ep := map[string]any{
		"type":        "wireguard",
		"tag":         e.ID,
		"private_key": normalizeWGKey(privKey),
		"peers":       peerEntries,
	}
	// The endpoint interface address (was `local_address` on the outbound).
	// sing-box requires it for a working tunnel; emit it when present.
	if la, ok := e.Params["local_address"]; ok {
		ep["address"] = la
	}
	// MTU caps the interface packet size; dropping it falls back to the kernel
	// default so large packets fragment/blackhole on a path that needs a smaller MTU
	// (e.g. WARP at 1280). sing-box takes it on the endpoint. The typed per-tunnel
	// control Endpoint.MTU (the Tunnels-page knob) wins when set (>0); a legacy
	// import that only populated Params["mtu"] still works as the fallback, so
	// existing profiles emit a byte-identical endpoint.
	if mtu := e.MTU; mtu > 0 {
		ep["mtu"] = mtu
	} else if mtu := intp(e.Params, "mtu"); mtu > 0 {
		ep["mtu"] = mtu
	}
	return ep, nil
}

// wgPeers builds the sing-box endpoint `peers` array from a multi-[Peer]
// Params["peers"] list (a wg-quick mesh .conf, parsed by importer.parseConf). It
// tolerates both []map[string]any (the importer's shape) and []any of maps (the
// shape a JSON round-trip through the store produces). Each entry reuses the same
// field mapping as the single-peer path: address/port/public_key/pre_shared_key/
// allowed_ips/persistent_keepalive_interval. A peer with no address is skipped (it
// can't connect). Returns nil when no usable multi-peer list is present so the
// caller falls back to the single-peer entry unchanged.
func wgPeers(params map[string]any) []map[string]any {
	raw, ok := params["peers"]
	if !ok {
		return nil
	}
	var list []map[string]any
	switch v := raw.(type) {
	case []map[string]any:
		list = v
	case []any:
		for _, it := range v {
			if m, ok := it.(map[string]any); ok {
				list = append(list, m)
			}
		}
	default:
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, p := range list {
		addr := str(p, "server")
		if addr == "" {
			continue
		}
		// Skip peers whose public key is not a valid 32-byte WireGuard base64 key —
		// sing-box fatals on "decode public key" for a bad key, which would block the
		// entire apply for all other endpoints. Drop the peer rather than brick.
		pubKey := str(p, "public_key")
		if !validWGKey(pubKey) {
			continue
		}
		peer := map[string]any{
			"address":     addr,
			"port":        intp(p, "port"),
			"public_key":  normalizeWGKey(pubKey),
			"allowed_ips": []string{"0.0.0.0/0", "::/0"},
		}
		// Honor a per-peer AllowedIPs when the .conf scoped one (mesh peers usually
		// carry distinct subnets); otherwise keep the catch-all default above.
		if aips := anyToStrings(p["allowed_ips"]); len(aips) > 0 {
			peer["allowed_ips"] = aips
		}
		if psk := str(p, "pre_shared_key"); psk != "" {
			peer["pre_shared_key"] = normalizeWGKey(psk)
		}
		if ka := intp(p, "persistent_keepalive"); ka > 0 {
			peer["persistent_keepalive_interval"] = ka
		}
		// `reserved` (WARP's 3 client-id bytes) is an endpoint-level param, not a
		// per-peer one. Propagate it onto each peer so a single-peer config routed
		// through this multi-peer path keeps its WARP bytes (parity with the legacy
		// single-peer emission in endpointFor).
		if r, ok := params["reserved"]; ok {
			peer["reserved"] = r
		}
		out = append(out, peer)
	}
	return out
}

// anyToStrings coerces a Params value into a []string, tolerating both the
// importer's native []string and the []any a JSON round-trip through the store
// produces. Non-string elements and empty/whitespace entries are dropped.
func anyToStrings(v any) []string {
	var raw []string
	switch t := v.(type) {
	case []string:
		raw = t
	case []any:
		for _, it := range t {
			if s, ok := it.(string); ok {
				raw = append(raw, s)
			}
		}
	default:
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// transportCapable reports whether a protocol's sing-box outbound accepts a
// v2ray-style `transport` block (ws/grpc/http/httpupgrade). Only the VLESS/
// VMess/Trojan families do; emitting one on any other outbound is a FATAL
// config-decode error in sing-box (guarded in outboundFor so a stray transport
// can never brick the shared singbox.json).
func transportCapable(p model.Protocol) bool {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan:
		return true
	default:
		return false
	}
}

// tlsCapable reports whether a protocol's sing-box outbound accepts a `tls`
// block. VLESS/VMess/Trojan (TCP+TLS), Hysteria2/TUIC (QUIC+TLS) and the HTTP
// (HTTPS) proxy do; shadowsocks and socks have NO tls container, so emitting one
// is a FATAL config-decode error in sing-box. WireGuard is a top-level endpoint
// (endpointFor), never reaching this outbound path. Guarded in outboundFor so a
// stray tls can never brick the shared singbox.json.
func tlsCapable(p model.Protocol) bool {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan,
		model.ProtoHysteria2, model.ProtoTUIC, model.ProtoHTTP, model.ProtoAnyTLS:
		return true
	default:
		return false
	}
}

func transportJSON(t *model.Transport) map[string]any {
	if t == nil || t.Type == "" {
		return nil
	}
	out := map[string]any{"type": t.Type}
	switch t.Type {
	case "ws":
		// A v2rayN/Xray ws share-link encodes early-data in the path as
		// "/path?ed=N" — N is the max_early_data byte cap, NOT part of the request
		// path. sing-box wants it as a separate transport field; leaving the literal
		// "?ed=N" in the path makes sing-box send it as the ws request path, and a
		// server that matches the bare path rejects the upgrade with a 404.
		path, med := splitEarlyDataHint(t.Path)
		if path != "" {
			out["path"] = path
		}
		if med > 0 {
			out["max_early_data"] = med
			// Sec-WebSocket-Protocol = the Xray-compatible header carrier; a server
			// that doesn't use early data simply ignores the extra header and still
			// completes the (now bare-path) upgrade.
			out["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		if t.Host != "" {
			out["headers"] = map[string]any{"Host": t.Host}
		}
	case "grpc":
		if t.ServiceName != "" {
			out["service_name"] = t.ServiceName
		}
	case "http":
		if t.Path != "" {
			out["path"] = t.Path
		}
		// The h2/http transport host is a string LIST: sing-box round-robins over it
		// for domain-fronting, so a multi-host link ("host=a.com,b.com") must become
		// ["a.com","b.com"], NOT a single element ["a.com,b.com"] (which sends a bogus
		// Host header with a literal comma). Split on the comma the share-link uses.
		if hosts := splitHosts(t.Host); len(hosts) > 0 {
			out["host"] = hosts
		}
	case "httpupgrade":
		// A v2rayN/Xray httpupgrade share-link carries the same "/path?ed=N"
		// early-data hint as ws. Unlike ws, sing-box's httpupgrade transport has
		// NO early-data fields — it REJECTS max_early_data ("unknown field",
		// verified on 1.12.17) — so we cannot translate the hint, only strip it.
		// Left literal, sing-box sends "GET /path?ed=N" and a server matching the
		// bare path fails the upgrade (`unexpected EOF`); passes `check` but every
		// connection dies at runtime. Stripping makes the path match (losing only
		// the first-RTT early-data optimization, which httpupgrade can't do here).
		path, _ := splitEarlyDataHint(t.Path)
		if path != "" {
			out["path"] = path
		}
		if t.Host != "" {
			out["host"] = t.Host // httpupgrade: host is a single string (NOT a list)
		}
	}
	return out
}

// splitHosts splits a comma-separated host list (h2/http domain-fronting can name
// several hosts) into individual trimmed entries; a single host yields a one-element
// list, and empty/blank-only input yields an empty list (caller omits the field).
func splitHosts(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitEarlyDataHint pulls the v2rayN/Xray early-data hint out of a ws/httpupgrade
// path. Such share-links carry it as "/path?ed=N" (N = max_early_data byte cap).
// Returns the clean path plus N (0 = none, path returned unchanged). Only the "ed"
// key is recognised, and the path is rewritten ONLY when a valid ed is found, so a
// path that legitimately contains a "?" but no ed is never altered. ws consumes N
// as max_early_data; httpupgrade only strips it (sing-box httpupgrade has no
// early-data fields), so the path matches the server instead of carrying "?ed=N".
func splitEarlyDataHint(p string) (string, int) {
	q := strings.IndexByte(p, '?')
	if q < 0 {
		return p, 0
	}
	for _, kv := range strings.Split(p[q+1:], "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k != "ed" {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return p[:q], n
		}
	}
	return p, 0
}

func tlsJSON(t *model.TLS) map[string]any {
	if t == nil || !t.Enabled {
		return nil
	}
	out := map[string]any{"enabled": true}
	if t.SNI != "" {
		out["server_name"] = t.SNI
	}
	if t.Insecure {
		out["insecure"] = true
	}
	if len(t.ALPN) > 0 {
		out["alpn"] = t.ALPN
	}
	if fp := safeEnum(normalizeUTLSFinger(t.Fingerprint), knownUTLSFinger); fp != "" {
		out["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	// Reality REQUIRES a public_key: sing-box rejects a reality block without one
	// ("invalid public_key"), and because every endpoint shares one singbox.json
	// (loaded all-or-nothing) that single bad outbound fails the WHOLE config — so
	// a truncated/garbled reality import would take the router's routing down on
	// apply. Emit reality only when the public_key is present; otherwise fall back
	// to the plain-TLS block already built above (the outbound stays valid, so any
	// rule/group referencing it doesn't dangle). sing-box also requires a uTLS
	// fingerprint for Reality, so default it to chrome when the link omitted one.
	// Reality needs a VALID public_key (x25519, base64 of 32 bytes); sing-box
	// rejects a malformed one ("invalid public_key") — bricking the whole config —
	// so an endpoint whose key is missing OR malformed degrades to plain TLS. The
	// short_id must be even-length hex <=16 chars; a malformed one also bricks
	// ("decode short_id"), so it is dropped (reality works without a short_id).
	if t.Type == "reality" && validRealityPubKey(t.PublicKey) {
		if _, ok := out["utls"]; !ok {
			out["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
		r := map[string]any{"enabled": true, "public_key": normalizeRealityPubKey(t.PublicKey)}
		if validShortID(t.ShortID) {
			r["short_id"] = t.ShortID
		}
		out["reality"] = r
	}
	// TLS handshake fragmentation (anti-DPI): split the ClientHello so a plaintext SNI-matching
	// firewall can't fingerprint it (sing-box 1.12+, client-only). Skip when a Reality block was
	// emitted — Reality has its own evasion and fragmenting its ClientHello disturbs the fingerprint
	// mimicry. Accepted (and harmless) on QUIC TLS too, verified on-device (1.12.17).
	if _, isReality := out["reality"]; !isReality {
		if t.Fragment {
			out["fragment"] = true
		}
		if t.RecordFragment {
			out["record_fragment"] = true
		}
	}
	return out
}

// validRealityPubKey reports whether s is a usable x25519 reality public key:
// base64 (std or url, padded or not) decoding to exactly 32 bytes.
func validRealityPubKey(s string) bool {
	if s == "" {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return true
		}
	}
	return false
}

// normalizeRealityPubKey re-encodes a reality public key (in any base64 variant
// validRealityPubKey accepts) as base64url-WITHOUT-padding — the only form
// sing-box's reality decoder accepts. A std-base64 key (`=` padding, or `+`/`/`
// chars) passes validRealityPubKey but sing-box rejects it verbatim with "decode
// public_key: illegal base64 data", failing the whole config; emitting the
// canonical form keeps such an import working. The caller has already gated on
// validRealityPubKey so the decode is expected to succeed; on the impossible miss
// return s unchanged.
func normalizeRealityPubKey(s string) string {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return base64.RawURLEncoding.EncodeToString(b)
		}
	}
	return s
}

// validShortID reports whether s is a usable reality short_id: an even-length hex
// string of at most 16 chars (8 bytes). Empty / odd-length / non-hex / over-length
// are rejected (so the caller drops them rather than emit a config sing-box fails).
func validShortID(s string) bool {
	if len(s) == 0 || len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SagerNet's official rule-set repos host the geosite/geoip databases as the
// per-category .srs files sing-box 1.12 expects (the built-in databases were
// removed). A geosite "google" -> geosite-google.srs, a geoip "cn" -> geoip-cn.srs.
const (
	geositeSRSBase = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-"
	geoipSRSBase   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-"
)

// routeFrom builds the route from the user's rules. It returns the rule-sets
// synthesised from any geosite/geoip rule matchers (see geoRuleSets) and
// blockDefault so the caller can emit the terminal catch-all reject AFTER the
// routing-list rules — emitting it here would shadow those rules (first-match
// wins), breaking a block-by-default ("whitelist": route only listed traffic) posture.
func routeFrom(p *model.Profile, hybrid bool) (out map[string]any, geoSets []map[string]any, blockDefault bool) {
	var rules []map[string]any
	seen := map[string]bool{} // dedup synthesised geosite/geoip rule-set tags
	final := model.OutboundDirect
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled {
			continue // an inert no-op rule — never emitted on any plane
		}
		if r.Default {
			// `final` must be a real outbound in sing-box >=1.12; a default that
			// targets block becomes a terminal catch-all reject rule instead. A kernel
			// default keeps its outbound (hybridKeptKernelRefs records it), so `final`
			// never dangles — unmatched TUN traffic still routes via that bound outbound.
			if isBlock(r.Outbound) {
				blockDefault = true
			} else {
				final = canonicalOutbound(r.Outbound)
			}
			continue
		}
		// Hybrid: a pure-IP-CIDR rule (no domain/geo/port matcher) pointed at a kernel
		// egress is kernel-routed by pbr with IDENTICAL semantics — drop it from sing-box.
		// A rule with any domain/geo/port matcher is NOT dropped: pbr ignores those (it
		// would over-route the whole IP set), so it stays in sing-box, routed through the
		// kept kernel outbound. ipOnlyKernelRule encodes exactly that "pbr routes it the
		// same" test, matching pbr.Compile's IPCIDR-only zone construction.
		if hybrid && kernelEgress(p, r.Outbound) && ipOnlyKernelRule(r) {
			continue
		}
		rule := ruleMatch(r)
		// geosite/geoip can't be inline matchers on 1.12 (the databases were removed:
		// "geosite database is deprecated" fails the whole config). Convert them to
		// remote rule-set references instead; the synthesised sets are merged into the
		// route's rule_set by Generate. A rule with only domain/ip/port produces no
		// geoSets, so its output is unchanged.
		gs, gi := geoRuleSets(r, &geoSets, seen)
		// A rule whose only matchers are kernel-only (source_mac / source_iface) has no
		// sing-box expression: ruleMatch is empty and there are no geo sets. Emitting it
		// would be a condition-less match-all that shadows every later rule and the final —
		// a routing leak. Skip it on the sing-box plane (the kernel plane enforces it in
		// fast/hybrid; in pure tun/mixed a kernel-only source rule simply cannot apply). §3.7
		if len(rule) == 0 && len(gs) == 0 && len(gi) == 0 {
			continue
		}
		switch {
		case len(gs) > 0 && len(gi) > 0:
			// A rule with BOTH geosite AND geoip: inline these were different field
			// types and thus AND'd, but two tags in ONE rule_set field are OR'd — so a
			// naive merge would silently flip AND→OR. Preserve the AND with a logical
			// rule: each geo type and the domain/ip/port matchers become AND'd sub-rules.
			sub := []map[string]any{}
			if len(rule) > 0 {
				sub = append(sub, rule)
			}
			sub = append(sub, map[string]any{"rule_set": gs}, map[string]any{"rule_set": gi})
			rule = map[string]any{"type": "logical", "mode": "and", "rules": sub}
		case len(gs) > 0:
			rule["rule_set"] = gs
		case len(gi) > 0:
			rule["rule_set"] = gi
		}
		if isBlock(r.Outbound) {
			rule["action"] = "reject"
		} else {
			rule["action"] = "route"
			rule["outbound"] = canonicalOutbound(r.Outbound)
		}
		rules = append(rules, rule)
	}
	out = map[string]any{"final": final}
	if len(rules) > 0 {
		out["rules"] = rules
	}
	return out, geoSets, blockDefault
}

// geoRuleSets converts a rule's geosite/geoip names into remote rule-set entries
// (sing-box 1.12 removed the built-in geoip/geosite databases — an inline geosite/
// geoip matcher fails the whole shared config and takes all routing down on apply).
// New sets are appended to *sets (deduped by tag across all rules); the geosite and
// geoip tags are returned SEPARATELY because a rule with BOTH must AND them, not OR
// them (see routeFrom) — geosite-vs-geoip are different inline field types, so they
// were AND'd, but two tags in one rule_set field are OR'd. download_detour=direct so
// the lists fetch over the WAN even before tunnel routes exist; they cache via cache_file.
func geoRuleSets(r *model.Rule, sets *[]map[string]any, seen map[string]bool) (gs, gi []string) {
	add := func(tag, url string) string {
		if !seen[tag] {
			seen[tag] = true
			*sets = append(*sets, map[string]any{
				"tag": tag, "type": "remote", "format": "binary",
				"url": url, "download_detour": model.OutboundDirect, "update_interval": "1d",
			})
		}
		return tag
	}
	for _, g := range r.GeoSite {
		if g = strings.TrimSpace(g); g != "" {
			gs = append(gs, add("geosite-"+g, geositeSRSBase+g+".srs"))
		}
	}
	for _, c := range r.GeoIP {
		if c = strings.TrimSpace(c); c != "" {
			gi = append(gi, add("geoip-"+c, geoipSRSBase+c+".srs"))
		}
	}
	return gs, gi
}

// blockAllRule is the terminal catch-all reject emitted for a block-by-default
// posture; it must be the LAST route rule.
func blockAllRule() map[string]any {
	return map[string]any{"network": []string{"tcp", "udp"}, "action": "reject"}
}

// ruleMatch builds the matcher portion of a route rule (no action). geosite/geoip
// are NOT emitted inline (sing-box 1.12 removed those databases) — routeFrom turns
// them into remote rule-set references instead.
func ruleMatch(r *model.Rule) map[string]any {
	rule := map[string]any{}
	addIf(rule, "domain_suffix", r.DomainSuffix)
	addIf(rule, "domain", r.Domain)
	addIf(rule, "ip_cidr", r.IPCIDR)
	if len(r.Port) > 0 {
		rule["port"] = r.Port
	}
	// Source matchers (sing-box plane). source_mac / source_iface are KERNEL-ONLY (no
	// sing-box matcher pre-1.14) — the pbr plane emits those, never here.
	addIf(rule, "source_ip_cidr", r.SourceIPCIDR)
	if len(r.SourcePort) > 0 {
		rule["source_port"] = r.SourcePort
	}
	return rule
}

// addIf sets m[key] to the NON-BLANK entries of vals, omitting the key when none
// remain. Blank entries must be dropped: an empty domain_suffix "" matches EVERY
// domain (every host ends with ""), so a mixed matcher like
// domain_suffix:["x",""] would silently become match-all and route all traffic to
// the rule's outbound — a routing leak. (An all-blank matcher is already rejected
// at Validate via ruleHasNoMatcher; this also sanitises a real+blank mix.)
func addIf(m map[string]any, key string, vals []string) {
	var kept []string
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			kept = append(kept, v)
		}
	}
	if len(kept) > 0 {
		m[key] = kept
	}
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intp(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case int:
			return t
		case float64:
			return int(t)
		}
	}
	return 0
}

// boolp reads a boolean param, tolerating the bool / "true" / "1" shapes a value
// can take after import or a JSON store round-trip.
func boolp(m map[string]any, k string) bool {
	switch t := m[k].(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	}
	return false
}
