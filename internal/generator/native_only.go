package generator

// native_only.go is the PURE, design-independent classification layer P4 (sing-box
// optionality, docs/NATIVE_P4_DESIGN.md) builds on: it answers "could this endpoint /
// profile be carried with NO sing-box process at all?" purely from the model, with no
// host probing and no routing-mode/TUN/default-egress analysis. It is intentionally
// SEPARATE from generator.Generate (which still always emits a sing-box config) so it
// can be reasoned about and unit-tested on its own. The apply path now uses it: the
// server's s.datapathNativeOnly (handleApply + SyncPlugins) calls DatapathNativeOnly to
// skip — and stop — the sing-box core when the kernel plane provably carries everything.
//
// The two functions here mirror — but do not duplicate — the engine classification
// generator.Generate already performs:
//   - EngineExternal      → a `direct` outbound bound to an OS interface (netifd owns
//                           it); the kernel carries the traffic, sing-box is only a
//                           bind_interface shim, not a proxy core. pbr kernel-routes it.
//   - EngineAmneziaWG     → a chained kernel awg interface (Plugin) + pbr fwmark route;
//                           sing-box's outbound is dead weight in hybrid mode. Kernel-native.
//   - EngineSingBox + WireGuard → a top-level sing-box `endpoints` entry. The WireGuard
//                           data path is realizable in the kernel, so the task classifies
//                           plain WireGuard as NOT requiring sing-box (a future native
//                           kernel-WG plane can carry it; the proxy core is not intrinsic).
//   - EngineSingBox + a proxy protocol (vless/vmess/trojan/shadowsocks/hysteria2/tuic)
//                           → a real sing-box outbound. Only sing-box can carry it.
//   - EngineOlcRTC (and any other userspace engine: OpenVPN/Xray/Mihomo) → reached by
//                           sing-box through a local SOCKS the plugin exposes (see
//                           Generate's external-engine branch), so sing-box is required.
//
// The protocol floor (the proxy protocols with no native path) is kept BYTE-IDENTICAL to
// platform.singboxRequired / Capabilities.SingboxRequired so this classifier and the
// host-capability probe never disagree about which protocols force the core.

import (
	"strings"

	"wakeroute/internal/model"
)

// singboxRequiredProtos is the set of proxy protocols that have NO kernel/firmware data
// path on any platform — running any of them means the sing-box userspace core MUST run.
// It is the exact mirror of platform.singboxRequired (vless/vmess/trojan/shadowsocks/
// hysteria2/tuic); keep the two in lockstep so EndpointNeedsSingbox and the host
// capability report (Capabilities.SingboxRequired) can never diverge.
var singboxRequiredProtos = map[model.Protocol]bool{
	model.ProtoVLESS:       true,
	model.ProtoVMess:       true,
	model.ProtoTrojan:      true,
	model.ProtoShadowsocks: true,
	model.ProtoHysteria2:   true,
	model.ProtoTUIC:        true,
}

// ProtocolNeedsSingbox reports whether a proxy protocol has NO kernel/firmware data path
// on any platform and so always forces the sing-box core. This is the protocol FLOOR,
// mirroring platform.singboxRequired / Capabilities.SingboxRequired exactly. It is a
// narrower question than EndpointNeedsSingbox, which also weighs the engine (e.g. socks/
// http endpoints are not in this floor yet still need the core as sing-box outbounds).
func ProtocolNeedsSingbox(p model.Protocol) bool { return singboxRequiredProtos[p] }

// SingboxRequiredProtocols returns the protocol FLOOR — every proxy protocol with no
// kernel/firmware data path, the set that forces the sing-box core — as a slice (unordered).
// It mirrors platform.Capabilities.SingboxRequired EXACTLY; a cross-package lockstep test
// enforces the two never drift, so the native-only classifier (which decides whether the core
// can be skipped) and the host-capability report can never disagree about a protocol.
func SingboxRequiredProtocols() []model.Protocol {
	out := make([]model.Protocol, 0, len(singboxRequiredProtos))
	for p := range singboxRequiredProtos {
		out = append(out, p)
	}
	return out
}

// EndpointNeedsSingbox reports whether an endpoint can ONLY be carried by the sing-box
// userspace core (i.e. it is NOT realizable purely by the kernel / a chained plugin).
//
// It is a PURE function of the model — no host probing, no routing-mode awareness. The
// classification follows generator.Generate's own engine handling:
//
//	NOT needed (kernel-native or plugin-carried):
//	  - EngineExternal      (an OS-owned interface; pbr kernel-routes it — KernelIface != "")
//	  - EngineAmneziaWG     (a kernel awg interface via the awg plugin — KernelIface != "")
//	  - EngineSingBox + ProtoWireGuard (plain WireGuard; a kernel WG data path can carry it)
//
//	Needed (only sing-box can carry it):
//	  - EngineSingBox + any proxy protocol (vless/vmess/trojan/shadowsocks/hysteria2/tuic)
//	  - EngineOlcRTC and every other userspace engine (OpenVPN/Xray/Mihomo/Nfqws): sing-box
//	    reaches them via a local SOCKS the plugin exposes, so the core is still required.
//
// A nil endpoint is treated as needing sing-box (the safe, conservative direction — never
// claim "native-only" for something we can't classify).
//
// The Enabled flag is NOT consulted here — this is a per-endpoint capability question;
// ProfileNativeOnly applies the enabled filter at the profile level.
func EndpointNeedsSingbox(e *model.Endpoint) bool {
	if e == nil {
		return true
	}
	switch e.Engine {
	case model.EngineExternal, model.EngineAmneziaWG:
		// Kernel-plane engines: realized by the kernel (+ the awg plugin for AmneziaWG),
		// never as a sing-box proxy outbound. pbr.KernelIface returns non-empty for both.
		return false
	case model.EngineSingBox:
		// A sing-box-engine endpoint carrying plain WireGuard is a top-level `endpoints`
		// entry whose data path the kernel can carry — classified native-only. Every other
		// sing-box protocol is a genuine proxy outbound that only sing-box can realize.
		if e.Protocol == model.ProtoWireGuard {
			return false
		}
		return true
	default:
		// EngineOlcRTC, EngineOpenVPN, EngineXray, EngineMihomo, EngineNfqws, or any
		// future/unknown engine: these are chained-SOCKS (or otherwise non-native)
		// engines sing-box must front, so the core is required — regardless of protocol
		// (a singbox-required proxy protocol on such an engine needs the core too).
		return true
	}
}

// DatapathNativeOnly is the FULL "skip sing-box" sufficiency check P4 builds on (the
// pure classifier half of docs/NATIVE_P4_DESIGN.md §(a)). It answers the decisive
// question: can this profile, under this routing mode, be carried entirely by the kernel
// plane (pbr fwmark routes + WAN fall-through) so the sing-box userspace core need not run
// at all? Skipping the core is the ONLY change that can black-hole traffic by omission, so
// this predicate is FAIL-SAFE FIRST: it returns true ONLY when every condition below holds
// and returns false on ANY ambiguity (nil/empty profile, non-fast mode, a default routed
// out a tunnel, or any reference that would survive into sing-box). When in doubt, KEEP
// sing-box (the caller runs the core) — that is always safe; it just runs as a redundant
// capture path in fast mode when the kernel already handles everything.
//
// It returns true IFF ALL of the following hold (design §(a) 1–5):
//
//  1. ProfileNativeOnly(p) — every enabled endpoint is kernel-native AND there is at least
//     one enabled endpoint. (Necessary but not sufficient on its own; see that doc.)
//  2. routingMode == "fast". Reject "tun"/"hybrid"/"mixed": tun/hybrid keep a capture-all
//     TUN as the default datapath (skipping the core there black-holes every non-carve-out
//     dest, design §0); mixed exists specifically to serve the sing-box mixed-proxy inbound.
//     Only "fast" is TUN-less with general traffic already on the kernel fast-path → WAN.
//  3. The profile's DEFAULT rule (if any) egresses direct/"". pbr installs NO kernel default
//     route through a tunnel (design §0 / decision 2): a default rule pointed at a tunnel/
//     group/proxy is NOT realizable without sing-box, so it forces the core. No default rule
//     at all is fine — the kernel default is already WAN (pbr.go falls through to the main
//     table). canonicalOutbound folds Direct/Block casing; a Block default is NOT direct/""
//     and is rejected (it implies a surviving reject-final that sing-box, not pbr's default
//     fall-through, expresses — conservative: keep the core).
//  4. hybridReachable(p) is EMPTY — no outbound survives into sing-box. This REUSES the
//     exact hybrid split (kernelEgress/ipOnlyKernelRule and the manual-list predicate) so
//     the skip-set can never drift from what pbr actually kernel-routes. A non-empty set
//     means at least one rule/list/final references a tag only sing-box can carry → KEEP it.
//     Because hybridReachable excludes direct/block builtins from its roots, a profile whose
//     only references are direct/block correctly yields an empty set.
//  5. No surviving domain/geosite/geoip matcher on a sing-box-carried path. pbr cannot
//     kernel-route domains/geo on OpenWrt, so a domain/geo carve-out that pbr can't collect
//     would silently die if the core were skipped. This is already IMPLIED by #4 (a domain/
//     geo rule is not ipOnlyKernelRule, so it stays in hybridReachable → non-empty → false),
//     but it is asserted explicitly as a defense-in-depth guard so the invariant survives any
//     future refactor of the hybrid split: if any enabled rule/list carries a domain/geo
//     matcher and would still be referenced, return false.
//
// The verdict is PURE (model + mode string only; no host I/O) and must be recomputed every
// apply from the live profile+mode — never cached across edits.
func DatapathNativeOnly(p *model.Profile, routingMode string) bool {
	// (1) Necessary floor: nil/empty/no-enabled-endpoints or any sing-box-only endpoint
	// fails here. ProfileNativeOnly also rules out nil p, so the calls below are nil-safe.
	if !ProfileNativeOnly(p) {
		return false
	}
	// (2) Only fast mode is TUN-less with a kernel-native default; everything else keeps
	// (or asks for) a sing-box datapath.
	if routingMode != "fast" {
		return false
	}
	// (3) A default rule must egress direct/"" (no kernel default route exists for a tunnel).
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.Default {
			continue
		}
		switch canonicalOutbound(r.Outbound) {
		case model.OutboundDirect, "":
			// kernel default is WAN/direct — OK.
		default:
			return false
		}
	}
	// (4) Nothing may survive into sing-box. Reuse the hybrid split verbatim so the skip-set
	// equals what pbr kernel-routes; any surviving outbound reference → keep the core.
	if len(hybridReachable(p)) > 0 {
		return false
	}
	// (5) Defense-in-depth: no enabled rule/list may carry a domain/geo matcher that would
	// survive. #4 already implies this (a domain/geo rule is not ipOnlyKernelRule → it is a
	// hybridReachable root → len>0 above), but assert it directly so the guarantee does not
	// depend on the hybrid-split internals staying as they are today.
	for i := range p.Rules {
		r := &p.Rules[i]
		if ruleHasDomainOrGeo(r) {
			return false
		}
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		// A remote Source is a sing-box domain rule_set; a manual list with any domain entry
		// is a domain matcher pbr can't kernel-route. Either forces the core.
		if rl.Source != "" {
			return false
		}
		if domains, _ := splitDomainsIPs(rl.Manual); len(domains) > 0 {
			return false
		}
	}
	// (6) pbr strips IPv6 for EngineExternal egresses (v4-only fail-closed — see
	// internal/pbr render_ipset/render). A v6 carve-out routed to an External iface would be
	// kernel-routed by NEITHER plane once sing-box is stopped (leak/black-hole). So if the
	// profile uses ANY EngineExternal endpoint AND any enabled carve-out carries a v6 CIDR,
	// keep the core. Coarse on purpose — it does not resolve each carve-out's egress, so it
	// also safely covers a group whose elected member is External — and over-keeping sing-box
	// is never a regression (that is exactly today's always-on behavior), never a black-hole.
	hasExternal := false
	for i := range p.Endpoints {
		if e := &p.Endpoints[i]; e.Enabled && e.Engine == model.EngineExternal {
			hasExternal = true
			break
		}
	}
	if hasExternal {
		for i := range p.Rules {
			if anyV6CIDR(p.Rules[i].IPCIDR) {
				return false
			}
		}
		for i := range p.RoutingLists {
			rl := &p.RoutingLists[i]
			if rl.Enabled && (anyV6CIDR(rl.Manual) || anyV6CIDR(rl.CIDRCache)) {
				return false
			}
		}
	}
	return true
}

// anyV6CIDR reports whether any entry is an IPv6 address/CIDR (contains ':'). Used to
// keep sing-box when a v6 carve-out coexists with an EngineExternal egress (pbr is v4-only
// for External), so the v6 traffic is never silently routed by neither plane.
func anyV6CIDR(cidrs []string) bool {
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			return true
		}
	}
	return false
}

// ruleHasDomainOrGeo reports whether a rule carries any domain/geosite/geoip matcher — the
// matchers pbr cannot kernel-route (it marks IP-CIDR zones only). Used by DatapathNativeOnly
// as an explicit guard so a surviving domain/geo carve-out can never be silently dropped by
// skipping sing-box.
func ruleHasDomainOrGeo(r *model.Rule) bool {
	return len(r.Domain) > 0 || len(r.DomainSuffix) > 0 ||
		len(r.GeoSite) > 0 || len(r.GeoIP) > 0
}

// ProfileNativeOnly reports whether a profile COULD run with NO sing-box process — i.e.
// EVERY enabled endpoint is kernel-native (!EndpointNeedsSingbox) AND there is at least
// one enabled endpoint. Disabled endpoints are ignored (they emit nothing). An empty
// profile — or one with no enabled endpoints — is NOT "native-only" for this purpose:
// there is nothing to route, so claiming the core can be skipped is meaningless and a
// future caller should treat "no enabled endpoints" as its own (separate) case rather
// than as a license to tear down sing-box.
//
// IMPORTANT — this is only a NECESSARY condition, not the full "skip sing-box" decision.
// Even when this returns true, P4 must still check the routing mode, the default egress,
// whether a TUN/gateway inbound is needed, and how groups/rules reference outbounds before
// it can safely run without the core. A future caller MUST NOT treat a true result here as
// sufficient on its own; it only rules sing-box OUT when it returns false.
//
// A nil profile returns false (no enabled endpoints).
func ProfileNativeOnly(p *model.Profile) bool {
	if p == nil {
		return false
	}
	enabled := 0
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled {
			continue
		}
		enabled++
		if EndpointNeedsSingbox(e) {
			return false
		}
	}
	return enabled > 0
}
