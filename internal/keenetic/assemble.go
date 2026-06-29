package keenetic

import (
	"encoding/json"
	"fmt"
	"strings"

	"velinx/internal/generator"
	"velinx/internal/model"
)

// assemble.go turns the reconciled model (BuildProfile) into the final sing-box routing
// config: generator.Generate produces the outbounds + domain rule_sets + failover groups,
// then a Keenetic post-process swaps the OpenWrt-shaped TUN for the Keenetic TUN (auto_route
// off — NDM routes the fakeip range into it) and injects the fakeip dns{} plane. The IP-CIDR
// lists carry no sing-box rule_set (CIDRSource/Manual-IP → kernel pbr only), so the sing-box
// side handles ONLY domain routing.

// censoredRuleSetTags returns the sing-box rule_set tags for the profile's DOMAIN lists —
// the sets that must resolve to fakeip so their lookups route over a tunnel. Mirrors the
// generator's tag scheme: a remote Source → "rs-<id>", a Manual list with any domain →
// "rsm-<id>". IP-only / CIDRSource lists produce no sing-box set (kernel-routed).
func censoredRuleSetTags(p *model.Profile) []string {
	var tags []string
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		if rl.Source != "" {
			tags = append(tags, "rs-"+rl.ID)
		}
		if hasDomain(rl.Manual) {
			tags = append(tags, "rsm-"+rl.ID)
		}
	}
	return tags
}

// hasDomain reports whether any entry is a domain (not an IP/CIDR).
func hasDomain(entries []string) bool {
	for _, e := range entries {
		if _, err := cidrToAddrMask(e); err != nil {
			return true
		}
	}
	return false
}

// InlineCIDRSources fetches each list's CIDRSource feed and inlines the CIDRs into Manual,
// clearing CIDRSource. The generator routes by Source (a domain rule_set) and Manual only — a
// CIDRSource feed ALONE produces no sing-box rule, so an IP-feed list (telegram/discord_ips)
// would leak its IP-literal traffic past sing-box. Inlining turns it into a Manual ip_cidr
// rule_set that routes (with failover) to its group. fetch is injected (the daemon fetches the
// feed THROUGH a tunnel at pre-flight). Must run before AssembleSingboxConfig.
func InlineCIDRSources(p *model.Profile, fetch func(url string) ([]string, error)) error {
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if rl.CIDRSource == "" {
			continue
		}
		cidrs, err := fetch(rl.CIDRSource)
		if err != nil {
			return fmt.Errorf("fetch CIDR feed %q (list %q): %w", rl.CIDRSource, rl.ID, err)
		}
		rl.Manual = append(rl.Manual, cidrs...)
		rl.CIDRSource = ""
	}
	return nil
}

// SubstituteRealOutbounds replaces placeholder proxy outbounds in the assembled config with
// the REAL ones from the live sing-box config (verbatim — real server/password/uuid/tls/flow),
// keyed by a live-tag → assembled-tag map (e.g. {"hy2-main":"hy2_main", "vless-main":
// "vless_main"}). BuildProfile uses PLACEHOLDER Hy2/VLESS params (so the secrets never enter
// Velinx's model/code); this swaps the working tunnels in at the JSON level right before
// apply. A live tag with no match is skipped (returns the tags it could not find).
func SubstituteRealOutbounds(cfg map[string]any, liveSingboxConfig []byte, tagMap map[string]string) (missing []string, err error) {
	var live struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(liveSingboxConfig, &live); err != nil {
		return nil, fmt.Errorf("parse live sing-box config: %w", err)
	}
	byTag := map[string]map[string]any{}
	for _, ob := range live.Outbounds {
		if tag, _ := ob["tag"].(string); tag != "" {
			byTag[tag] = ob
		}
	}
	obs, _ := cfg["outbounds"].([]map[string]any)
	asmToLive := map[string]string{}
	for liveTag, asmTag := range tagMap {
		asmToLive[asmTag] = liveTag
	}
	done := map[string]bool{}
	for i, ob := range obs {
		tag, _ := ob["tag"].(string)
		liveTag, ok := asmToLive[tag]
		if !ok {
			continue
		}
		real, found := byTag[liveTag]
		if !found {
			continue
		}
		repl := make(map[string]any, len(real))
		for k, v := range real {
			repl[k] = v
		}
		repl["tag"] = tag // keep the assembled tag (rule_sets/groups reference it)
		obs[i] = repl
		done[liveTag] = true
	}
	cfg["outbounds"] = obs
	for liveTag := range tagMap {
		if !done[liveTag] {
			missing = append(missing, liveTag)
		}
	}
	return missing, nil
}

// InlineDomainSources fetches each list's domain Source feed and inlines the parsed entries
// into Manual, clearing Source. The generator emits a remote rule_set with format:"binary"
// (.srs) for any non-.json Source URL — but keen-pbr's feeds are plain `.lst` / v2fly domain
// lists, which sing-box CANNOT load as a binary rule_set: it fails at RUNTIME (sing-box check
// passes only because it never fetches). Inlining produces an inline rule_set that works. fetch
// returns the already-parsed entries for a URL (the caller fetches + ParseDomainFeed's). Run
// before AssembleSingboxConfig (with InlineCIDRSources).
func InlineDomainSources(p *model.Profile, fetch func(url string) ([]string, error)) error {
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if rl.Source == "" {
			continue
		}
		if rl.Format == "binary" {
			continue // a proper .srs remote rule_set (catalog) — leave it remote, don't inline
		}
		entries, err := fetch(rl.Source)
		if err != nil {
			return fmt.Errorf("fetch domain feed %q (list %q): %w", rl.Source, rl.ID, err)
		}
		rl.Manual = append(rl.Manual, entries...)
		rl.Source = ""
	}
	return nil
}

// ParseDomainFeed parses a fetched feed body into clean domain/IP entries. Handles plain
// `.lst` (one entry per line, # / ! comments) and v2fly domain-list-community (`domain:X` /
// `full:X` → X; include:/regexp:/keyword: are skipped — unsupported as a simple suffix).
// Mixed domain+IP feeds pass through (the generator splits Manual into domain_suffix/ip_cidr).
func ParseDomainFeed(body string) []string {
	var out []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.IndexAny(line, " \t#"); i >= 0 { // strip inline comment / trailing junk
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case strings.HasPrefix(line, "domain:"):
			out = append(out, strings.TrimPrefix(line, "domain:"))
		case strings.HasPrefix(line, "full:"):
			out = append(out, strings.TrimPrefix(line, "full:"))
		case strings.HasPrefix(line, "include:"), strings.HasPrefix(line, "regexp:"), strings.HasPrefix(line, "keyword:"):
			continue // unsupported in a simple suffix rule_set
		case line == "":
			continue
		default:
			out = append(out, line)
		}
	}
	return out
}

// AssembleSingboxConfig builds the full Keenetic routing sing-box config from a reconciled
// profile. dohDetour is the tunnel the censored DoH resolves over (a live VPN endpoint, e.g.
// "netherlands"). Hybrid is OFF: on Keenetic the routing TUN is auto_route:false (NDM routes
// the default into it), so sing-box routes EVERY list (domain + IP, via ip_cidr rule_sets) and
// the kernel just owns the default/bypass/RU-direct — no route_exclude needed. Run
// InlineCIDRSources first so IP-feed lists become Manual ip_cidr rule_sets. Validate via
// sing-box check before any apply.
func AssembleSingboxConfig(p *model.Profile, dohDetour string) (map[string]any, error) {
	// The DoH detour MUST resolve to a live outbound (endpoint or group) the generator emits;
	// otherwise sing-box rejects the config at startup ("detour to unknown outbound") and — with no
	// `sing-box check` gate before the cutover's restart — the kernel default moves onto a dead
	// sing-box, black-holing the LAN until the failsafe rolls back. Fail at pre-flight instead.
	if dohDetour == "" || (p.EndpointByID(dohDetour) == nil && p.GroupByID(dohDetour) == nil) {
		return nil, fmt.Errorf("DoH detour %q is not a live outbound in the reconciled profile (would emit a dangling sing-box dns.detour)", dohDetour)
	}
	res, err := generator.Generate(p, generator.Options{TunEnabled: true, MixedPort: 7890})
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	cfg := res.Config

	// Replace the OpenWrt-shaped tun-in with the Keenetic TUN: auto_route:false (NDM installs
	// the route into it), gvisor, fixed interface_name. Keep all other inbounds (mixed/clash).
	inb, _ := cfg["inbounds"].([]map[string]any)
	out := make([]any, 0, len(inb))
	replaced := false
	for _, in := range inb {
		if in["tag"] == "tun-in" {
			out = append(out, keeneticTUN("tun-in", "wr-tun", "172.19.8.1/30", 1400))
			replaced = true
		} else {
			out = append(out, in)
		}
	}
	if !replaced {
		out = append(out, keeneticTUN("tun-in", "wr-tun", "172.19.8.1/30", 1400))
	}
	cfg["inbounds"] = out

	// Inject the fakeip DNS plane (the anti-leak core).
	cfg["dns"] = fakeipDNS(DNSOptions{DoHDetour: dohDetour, CensoredSets: censoredRuleSetTags(p)})

	// route.default_domain_resolver so sing-box can resolve a fakeip-recovered domain.
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		cfg["route"] = route
	}
	route["default_domain_resolver"] = map[string]any{"server": "dns_local"}

	// experimental.cache_file with store_fakeip so an all-down lookup returns the cached fakeip
	// (→ the kernel blackhole/route) instead of leaking.
	exp, _ := cfg["experimental"].(map[string]any)
	if exp == nil {
		exp = map[string]any{}
		cfg["experimental"] = exp
	}
	cf, _ := exp["cache_file"].(map[string]any)
	if cf == nil {
		cf = map[string]any{}
		exp["cache_file"] = cf
	}
	cf["enabled"] = true
	cf["store_fakeip"] = true

	return cfg, nil
}
