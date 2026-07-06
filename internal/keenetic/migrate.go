package keenetic

import (
	"fmt"

	"wayhop/internal/model"
)

// migrate.go builds the WayHop model of mama's LIVE Keenetic setup so WayHop can
// faithfully REPLACE keen-pbr + S89hy_failover (see memory keenetic-backend.md, DEPLOY
// phase). Endpoint IDs match the keen-pbr outbound tags + the S89 tiers. The adopted
// AmneziaWG tunnels are EngineExternal{interface:nwgX} (NDM-managed, reused not recreated —
// see CompileOptions.AdoptInterfaces); Hy2/VLESS are sing-box endpoints.

// Endpoint IDs (match keen-pbr outbound tags / S89 tiers).
const (
	EpKeentest    = "keentest"    // AmneziaWG nwg3 — blocked-in-RF + list-failover primary
	EpNetherlands = "netherlands" // AmneziaWG nwg1 — list-failover tier 2 (+IPv6-capable)
	EpNdVps       = "nd_vps"      // AmneziaWG nwg0 — list-failover tier 3
	EpNlFailover  = "nl_failover" // AmneziaWG nwg5 — S89 DEFAULT tier 2 (→NL)
	EpHy2         = "hy2_main"    // sing-box Hysteria2 — S89 DEFAULT tier 1 (singtun)
	EpVless       = "vless_main"  // sing-box VLESS-Reality — S89 DEFAULT tier 3 (vlesstun)
)

// orderedToleranceMS: a large urltest tolerance so the group sticks to the first live member
// and only moves on a member's DEATH (approximates keen-pbr/S89 strict priority order; the
// user chose strict order). True strict order for the kernel-routed default + IP lists comes
// from metric tiers (Phase 5); domain-list failover uses this sticky urltest.
const orderedToleranceMS = 10000

// LiveAdoptInterfaces maps the adopted AmneziaWG endpoints to their live kernel interfaces.
func LiveAdoptInterfaces() map[string]string {
	return map[string]string{
		EpKeentest: "nwg3", EpNetherlands: "nwg1", EpNdVps: "nwg0", EpNlFailover: "nwg5",
	}
}

func liveEndpoints() []model.Endpoint {
	awg := func(id, iface string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Engine: model.EngineExternal, Enabled: true,
			Params: map[string]any{"interface": iface}}
	}
	return []model.Endpoint{
		awg(EpKeentest, "nwg3"),
		awg(EpNetherlands, "nwg1"),
		awg(EpNdVps, "nwg0"),
		awg(EpNlFailover, "nwg5"),
		// ⚠️ Hy2/VLESS params are PLACEHOLDERS — the real server/password/uuid/TLS are read
		// from the live /opt/etc/sing-box/config.json at migration/pre-flight (Phase 3).
		{ID: EpHy2, Name: EpHy2, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "203.0.113.10", Port: 8444, Enabled: true,
			Params: map[string]any{"password": "PLACEHOLDER"},
			TLS:    &model.TLS{Enabled: true, SNI: "PLACEHOLDER", Insecure: true}},
		{ID: EpVless, Name: EpVless, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "203.0.113.10", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "00000000-0000-0000-0000-000000000000"}},
	}
}

func liveGroups() []model.Group {
	h := func() *model.Health {
		return &model.Health{URL: "https://www.gstatic.com/generate_204", Tolerance: orderedToleranceMS}
	}
	return []model.Group{
		// Blocked-in-RF (discord/fb/insta/telegram/twitter): TUNNEL-ONLY, no WAN fallback. The
		// RU WAN BLOCKS these (DPI/TSPU), so a WAN fallback is useless — it only breaks Telegram.
		// With no terminal WAN member, if every tunnel probe fails (e.g. ICMP starved under a
		// CPU-load spike) the cron KEEPS the current tunnel instead of demoting → Telegram, a
		// critical family-comms path, stays on a VPN even when the probe momentarily lies.
		// (The default 3-tier still falls to WAN for GENERAL traffic — that's where no-kill-switch
		// applies; censored content has nowhere useful to fall.)
		{ID: "blocked_rf", Name: "Blocked in RF", Type: model.GroupURLTest,
			Members: []string{EpKeentest, EpNdVps}, Test: h()},
		// List failover — TUNNEL-ONLY (NL → nd_vps, no WAN). These route LISTED traffic: mostly
		// RU-censored (rkn/antifilter/adult/news/ooni/tiktok/roblox — WAN is blocked for them) plus
		// VPN-optimized (youtube/anydesk). A WAN fallback either breaks the censored ones or
		// de-optimizes the rest, and the probe flaps to WAN under CPU load. With no terminal WAN,
		// an all-tunnels-probe-miss KEEPS the current tunnel (which is actually up). General
		// internet keeps its WAN fallback via the default 3-tier (S89) — that's the no-kill-switch.
		{ID: "failover_with_wan", Name: "VPN tunnels", Type: model.GroupURLTest,
			Members: []string{EpKeentest, EpNetherlands, EpNdVps}, Test: h()},
		{ID: "failover_strict", Name: "VPN tunnels (strict)", Type: model.GroupURLTest,
			Members: []string{EpKeentest, EpNetherlands, EpNdVps}, Test: h()},
		// Default 3-tier (S89 order): Hy2 → AmneziaWG(NL) → VLESS → WAN.
		{ID: "default_3tier", Name: "Default 3-tier", Type: model.GroupURLTest,
			Members: []string{EpHy2, EpNlFailover, EpVless, model.OutboundDirect}, Test: h()},
	}
}

// LiveProfile is the WayHop model of mama's setup — endpoints + the failover groups + a
// default rule (→ the 3-tier failover). The keen-pbr routing lists are added by BuildProfile.
// Compile it with CompileOptions{AdoptInterfaces: …} so the live AmneziaWG tunnels are reused,
// never recreated.
func LiveProfile() *model.Profile {
	return &model.Profile{
		Endpoints: liveEndpoints(),
		Groups:    liveGroups(),
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "default_3tier"}},
	}
}

// keenPBRCatalogSRS maps keen-pbr list IDs to WayHop-catalog .srs rule-sets — the SAME
// upstreams (itdoginfo / 1andrevich / antizapret) as compiled binary rule-sets sing-box loads
// natively as remote rule_sets. Used for the big/common lists so they aren't inlined as tens of
// thousands of domains (rkn_full alone is ~81k → refilter .srs; antifilter ~15k → antizapret).
// Verified upstreams are the same .lst content keen-pbr fetches, in .srs form.
func keenPBRCatalogSRS() map[string]string {
	const itd = "https://github.com/itdoginfo/allow-domains/releases/latest/download/"
	return map[string]string{
		"rkn_full":       "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
		"rkn_community":  "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
		"antifilter_all": "https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs",
		"youtube":        itd + "youtube.srs",
		"rkn_blocked":    itd + "block.srs",
		"adult":          itd + "porn.srs",
		"ru_outside":     itd + "russia_outside.srs",
		"discord_dom":    itd + "discord.srs",
		"instagram":      itd + "meta.srs",
		"tiktok":         itd + "tiktok.srs",
		"google_ai":      itd + "google_ai.srs",
	}
}

// applyCatalogSRS rewrites mapped lists to a catalog .srs rule-set (Format "binary", a remote
// rule_set sing-box loads natively) instead of the raw .lst feed — so the big lists are NOT
// inlined. Unmapped Source lists keep their URL and are inlined (small) by InlineDomainSources.
func applyCatalogSRS(p *model.Profile) {
	m := keenPBRCatalogSRS()
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if rl.Source == "" {
			continue
		}
		if srs, ok := m[rl.ID]; ok {
			rl.Source = srs
			rl.Format = "binary"
		}
	}
}

// keenPBROutboundMap maps keen-pbr outbound tags to the WayHop failover groups.
func keenPBROutboundMap() map[string]string {
	return map[string]string{
		"keentest":               "blocked_rf",
		"auto_failover_with_wan": "failover_with_wan",
		"auto_failover_strict":   "failover_strict",
		"auto_failover_soft":     "failover_with_wan",
	}
}

// BuildProfile assembles the full WayHop model for the cutover: the LiveProfile skeleton +
// the keen-pbr routing lists (ImportKeenPBR), RECONCILED against the live interfaces so an
// endpoint with no live interface (keentest/nwg3 is gone) is dropped and remapped to remapTo
// (default the next live tier — see the keentest open decision in keenetic-backend.md). It
// returns the validated profile, the adopt map (built from the LIVE interfaces, not hardcoded),
// and any reconciliation warnings.
func BuildProfile(keenpbrConfig []byte, files map[string][]string, live []WGInterface, remapTo string) (*model.Profile, map[string]string, []string, error) {
	if remapTo == "" {
		remapTo = EpNetherlands
	}
	p := LiveProfile()
	lists, err := ImportKeenPBR(keenpbrConfig, files, keenPBROutboundMap())
	if err != nil {
		return nil, nil, nil, err
	}
	// Drop keen-pbr lists not referenced by any rule (empty Outbound): they route nothing, so
	// omitting them preserves behavior and keeps the profile valid.
	active := lists[:0]
	for _, l := range lists {
		if l.Outbound != "" {
			active = append(active, l)
		}
	}
	p.RoutingLists = active
	applyCatalogSRS(p) // big/common lists → catalog .srs (avoid inlining 81k+ domains)

	adopt, missing := ReconcileAdopt(live, LiveAdoptInterfaces())
	// If the remap target itself has no live interface (e.g. the default EpNetherlands when nwg1 is
	// down), remapping references to it just dangles ("member does not resolve") and aborts the
	// whole migration even though other tunnels are alive. Fall back to the first surviving native
	// tunnel so one down primary self-heals instead of failing the cutover.
	miss := map[string]bool{}
	for _, m := range missing {
		miss[m] = true
	}
	var warnings []string
	if miss[remapTo] {
		if alt := firstLiveTunnel(p, miss); alt != "" {
			warnings = append(warnings, fmt.Sprintf("remap target %q has no live interface — remapping to %q instead", remapTo, alt))
			remapTo = alt
		}
	}
	warnings = append(warnings, remapMissing(p, missing, remapTo)...)

	if err := p.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("assembled profile invalid: %w", err)
	}
	return p, adopt, warnings, nil
}

// firstLiveTunnel returns the first surviving native (AmneziaWG/External) tunnel endpoint — the
// remap fallback when the configured remapTo target is itself missing. Prefers the failover tiers
// in a stable order, then any other surviving External endpoint. p still holds every endpoint here
// (remapMissing drops the missing ones later), so an id absent from miss + present in p is live.
func firstLiveTunnel(p *model.Profile, miss map[string]bool) string {
	for _, id := range []string{EpNetherlands, EpNdVps, EpNlFailover, EpKeentest} {
		if !miss[id] && p.EndpointByID(id) != nil {
			return id
		}
	}
	for _, e := range p.Endpoints {
		if !miss[e.ID] && e.Engine == model.EngineExternal {
			return e.ID
		}
	}
	return ""
}

// remapMissing drops endpoints with no live interface and remaps every reference to them
// (group members, list/rule outbounds) to remapTo, de-duplicating group members so a tier
// that already contained remapTo doesn't list it twice.
func remapMissing(p *model.Profile, missing []string, remapTo string) []string {
	if len(missing) == 0 {
		return nil
	}
	miss := map[string]bool{}
	for _, m := range missing {
		miss[m] = true
	}
	var warnings []string

	var kept []model.Endpoint
	for _, e := range p.Endpoints {
		if miss[e.ID] {
			warnings = append(warnings, fmt.Sprintf("endpoint %q has no live interface — remapped to %q", e.ID, remapTo))
			continue
		}
		kept = append(kept, e)
	}
	p.Endpoints = kept

	for i := range p.Groups {
		var out []string
		seen := map[string]bool{}
		for _, m := range p.Groups[i].Members {
			if miss[m] {
				m = remapTo
			}
			if seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
		p.Groups[i].Members = out
	}
	for i := range p.RoutingLists {
		if miss[p.RoutingLists[i].Outbound] {
			p.RoutingLists[i].Outbound = remapTo
		}
	}
	for i := range p.Rules {
		if miss[p.Rules[i].Outbound] {
			p.Rules[i].Outbound = remapTo
		}
	}
	return warnings
}
