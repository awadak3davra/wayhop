package model

import (
	"strings"
	"testing"
)

// TestRoutingPresets_Invariants guards the curated catalog: IDs are unique and every preset has
// the required fields with a valid Kind/Format/Suggest enum. A malformed entry would surface in
// the UI as a broken one-click list, so pin it here.
func TestRoutingPresets_Invariants(t *testing.T) {
	kinds := map[string]bool{"domain": true, "ip": true, "mixed": true}
	formats := map[string]bool{"binary": true, "source": true}
	suggests := map[string]bool{"proxy": true, "direct": true, "block": true}

	seen := map[string]bool{}
	for _, p := range RoutingPresets() {
		if p.ID == "" || p.Name == "" || p.Category == "" {
			t.Errorf("preset %q has an empty required field: %+v", p.ID, p)
		}
		// A preset carries exactly one source, and which one decides its datapath: a .srs rule-set is
		// read by the proxy core and carries a Format; a CIDR feed goes to the kernel's hash sets; a
		// domain feed goes to the resolver. Two at once would leave the list's plane ambiguous, none
		// would make it a one-click list that fetches nothing.
		sources := 0
		for _, s := range []string{p.Source, p.CIDRSource, p.DomainSource} {
			if s != "" {
				sources++
			}
		}
		if sources != 1 {
			t.Errorf("preset %q must have exactly one of Source / CIDRSource / DomainSource: %+v", p.ID, p)
		}
		// Only the compiled rule-set format needs the core. Domain MATCHING does not — that is the
		// whole point of the resolver plane, and a domain preset that still claimed to need sing-box
		// would keep a list greyed out for a reason that stopped being true.
		if (p.Source != "") != p.RequiresCore {
			t.Errorf("preset %q: RequiresCore must track having a rule-set Source: %+v", p.ID, p)
		}
		if seen[p.ID] {
			t.Errorf("duplicate preset ID %q", p.ID)
		}
		seen[p.ID] = true
		if !kinds[p.Kind] {
			t.Errorf("preset %q has invalid Kind %q", p.ID, p.Kind)
		}
		if p.Source != "" && !formats[p.Format] {
			t.Errorf("preset %q has invalid Format %q", p.ID, p.Format)
		}
		if p.CIDRSource != "" && p.Format != "" {
			t.Errorf("preset %q is a CIDR feed and must carry no rule-set Format", p.ID)
		}
		if !suggests[p.Suggest] {
			t.Errorf("preset %q has invalid Suggest %q", p.ID, p.Suggest)
		}
	}
}

// TestRoutingPresets_TelegramCalls (QW4): Telegram CALLS travel over raw UDP IPs that the
// domain-only svc-telegram preset can't match, so the catalog ships a dedicated IP-kind voice
// preset. Without it, a user routing "Telegram" via a tunnel still has calls fall off to the WAN.
func TestRoutingPresets_TelegramCalls(t *testing.T) {
	var calls *RoutingPreset
	for i := range RoutingPresets() {
		if p := RoutingPresets()[i]; p.ID == "svc-telegram-calls" {
			calls = &p
			break
		}
	}
	if calls == nil {
		t.Fatal("missing svc-telegram-calls preset (Telegram voice/call IPs)")
	}
	if calls.Kind != "ip" {
		t.Errorf("svc-telegram-calls Kind = %q, want ip (calls are IP-routed, not domain)", calls.Kind)
	}
	if calls.Suggest != "proxy" {
		t.Errorf("svc-telegram-calls Suggest = %q, want proxy", calls.Suggest)
	}
}

// TestRoutingPresets_Crypto: the Crypto preset routes crypto exchanges/wallets/DeFi via a tunnel.
// It must be a domain rule-set suggested for proxy (route via the VPS the user picks), sourced from
// the sing-geosite cryptocurrency category.
func TestRoutingPresets_Crypto(t *testing.T) {
	var crypto *RoutingPreset
	for i := range RoutingPresets() {
		if p := RoutingPresets()[i]; p.ID == "svc-crypto" {
			crypto = &p
			break
		}
	}
	if crypto == nil {
		t.Fatal("missing svc-crypto preset (crypto exchanges/wallets -> tunnel)")
	}
	if crypto.Kind != "domain" {
		t.Errorf("svc-crypto Kind = %q, want domain", crypto.Kind)
	}
	if crypto.Suggest != "proxy" {
		t.Errorf("svc-crypto Suggest = %q, want proxy (route via the chosen VPS tunnel)", crypto.Suggest)
	}
	if !strings.Contains(crypto.Source, "cryptocurrency") {
		t.Errorf("svc-crypto Source = %q, want the sing-geosite cryptocurrency rule-set", crypto.Source)
	}
}

// TestRoutingPresets_Streaming: the streaming geo-unblock presets (Netflix/Disney+/Prime/Spotify)
// are domain rule-sets suggested for proxy (route via the chosen clean egress).
func TestRoutingPresets_Streaming(t *testing.T) {
	byID := map[string]RoutingPreset{}
	for _, p := range RoutingPresets() {
		byID[p.ID] = p
	}
	for _, id := range []string{"svc-netflix", "svc-disney", "svc-primevideo", "svc-spotify"} {
		p, ok := byID[id]
		if !ok {
			t.Errorf("missing streaming preset %q", id)
			continue
		}
		if p.Kind != "domain" {
			t.Errorf("%s Kind = %q, want domain", id, p.Kind)
		}
		if p.Suggest != "proxy" {
			t.Errorf("%s Suggest = %q, want proxy", id, p.Suggest)
		}
		if !strings.HasPrefix(p.Source, "https://") {
			t.Errorf("%s Source = %q, want an https rule-set URL", id, p.Source)
		}
	}
}

// The hosting-network presets exist to reach sites that stall on a throttled WAN, which is exactly
// the router that may run without a core, so they must stay plain CIDR feeds on the weekly cadence
// of the ranges they carry. Telegram's ranges come from what Telegram's ASNs announce: every
// file-based list checked missed or added a network.
func TestRoutingPresets_HostingNetworksAndTelegramAreKernelFeeds(t *testing.T) {
	byID := map[string]RoutingPreset{}
	for _, p := range RoutingPresets() {
		byID[p.ID] = p
	}
	for _, id := range []string{"cidr-cloudflare", "cidr-cloudfront", "cidr-hetzner", "cidr-digitalocean", "cidr-ovh", "cidr-telegram",
		"cidr-roblox", "cidr-google-meet"} {
		p, ok := byID[id]
		if !ok {
			t.Errorf("missing preset %q", id)
			continue
		}
		if p.CIDRSource == "" || p.RequiresCore || p.Kind != "ip" {
			t.Errorf("%s must be a coreless CIDR feed: %+v", id, p)
		}
		if p.RefreshHours != 168 {
			t.Errorf("%s refresh_hours = %d, want the weekly cadence of service ranges", id, p.RefreshHours)
		}
	}
	if got := byID["cidr-telegram"].CIDRSource; got != "asn:62041,59930,62014,44907,211157" {
		t.Errorf("cidr-telegram source = %q, want Telegram's five ASNs", got)
	}
	// Same reason for Roblox: the file list missed three of its networks and kept one nobody announces.
	if got := byID["cidr-roblox"].CIDRSource; got != "asn:22697" {
		t.Errorf("cidr-roblox source = %q, want Roblox's own ASN", got)
	}
	for _, id := range []string{"antizapret", "rkn"} {
		if _, ok := byID[id]; ok {
			t.Errorf("preset %q points at a feed frozen since early 2026; the runetfreedom presets replace it", id)
		}
	}
}

// The 12-hour tier is for feeds that really regenerate daily. Re:filter, legiz's bundle and
// itdoginfo's lists change every few weeks, so twice-daily fetches of them were downloads of
// unchanged files; they take the daily default.
func TestRoutingPresetsTwiceDailyOnlyForDailyRegistries(t *testing.T) {
	want := map[string]bool{"cidr-antifilter": true, "ru-blocked": true, "ru-blocked-all": true}
	daily := map[string]bool{"cidr-refilter": true, "refilter-domains": true, "refilter-ip": true, "ru-bundle": true, "ru-inside": true}
	for _, p := range RoutingPresets() {
		if (p.RefreshHours == 12) != want[p.ID] {
			t.Errorf("preset %q: refresh_hours %d", p.ID, p.RefreshHours)
		}
		if daily[p.ID] && p.RefreshHours != 24 {
			t.Errorf("preset %q: refresh_hours %d, want the daily default", p.ID, p.RefreshHours)
		}
		delete(daily, p.ID)
	}
	for id := range daily {
		t.Errorf("preset %q is gone; update this test", id)
	}
}

// The RU-direct presets keep RU services on the subscriber's own ISP: they suggest "direct", need no
// proxy core, read the daily-rebuilt release branch (not the lagging release asset) and refresh daily.
func TestRoutingPresetsRUDirect(t *testing.T) {
	byID := map[string]RoutingPreset{}
	for _, p := range RoutingPresets() {
		byID[p.ID] = p
	}
	for id, kind := range map[string]string{"ru-direct": "domain", "ru-direct-standard": "domain", "cidr-ru-direct": "ip"} {
		p, ok := byID[id]
		if !ok {
			t.Errorf("missing preset %q", id)
			continue
		}
		src := p.DomainSource + p.CIDRSource
		if p.Kind != kind || p.RequiresCore || p.Suggest != "direct" || p.RefreshHours != 24 ||
			!strings.HasPrefix(src, "https://raw.githubusercontent.com/kyoresuas/ru-direct/release/") {
			t.Errorf("%s: %+v", id, p)
		}
	}
}

// Every preset carries a cadence the refresh loop will accept as-is. A catalog entry that arrives
// below the flash floor would be silently clamped — right result, wrong place to decide it — and one
// above the ceiling would be clamped down to a number nobody chose.
func TestRoutingPresetsCarryAFlashSafeCadence(t *testing.T) {
	for _, p := range RoutingPresets() {
		if p.RefreshHours < MinCIDRRefreshHours || p.RefreshHours > MaxCIDRRefreshHours {
			t.Errorf("preset %q: refresh_hours %d outside [%d,%d]",
				p.ID, p.RefreshHours, MinCIDRRefreshHours, MaxCIDRRefreshHours)
		}
		if !ValidRefreshHours(RoutingList{CIDRSource: p.CIDRSource, Source: p.Source, RefreshHours: p.RefreshHours}) {
			t.Errorf("preset %q: refresh_hours %d is not a value the API would accept", p.ID, p.RefreshHours)
		}
	}
}

// The registries move faster than the service ranges, and the catalog is where that difference is
// known. Asserting the relation rather than the numbers keeps the test honest if the numbers change.
func TestRoutingPresetsRefreshBlocklistsFasterThanStaticRanges(t *testing.T) {
	byID := map[string]RoutingPreset{}
	for _, p := range RoutingPresets() {
		byID[p.ID] = p
	}
	registry, ranges := byID["cidr-antifilter"], byID["cidr-telegram"]
	if registry.ID == "" || ranges.ID == "" {
		t.Fatal("the two presets this compares are gone; update the test with the catalog")
	}
	if registry.RefreshHours >= ranges.RefreshHours {
		t.Errorf("a blocking registry (%dh) should refresh more often than a company's IP ranges (%dh)",
			registry.RefreshHours, ranges.RefreshHours)
	}
}
