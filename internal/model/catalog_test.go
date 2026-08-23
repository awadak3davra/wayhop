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
