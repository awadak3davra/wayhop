package model

import "testing"

// TestRoutingPresets_Invariants guards the curated catalog: IDs are unique and every preset has
// the required fields with a valid Kind/Format/Suggest enum. A malformed entry would surface in
// the UI as a broken one-click list, so pin it here.
func TestRoutingPresets_Invariants(t *testing.T) {
	kinds := map[string]bool{"domain": true, "ip": true, "mixed": true}
	formats := map[string]bool{"binary": true, "source": true}
	suggests := map[string]bool{"proxy": true, "direct": true, "block": true}

	seen := map[string]bool{}
	for _, p := range RoutingPresets() {
		if p.ID == "" || p.Name == "" || p.Source == "" || p.Category == "" {
			t.Errorf("preset %q has an empty required field: %+v", p.ID, p)
		}
		if seen[p.ID] {
			t.Errorf("duplicate preset ID %q", p.ID)
		}
		seen[p.ID] = true
		if !kinds[p.Kind] {
			t.Errorf("preset %q has invalid Kind %q", p.ID, p.Kind)
		}
		if !formats[p.Format] {
			t.Errorf("preset %q has invalid Format %q", p.ID, p.Format)
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
