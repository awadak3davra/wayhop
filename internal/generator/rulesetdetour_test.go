package generator

import (
	"testing"

	"wayhop/internal/model"
)

// profileWithRemoteList builds a profile with one remote routing list, optionally naming a per-list
// DownloadVia.
func profileWithRemoteList(downloadVia string) *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "vps", Name: "vps", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
				Server: "203.0.113.9", Port: 443, Enabled: true, Params: map[string]any{"password": "x"}},
		},
		RoutingLists: []model.RoutingList{{
			ID: "blocked", Name: "blocked", Enabled: true, Outbound: "vps",
			Source: "https://example.invalid/list.srs", DownloadVia: downloadVia,
		}},
	}
}

func detourOf(t *testing.T, sets []map[string]any, tag string) string {
	t.Helper()
	for _, s := range sets {
		if s["tag"] == tag {
			d, _ := s["download_detour"].(string)
			return d
		}
	}
	t.Fatalf("rule-set %q not found in %v", tag, sets)
	return ""
}

// TestRuleSetDetour covers the censored-network fix: remote rule-sets download over `direct` by
// default, which on an RKN-style censored WAN times out or returns a block page that sing-box
// rejects as an invalid rule-set file — and ANY failing rule-set aborts the whole core at startup.
// RuleSetDetour lets those downloads ride a working tunnel instead.
func TestRuleSetDetour(t *testing.T) {
	t.Run("unset keeps the historical direct default", func(t *testing.T) {
		sets, _ := routingFrom(profileWithRemoteList(""), false, "")
		if got := detourOf(t, sets, "rs-blocked"); got != model.OutboundDirect {
			t.Errorf("download_detour = %q, want %q", got, model.OutboundDirect)
		}
	})

	t.Run("profile-wide detour routes downloads through the tunnel", func(t *testing.T) {
		sets, _ := routingFrom(profileWithRemoteList(""), false, "vps")
		if got := detourOf(t, sets, "rs-blocked"); got != "vps" {
			t.Errorf("download_detour = %q, want vps", got)
		}
	})

	t.Run("per-list DownloadVia still wins over the profile default", func(t *testing.T) {
		sets, _ := routingFrom(profileWithRemoteList("direct"), false, "vps")
		if got := detourOf(t, sets, "rs-blocked"); got != model.OutboundDirect {
			t.Errorf("per-list DownloadVia must win, got %q", got)
		}
	})
}

// TestRuleSetDetour_ThreadedThroughGenerate proves the option reaches the emitted config (not just
// the helper), so a user setting it actually changes what sing-box downloads through.
func TestRuleSetDetour_ThreadedThroughGenerate(t *testing.T) {
	res, err := Generate(profileWithRemoteList(""), Options{MixedPort: 7890, RuleSetDetour: "vps"})
	if err != nil {
		t.Fatal(err)
	}
	route, _ := res.Config["route"].(map[string]any)
	sets, _ := route["rule_set"].([]map[string]any)
	if len(sets) == 0 {
		t.Fatalf("no rule_set emitted: %v", route)
	}
	if got := detourOf(t, sets, "rs-blocked"); got != "vps" {
		t.Errorf("Generate did not thread RuleSetDetour: download_detour = %q, want vps", got)
	}
}
