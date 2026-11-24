package server

import (
	"slices"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func scopedProf() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "nl", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}},
			{ID: "de", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.2", Params: map[string]any{"interface": "nwg2"}},
		},
		Groups:       []model.Group{{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl"}, KillSwitch: true}},
		DeviceGroups: []model.DeviceGroup{{ID: "g", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:01"}}}},
	}
}

func findingsBySetting(us []platform.Unsupported) map[string]platform.Unsupported {
	m := map[string]platform.Unsupported{}
	for _, u := range us {
		m[u.Setting] = u
	}
	return m
}

// A routing rule with a source matcher into a kill-switched group has no backstop either
// (it is scoped to some devices), and was dropped silently by the list-only zone mapping.
func TestKillSwitchScopedRuleIsRefused(t *testing.T) {
	for _, r := range []model.Rule{
		{ID: "tv", Outbound: "grp", SourceMAC: []string{"aa:bb:cc:dd:ee:01"}, IPCIDR: []string{"198.51.100.0/24"}},
		{ID: "tv", Outbound: "grp", SourceIPCIDR: []string{"192.168.1.20/32"}}, // source only: every destination
	} {
		prof := scopedProf()
		prof.Rules = []model.Rule{r}
		got := findingsBySetting(keeneticKillSwitchPreflight(config.Config{}, prof, true))
		f, ok := got[findingBackstopScoped+":rule_tv"]
		if !ok || f.Severity != platform.SeverityBlocked || !strings.Contains(f.Reason, "rule") {
			t.Fatalf("rule %+v: findings %v", r, got)
		}
		if _, ok := got[findingKillSwitchNeedsOpt]; !ok {
			t.Fatalf("no /opt finding for a scoped rule: %v", got)
		}
		for _, ef := range evaluatePlanFindings(platform.CapabilitySet{}, keeneticKillSwitchPreflight(config.Config{}, prof, true)) {
			if ef.ID == findingBackstopScoped && (ef.Blocks != platform.BlocksApply || ef.Item != "rule_tv") {
				t.Fatalf("evaluated: %+v", ef)
			}
		}
	}
	// A destination-only rule into the same group is backstopped like a list: not refused.
	prof := scopedProf()
	prof.Rules = []model.Rule{{ID: "dst", Outbound: "grp", IPCIDR: []string{"198.51.100.0/24"}}}
	for s := range findingsBySetting(keeneticKillSwitchPreflight(config.Config{}, prof, true)) {
		if strings.HasPrefix(s, findingBackstopScoped) {
			t.Fatalf("a destination-only rule refused: %s", s)
		}
	}
}

// Zones map back to the item they came from, not by name prefix: list "x" is not named
// for a zone of list "x_dns".
func TestKillSwitchScopedZoneMapsToItsOwnList(t *testing.T) {
	prof := scopedProf()
	prof.RoutingLists = []model.RoutingList{
		{ID: "x", Enabled: true, Outbound: "grp", Manual: []string{"198.18.0.0/24"}},
		{ID: "x_dns", Enabled: true, Outbound: "grp", Manual: []string{"198.18.1.0/24"}, ScopeMode: "only", ScopeGroups: []string{"g"}},
	}
	var scoped []string
	for _, f := range keeneticKillSwitchPreflight(config.Config{}, prof, true) {
		if strings.HasPrefix(f.Setting, findingBackstopScoped+":") {
			scoped = append(scoped, f.Setting)
		}
	}
	if !slices.Equal(scoped, []string{findingBackstopScoped + ":x_dns"}) {
		t.Fatalf("scoped findings = %v", scoped)
	}
}

// A device-scoped list that fails closed by its own "block" with no kill switch anywhere
// is refused for that cause, and not sent to a kill switch that is off.
func TestScopedBlockListNamesItsCause(t *testing.T) {
	prof := scopedProf()
	prof.Groups[0].KillSwitch = false
	prof.RoutingLists = []model.RoutingList{{ID: "kids", Enabled: true, Outbound: "nl", Candidates: []string{"nl", "de"},
		Manual: []string{"198.18.0.0/24"}, ScopeMode: "only", ScopeGroups: []string{"g"},
		Fastest: &model.FastestPolicy{Enabled: true, OnAllDown: model.OnAllDownBlock}}}
	f, ok := findingsBySetting(keeneticKillSwitchPreflight(config.Config{}, prof, true))[findingBackstopScoped+":kids"]
	if !ok || f.Severity != platform.SeverityBlocked {
		t.Fatalf("not refused: %+v", f)
	}
	if strings.Contains(f.Reason, "kill switch") || strings.Contains(f.Remedy, "kill switch") || !strings.Contains(f.Reason, "block when all tunnels are down") {
		t.Fatalf("cause: %s | %s", f.Reason, f.Remedy)
	}
	prof.Groups[0].KillSwitch = true
	prof.RoutingLists[0].Outbound, prof.RoutingLists[0].Candidates, prof.RoutingLists[0].Fastest = "grp", nil, nil
	f = findingsBySetting(keeneticKillSwitchPreflight(config.Config{}, prof, true))[findingBackstopScoped+":kids"]
	if !strings.Contains(f.Reason, "kill switch") || !strings.Contains(f.Remedy, "kill switch off") {
		t.Fatalf("kill switch cause: %s | %s", f.Reason, f.Remedy)
	}
}
