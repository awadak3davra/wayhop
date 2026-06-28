package generator

import (
	"testing"

	"wakeroute/internal/model"
)

// TestCacheFileForGroups: a profile with a selector/urltest group enables cache_file even when there
// are no routing lists, so sing-box persists the chosen exit across an Apply/reboot. It must NOT emit
// the removed `store_selected` field — sing-box 1.12.x rejects it as unknown, which would take all
// routing down on apply (verified on-device). With neither groups nor lists, cache_file stays absent.
func TestCacheFileForGroups(t *testing.T) {
	a := generator_singBoxEndpoint("a", model.ProtoVLESS, map[string]any{"uuid": "u"})
	b := generator_singBoxEndpoint("b", model.ProtoVLESS, map[string]any{"uuid": "u"})

	res, err := Generate(&model.Profile{
		Endpoints: []model.Endpoint{a, b},
		Groups:    []model.Group{{ID: "g", Name: "G", Type: model.GroupSelector, Members: []string{"a", "b"}}},
	}, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	exp, _ := res.Config["experimental"].(map[string]any)
	cf, ok := exp["cache_file"].(map[string]any)
	if !ok || cf["enabled"] != true {
		t.Fatalf("group profile must enable cache_file, got experimental=%v", exp)
	}
	// Regression guard: store_selected was removed in modern sing-box and bricks 1.12.x.
	if _, bad := cf["store_selected"]; bad {
		t.Error("must NOT emit cache_file.store_selected — sing-box 1.12.x rejects it (config-bricking)")
	}

	// No groups, no lists -> no cache_file.
	res2, err := Generate(&model.Profile{Endpoints: []model.Endpoint{a}}, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate (no groups): %v", err)
	}
	exp2, _ := res2.Config["experimental"].(map[string]any)
	if _, ok := exp2["cache_file"]; ok {
		t.Errorf("no groups + no lists must NOT enable cache_file, got experimental=%v", exp2)
	}
}
