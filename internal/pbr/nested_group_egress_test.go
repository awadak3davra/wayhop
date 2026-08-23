package pbr

import (
	"testing"

	"wayhop/internal/model"
)

// TestResolveEgressNestedGroup: resolveEgress must DESCEND into nested groups when picking the
// kernel primary. With G = {G2(={e_primary}), e_kernel}, the preferred member is e_primary (reached
// only through the nested group G2); without recursion resolveEgress skipped G2 and wrongly elected
// the later direct member e_kernel, or — for an all-nested group — dropped the list from routing.
func TestResolveEgressNestedGroup(t *testing.T) {
	mk := func(members []string) *model.Profile {
		return &model.Profile{
			Endpoints: []model.Endpoint{
				{ID: "e_primary", Engine: model.EngineExternal, Server: "1.1.1.1", Enabled: true, Params: map[string]any{"interface": "awg_pri"}},
				{ID: "e_kernel", Engine: model.EngineExternal, Server: "2.2.2.2", Enabled: true, Params: map[string]any{"interface": "awg_ker"}},
			},
			Groups: []model.Group{
				{ID: "g2", Name: "G2", Type: model.GroupSelector, Members: []string{"e_primary"}},
				{ID: "g", Name: "G", Type: model.GroupSelector, Members: members},
			},
			RoutingLists: []model.RoutingList{{ID: "l", Name: "L", Manual: []string{"8.8.8.0/24"}, Outbound: "g", Enabled: true}},
		}
	}
	ifaceOf := func(p *model.Profile) string {
		plan, _, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		for _, eg := range plan.Egresses {
			if eg.Tag == "g" {
				return eg.Iface
			}
		}
		return ""
	}

	// Nested group FIRST in preference order → its member must win over the later direct member.
	if got := ifaceOf(mk([]string{"g2", "e_kernel"})); got != "awg_pri" {
		t.Errorf("nested-group member must be the kernel primary: got %q, want awg_pri", got)
	}
	// All-nested group → still resolves through the nested group (was dropped entirely before).
	if got := ifaceOf(mk([]string{"g2"})); got != "awg_pri" {
		t.Errorf("all-nested group must still resolve to awg_pri, got %q", got)
	}
}
