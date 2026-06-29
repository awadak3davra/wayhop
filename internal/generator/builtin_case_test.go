package generator

import (
	"testing"

	"velinx/internal/model"
)

// #2: a rule outbound in non-canonical case ("Block"/"Direct") must still produce
// a valid config — "Block" -> reject action, "Direct" -> the canonical lowercase
// "direct" tag — not a dangling reference that sing-box would reject.
func TestRouteCaseInsensitiveBuiltins(t *testing.T) {
	vless := generator_singBoxEndpoint("e", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{vless},
		Rules: []model.Rule{
			{ID: "r1", Domain: []string{"a.com"}, Outbound: "Block"},
			{ID: "r2", Domain: []string{"b.com"}, Outbound: "Direct"},
			{ID: "d", Default: true, Outbound: vless.ID},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	rules := res.Config["route"].(map[string]any)["rules"].([]map[string]any)
	if rules[0]["action"] != "reject" {
		t.Fatalf(`"Block" rule -> action %v, want reject`, rules[0]["action"])
	}
	if rules[1]["action"] != "route" || rules[1]["outbound"] != "direct" {
		t.Fatalf(`"Direct" rule -> %v / %v, want route / "direct"`, rules[1]["action"], rules[1]["outbound"])
	}
}
