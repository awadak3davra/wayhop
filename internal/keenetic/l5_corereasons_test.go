package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCoreReasonsAgreeWithPlanRequiresCore (L5): the sentence the panel prints must be the branch
// Apply takes. A reasons list derived from a second walk would drift from the decision the first
// time either changed, and the operator would read a confident explanation of the wrong thing.
func TestCoreReasonsAgreeWithPlanRequiresCore(t *testing.T) {
	native := model.Endpoint{ID: "n", Name: "Native", Enabled: true, Engine: model.EngineExternal, Owner: model.OwnerExternal,
		Params: map[string]any{"interface": "nwg0"}}
	proxy := model.Endpoint{ID: "p", Name: "Proxy", Enabled: true, Engine: model.EngineSingBox,
		Protocol: "vless", Server: "198.51.100.4", Port: 443}
	plainDefault := model.Rule{ID: "d", Default: true, Outbound: model.OutboundDirect}

	cases := []struct {
		name string
		p    model.Profile
		want bool
	}{
		{"native only", model.Profile{Endpoints: []model.Endpoint{native}, Rules: []model.Rule{plainDefault}}, false},
		{"a proxy connection", model.Profile{Endpoints: []model.Endpoint{native, proxy}, Rules: []model.Rule{plainDefault}}, true},
		{"encrypted DNS", model.Profile{Endpoints: []model.Endpoint{native}, Rules: []model.Rule{plainDefault},
			DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{{Tag: "doh", Type: "https", Enabled: true}}}}, true},
		{"a scoped list", model.Profile{Endpoints: []model.Endpoint{native}, Rules: []model.Rule{plainDefault},
			RoutingLists: []model.RoutingList{{ID: "l", Enabled: true, Outbound: "n", ScopeMode: "only"}}}, true},
	}
	for _, c := range cases {
		reasons := CoreReasons(&c.p, true)
		if got := PlanRequiresCore(&c.p, true); got != c.want {
			t.Errorf("%s: PlanRequiresCore=%v want %v", c.name, got, c.want)
		}
		if (len(reasons) > 0) != c.want {
			t.Errorf("%s: reasons %v disagree with the decision (want required=%v)", c.name, reasons, c.want)
		}
	}
}

// TestCoreReasonsNameTheObject (L5): "the profile is not native-only" is a fact; "routing list X is
// scoped to specific devices" is a next step. Measured on a live Keenetic, where everything
// but the DNS plane is native and the panel never said which one thing was keeping the core alive.
func TestCoreReasonsNameTheObject(t *testing.T) {
	p := model.Profile{
		Endpoints: []model.Endpoint{{ID: "n", Name: "Native", Enabled: true, Engine: model.EngineExternal, Owner: model.OwnerExternal,
			Params: map[string]any{"interface": "nwg0"}}},
		Rules:        []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{{ID: "work-tools", Enabled: true, Outbound: "n", ScopeMode: "only"}},
		DNS: &model.DNSSettings{Enabled: true,
			Servers: []model.DNSServer{{Tag: "doh", Type: "https", Enabled: true}}},
	}
	reasons := CoreReasons(&p, true)
	if len(reasons) < 2 {
		t.Fatalf("both the DNS plane and the scoped list must be listed, got %v", reasons)
	}
	joined := strings.Join(reasons, "; ")
	if !strings.Contains(joined, "work-tools") {
		t.Errorf("the list is named, not merely counted: %q", joined)
	}
	// Tightened when the DNS reason stopped reciting the four things that COULD require the core and
	// started naming the one that does: the assertion moved with it, from the generic phrase to the
	// resolver tag, because the tag is the part the operator can act on.
	if !strings.Contains(joined, `"doh"`) {
		t.Errorf("the resolver that requires the core is named, not the category: %q", joined)
	}
	if strings.Contains(joined, "an encrypted resolver, a fakeip plane") {
		t.Errorf("a list of what it might have been is not an answer: %q", joined)
	}
}
