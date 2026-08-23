package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestInvalidProfileNamesTheObjectAndARealWayOut (L5): a blocking finding must name the object that
// has to change and an action that exists.
//
// Measured on the demo profile. The review said:
//
//	The configuration is invalid
//	rule "st-rule-6": outbound "st-grp-0" does not resolve
//	How to fix: Correct or disable the affected object, then review again.
//	Items: profile
//
// Two faults in four lines. "Items: profile" points at the whole configuration when exactly one
// object is at fault — and there were TWO such rules, st-rule-6 and st-rule-12, both pointing at a
// group that is not in the profile. And "correct or disable the affected object" names an action the
// panel cannot perform: state.profile.rules is read in five places (dashboard verdict, tunnelled
// count, failover chain, DNS detour guess) and rendered as an editable row in none, so neither rule
// appears in the DOM on any page. The operator is told to fix something no page can touch.
func TestInvalidProfileNamesTheObjectAndARealWayOut(t *testing.T) {
	// A rule whose outbound is a group that does not exist — the measured shape.
	profile := model.Profile{
		Endpoints: []model.Endpoint{{ID: "ep", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "nwg0"}}},
		Rules:     []model.Rule{{ID: "st-rule-6", Outbound: "st-grp-0", Domain: []string{"example.com"}}},
	}
	err := profile.Validate()
	if err == nil {
		t.Fatal("a rule pointing at a group that is not in the profile must not validate")
	}
	// The message an operator reads is unchanged — only its Go type gained structure.
	if !strings.Contains(err.Error(), `rule "st-rule-6": outbound "st-grp-0" does not resolve`) {
		t.Fatalf("the wording must not move: %q", err.Error())
	}

	item := invalidProfileItem(err)
	if !strings.Contains(item, "st-rule-6") {
		t.Errorf("the finding must name the one object at fault, got %q", item)
	}
	if item == "profile" || item == "" {
		t.Errorf("naming the whole configuration is what this replaces, got %q", item)
	}

	remedy := invalidProfileRemedy(err)
	if strings.Contains(remedy, "Correct or disable the affected object") {
		t.Errorf("a rule cannot be corrected or disabled from any page — that remedy is the defect: %q", remedy)
	}
	// The sentence names what is MISSING — that is the half the operator has to decide about (bring
	// it back, or drop the rule). Which rule to remove is carried by the action below, not repeated
	// here, so the id is asserted against the structure rather than against prose.
	if !strings.Contains(remedy, "st-grp-0") {
		t.Errorf("the way out must name the missing target: %q", remedy)
	}
	// The assertions that actually pin the rule case. An earlier version of this test checked only
	// "not the generic sentence" plus "names both ids" — which the ordinary unresolved-reference
	// wording also satisfies, so a mutation that sent rules down the ordinary branch passed.
	//
	// The distinguishing fact is that a rule cannot be repointed from any page. This gate first
	// required the remedy to name DELETE /api/rules/<id>, because prose was then the only way out.
	// It no longer is: the finding carries the action structurally and the review renders a button,
	// so the pin moved from the sentence to the STRUCTURE — a string can be reworded, an action
	// cannot be faked. The remedy is still forbidden from proposing a screen that does not exist.
	if strings.Contains(remedy, "Point it at an exit") {
		t.Errorf("that instruction is a panel action, and rules have no page: %q", remedy)
	}
	fix := invalidProfileFix(err)
	if fix == nil || fix.Action != "delete_rule" || fix.ID != "st-rule-6" {
		t.Fatalf("the one class with no page must carry its action, got %+v", fix)
	}

	// A routing list holds the same class of break, but the panel DOES have a row for it, so the
	// remedy must stay about the panel rather than about an API call.
	listProfile := model.Profile{
		Endpoints:    []model.Endpoint{{ID: "ep", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "nwg0"}}},
		Rules:        []model.Rule{{ID: "default", Default: true, Outbound: "direct"}},
		RoutingLists: []model.RoutingList{{ID: "rl-1", Enabled: true, Outbound: "gone", Manual: []string{"1.2.3.4"}}},
	}
	rlErr := listProfile.Validate()
	if rlErr == nil {
		t.Fatal("a routing list pointing at a missing outbound must not validate")
	}
	rlRemedy := invalidProfileRemedy(rlErr)
	if strings.Contains(rlRemedy, "/api/") {
		t.Errorf("a routing list is editable in the panel — do not send its owner to the API: %q", rlRemedy)
	}
	if !strings.Contains(rlRemedy, "rl-1") || !strings.Contains(rlRemedy, "gone") {
		t.Errorf("and it must still name the object and what it points at: %q", rlRemedy)
	}
	// And it must NOT get the button: a routing list has its own page, and an action here would pull
	// the operator away from the screen where the object lives and everything around it can be seen.
	if f := invalidProfileFix(rlErr); f != nil {
		t.Errorf("only the kind with no page gets an action, got %+v", f)
	}

	// The neighbouring class must keep its own remedy: a reference to something switched OFF is a
	// different fix, and collapsing the two is what this whole branch exists to avoid.
	offProfile := model.Profile{
		Endpoints: []model.Endpoint{{ID: "ep", Enabled: false, Engine: model.EngineExternal, Params: map[string]any{"interface": "nwg0"}}},
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "ep"}},
	}
	offErr := offProfile.Validate()
	if offErr == nil {
		// Asserted rather than skipped: a fixture that quietly starts validating would turn the check
		// below into no check at all, which is the failure mode these gates keep producing.
		t.Fatal("a live reference to a switched-off endpoint must not validate")
	}
	if r := invalidProfileRemedy(offErr); !strings.Contains(r, "switch it back on") {
		t.Errorf("the disabled-reference class must keep its own way out: %q", r)
	}
	// And it names its object, like the other class. Measured once several problems were listed
	// together: twelve entries named a routing list and the first read "profile", the whole
	// configuration, only because that one was the switched-off class.
	if item := invalidProfileItem(offErr); !strings.Contains(item, "default") || item == "profile" {
		t.Errorf("a switched-off reference must name the object holding it, got %q", item)
	}
}
