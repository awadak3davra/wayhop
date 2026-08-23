package model

import (
	"strings"
	"testing"
)

// TestCollectRefProblemsEnumeratesAll (L5): the review must be able to say how much is broken.
//
// Validate stops at the first failure, which is correct for a gate and wrong for a review: the panel
// named one object, the operator fixed it, re-reviewed, and met the next. Measured on the demo
// profile — st-rule-6 and st-rule-12 both point at "st-grp-0", which is not in the profile, and
// st-rule-7 points at a disabled endpoint. Three round trips, and no count anywhere.
func TestCollectRefProblemsEnumeratesAll(t *testing.T) {
	p := Profile{
		Endpoints: []Endpoint{
			{ID: "up", Enabled: true, Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}},
			{ID: "off", Enabled: false, Engine: EngineExternal, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []Rule{
			{ID: "r-missing-1", Outbound: "gone", Domain: []string{"a.example"}},
			{ID: "r-off", Outbound: "off", Domain: []string{"b.example"}},
			{ID: "r-missing-2", Outbound: "gone", Domain: []string{"c.example"}},
		},
	}
	got := CollectRefProblems(p)
	if len(got) != 3 {
		t.Fatalf("every broken reference must be listed, got %d: %+v", len(got), got)
	}
	byID := map[string]RefProblem{}
	for _, rp := range got {
		byID[rp.ID] = rp
	}
	for _, id := range []string{"r-missing-1", "r-off", "r-missing-2"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s is broken and must be reported: %+v", id, got)
		}
	}
	// The two classes stay apart: they have different remedies, and merging them would put "switch it
	// back on" in front of an operator whose target does not exist.
	if !byID["r-missing-1"].Missing || byID["r-missing-1"].Target != "gone" {
		t.Errorf("a target that is not in the profile is Missing: %+v", byID["r-missing-1"])
	}
	if byID["r-off"].Missing || byID["r-off"].Target != "off" {
		t.Errorf("a target that is switched off is not Missing: %+v", byID["r-off"])
	}

	// The caller's profile must come back untouched — this function looks, it does not edit.
	if p.Rules[0].Outbound != "gone" || p.Rules[1].Outbound != "off" {
		t.Errorf("the scan rewrote the caller's profile: %+v", p.Rules)
	}
}

// TestCollectRefProblemsStopsAtAnotherKind (L5): a fault that is not a reference has its own remedy,
// and counting past it would report a profile as more broken in one way than it is.
func TestCollectRefProblemsStopsAtAnotherKind(t *testing.T) {
	p := Profile{
		Endpoints: []Endpoint{{ID: "up", Enabled: true, Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}}},
		Rules: []Rule{
			{ID: "r-missing", Outbound: "gone", Domain: []string{"a.example"}},
			{ID: "r-nomatch", Outbound: "up"}, // no match condition — a different class entirely
		},
	}
	got := CollectRefProblems(p)
	if len(got) != 1 || got[0].ID != "r-missing" {
		t.Fatalf("the reference problem is reported and the scan then stops: %+v", got)
	}

	// A profile whose FIRST fault is not a reference yields nothing, so the caller keeps its
	// single-error path rather than reporting an empty list as "nothing wrong".
	onlyOther := Profile{
		Endpoints: []Endpoint{{ID: "up", Enabled: true, Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}}},
		Rules:     []Rule{{ID: "r-nomatch", Outbound: "up"}},
	}
	if got := CollectRefProblems(onlyOther); len(got) != 0 {
		t.Errorf("a non-reference fault is not a reference problem: %+v", got)
	}

	// A valid profile yields nothing at all, which is the ordinary case and must not loop.
	fine := Profile{
		Endpoints: []Endpoint{{ID: "up", Enabled: true, Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}}},
		Rules:     []Rule{{ID: "default", Default: true, Outbound: "up"}},
	}
	if got := CollectRefProblems(fine); len(got) != 0 {
		t.Errorf("a valid profile has no problems: %+v", got)
	}
}

// TestCollectRefProblemsCoversGroupsAndLists (L5): every object kind that can hold a reference.
func TestCollectRefProblemsCoversGroupsAndLists(t *testing.T) {
	p := Profile{
		Endpoints:    []Endpoint{{ID: "up", Enabled: true, Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}}},
		Groups:       []Group{{ID: "g", Type: "fallback", Members: []string{"up", "ghost"}}},
		RoutingLists: []RoutingList{{ID: "rl", Enabled: true, Outbound: "nowhere", Manual: []string{"203.0.113.0/24"}}},
		Rules:        []Rule{{ID: "default", Default: true, Outbound: "up"}},
	}
	got := CollectRefProblems(p)
	kinds := map[string]string{}
	for _, rp := range got {
		kinds[rp.Kind] = rp.Target
	}
	if kinds["group"] != "ghost" {
		t.Errorf("a group member that does not resolve must be reported: %+v", got)
	}
	if kinds["routing list"] != "nowhere" {
		t.Errorf("a routing list outbound that does not resolve must be reported: %+v", got)
	}
	// The bound exists and is not a silent truncation of a normal profile.
	if len(got) > MaxRefProblems {
		t.Errorf("the scan must stay within its bound: %d", len(got))
	}
	for _, rp := range got {
		if !strings.Contains(rp.Message, rp.ID) {
			t.Errorf("each problem carries the sentence naming its object: %+v", rp)
		}
	}
}
