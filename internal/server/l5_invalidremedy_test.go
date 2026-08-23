package server

import (
	"errors"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestInvalidProfileRemedy (L5): a blocked Apply must name a way out that exists.
//
// Measured on the demo profile: "group \"seed-grp-eu\": member \"seed-trojan-fi\" is disabled" blocked
// Apply for the WHOLE configuration, and the remedy read "Correct or disable the affected object".
// The object was already disabled - that being the entire problem - so the only action the sentence
// named was the one with no effect, while the two that work went unsaid.
//
// This class earns its own sentence because the store refuses to CREATE it: a valid profile cannot be
// edited into one. A profile that holds such a reference therefore arrived by restore or import, so
// the operator reading the block is not the person who switched anything off and has nothing to
// reason from.
func TestInvalidProfileRemedy(t *testing.T) {
	// The real error, from the real validator, not a hand-made stand-in.
	p := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "live", Name: "Live", Engine: model.EngineSingBox, Protocol: "vless",
				Server: "198.51.100.4", Port: 443, Enabled: true},
			{ID: "off", Name: "Off", Engine: model.EngineSingBox, Protocol: "vless",
				Server: "198.51.100.5", Port: 443, Enabled: false},
		},
		Groups: []model.Group{{ID: "g", Name: "G", Type: "fallback", Members: []string{"live", "off"}}},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("a group holding a disabled member must not validate")
	}
	var dre *model.DisabledRefError
	if !errors.As(err, &dre) {
		t.Fatalf("it must be the disabled-reference class, got %T: %v", err, err)
	}

	got := invalidProfileRemedy(err)
	// Both ways out must be named: the switch, and dropping the reference.
	if !strings.Contains(strings.ToLower(got), "switch it back on") {
		t.Errorf("the remedy must offer turning it back on: %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "out of the group") {
		t.Errorf("the remedy must offer removing the reference: %q", got)
	}
	// And the action that cannot help must not be the advice.
	if strings.Contains(got, "Correct or disable the affected object") {
		t.Errorf("telling the operator to disable an already-disabled object is the defect: %q", got)
	}

	// A draft that is merely unfinished keeps the general sentence - it is right for that case, and
	// the specific one would send the operator looking for a switch nobody flipped.
	draft := model.Profile{Groups: []model.Group{{ID: "g", Name: "G", Type: "fallback"}}}
	derr := draft.Validate()
	if derr == nil {
		t.Fatal("a group with no members must not validate")
	}
	if r := invalidProfileRemedy(derr); !strings.Contains(r, "Correct or disable the affected object") {
		t.Errorf("an unfinished draft keeps the general remedy, got %q", r)
	}
}
