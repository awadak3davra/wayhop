package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestMaterializeRefusesToRunAnEngineOnSomeoneElsesTunnel (L5): WayHop must never point a plugin
// engine at an interface the router owns.
//
// The plugin manager starts and stops a process and, for AmneziaWG, CREATES AND DELETES a kernel
// interface. An adopted tunnel is the operator's own — on the live Keenetic, nwg0/nwg1/nwg3/nwg4/nwg5
// are KeeneticOS tunnels WayHop merely routes through, stored with Owner=external precisely so no
// destructive native operation can touch them. Materialization gates on that, and nothing pinned the
// gate: the two ownership refusals in nativeplan have a test, this one had none, and it is the one
// whose failure would delete the operator's interface rather than refuse a plan.
func TestMaterializeRefusesToRunAnEngineOnSomeoneElsesTunnel(t *testing.T) {
	// An adopted tunnel that has somehow been pointed at the AmneziaWG engine: the exact shape the
	// gate exists for. Owner=external is what adoption writes (see vpndiscover.go).
	adopted := model.Endpoint{
		ID: "external-nwg3", Name: "Adopted (native)", Enabled: true,
		Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Owner:  model.OwnerExternal,
		Params: map[string]any{"interface": "nwg3"},
	}
	_, _, err := materialize(materializeInput{
		desired: DesiredSnapshot{Profile: model.Profile{Endpoints: []model.Endpoint{adopted}}},
	})
	if err == nil {
		t.Fatal("materialization must refuse to start an engine on a tunnel WayHop does not own")
	}
	stage, detail, _ := materializeFailure(err)
	if stage != "plugins" {
		t.Errorf("the refusal belongs to the plugin stage, got %q (%s)", stage, detail)
	}
	if !strings.Contains(detail, "not owned by WayHop") {
		t.Errorf("and must say why, got %q", detail)
	}

	// An unrecognised owner fails closed too: the gate is "WayHop owns this", not "this is not
	// external". A future ownership class nobody has taught this build about must not inherit
	// destructive authority by default.
	//
	// Asserted on the STAGE, not merely on "some error": materialization fails later anyway for an
	// endpoint with no server, so `err != nil` is satisfied by a failure that has nothing to do with
	// ownership. An earlier version checked only that, and the mutation replacing the gate with
	// `Owner == OwnerExternal` — which lets an unrecognised owner straight through — passed it.
	future := adopted
	future.Owner = model.Owner("future-owner")
	_, _, futureErr := materialize(materializeInput{
		desired: DesiredSnapshot{Profile: model.Profile{Endpoints: []model.Endpoint{future}}},
	})
	if futureErr == nil {
		t.Fatal("an owner this build does not recognise must also be refused")
	}
	if stage, detail, _ := materializeFailure(futureErr); stage != "plugins" || !strings.Contains(detail, "not owned by WayHop") {
		t.Errorf("and refused BY THE OWNERSHIP GATE, not by a later stage: %q / %q", stage, detail)
	}

	// The positive control: WayHop's own tunnel is exactly what the plugin engine is for, so the
	// gate must not stand in front of it. Without this, refusing everything would pass the above.
	mine := adopted
	mine.ID = "wayhop-awg"
	mine.Owner = model.OwnerWayHop
	if _, _, err := materialize(materializeInput{
		desired: DesiredSnapshot{Profile: model.Profile{Endpoints: []model.Endpoint{mine}}},
	}); err != nil {
		if stage, detail, _ := materializeFailure(err); stage == "plugins" && strings.Contains(detail, "not owned by WayHop") {
			t.Errorf("a tunnel WayHop owns must not be refused by the ownership gate: %v", err)
		}
	}
}
