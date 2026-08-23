package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

func rl(id, name, outbound string) model.RoutingList {
	return model.RoutingList{ID: id, Name: name, Outbound: outbound, Enabled: true}
}

// changeCount is the number of pending changes between two states — the property every undo must
// reduce, and which proves the underlying DATA changed (not just a hidden UI row).
func changeCount(base, desired model.Profile, bc, dc config.Config) int {
	return Diff("", "", base, desired, bc, dc).Count()
}

// §1.5: undo ONE field while PRESERVING the object's other pending edits.
func TestUndo_FieldPreservesOtherEdits(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "Renamed", func(e *model.Endpoint) {
		e.Port = 8443
	})}}
	if got := changeCount(base, desired, config.Config{}, config.Config{}); got != 2 {
		t.Fatalf("setup: want 2 pending changes (Name, Port), got %d", got)
	}

	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "a", Field: "Port"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints[0].Port != 443 {
		t.Errorf("Port should be reverted to 443, got %d", got.Endpoints[0].Port)
	}
	if got.Endpoints[0].Name != "Renamed" {
		t.Errorf("the unrelated Name edit must be PRESERVED, got %q", got.Endpoints[0].Name)
	}
	if n := changeCount(base, got, config.Config{}, config.Config{}); n != 1 {
		t.Errorf("one change should remain after a field undo, got %d", n)
	}
}

// §1.5: undoing a secret field reverts the real value (without the diff ever exposing it).
func TestUndo_SecretField(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A")}} // password: SUPERSECRET
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) {
		e.Params = map[string]any{"password": "NEW"}
	})}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "a", Field: "Password"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints[0].Params["password"] != "SUPERSECRET" {
		t.Errorf("secret not reverted: %v", got.Endpoints[0].Params["password"])
	}
	if changeCount(base, got, config.Config{}, config.Config{}) != 0 {
		t.Error("undoing the only change should leave no pending changes")
	}
}

// §1.5: remove a newly ADDED object.
func TestUndo_RemovesAddedObject(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "A"), ep("b", "B")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].ID != "a" {
		t.Errorf("added endpoint should be dropped, got %+v", got.Endpoints)
	}
}

// §1.5: RESTORE a removed object, at its baseline position.
func TestUndo_RestoresRemovedObject(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A"), ep("b", "B"), ep("c", "C")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "A"), ep("c", "C")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 3 || got.Endpoints[1].ID != "b" {
		t.Errorf("removed endpoint should be restored at position 1, got %+v", ids(got.Endpoints))
	}
	if changeCount(base, got, config.Config{}, config.Config{}) != 0 {
		t.Error("restoring the only removal should clear all pending changes")
	}
}

// §1.5: undo a REORDER — the rule returns to its baseline position.
func TestUndo_Reorder(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "x"), rl("b", "B", "x"), rl("c", "C", "x")}}
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("c", "C", "x"), rl("a", "A", "x"), rl("b", "B", "x")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if got.RoutingLists[2].ID != "c" {
		t.Errorf("c should return to position 2, got order %v", routingIDs(got.RoutingLists))
	}
	if changeCount(base, got, config.Config{}, config.Config{}) != 0 {
		t.Errorf("order should match baseline again, got %v", routingIDs(got.RoutingLists))
	}
}

// §1.5: undo a whole SUBSYSTEM, leaving other subsystems' changes intact.
func TestUndo_SubsystemPreservesOthers(t *testing.T) {
	base := model.Profile{
		Endpoints:    []model.Endpoint{ep("a", "A")},
		RoutingLists: []model.RoutingList{rl("r1", "R1", "a"), rl("r2", "R2", "a")},
	}
	desired := model.Profile{
		Endpoints:    []model.Endpoint{ep("a", "A-edited")},                                // connections
		RoutingLists: []model.RoutingList{rl("r1", "R1-edited", "a"), rl("r2", "R2", "a")}, // routing
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeSubsystem, Subsystem: SubRouting})
	if err != nil {
		t.Fatal(err)
	}
	if got.RoutingLists[0].Name != "R1" {
		t.Errorf("routing change should be reverted, got %q", got.RoutingLists[0].Name)
	}
	if got.Endpoints[0].Name != "A-edited" {
		t.Errorf("the connections change must be PRESERVED, got %q", got.Endpoints[0].Name)
	}
	cs := Diff("", "", base, got, config.Config{}, config.Config{})
	for _, c := range cs.Changes {
		if c.Subsystem == SubRouting {
			t.Errorf("no routing changes should remain, got %+v", c)
		}
	}
}

// §1.5: discard ALL pending changes restores the complete baseline.
func TestUndo_All(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "A2"), ep("b", "B")}}
	bc := config.Config{RoutingMode: "tun"}
	dc := config.Config{RoutingMode: "hybrid", Offload: "hw"}

	gotP, gotC, err := Undo(base, desired, bc, dc, UndoRequest{Scope: ScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	if changeCount(base, gotP, bc, gotC) != 0 {
		t.Error("discard-all must leave zero pending changes")
	}
	if gotC.RoutingMode != "tun" || gotC.Offload != "" {
		t.Errorf("config not restored to baseline: %+v", gotC)
	}
}

// Settings undo at field level touches ONLY that setting.
func TestUndo_SettingField(t *testing.T) {
	bc := config.Config{RoutingMode: "tun", Offload: "off"}
	dc := config.Config{RoutingMode: "hybrid", Offload: "hw"}
	_, gotC, err := Undo(model.Profile{}, model.Profile{}, bc, dc, UndoRequest{Scope: ScopeField, ID: "settings", Field: "Flow offload"})
	if err != nil {
		t.Fatal(err)
	}
	if gotC.Offload != "off" {
		t.Errorf("offload should revert, got %q", gotC.Offload)
	}
	if gotC.RoutingMode != "hybrid" {
		t.Errorf("the unrelated routing-mode edit must be preserved, got %q", gotC.RoutingMode)
	}
}

// An undo that matches nothing must ERROR, never silently claim success (§1.5: the pending count and
// state must stay truthful).
func TestUndo_UnknownTargetsError(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A")}}
	same := base
	for _, req := range []UndoRequest{
		{Scope: ScopeObject, ID: "nope"},
		{Scope: ScopeField, ID: "a", Field: "NoSuchField"},
		{Scope: ScopeField, ID: "a"},               // missing field
		{Scope: ScopeObject},                       // missing id
		{Scope: ScopeSubsystem},                    // missing subsystem
		{Scope: ScopeSubsystem, Subsystem: SubDNS}, // no changes there
		{Scope: "bogus"},
	} {
		if _, _, err := Undo(base, same, config.Config{}, config.Config{}, req); err == nil {
			t.Errorf("expected an error for %+v", req)
		}
	}
}

func ids(es []model.Endpoint) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func routingIDs(rs []model.RoutingList) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}
