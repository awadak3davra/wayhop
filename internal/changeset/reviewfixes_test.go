package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Regression guards for defects found by adversarial review of the change-set/undo work.

// #1/#10/#15 (HIGH): "Discard all" must revert only what the review REPORTED. Diff does not cover
// Profile.Rules/DeviceGroups/DNS, nor config fields outside the three reviewable settings — returning
// the baseline verbatim silently destroyed all of it.
func TestUndoAll_PreservesUnreviewedState(t *testing.T) {
	base := model.Profile{
		Endpoints: []model.Endpoint{ep("a", "A")},
		Rules:     []model.Rule{{ID: "old-rule"}},
	}
	desired := model.Profile{
		Endpoints:    []model.Endpoint{ep("a", "A-edited")},            // reviewed
		Rules:        []model.Rule{{ID: "old-rule"}, {ID: "new-rule"}}, // NOT diffed
		DeviceGroups: []model.DeviceGroup{{ID: "dg1", Name: "Kids"}},   // NOT diffed
		DNS:          &model.DNSSettings{Enabled: true},                // NOT diffed
	}
	baseCfg := config.Config{RoutingMode: "tun", Listen: ":8088"}
	desiredCfg := config.Config{RoutingMode: "hybrid", Listen: ":8443"} // only RoutingMode is reviewed

	gotP, gotC, err := Undo(base, desired, baseCfg, desiredCfg, UndoRequest{Scope: ScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	// Reviewed changes ARE reverted.
	if gotP.Endpoints[0].Name != "A" {
		t.Errorf("reviewed endpoint edit should revert, got %q", gotP.Endpoints[0].Name)
	}
	if gotC.RoutingMode != "tun" {
		t.Errorf("reviewed setting should revert, got %q", gotC.RoutingMode)
	}
	// Unreviewed state MUST survive.
	if len(gotP.Rules) != 2 {
		t.Errorf("Rules were never reviewed and must survive discard-all, got %d", len(gotP.Rules))
	}
	if len(gotP.DeviceGroups) != 1 {
		t.Errorf("DeviceGroups must survive discard-all, got %d", len(gotP.DeviceGroups))
	}
	if gotP.DNS == nil {
		t.Error("the DNS plane must survive discard-all")
	}
	if gotC.Listen != ":8443" {
		t.Errorf("an unreviewed config field must NOT be reverted (panel-lockout risk), got %q", gotC.Listen)
	}
}

// #2/#9/#17 (HIGH): all settings share the synthetic id "settings" but land in DIFFERENT subsystems,
// so undoing one subsystem must not drag the others back.
func TestUndoSubsystem_DoesNotOverRevertSettings(t *testing.T) {
	baseCfg := config.Config{RoutingMode: "tun", Offload: "off"}
	desiredCfg := config.Config{RoutingMode: "hybrid", Offload: "hw"}

	_, gotC, err := Undo(model.Profile{}, model.Profile{}, baseCfg, desiredCfg,
		UndoRequest{Scope: ScopeSubsystem, Subsystem: SubOffload})
	if err != nil {
		t.Fatal(err)
	}
	if gotC.Offload != "off" {
		t.Errorf("the offload subsystem should revert, got %q", gotC.Offload)
	}
	if gotC.RoutingMode != "hybrid" {
		t.Errorf("routing mode is a DIFFERENT subsystem and must be preserved, got %q", gotC.RoutingMode)
	}
}

// #4 (MEDIUM): adding or removing a list shifts absolute indices and fabricated "reordered" rows for
// untouched rules. Relative order must be used.
func TestDiff_NoPhantomReorderOnInsert(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "x"), rl("b", "B", "x")}}
	// Insert a new list FIRST; a and b keep their relative order and must not be reported as moved.
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("new", "New", "x"), rl("a", "A", "x"), rl("b", "B", "x")}}

	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	for _, c := range cs.Changes {
		if c.Action == ActionReordered {
			t.Errorf("inserting a list must not fabricate a reorder for %q: %+v", c.ID, c)
		}
	}
}

// A REAL reorder is still detected.
func TestDiff_RealReorderStillDetected(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "x"), rl("b", "B", "x")}}
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("b", "B", "x"), rl("a", "A", "x")}}
	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	var n int
	for _, c := range cs.Changes {
		if c.Action == ActionReordered {
			n++
		}
	}
	if n == 0 {
		t.Error("a genuine swap must still be reported as reordered")
	}
}

// #3 (HIGH): undoing a move must not reshuffle rules the user never touched.
func TestUndoRouting_DoesNotDisturbUntouchedRules(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "x"), rl("b", "B", "x"), rl("c", "C", "x")}}
	// User removed "a" AND moved "c" to the front.
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("c", "C", "x"), rl("b", "B", "x")}}

	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	// c returns after b (its baseline-relative spot); the removal of "a" stays pending.
	if order := routingIDs(got.RoutingLists); strings.Join(order, ",") != "b,c" {
		t.Errorf("undoing c's move should yield [b c] (a's removal stays pending), got %v", order)
	}
}

// #19 (MEDIUM): "Position" is emitted as a FIELD, so field-scope undo must handle it.
func TestUndoField_Position(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "x"), rl("b", "B", "x")}}
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("b", "B", "x"), rl("a", "A", "x")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "a", Field: "Position"})
	if err != nil {
		t.Fatalf("Position must be undoable at field scope: %v", err)
	}
	if routingIDs(got.RoutingLists)[0] != "a" {
		t.Errorf("a should return to the front, got %v", routingIDs(got.RoutingLists))
	}
}

// #5 (MEDIUM): group fields the differ emits must be undoable at field scope.
func TestUndoField_GroupFields(t *testing.T) {
	base := model.Profile{Groups: []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"a"}}}}
	desired := model.Profile{Groups: []model.Group{{ID: "g", Name: "G2", Type: model.GroupSelector, Members: []string{"a", "b"}}}}

	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "g", Field: "Members"})
	if err != nil {
		t.Fatalf("group Members must be undoable: %v", err)
	}
	if len(got.Groups[0].Members) != 1 {
		t.Errorf("members should revert, got %v", got.Groups[0].Members)
	}
	if got.Groups[0].Name != "G2" {
		t.Errorf("the unrelated Name edit must be preserved, got %q", got.Groups[0].Name)
	}
}

// #7/#8 (HIGH, security): a nested param (WireGuard "peers" carrying pre_shared_key) must never have
// its contents rendered — a top-level key check cannot see inside it.
func TestDiff_NestedParamNeverRendered(t *testing.T) {
	mk := func(psk string) model.Endpoint {
		return ep("w", "WG", func(e *model.Endpoint) {
			e.Params = map[string]any{"peers": []any{map[string]any{
				"public_key": "PUB=", "pre_shared_key": psk,
			}}}
		})
	}
	cs := Diff("", "", model.Profile{Endpoints: []model.Endpoint{mk("OLD-PSK-SECRET")}},
		model.Profile{Endpoints: []model.Endpoint{mk("NEW-PSK-SECRET")}}, config.Config{}, config.Config{})

	if cs.Count() == 0 {
		t.Fatal("a changed peers param should still be reported as a change")
	}
	for _, c := range cs.Changes {
		blob := c.Before + " " + c.After
		for _, leak := range []string{"OLD-PSK-SECRET", "NEW-PSK-SECRET"} {
			if strings.Contains(blob, leak) {
				t.Fatalf("nested secret leaked: %q in %+v", leak, c)
			}
		}
	}
}

// #20 (MEDIUM): an absent key and an explicitly-empty one are the same thing — reporting a change
// (and for a secret, the false "Set → Removed") was wrong.
func TestDiff_AbsentVsEmptyParamIsNotAChange(t *testing.T) {
	absent := ep("a", "A", func(e *model.Endpoint) { e.Params = map[string]any{} })
	empty := ep("a", "A", func(e *model.Endpoint) { e.Params = map[string]any{"password": ""} })

	cs := Diff("", "", model.Profile{Endpoints: []model.Endpoint{absent}},
		model.Profile{Endpoints: []model.Endpoint{empty}}, config.Config{}, config.Config{})
	for _, c := range cs.Changes {
		if strings.EqualFold(c.Field, "Password") {
			t.Errorf("absent vs empty must not be a change, got %+v", c)
		}
	}
}

// #6/#11/#18 (MEDIUM): the differ was blind to whole field families, so /api/changeset could report
// count:0 while an Apply genuinely rewrote the routing/DNS planes. Each family must now be visible.
func TestDiff_CoversPreviouslyBlindFamilies(t *testing.T) {
	cases := []struct {
		name          string
		base, desired model.Profile
		wantSubsystem Subsystem
	}{
		{
			name:          "Rules (per-device routing)",
			base:          model.Profile{Rules: []model.Rule{{ID: "r1", Outbound: "a"}}},
			desired:       model.Profile{Rules: []model.Rule{{ID: "r1", Outbound: "b"}}},
			wantSubsystem: SubDeviceRules,
		},
		{
			name:          "Rule added",
			base:          model.Profile{},
			desired:       model.Profile{Rules: []model.Rule{{ID: "r1", Outbound: "a"}}},
			wantSubsystem: SubDeviceRules,
		},
		{
			name:          "DeviceGroups",
			base:          model.Profile{DeviceGroups: []model.DeviceGroup{{ID: "g", Name: "Kids"}}},
			desired:       model.Profile{DeviceGroups: []model.DeviceGroup{{ID: "g", Name: "Kids", Members: []model.DeviceMember{{}}}}},
			wantSubsystem: SubDeviceRules,
		},
		{
			name:          "DNS plane enabled",
			base:          model.Profile{DNS: &model.DNSSettings{Enabled: false}},
			desired:       model.Profile{DNS: &model.DNSSettings{Enabled: true}},
			wantSubsystem: SubDNS,
		},
		{
			name:          "DNS plane added",
			base:          model.Profile{},
			desired:       model.Profile{DNS: &model.DNSSettings{Enabled: true}},
			wantSubsystem: SubDNS,
		},
		{
			name: "endpoint TLS settings",
			base: model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) {
				e.TLS = &model.TLS{Enabled: true, SNI: "old.example"}
			})}},
			desired: model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) {
				e.TLS = &model.TLS{Enabled: true, SNI: "new.example"}
			})}},
			wantSubsystem: SubConnections,
		},
		{
			name: "endpoint Transport",
			base: model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) {
				e.Transport = &model.Transport{Type: "ws"}
			})}},
			desired: model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) {
				e.Transport = &model.Transport{Type: "grpc"}
			})}},
			wantSubsystem: SubConnections,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs := Diff("", "", c.base, c.desired, config.Config{}, config.Config{})
			if cs.Count() == 0 {
				t.Fatalf("change is invisible to the review — Apply would change more than reported")
			}
			var ok bool
			for _, ch := range cs.Changes {
				if ch.Subsystem == c.wantSubsystem {
					ok = true
				}
			}
			if !ok {
				t.Errorf("expected a change in subsystem %q, got %+v", c.wantSubsystem, cs.Changes)
			}
		})
	}
}

// Reality/TLS credentials must not be rendered even though TLS is now diffed.
func TestDiff_TLSCredentialsNotRendered(t *testing.T) {
	mk := func(short string) model.Endpoint {
		return ep("a", "A", func(e *model.Endpoint) {
			e.TLS = &model.TLS{Enabled: true, Type: "reality", SNI: "x.example", PublicKey: "PUBKEY-DATA", ShortID: short}
		})
	}
	cs := Diff("", "", model.Profile{Endpoints: []model.Endpoint{mk("OLD-SHORTID")}},
		model.Profile{Endpoints: []model.Endpoint{mk("NEW-SHORTID")}}, config.Config{}, config.Config{})
	for _, c := range cs.Changes {
		blob := c.Before + " " + c.After
		for _, leak := range []string{"OLD-SHORTID", "NEW-SHORTID", "PUBKEY-DATA"} {
			if strings.Contains(blob, leak) {
				t.Errorf("TLS credential leaked into the diff: %q in %+v", leak, c)
			}
		}
	}
}
