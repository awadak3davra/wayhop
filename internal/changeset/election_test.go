package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

func TestGroupElectionModeDiffAndUndo(t *testing.T) {
	base := model.Profile{Groups: []model.Group{{
		ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"a"},
	}}}
	desired := model.Profile{Groups: []model.Group{{
		ID: "g", Name: "G", Type: model.GroupURLTest, ElectionMode: model.ElectionMixed, Members: []string{"a"},
	}}}
	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	if cs.Count() != 1 {
		t.Fatalf("election-only edit produced %+v", cs.Changes)
	}
	ch := find(t, cs, "g", "Election mode")
	if ch.Before != "latency" || ch.After != "mixed" {
		t.Fatalf("election row = %q -> %q", ch.Before, ch.After)
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{
		Scope: ScopeField, ID: "g", ObjectType: "group", Field: "Election mode",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Groups[0].ElectionMode != "" {
		t.Fatalf("undo left election mode %q", got.Groups[0].ElectionMode)
	}
	if left := Diff("", "", base, got, config.Config{}, config.Config{}); left.Count() != 0 {
		t.Fatalf("election undo left rows: %+v", left.Changes)
	}

	// Empty and explicit latency have the same effective group policy and make no review noise.
	desired.Groups[0].ElectionMode = model.ElectionLatency
	if cs := Diff("", "", base, desired, config.Config{}, config.Config{}); cs.Count() != 0 {
		t.Fatalf("empty vs explicit latency produced noise: %+v", cs.Changes)
	}
}

func TestFastestElectionModeWordDiffAndUndo(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{{
		ID: "media", Name: "Media", Outbound: "a", Enabled: true,
		Fastest: &model.FastestPolicy{Enabled: true},
	}}}
	desired := model.Profile{RoutingLists: []model.RoutingList{{
		ID: "media", Name: "Media", Outbound: "a", Enabled: true,
		Fastest: &model.FastestPolicy{Enabled: true, Mode: model.ElectionMixed},
	}}}
	// FastestWord has no RoutingList context: an unset mode is named as the list's own default.
	if got := FastestWord(base.RoutingLists[0].Fastest); !strings.Contains(got, "mode auto") {
		t.Fatalf("empty fastest mode missing from review word: %q", got)
	}
	if got := FastestWord(desired.RoutingLists[0].Fastest); !strings.Contains(got, "mode mixed") {
		t.Fatalf("raw fastest mode missing from review word: %q", got)
	}
	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	if cs.Count() != 1 {
		t.Fatalf("fastest-mode-only edit produced %+v", cs.Changes)
	}
	ch := find(t, cs, "media", "Fastest tunnel")
	if !strings.Contains(ch.After, "mode mixed") {
		t.Fatalf("fastest review row does not show mode: %+v", ch)
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{
		Scope: ScopeField, ID: "media", ObjectType: "routing_list", Field: "Fastest tunnel",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.RoutingLists[0].Fastest == nil || got.RoutingLists[0].Fastest.Mode != "" {
		t.Fatalf("fastest mode undo failed: %+v", got.RoutingLists[0].Fastest)
	}
	if left := Diff("", "", base, got, config.Config{}, config.Config{}); left.Count() != 0 {
		t.Fatalf("fastest mode undo left rows: %+v", left.Changes)
	}
}
