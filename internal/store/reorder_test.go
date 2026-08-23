package store

import (
	"errors"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

func reorderStore(t *testing.T, ids ...string) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, id := range ids {
		if err := s.UpsertRoutingList(model.RoutingList{ID: id, Name: id, Outbound: "direct", Enabled: true}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	return s
}

func listIDs(s *Store) []string {
	p := s.Profile()
	out := make([]string, 0, len(p.RoutingLists))
	for i := range p.RoutingLists {
		out = append(out, p.RoutingLists[i].ID)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReorderRoutingLists_AppliesTheGivenOrder(t *testing.T) {
	s := reorderStore(t, "a", "b", "c")
	if got := listIDs(s); !eq(got, []string{"a", "b", "c"}) {
		t.Fatalf("seed order wrong: %v", got)
	}
	if err := s.ReorderRoutingLists([]string{"c", "a", "b"}); err != nil {
		t.Fatalf("reorder: %v", err)
	}
	if got := listIDs(s); !eq(got, []string{"c", "a", "b"}) {
		t.Errorf("order not applied: %v", got)
	}
}

// A reorder must never be a way to lose a rule. Each rejection also has to leave the stored order
// untouched — a half-applied reorder would be the worst outcome of all.
func TestReorderRoutingLists_RefusesAnythingButAPermutation(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
	}{
		{"a list is missing", []string{"a", "b"}},
		{"an unknown id appears", []string{"a", "b", "ghost"}},
		{"an id is repeated instead of another", []string{"a", "b", "b"}},
		{"too many ids", []string{"a", "b", "c", "a"}},
		{"empty body", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := reorderStore(t, "a", "b", "c")
			before := listIDs(s)
			if err := s.ReorderRoutingLists(c.ids); err == nil {
				t.Fatalf("expected refusal for %v", c.ids)
			}
			if got := listIDs(s); !eq(got, before) {
				t.Errorf("a refused reorder must change nothing: %v -> %v", before, got)
			}
		})
	}
}

// The reorder must move the WHOLE list, not just its id: a rewritten slice that dropped the
// per-list settings would be a silent data loss.
func TestReorderRoutingLists_CarriesEachListIntact(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	seed := []model.RoutingList{
		{ID: "a", Name: "A list", Source: "https://example.invalid/a.srs", Outbound: "direct", RefreshHours: 12, Enabled: true},
		{ID: "b", Name: "B list", Manual: []string{"x.example"}, Outbound: "block", Enabled: false},
	}
	for _, rl := range seed {
		if err := s.UpsertRoutingList(rl); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := s.ReorderRoutingLists([]string{"b", "a"}); err != nil {
		t.Fatalf("reorder: %v", err)
	}
	p := s.Profile()
	if p.RoutingLists[0].ID != "b" || p.RoutingLists[1].ID != "a" {
		t.Fatalf("order not applied: %v", listIDs(s))
	}
	if p.RoutingLists[0].Outbound != "block" || p.RoutingLists[0].Enabled {
		t.Errorf("list b lost its settings: %+v", p.RoutingLists[0])
	}
	if p.RoutingLists[1].Source != seed[0].Source || p.RoutingLists[1].RefreshHours != 12 {
		t.Errorf("list a lost its settings: %+v", p.RoutingLists[1])
	}
}

// Reordering is a commit like any other, so readers keyed on the generation must see it.
func TestReorderRoutingLists_BumpsGeneration(t *testing.T) {
	s := reorderStore(t, "a", "b")
	before := s.Gen()
	if err := s.ReorderRoutingLists([]string{"b", "a"}); err != nil {
		t.Fatalf("reorder: %v", err)
	}
	if s.Gen() <= before {
		t.Errorf("generation did not advance: %d -> %d", before, s.Gen())
	}
}

// A refused reorder must not be mistaken for a store-level failure by callers matching on errors.
func TestReorderRoutingLists_ErrorIsNotErrStaleGen(t *testing.T) {
	s := reorderStore(t, "a")
	err := s.ReorderRoutingLists([]string{"ghost"})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if errors.Is(err, ErrStaleGen) {
		t.Error("an invalid permutation is not a staleness conflict")
	}
}
