package store

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"wayhop/internal/model"
)

// storemodelconfig_newStore opens a fresh Store backed by a unique temp file.
func storemodelconfig_newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "storemodelconfig_profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s, path
}

// storemodelconfig_seedEndpoint inserts a minimal valid endpoint.
func storemodelconfig_seedEndpoint(t *testing.T, s *Store, id string) {
	t.Helper()
	e := model.Endpoint{
		ID:       id,
		Name:     "ep-" + id,
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVLESS,
		Server:   "1.1.1.1",
		Port:     443,
		Enabled:  true,
	}
	if err := s.UpsertEndpoint(e); err != nil {
		t.Fatalf("seed endpoint %s: %v", id, err)
	}
}

// TestStoremodelconfigDeleteEndpointBlockedByRule verifies that deleting an
// endpoint still targeted by a rule is refused with an error, and the endpoint
// remains present.
func TestStoremodelconfigDeleteEndpointBlockedByRule(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")

	if err := s.UpsertRule(model.Rule{ID: "r1", Domain: []string{"x.com"}, Outbound: "e1"}); err != nil {
		t.Fatal(err)
	}

	err := s.DeleteEndpoint("e1")
	if err == nil {
		t.Fatal("expected DeleteEndpoint to be blocked by rule r1")
	}
	// The endpoint must still be present (delete refused, not partially applied).
	p := s.Profile()
	if p.EndpointByID("e1") == nil {
		t.Fatal("endpoint e1 should remain after a blocked delete")
	}
}

// TestStoremodelconfigDeleteEndpointBlockedByRoutingList verifies that deleting an
// endpoint a routing list routes (or downloads) via is refused — a dangling
// outbound would fail Validate() and block every Apply.
func TestStoremodelconfigDeleteEndpointBlockedByRoutingList(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")

	if err := s.UpsertRoutingList(model.RoutingList{ID: "rl1", Manual: []string{"x.com"}, Outbound: "e1", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteEndpoint("e1"); err == nil {
		t.Fatal("expected DeleteEndpoint to be blocked by routing list rl1")
	}
	p := s.Profile()
	if p.EndpointByID("e1") == nil {
		t.Fatal("endpoint e1 should remain after a blocked delete")
	}
}

// TestStoremodelconfigDeleteEndpointPrunesGroupMembers verifies that deleting an
// endpoint that is NOT referenced by any rule succeeds and prunes the endpoint
// from every group's Members list, leaving unrelated members intact.
func TestStoremodelconfigDeleteEndpointPrunesGroupMembers(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")
	storemodelconfig_seedEndpoint(t, s, "e2")

	// Two groups, both referencing e1 and e2 (e1 must not be the sole member of a
	// group, or deleting it would be refused to avoid leaving an empty group).
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1", "e2"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g2", Name: "G2", Type: model.GroupSelector, Members: []string{"e1", "e2"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteEndpoint("e1"); err != nil {
		t.Fatalf("DeleteEndpoint(e1): %v", err)
	}

	p := s.Profile()
	if p.EndpointByID("e1") != nil {
		t.Fatal("e1 should be gone after delete")
	}
	g1 := p.GroupByID("g1")
	if g1 == nil {
		t.Fatal("g1 missing")
	}
	if !reflect.DeepEqual(g1.Members, []string{"e2"}) {
		t.Fatalf("g1 members: want [e2], got %v", g1.Members)
	}
	g2 := p.GroupByID("g2")
	if g2 == nil {
		t.Fatal("g2 missing")
	}
	if !reflect.DeepEqual(g2.Members, []string{"e2"}) {
		t.Fatalf("g2 members: want [e2], got %v", g2.Members)
	}
}

// TestStoremodelconfigDeleteEndpointNotFound verifies a missing endpoint id
// returns an error.
func TestStoremodelconfigDeleteEndpointNotFound(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	if err := s.DeleteEndpoint("nope"); err == nil {
		t.Fatal("expected error deleting a non-existent endpoint")
	}
}

// TestStoremodelconfigDeleteGroupBlockedByRule verifies a group targeted by a
// rule cannot be deleted, while one not targeted can.
func TestStoremodelconfigDeleteGroupBlockedByRule(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r1", Default: true, Outbound: "g1"}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteGroup("g1"); err == nil {
		t.Fatal("expected DeleteGroup(g1) to be blocked by rule r1")
	}
	pBlocked := s.Profile()
	if pBlocked.GroupByID("g1") == nil {
		t.Fatal("g1 should remain after a blocked delete")
	}

	// Repoint the rule away from the group, then deletion succeeds.
	if err := s.UpsertRule(model.Rule{ID: "r1", Default: true, Outbound: model.OutboundDirect}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("g1"); err != nil {
		t.Fatalf("DeleteGroup(g1) after repoint: %v", err)
	}
	pAfter := s.Profile()
	if pAfter.GroupByID("g1") != nil {
		t.Fatal("g1 should be gone after delete")
	}
}

// TestStoremodelconfigDeleteGroupNotFound verifies a missing group id errors.
func TestStoremodelconfigDeleteGroupNotFound(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	if err := s.DeleteGroup("nope"); err == nil {
		t.Fatal("expected error deleting a non-existent group")
	}
}

// TestStoremodelconfigDeleteRuleNotFound verifies a missing rule id errors.
func TestStoremodelconfigDeleteRuleNotFound(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	if err := s.DeleteRule("nope"); err == nil {
		t.Fatal("expected error deleting a non-existent rule")
	}
}

// TestStoremodelconfigUpsertRequiresID verifies that upserts reject empty IDs.
func TestStoremodelconfigUpsertRequiresID(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	if err := s.UpsertEndpoint(model.Endpoint{}); err == nil {
		t.Fatal("expected error upserting endpoint with empty id")
	}
	if err := s.UpsertGroup(model.Group{}); err == nil {
		t.Fatal("expected error upserting group with empty id")
	}
	if err := s.UpsertRule(model.Rule{}); err == nil {
		t.Fatal("expected error upserting rule with empty id")
	}
}

// TestStoremodelconfigRemoveString documents removeString's behavior: it drops
// every occurrence of the target, preserves order of the rest, and returns the
// input unchanged when the target is absent (including nil/empty inputs).
func TestStoremodelconfigRemoveString(t *testing.T) {
	cases := []struct {
		name   string
		in     []string
		target string
		want   []string
	}{
		{"single", []string{"a", "b", "c"}, "b", []string{"a", "c"}},
		{"all-occurrences", []string{"x", "a", "x", "b", "x"}, "x", []string{"a", "b"}},
		{"absent", []string{"a", "b"}, "z", []string{"a", "b"}},
		{"empty-to-empty", []string{"only"}, "only", []string{}},
		{"nil-input", nil, "x", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := removeString(tc.in, tc.target)
			// reflect.DeepEqual treats nil and empty slices as different; normalise
			// by comparing lengths then elementwise so a returned nil matches [].
			if len(got) != len(tc.want) {
				t.Fatalf("len: want %v, got %v", tc.want, got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("want %v, got %v", tc.want, got)
				}
			}
		})
	}
}

// TestStoremodelconfigConcurrentCRUDRaceClean exercises the mutex-guarded CRUD
// surface from many goroutines. Run with -race it must report no data races.
// Each goroutine owns a disjoint ID namespace so the final state is
// deterministic.
func TestStoremodelconfigConcurrentCRUDRaceClean(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)

	const workers = 8
	const perWorker = 25

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("w%d-e%d", w, i)
				e := model.Endpoint{
					ID:       id,
					Name:     id,
					Engine:   model.EngineSingBox,
					Protocol: model.ProtoVLESS,
					Server:   "1.1.1.1",
					Port:     443,
					Enabled:  true,
				}
				if err := s.UpsertEndpoint(e); err != nil {
					t.Errorf("upsert %s: %v", id, err)
					return
				}
				// Replace in place (exercises the update path under contention).
				e.Name = id + "-v2"
				if err := s.UpsertEndpoint(e); err != nil {
					t.Errorf("re-upsert %s: %v", id, err)
					return
				}
				// Delete the even ones so the final count is predictable.
				if i%2 == 0 {
					if err := s.DeleteEndpoint(id); err != nil {
						t.Errorf("delete %s: %v", id, err)
						return
					}
				}
			}
		}(w)
	}

	// A concurrent reader of the locked accessor. Profile() copies under RLock;
	// we only read scalar fields it returns, never mutating shared state here.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = len(s.Profile().Endpoints)
		}
	}()

	wg.Wait()

	// Of perWorker indices [0,perWorker), the odd ones survive.
	odd := 0
	for i := 0; i < perWorker; i++ {
		if i%2 != 0 {
			odd++
		}
	}
	want := workers * odd
	if got := len(s.Profile().Endpoints); got != want {
		t.Fatalf("surviving endpoints: want %d, got %d", want, got)
	}
}
