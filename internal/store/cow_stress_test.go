package store

import (
	"path/filepath"
	"sync"
	"testing"

	"wayhop/internal/model"
)

// Copy-on-write deep-read stress: many readers DEEP-read the nested, shared-by-reference
// fields (Endpoint.Params map, Group.Members, RoutingList.CIDRCache/Manual, Rule fields)
// while many writers churn every mutator type and REPLACE those fields. Under CoW the
// published profile is immutable, so a reader holding an older snapshot must be able to
// read the nested fields with no race even as writers publish new profiles carrying new
// nested values. This is stronger than the length-only readers in race_test.go. Run -race.
func TestProfileCoWDeepReadStress(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := func(id string, j int) model.Endpoint {
		return model.Endpoint{
			ID: id, Name: "n", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "h", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": id, "seq": j}, // a fresh map every write
		}
	}
	// Seed a profile with every kind of nested field populated.
	for i := 0; i < 5; i++ {
		if err := s.UpsertEndpoint(ep("e"+string(rune('0'+i)), i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e0", "e1", "e2"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoutingList(model.RoutingList{ID: "rl", Name: "L", Manual: []string{"a.com", "b.com"}, Outbound: model.OutboundDirect, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	var rwg, wwg sync.WaitGroup
	stop := make(chan struct{})

	// Deep readers — touch nested fields, not just lengths.
	for r := 0; r < 8; r++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := s.Profile()
				sink := 0
				for i := range p.Endpoints {
					for k := range p.Endpoints[i].Params { // concurrent map READ of an immutable map
						sink += len(k)
					}
				}
				for i := range p.Groups {
					for _, m := range p.Groups[i].Members {
						sink += len(m)
					}
				}
				for i := range p.RoutingLists {
					for _, c := range p.RoutingLists[i].CIDRCache {
						sink += len(c)
					}
					for _, m := range p.RoutingLists[i].Manual {
						sink += len(m)
					}
				}
				for i := range p.Rules {
					for _, d := range p.Rules[i].Domain {
						sink += len(d)
					}
				}
				_ = sink
			}
		}()
	}

	// Writers — churn every mutator, replacing nested fields (new Params map, new CIDRCache,
	// new Members, add/remove a rule, delete the endpoint which prunes it from g.Members).
	for w := 0; w < 4; w++ {
		wwg.Add(1)
		go func(w int) {
			defer wwg.Done()
			id := "w" + string(rune('0'+w))
			for j := 0; j < 120; j++ {
				_ = s.UpsertEndpoint(ep(id, j))
				_ = s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e0", id, "e2"}})
				_ = s.SetRoutingListCache("rl", []string{"1.0.0.0/8", id + ".0.0.0/8"})
				_ = s.UpsertRule(model.Rule{ID: "r" + id, Domain: []string{id + ".com"}, Outbound: model.OutboundDirect})
				_ = s.DeleteRule("r" + id)
				_ = s.DeleteEndpoint(id) // prunes id from g.Members in place (on the clone)
			}
		}(w)
	}

	wwg.Wait()
	close(stop)
	rwg.Wait()
}

// A reader that captured a snapshot BEFORE a mutation must keep seeing the OLD values
// afterward — the essence of copy-on-write. Verifies the published profile is never
// mutated behind a reader's back (value-level, not just race-freedom).
func TestProfileSnapshotIsStable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e0", Name: "ORIGINAL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before := s.Profile() // capture

	// Mutate the same endpoint and add another.
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e0", Name: "CHANGED", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e1", Name: "NEW", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// The pre-mutation snapshot must be unchanged.
	if len(before.Endpoints) != 1 {
		t.Fatalf("snapshot grew behind the reader's back: %d endpoints", len(before.Endpoints))
	}
	if before.Endpoints[0].Name != "ORIGINAL" {
		t.Fatalf("snapshot mutated behind the reader's back: name=%q, want ORIGINAL", before.Endpoints[0].Name)
	}
	// And the live profile reflects the mutations.
	after := s.Profile()
	if len(after.Endpoints) != 2 || after.Endpoints[0].Name != "CHANGED" {
		t.Fatalf("live profile did not reflect mutations: %+v", after.Endpoints)
	}
}
