package store

import (
	"path/filepath"
	"sync"
	"testing"

	"wayhop/internal/model"
)

// Regression for the Profile() slice-aliasing race: a caller iterating the
// returned profile's slices must not race a concurrent writer compacting/
// replacing the store's backing arrays. Run with -race.
func TestProfileConcurrentMutationNoRace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		_ = s.UpsertEndpoint(model.Endpoint{
			ID: "e" + string(rune('0'+i)), Name: "n", Engine: model.EngineSingBox,
			Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true,
		})
	}

	var wg sync.WaitGroup
	// Readers iterate the returned slices (lock-free, as real callers do).
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				p := s.Profile()
				n := 0
				for range p.Endpoints {
					n++
				}
				_ = n
			}
		}()
	}
	// Writers mutate the backing arrays (upsert replaces, delete compacts).
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = s.UpsertEndpoint(model.Endpoint{
					ID: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
					Server: "h", Port: 443, Enabled: true,
				})
				_ = s.DeleteEndpoint(id)
			}
		}("w" + string(rune('0'+w)))
	}
	wg.Wait()
}

// #6: Group.Members is compacted in place by DeleteEndpoint's prune; a reader
// iterating a group's members from Profile() must get a cloned slice, not the
// aliased backing array. Run with -race.
func TestProfileGroupMembersNoRace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id string) model.Endpoint {
		return model.Endpoint{ID: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true}
	}
	for i := 0; i < 6; i++ {
		_ = s.UpsertEndpoint(mk("e" + string(rune('0'+i))))
	}
	_ = s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e0", "e1", "e2", "e3", "e4", "e5"}})

	var wg sync.WaitGroup
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 800; j++ {
				p := s.Profile()
				for _, g := range p.Groups {
					n := 0
					for range g.Members {
						n++
					}
					_ = n
				}
			}
		}()
	}
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				_ = s.UpsertEndpoint(mk(id))
				_ = s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e0", "e1", id, "e3", "e4", "e5"}})
				_ = s.DeleteEndpoint(id) // prunes id from g.Members in place
			}
		}("m" + string(rune('0'+w)))
	}
	wg.Wait()
}

// RoutingLists is compacted in place by DeleteRoutingList and appended to by
// UpsertRoutingList; a reader iterating the slice from Profile() must get a
// cloned slice, not the aliased backing array. Run with -race.
func TestProfileRoutingListsNoRace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		_ = s.UpsertRoutingList(model.RoutingList{
			ID: "rl" + string(rune('0'+i)), Name: "L", Manual: []string{"a.com", "1.2.3.4"},
			Outbound: model.OutboundDirect, Enabled: true,
		})
	}

	var wg sync.WaitGroup
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				p := s.Profile()
				n := 0
				for range p.RoutingLists {
					n++
				}
				_ = n
			}
		}()
	}
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = s.UpsertRoutingList(model.RoutingList{ID: id, Manual: []string{"x.com"}, Outbound: model.OutboundDirect, Enabled: true})
				_ = s.DeleteRoutingList(id) // compacts RoutingLists[:0] in place
			}
		}("z" + string(rune('0'+w)))
	}
	wg.Wait()
}
