package serverstore

import (
	"path/filepath"
	"sync"
	"testing"
)

// List/Get must return a Server whose Installed slice is a CLONE, not an alias of
// the stored backing array: a lock-free reader iterating Installed (as the GET
// /servers handler does when marshalling the result) would otherwise race a
// concurrent writer that rewrites Installed in place. Run with -race.
func TestListGetInstalledNoRace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Upsert(Server{ID: "sv", Name: "S", Host: "h", Port: 22, User: "root",
		Installed: []string{"a", "b", "c", "d"}})

	var wg sync.WaitGroup
	// Readers iterate the returned Installed lock-free, like the GET handler.
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1500; j++ {
				for _, sv := range s.List() {
					for range sv.Installed {
					}
				}
				if got, ok := s.Get("sv"); ok {
					for range got.Installed {
					}
				}
			}
		}()
	}
	// Writer rewrites Installed IN PLACE (reuses the backing array, overwrites
	// index 0…) — the pattern a future Init-Server protocol-list edit would use.
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 800; j++ {
				_ = s.Patch("sv", func(sv *Server) {
					sv.Installed = append(sv.Installed[:0], "x", "y", "z", "w")
				})
			}
		}()
	}
	wg.Wait()
}
