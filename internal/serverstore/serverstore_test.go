package serverstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestServersMigrationCompat locks the deploy/rollback compat for saved Init-Server records
// (servers.json), the same invariant as the config/profile guards: BACKWARD an old-style
// record loads intact; FORWARD a record carrying fields this binary doesn't know still loads
// (so a post-deploy rollback fed the new servers.json isn't bricked). Holds while Open stays
// lenient (plain json.Unmarshal); a Server field rename/retype, or DisallowUnknownFields,
// fails here before it can drop a router's saved provisioning records.
func TestServersMigrationCompat(t *testing.T) {
	base, err := json.Marshal([]Server{{ID: "s1", Name: "vps", Host: "1.2.3.4", Port: 22, User: "root"}})
	if err != nil {
		t.Fatal(err)
	}
	open := func(b []byte) (*Store, error) {
		p := filepath.Join(t.TempDir(), "servers.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return Open(p)
	}

	// BACKWARD: an old-style record (no omitempty extras) loads intact.
	s, err := open(base)
	if err != nil {
		t.Fatalf("backward: Open(old-style servers) errored: %v", err)
	}
	if l := s.List(); len(l) != 1 || l[0].ID != "s1" || l[0].Host != "1.2.3.4" {
		t.Fatalf("backward: server not migrated cleanly: %+v", l)
	}

	// FORWARD/ROLLBACK: a record carrying an unknown future field must still load, intact.
	fwd := []byte(`[{"id":"s1","name":"vps","host":"1.2.3.4","port":22,"user":"root","future_field":"surprise"}]`)
	s2, err := open(fwd)
	if err != nil {
		t.Fatalf("forward: Open(servers with unknown field) errored — rollback would brick: %v", err)
	}
	if l := s2.List(); len(l) != 1 || l[0].ID != "s1" {
		t.Errorf("forward: server lost when an unknown field was present: %+v", l)
	}
}

// An empty or whitespace-only servers.json must load as an empty list and rewrite
// a valid file — NOT brick boot with "unexpected end of JSON input". A non-empty
// garbage file still errors.
func TestOpenEmptyOrGarbage(t *testing.T) {
	for _, content := range []string{"", "   ", "\n\t \n"} {
		path := filepath.Join(t.TempDir(), "servers.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open(empty %q) returned error: %v", content, err)
		}
		if len(s.List()) != 0 {
			t.Fatalf("Open(empty) did not yield an empty list: %v", s.List())
		}
		// The file must have been rewritten so a reopen succeeds (valid JSON).
		if _, err := Open(path); err != nil {
			t.Fatalf("reopen after empty-file recreate errored: %v", err)
		}
	}

	// A genuinely-corrupt NON-empty file must still surface its parse error.
	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open(garbage) should error, not swallow real corruption")
	}
}

// When the underlying atomic write fails, a mutator must leave the in-memory list
// unchanged (persist-then-commit) — otherwise a "deleted" server still answers
// reads and the change silently reverts on reboot. We point the store at an
// unwritable path: a regular file used as a directory component makes MkdirAll fail.
func TestMutatorWriteFailureLeavesMemoryUnchanged(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "servers.json")
	s, err := Open(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(Server{ID: "a", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(Server{ID: "b", Name: "B"}); err != nil {
		t.Fatal(err)
	}

	// Redirect persistence to an unwritable location: a file standing in for a dir.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blocker, "sub", "servers.json") // MkdirAll over a file → error

	snapshot := s.List()

	if err := s.Upsert(Server{ID: "c", Name: "C"}); err == nil {
		t.Fatal("Upsert should have failed on the unwritable path")
	}
	if err := s.Patch("a", func(sv *Server) { sv.Name = "MUTATED" }); err == nil {
		t.Fatal("Patch should have failed on the unwritable path")
	}
	if err := s.Delete("b"); err == nil {
		t.Fatal("Delete should have failed on the unwritable path")
	}

	got := s.List()
	if len(got) != len(snapshot) {
		t.Fatalf("in-memory list size changed after failed writes: got %d want %d", len(got), len(snapshot))
	}
	for i := range got {
		if got[i].ID != snapshot[i].ID || got[i].Name != snapshot[i].Name {
			t.Fatalf("in-memory list diverged after failed writes: %+v vs %+v", got, snapshot)
		}
	}
	// Specifically: the failed Patch must not have leaked into the live element.
	if a, _ := s.Get("a"); a.Name != "A" {
		t.Fatalf("failed Patch mutated the live element: Name=%q", a.Name)
	}
}

// TestPatchInPlaceSliceMutationDoesNotLeakOnWriteFailure covers the slice case that
// TestMutatorWriteFailureLeavesMemoryUnchanged (a Name value mutation) cannot catch:
// Patch deep-clones Installed before fn, so an IN-PLACE mutation — append(sv.Installed[:0],
// ...), the pattern race_test.go notes a future Init-Server protocol-list edit would use —
// cannot write through a shared backing array into the live element when the save fails.
func TestPatchInPlaceSliceMutationDoesNotLeakOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(Server{ID: "a", Name: "A", Installed: []string{"orig1", "orig2"}}); err != nil {
		t.Fatal(err)
	}

	// Redirect persistence to an unwritable location so the next Patch's save fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blocker, "sub", "servers.json") // MkdirAll over a file → error

	if err := s.Patch("a", func(sv *Server) { sv.Installed = append(sv.Installed[:0], "HACKED") }); err == nil {
		t.Fatal("Patch should have failed on the unwritable path")
	}
	got, _ := s.Get("a")
	if len(got.Installed) != 2 || got.Installed[0] != "orig1" || got.Installed[1] != "orig2" {
		t.Fatalf("failed Patch leaked an in-place Installed mutation into the live element: %v", got.Installed)
	}
}

func TestCRUDAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatal("new store should be empty")
	}
	if err := s.Upsert(Server{ID: "srv-a", Name: "A", Host: "1.2.3.4", Port: 22, User: "root", Installed: []string{"amneziawg"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(Server{ID: "srv-b", Name: "B", Host: "5.6.7.8"}); err != nil {
		t.Fatal(err)
	}
	// Update existing (no duplicate).
	if err := s.Upsert(Server{ID: "srv-a", Name: "A2", Host: "1.2.3.4", Hardened: true}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.List()); got != 2 {
		t.Fatalf("list size = %d, want 2", got)
	}
	a, ok := s.Get("srv-a")
	if !ok || a.Name != "A2" || !a.Hardened {
		t.Fatalf("get srv-a = %+v ok=%v", a, ok)
	}

	// Patch.
	if err := s.Patch("srv-b", func(sv *Server) { sv.Installed = []string{"vless-reality"} }); err != nil {
		t.Fatal(err)
	}
	if err := s.Patch("missing", func(*Server) {}); err == nil {
		t.Fatal("patch of missing server should error")
	}

	// Reload from disk → persisted.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := s2.Get("srv-b")
	if !ok || len(b.Installed) != 1 || b.Installed[0] != "vless-reality" {
		t.Fatalf("reloaded srv-b = %+v ok=%v", b, ok)
	}

	// Delete.
	if err := s2.Delete("srv-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("srv-a"); ok {
		t.Fatal("srv-a should be deleted")
	}
	if err := s2.Delete("srv-a"); err == nil {
		t.Fatal("deleting missing server should error")
	}
}

func TestUpsertRequiresID(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "servers.json"))
	if err := s.Upsert(Server{Host: "1.1.1.1"}); err == nil {
		t.Fatal("upsert without id should error")
	}
}
