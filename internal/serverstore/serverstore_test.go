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
// unparsable file is covered by TestOpenUnparsableSetsItAsideAndStartsEmpty.
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
}

// A NON-empty file that does not parse must not keep the daemon from starting: main treats an Open
// error as fatal, and the init system respawned it into the same failure with the panel unreachable,
// all over a convenience list with no secrets. The usual shape is a USB stick that acknowledged a
// FLUSH and lost the block: the right length, all NULs, which TrimSpace does not strip. The file is
// set aside with its bytes intact and the store starts empty.
func TestOpenUnparsableSetsItAsideAndStartsEmpty(t *testing.T) {
	for name, content := range map[string][]byte{
		"garbage":    []byte("{not json"),
		"nul-filled": make([]byte, 312),
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "servers.json")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(path)
		if err != nil {
			t.Fatalf("%s: Open must not fail on an unparsable list: %v", name, err)
		}
		if len(s.List()) != 0 {
			t.Fatalf("%s: want an empty list, got %v", name, s.List())
		}
		aside, _ := filepath.Glob(filepath.Join(dir, "servers.json.corrupt-*"))
		if len(aside) != 1 {
			t.Fatalf("%s: the unparsable file must be kept aside once, found %v", name, aside)
		}
		if got, _ := os.ReadFile(aside[0]); string(got) != string(content) {
			t.Fatalf("%s: the set-aside copy lost bytes", name)
		}
		// The store is usable and the next start reads what it wrote.
		if err := s.Upsert(Server{ID: "a", Name: "A"}); err != nil {
			t.Fatalf("%s: Upsert after recovery: %v", name, err)
		}
		re, err := Open(path)
		if err != nil || len(re.List()) != 1 {
			t.Fatalf("%s: reopen = %v, %v", name, re, err)
		}
	}
}

// A read error other than "absent" is not corruption and still fails: starting empty would hide it,
// and the next write would replace a list that may be intact.
func TestOpenUnreadableStillFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.Mkdir(path, 0o755); err != nil { // reading a directory fails with something other than ENOENT
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open must report a read error that is not a missing file")
	}
}

// A kill between atomicfile.Write's temp creation and its rename left servers.json.NNN.tmp behind for
// good, one more with every crash. Open sweeps them before any writer starts.
func TestOpenSweepsTempsACrashLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	orphan := path + ".123456.tmp"
	if err := os.WriteFile(orphan, []byte(`[{"id":"a"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("an orphaned servers temp survived Open: %v", err)
	}
}

// PatchOrCreate finds or creates the record and applies fn under ONE hold of the lock. Two callers
// creating the same new id used to miss in Patch, then each Upsert a whole record, the later one
// replacing the earlier; here the second caller finds the first one's record and merges into it.
func TestPatchOrCreate(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	add := func(proto string) func(*Server) {
		return func(sv *Server) { sv.Installed = append(sv.Installed, proto) }
	}
	created, err := s.PatchOrCreate("srv-a", Server{Name: "A", CreatedAt: "first"}, add("awg"))
	if err != nil || !created {
		t.Fatalf("first call: created=%v err=%v, want a new record", created, err)
	}
	created, err = s.PatchOrCreate("srv-a", Server{Name: "B", CreatedAt: "second"}, add("hy2"))
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v, want the existing record patched", created, err)
	}
	sv, ok := s.Get("srv-a")
	if !ok || sv.ID != "srv-a" || sv.Name != "A" || sv.CreatedAt != "first" {
		t.Fatalf("record = %+v, want the first caller's identity kept", sv)
	}
	if len(sv.Installed) != 2 || sv.Installed[0] != "awg" || sv.Installed[1] != "hy2" {
		t.Fatalf("Installed = %v, want both callers' protocols", sv.Installed)
	}
	if _, err := s.PatchOrCreate("", Server{}, add("x")); err == nil {
		t.Fatal("an empty id must be refused")
	}

	// Persist-then-commit: a failed write creates nothing in memory.
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	bad, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil { // the final rename onto a directory fails
		t.Fatal(err)
	}
	if _, err := bad.PatchOrCreate("srv-b", Server{}, add("awg")); err == nil {
		t.Fatal("a failed write must be reported")
	}
	if len(bad.List()) != 0 {
		t.Fatalf("a record whose write failed was committed: %v", bad.List())
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
