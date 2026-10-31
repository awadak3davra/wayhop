package binstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A kill or a power cut after the new gzip took the name but before its record did leaves the record
// beside it still describing the old gzip. The record written for the new one first (StoreCompressed)
// is what Read falls back to, so the binary stays runnable; before the rename it describes a file that
// is not there yet, and the old record still wins.
func TestReadFallsBackToThePendingRecordAfterAKill(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	store(t, dir, "bin", []byte("old build"), "v1")
	gzPath := Stored(dir, "bin", true)
	tmp := gzPath + ".new"
	if err := os.WriteFile(tmp, gz(t, []byte("new build")), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(tmp)
	if err != nil {
		t.Fatal(err)
	}
	pending := fmt.Sprintf("v2 1 %d %d %s\n", fi.Size(), fi.ModTime().UnixNano(), sum)
	if err := os.WriteFile(nextPath(dir, "bin"), []byte(pending), 0o644); err != nil {
		t.Fatal(err)
	}
	if r, ok := Read(dir, "bin"); !ok || r.Version != "v1" {
		t.Fatalf("before the rename: Read = %+v, %v; want the old record", r, ok)
	}
	if err := os.Rename(tmp, gzPath); err != nil {
		t.Fatal(err)
	}
	// Killed here: the gzip is the new one, the record under its own name still the old one.
	if r, ok := Read(dir, "bin"); !ok || r.Version != "v2" || !r.Compressed {
		t.Fatalf("after the rename: Read = %+v, %v; want the pending record", r, ok)
	}
	p, err := Unpack(dir, "bin", run)
	if err != nil {
		t.Fatalf("the new gzip cannot be unpacked to run: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new build" {
		t.Errorf("unpacked %q", b)
	}
}

// The next install reuses the pending record's name. A record a kill left pending is the only one that
// describes the stored gzip, so it takes its own name before that name is rewritten: killed during the
// rewrite, the gzip would otherwise have no record at all.
func TestAPendingRecordIsSettledBeforeItsNameIsReused(t *testing.T) {
	dir := t.TempDir()
	store(t, dir, "bin", []byte("build A"), "v1")
	gzPath := Stored(dir, "bin", true)
	src := gzPath + ".new"
	// Build B stored and killed before its record took its name (as StoreCompressed would leave it).
	if err := os.WriteFile(src, gz(t, []byte("build B")), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := describe(src, "v2", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextPath(dir, "bin"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(src, gzPath); err != nil {
		t.Fatal(err)
	}
	ws := writeSynced
	t.Cleanup(func() { writeSynced = ws })
	writeSynced = func(p string, b []byte, mode os.FileMode) error {
		if r, ok := readRecord(dir, "bin", recordPath(dir, "bin")); !ok || r.Version != "v2" {
			t.Errorf("the pending record is rewritten while it is the only record of the stored gzip (record %+v, %v)", r, ok)
		}
		return ws(p, b, mode)
	}
	if err := os.WriteFile(src, gz(t, []byte("build C")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StoreCompressed(dir, "bin", "v3", src); err != nil {
		t.Fatal(err)
	}
	if r, ok := Read(dir, "bin"); !ok || r.Version != "v3" {
		t.Errorf("Read = %+v, %v", r, ok)
	}
}

// StoreCompressed replaces whichever form is stored, and leaves one record that names the gzip.
func TestStoreCompressedReplacesTheRawBinaryAndRecordsTheGzip(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(Stored(dir, "bin", false), []byte("raw build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, "bin", "v1", false); err != nil {
		t.Fatal(err)
	}
	src := Stored(dir, "bin", true) + ".new"
	if err := os.WriteFile(src, gz(t, []byte("packed build")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StoreCompressed(dir, "bin", "v2", src); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{Stored(dir, "bin", false), src, nextPath(dir, "bin"), recordPath(dir, "bin") + ".new"} {
		if exists(p) {
			t.Errorf("%s survived", p)
		}
	}
	if r, ok := Read(dir, "bin"); !ok || r.Version != "v2" || !r.Compressed {
		t.Fatalf("Read = %+v, %v", r, ok)
	}
	if p, err := Unpack(dir, "bin", run); err != nil {
		t.Fatal(err)
	} else if b, _ := os.ReadFile(p); string(b) != "packed build" {
		t.Errorf("unpacked %q", b)
	}
}

// Unpack must invalidate the copy's marker before it replaces the copy. Killed in between (SIGKILL,
// OOM: the tmpfs survives), a marker that outlived its copy would vouch for the wrong build as soon as
// the store holds the marker's build again - a downgrade - and Unpack would reuse the copy it holds.
func TestUnpackInvalidatesTheMarkerBeforeReplacingTheCopy(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	store(t, dir, "bin", []byte("build A"), "v1")
	if _, err := Unpack(dir, "bin", run); err != nil {
		t.Fatal(err)
	}
	store(t, dir, "bin", []byte("build B"), "v2")
	// The copy is replaced, and the daemon dies before anything after that rename runs.
	killed := errors.New("killed")
	gunzip = func(src, dst string) error {
		if err := Gunzip(src, dst); err != nil {
			return err
		}
		return killed
	}
	_, err := Unpack(dir, "bin", run)
	gunzip = Gunzip
	if !errors.Is(err, killed) {
		t.Fatalf("Unpack = %v", err)
	}
	// Build A again, byte for byte (the release gzip is stored verbatim): the same digest on record.
	store(t, dir, "bin", []byte("build A"), "v1")
	p, err := Unpack(dir, "bin", run)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "build A" {
		t.Errorf("the record says build A, but the copy that runs holds %q", b)
	}
}

// A package taking name over drops the stored gzip, so a record a kill left pending for that gzip
// describes nothing any more and goes with it.
func TestRemoveStaleCompressedDropsAPendingRecord(t *testing.T) {
	dir := t.TempDir()
	store(t, dir, "bin", []byte("build A"), "v1")
	rec, err := describe(Stored(dir, "bin", true), "v1", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextPath(dir, "bin"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveStaleCompressed(dir, "bin", ""); err != nil {
		t.Fatal(err)
	}
	if exists(nextPath(dir, "bin")) {
		t.Error("the pending record of the removed gzip survived")
	}
}

// durableLog records the durability steps a write takes, and what the target held at each.
type durableLog struct {
	steps []string
}

func (l *durableLog) install(t *testing.T, target string) {
	t.Helper()
	ws, sd := writeSynced, syncDir
	t.Cleanup(func() { writeSynced, syncDir = ws, sd })
	writeSynced = func(p string, b []byte, mode os.FileMode) error {
		l.steps = append(l.steps, "synced "+filepath.Base(p))
		return ws(p, b, mode)
	}
	syncDir = func(d string) {
		b, _ := os.ReadFile(target)
		l.steps = append(l.steps, fmt.Sprintf("dir synced, %s holds %d bytes", filepath.Base(target), len(b)))
		sd(d)
	}
}

// A record that reaches the flash as an empty file after a power cut makes a compressed binary
// unrunnable (Read fails, Unpack says ErrNotStored, nothing starts): its contents are synced before
// the rename, and the directory after it.
func TestWriteSyncsTheRecordBeforeAndAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	store(t, dir, "bin", []byte("payload"), "v1")
	var l durableLog
	l.install(t, recordPath(dir, "bin"))
	if err := Write(dir, "bin", "v2", true); err != nil {
		t.Fatal(err)
	}
	if len(l.steps) != 2 || l.steps[0] != "synced .bin.version.new" || l.steps[1] == "" {
		t.Fatalf("durability steps %q; want the record synced, then its directory", l.steps)
	}
	b, _ := os.ReadFile(recordPath(dir, "bin"))
	if want := fmt.Sprintf("dir synced, .bin.version holds %d bytes", len(b)); l.steps[1] != want {
		t.Errorf("second step %q, want %q", l.steps[1], want)
	}
}
