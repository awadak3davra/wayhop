package updatetx

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The marker exists to survive a power cut inside the window. Renamed into place unsynced, it can
// reach the flash empty (UBIFS does not sync data on rename; a new name on ext4 does not trigger
// auto_da_alloc), and verify.sh drops an empty marker at boot, so the broken build is never rolled
// back. Its contents are synced before the rename, and the directory after it.
func TestMarkerIsSyncedBeforeAndAfterTheRename(t *testing.T) {
	etc := t.TempDir()
	target := filepath.Join(etc, MarkerFile)
	var steps []string
	ws, sd := writeSynced, syncDir
	t.Cleanup(func() { writeSynced, syncDir = ws, sd })
	writeSynced = func(p string, b []byte, mode os.FileMode) error {
		steps = append(steps, "synced "+filepath.Base(p))
		return ws(p, b, mode)
	}
	syncDir = func(d string) {
		b, _ := os.ReadFile(target)
		steps = append(steps, fmt.Sprintf("dir %s synced, marker %d bytes", filepath.Base(d), len(b)))
		sd(d)
	}
	m := Marker{Bin: "/usr/sbin/wayhop", Init: "/etc/init.d/wayhop", To: "v0.5.8", By: "panel"}
	if err := m.Write(etc); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	want := []string{"synced " + MarkerFile + ".new", fmt.Sprintf("dir %s synced, marker %d bytes", filepath.Base(etc), len(b))}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Errorf("durability steps %q, want %q", steps, want)
	}
}

// A marker nobody is finishing (an installer interrupted over SSH, a supervisor killed) is acted on
// only at the next boot; it must not read as an update in flight until then.
func TestPendingSinceIsTheMarkersAge(t *testing.T) {
	etc := t.TempDir()
	if _, ok := PendingSince(etc); ok {
		t.Fatal("no marker reads as pending")
	}
	if err := (Marker{Bin: "/usr/sbin/wayhop", Init: "/etc/init.d/wayhop"}).Write(etc); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(etc, MarkerFile), old, old); err != nil {
		t.Fatal(err)
	}
	if since, ok := PendingSince(etc); !ok || !since.Equal(old) {
		t.Errorf("PendingSince = %v, %v; want %v", since, ok, old)
	}
}
