//go:build unix

package binstore

import (
	"os"
	"path/filepath"
	"testing"
)

// The attack itself: another user made the directory before WayHop did. Needs root to hand
// the directory to another uid, so CI (not root) skips it.
func TestEnsureRunDirRefusesAnotherUsersDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the directory to another user")
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if EnsureRunDir(dir) == nil {
		t.Error("a run dir another user owns was taken")
	}
}
