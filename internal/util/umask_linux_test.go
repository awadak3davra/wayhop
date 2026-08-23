package util

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// The claim under test is not "the daemon's own files are 0600" — atomicfile already chmods those,
// so a test of them would pass with or without the umask. The claim is about a file WayHop NEVER
// OPENS: sing-box creates cache.db itself, and the only thing the daemon controls is the umask its
// child inherits. So the child is what these tests exercise.
//
// This file is linux-only by build constraint rather than by a runtime skip: a skipped test reports
// coverage it does not have, whereas a file that is not part of the Windows build is honestly absent
// and still runs for real on the Linux CI and on the router.

func restoreUmask(t *testing.T) {
	t.Helper()
	prev, applied := RestrictNewFiles()
	if !applied {
		t.Fatal("RestrictNewFiles reported no change on linux, where it must apply one")
	}
	t.Cleanup(func() { syscall.Umask(prev) })
}

// A child process creating a file must land at 0600 — this is cache.db's case exactly.
func TestRestrictNewFiles_ChildProcessFileIsOwnerOnly(t *testing.T) {
	restoreUmask(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "cache.db")

	// `sh` creates the file with 0666&~umask, the same way sing-box's bbolt open does.
	if out, err := exec.Command("sh", "-c", "echo x > "+target).CombinedOutput(); err != nil {
		t.Fatalf("sh: %v: %s", err, out)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("a child-created file is %04o, want 0600 — the cache would be world-readable", got)
	}
}

// The regression: with the daemon's default umask the same child lands at 0644, which is the state
// found on the router. Without this the test above could pass on a host that happened to boot with a
// restrictive umask, and would prove nothing about the code.
func TestRestrictNewFiles_WithoutItTheChildIsWorldReadable(t *testing.T) {
	prev := syscall.Umask(0o022) // the default a router's init gives the daemon
	t.Cleanup(func() { syscall.Umask(prev) })

	dir := t.TempDir()
	target := filepath.Join(dir, "cache.db")
	if out, err := exec.Command("sh", "-c", "echo x > "+target).CombinedOutput(); err != nil {
		t.Fatalf("sh: %v: %s", err, out)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Fatalf("under umask 022 a child file is %04o; this host does not reproduce the condition the "+
			"fix addresses, so the test above is not evidence", got)
	}
}

// Directories the daemon creates become owner-only too. Asserted rather than left implicit: it is a
// deliberate consequence, and the place to notice it is here rather than on a router.
func TestRestrictNewFiles_DirectoriesAreOwnerOnly(t *testing.T) {
	restoreUmask(t)
	dir := filepath.Join(t.TempDir(), "wayhop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("directory is %04o, want 0700", got)
	}
}

// atomicfile chmods explicitly, so a caller asking for an executable mode must still get one — the
// umask must not silently turn a Keenetic firewall hook into a non-executable file.
func TestRestrictNewFiles_ExplicitChmodStillWins(t *testing.T) {
	restoreUmask(t)
	target := filepath.Join(t.TempDir(), "hook.sh")
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("explicitly chmodded file is %04o, want 0755 — the umask must not defeat an explicit mode", got)
	}
}
