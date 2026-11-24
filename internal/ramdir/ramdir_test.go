package ramdir

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func stubRAM(t *testing.T, ram bool, err error) {
	t.Helper()
	prev := isRAMFS
	isRAMFS = func(string) (bool, error) { return ram, err }
	t.Cleanup(func() { isRAMFS = prev })
}

func TestResolve_RAM(t *testing.T) {
	stubRAM(t, true, nil)
	want := filepath.Join(t.TempDir(), "wayhop", "state")
	got, err := Resolve(want)
	if err != nil || got != want {
		t.Fatalf("Resolve = %q, %v; want %q", got, err, want)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}
}

// A directory on disk is refused: the caller falls back to memory, never to wearing flash.
func TestResolve_NotRAMFallsBack(t *testing.T) {
	stubRAM(t, false, nil)
	got, err := Resolve(filepath.Join(t.TempDir(), "state"))
	if err == nil || got != "" {
		t.Fatalf("Resolve = %q, %v; want refusal", got, err)
	}
	if MustResolveOrLog(filepath.Join(t.TempDir(), "state")) != "" {
		t.Fatal("MustResolveOrLog must return empty on fallback")
	}
}

func TestResolve_StatfsErrorFallsBack(t *testing.T) {
	stubRAM(t, true, errors.New("boom"))
	if got, err := Resolve(filepath.Join(t.TempDir(), "state")); err == nil || got != "" {
		t.Fatalf("Resolve = %q, %v; want refusal", got, err)
	}
}

func TestResolve_Relative(t *testing.T) {
	stubRAM(t, true, nil)
	if _, err := Resolve("rel/state"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestResolve_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	stubRAM(t, true, nil)
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(link); err == nil || got != "" {
		t.Fatalf("symlink accepted: %q", got)
	}
}
