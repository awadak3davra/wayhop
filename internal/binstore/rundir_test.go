package binstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsureRunDir(t *testing.T) {
	base := t.TempDir()
	fresh := filepath.Join(base, "run")
	if err := EnsureRunDir(fresh); err != nil {
		t.Fatalf("a new run dir was refused: %v", err)
	}
	if err := EnsureRunDir(fresh); err != nil {
		t.Fatalf("its own run dir was refused the second time: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if EnsureRunDir(file) == nil {
		t.Error("a file was taken for the run dir")
	}
	if runtime.GOOS == "windows" {
		return // no owner or mode to check, and symlinks need a privilege
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	if EnsureRunDir(link) == nil {
		t.Error("a symlink was taken for the run dir")
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if EnsureRunDir(open) == nil {
		t.Error("a run dir others can write to was taken")
	}
}
