package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// An identical rewrite must not touch the file: no temp, no rename (the inode and mtime stay), and it
// is counted as skipped, not as a write.
func TestWrite_SkipsUnchangedContent(t *testing.T) {
	resetStats()
	dir := t.TempDir()
	p := filepath.Join(dir, "profile.json")
	if err := Write(p, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(old) {
		t.Fatalf("identical rewrite touched the file: mtime %v, want %v", fi.ModTime(), old)
	}
	// Changed content of the same length is still written.
	if err := Write(p, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != `{"a":2}` {
		t.Fatalf("changed content not written: %q", got)
	}
	st, _ := Stats()
	if len(st) != 1 || st[0].Class != "profile.json" || st[0].Writes != 2 || st[0].Skipped != 1 || st[0].Bytes != 14 || st[0].SkippedBytes != 7 {
		t.Fatalf("stats = %+v", st)
	}
}

// Same bytes, different mode: the mode is corrected without a rewrite.
func TestWrite_UnchangedContentFixesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	p := filepath.Join(t.TempDir(), "hook.sh")
	if err := Write(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", fi.Mode().Perm())
	}
}

func TestStats_ClassesAndRAM(t *testing.T) {
	resetStats()
	ram := t.TempDir()
	SetRAMDirs(ram)
	flash := t.TempDir()
	_ = Write(filepath.Join(flash, "wayhop-backup-20261121T101010Z.json"), []byte("x"), 0o600)
	_ = Write(filepath.Join(flash, "wayhop-backup-20261122T101010Z.json"), []byte("yy"), 0o600)
	_ = Write(filepath.Join(ram, "list-cache.json"), []byte("zzz"), 0o600)
	st, _ := Stats()
	if len(st) != 2 {
		t.Fatalf("stats = %+v", st)
	}
	if st[0].RAM || st[0].Class != "wayhop-backup-*T*Z.json" || st[0].Writes != 2 || st[0].Bytes != 3 {
		t.Fatalf("flash class = %+v", st[0])
	}
	if !st[1].RAM || st[1].Class != "list-cache.json" {
		t.Fatalf("ram class = %+v", st[1])
	}
	resetStats()
}
