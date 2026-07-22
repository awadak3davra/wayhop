package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// further_test.go is the first coverage for the durable-write path that protects
// the router config from corruption on power loss. It exercises Write /
// WriteSynced / SyncDir: the round-trip contract, overwrite-replaces-and-honors-
// perm, MkdirAll of missing parents, the parent-is-a-regular-file error path
// (which must not leave a half-written target), the WriteSynced "no rename"
// invariant, and SyncDir being a harmless no-op on a missing directory.
//
// Helpers are prefixed "af_" to avoid clashing with any future test symbols in
// this package.

// af_read reads a file or fails the test.
func af_read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// af_exists reports whether a path exists.
func af_exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// af_assertPerm checks a file's permission bits in an OS-aware way: the exact
// requested mode on Unix, and merely "owner-writable, not a directory" on
// Windows where the Go runtime only honours the read-only bit.
func af_assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("%s is a directory; want a regular file", path)
	}
	if runtime.GOOS == "windows" {
		if info.Mode().Perm()&0o200 == 0 {
			t.Fatalf("%s perms = %v; want owner-writable on Windows", path, info.Mode().Perm())
		}
		return
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s perms = %v; want %v", path, got, want)
	}
}

// ---- Write: durable round trip ------------------------------------------------

// Write then read back must yield byte-identical contents across empty, text and
// binary payloads — the core durability contract.
func TestAtomicWrite_RoundTripsBytes(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"empty":     {},
		"text":      []byte("{\"log\":{\"level\":\"info\"}}\n"),
		"binary":    {0x00, 0x01, 0xFF, 0xFE, 0x0A, 0x0D, 0x00},
		"unicode":   []byte("конфиг 配置 🛰"),
		"with-null": []byte("a\x00b\x00c"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "rt-"+name+".json")
			if err := Write(path, data, 0o600); err != nil {
				t.Fatalf("Write error = %v; want nil", err)
			}
			if got := af_read(t, path); string(got) != string(data) {
				t.Fatalf("round-trip bytes = %q; want %q", got, data)
			}
		})
	}
}

// Write must not leave the temp file (path+".tmp") behind after a successful
// commit — the rename consumes it.
func TestAtomicWrite_RemovesTempAfterCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := Write(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("Write error = %v; want nil", err)
	}
	if af_exists(path + ".tmp") {
		t.Fatalf("Write left a stale temp file %q after a successful commit", path+".tmp")
	}
}

// ---- Write: overwrite ---------------------------------------------------------

// Overwriting an existing file must fully replace its contents (no leftover tail
// bytes from a longer previous payload) and apply the requested perm.
func TestAtomicWrite_OverwriteReplacesContentsAndPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Seed with a long payload at a different mode.
	long := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-original-long-config")
	if err := Write(path, long, 0o644); err != nil {
		t.Fatalf("seed Write error = %v", err)
	}

	// Replace with a strictly shorter payload at a tighter mode.
	short := []byte("short")
	if err := Write(path, short, 0o600); err != nil {
		t.Fatalf("overwrite Write error = %v", err)
	}

	if got := af_read(t, path); string(got) != string(short) {
		t.Fatalf("overwrite contents = %q; want %q (must not retain bytes from the longer original)", got, short)
	}
	af_assertPerm(t, path, 0o600)
}

// ---- Write: creates parent dirs ----------------------------------------------

// Write must MkdirAll a missing parent chain so the daemon can lay down a fresh
// config tree on first boot.
func TestAtomicWrite_CreatesMissingParentDirs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a", "b", "c", "config.json")
	if af_exists(filepath.Dir(path)) {
		t.Fatalf("test precondition broken: parent %q already exists", filepath.Dir(path))
	}

	data := []byte("nested")
	if err := Write(path, data, 0o600); err != nil {
		t.Fatalf("Write into a missing parent chain error = %v; want nil (MkdirAll)", err)
	}
	if got := af_read(t, path); string(got) != string(data) {
		t.Fatalf("nested write contents = %q; want %q", got, data)
	}
}

// ---- Write: parent component is a regular file (error path) -------------------

// When a path component is a regular file (so MkdirAll cannot create the parent
// directory), Write must return an error and must NOT leave a half-written target
// or a stray temp file.
func TestAtomicWrite_ErrorsWhenParentIsRegularFile(t *testing.T) {
	dir := t.TempDir()

	// "blocker" is a regular file; we then try to write UNDER it as if it were a
	// directory. MkdirAll(dir/blocker/sub) must fail because blocker is not a dir.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("i am a file, not a dir"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}

	target := filepath.Join(blocker, "sub", "config.json")
	err := Write(target, []byte("should-not-land"), 0o600)
	if err == nil {
		t.Fatal("Write under a regular-file path component returned nil error; want an error")
	}

	// No half-written target.
	if af_exists(target) {
		t.Fatalf("Write left a target %q despite failing; want none", target)
	}
	// No stray temp file next to the (impossible) target.
	if af_exists(target + ".tmp") {
		t.Fatalf("Write left a stray temp file %q after failing", target+".tmp")
	}
	// The blocker file itself must be untouched and still a regular file.
	info, statErr := os.Stat(blocker)
	if statErr != nil {
		t.Fatalf("stat blocker after failed Write: %v", statErr)
	}
	if info.IsDir() {
		t.Fatal("Write turned the blocker file into a directory; want it left as a regular file")
	}
	if got := af_read(t, blocker); string(got) != "i am a file, not a dir" {
		t.Fatalf("blocker contents mutated by failed Write = %q", got)
	}
}

// ---- WriteSynced: does not rename --------------------------------------------

// WriteSynced writes (and fsyncs) exactly the path given and must NOT perform a
// rename: a caller-named ".tmp" path must exist with the data, while the
// rename target (the same path without ".tmp") must stay absent.
func TestWriteSynced_DoesNotRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	tmp := target + ".tmp"

	data := []byte("validate-me-before-commit")
	if err := WriteSynced(tmp, data, 0o600); err != nil {
		t.Fatalf("WriteSynced error = %v; want nil", err)
	}

	if !af_exists(tmp) {
		t.Fatalf("WriteSynced did not create the file it was told to write %q", tmp)
	}
	if got := af_read(t, tmp); string(got) != string(data) {
		t.Fatalf("WriteSynced contents = %q; want %q", got, data)
	}
	// The rename target must NOT exist — WriteSynced never renames.
	if af_exists(target) {
		t.Fatalf("WriteSynced unexpectedly produced the rename target %q; it must not rename", target)
	}
	af_assertPerm(t, tmp, 0o600)
}

// WriteSynced truncates an existing file: writing a shorter payload over a longer
// one must not leave trailing bytes (O_TRUNC contract).
func TestWriteSynced_TruncatesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := WriteSynced(path, []byte("LONG-ORIGINAL-PAYLOAD"), 0o600); err != nil {
		t.Fatalf("seed WriteSynced error = %v", err)
	}
	if err := WriteSynced(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("second WriteSynced error = %v", err)
	}
	if got := af_read(t, path); string(got) != "x" {
		t.Fatalf("WriteSynced did not truncate: = %q; want %q", got, "x")
	}
}

// WriteSynced must error when the parent directory does not exist (it does NOT
// MkdirAll — that is Write's job).
func TestWriteSynced_ErrorsWhenParentMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope", "f") // "nope" never created
	if err := WriteSynced(path, []byte("data"), 0o600); err == nil {
		t.Fatal("WriteSynced into a missing parent dir returned nil error; want an error")
	}
	if af_exists(path) {
		t.Fatalf("WriteSynced created %q despite the missing parent", path)
	}
}

// ---- SyncDir ------------------------------------------------------------------

// SyncDir on a missing directory must be a harmless no-op: no panic, no error
// surface (it returns nothing), and it must not create the directory.
func TestSyncDir_NoOpOnMissingDir(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")

	// Must not panic.
	SyncDir(missing)

	if af_exists(missing) {
		t.Fatalf("SyncDir created %q; it must be a pure no-op on a missing dir", missing)
	}
}

// SyncDir on an existing directory must not panic and must leave the directory
// (and its contents) intact.
func TestSyncDir_LeavesExistingDirIntact(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child.json")
	if err := os.WriteFile(child, []byte("c"), 0o600); err != nil {
		t.Fatalf("seed child: %v", err)
	}

	SyncDir(dir) // best-effort fsync; must not panic or disturb contents

	if !af_exists(dir) {
		t.Fatal("SyncDir removed the directory")
	}
	if got := af_read(t, child); string(got) != "c" {
		t.Fatalf("SyncDir disturbed dir contents: child = %q; want %q", got, "c")
	}
}

// TestWrite_HonorsExecPermViaCreateTemp guards the atomicfile.Write path specifically: CreateTemp
// makes the temp 0600 and OpenFile's perm is IGNORED when re-opening that existing file, so without
// an explicit Chmod a caller asking for an executable 0755 (e.g. a Keenetic firewall hook) silently
// got 0600 and never ran. (Regression guard for the perm bug found in external review.)
func TestWrite_HonorsExecPermViaCreateTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix exec bit not meaningful on windows")
	}
	p := filepath.Join(t.TempDir(), "hook.sh")
	if err := Write(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Fatalf("Write mode = %o, want 0755 (the CreateTemp-0600 regression)", got)
	}
}
