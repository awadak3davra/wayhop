package core

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fileops_test.go covers the deterministic file-operation paths of SingBox that
// need no real sing-box binary: Backup / Restore / Commit / copyFile, plus the
// Available()=true branch (an existing on-disk binary) and the CheckConfig()
// missing-binary error branch. Helpers are prefixed "corefileops_" to avoid
// clashing with the symbols in singbox_test.go and lifecycle_real_test.go.

// corefileops_writeFile creates a file with the given bytes, failing the test on
// error. Returns the path it wrote (for fluent use).
func corefileops_writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// corefileops_read reads a file or fails the test.
func corefileops_read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// corefileops_exists reports whether a path exists.
func corefileops_exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---- Backup -------------------------------------------------------------------

// Backup copies the active config to <config>.bak.
func TestCorefileops_BackupCopiesActiveConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	want := []byte(`{"log":{"level":"info"}}`)
	corefileops_writeFile(t, cfg, want)

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() error = %v; want nil", err)
	}

	bak := cfg + ".bak"
	if !corefileops_exists(bak) {
		t.Fatalf("Backup() did not create %s", bak)
	}
	if got := corefileops_read(t, bak); string(got) != string(want) {
		t.Fatalf("backup contents = %q; want %q", got, want)
	}
	// The original must be left untouched.
	if got := corefileops_read(t, cfg); string(got) != string(want) {
		t.Fatalf("active config mutated by Backup: = %q; want %q", got, want)
	}
}

// Backup is a no-op (nil error, no .bak created) when the active config is absent.
func TestCorefileops_BackupIsNoOpWhenConfigAbsent(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json") // never created

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() with no config error = %v; want nil (no-op)", err)
	}
	if corefileops_exists(cfg + ".bak") {
		t.Fatal("Backup() created a .bak even though the active config was absent")
	}
}

// Backup over an existing stale .bak must overwrite it with the current config.
func TestCorefileops_BackupOverwritesStaleBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	bak := cfg + ".bak"
	corefileops_writeFile(t, bak, []byte("STALE-OLD-BACKUP"))
	fresh := []byte("FRESH-CONFIG")
	corefileops_writeFile(t, cfg, fresh)

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() error = %v; want nil", err)
	}
	if got := corefileops_read(t, bak); string(got) != string(fresh) {
		t.Fatalf("Backup() did not overwrite stale .bak: = %q; want %q", got, fresh)
	}
}

// ---- Restore ------------------------------------------------------------------

// Restore restores the config from <config>.bak.
func TestCorefileops_RestoreFromBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	bak := cfg + ".bak"

	good := []byte("GOOD-BACKUP-CONTENTS")
	corefileops_writeFile(t, bak, good)
	// The active config currently holds a different (broken) payload.
	corefileops_writeFile(t, cfg, []byte("BROKEN-CURRENT"))

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore() error = %v; want nil", err)
	}
	if got := corefileops_read(t, cfg); string(got) != string(good) {
		t.Fatalf("Restore() did not restore backup: config = %q; want %q", got, good)
	}
}

// Restore must restore even when the active config does not yet exist (the
// failsafe path where the broken config was already removed).
func TestCorefileops_RestoreWhenActiveConfigMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json") // absent
	bak := cfg + ".bak"
	good := []byte("ONLY-THE-BACKUP-EXISTS")
	corefileops_writeFile(t, bak, good)

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore() error = %v; want nil", err)
	}
	if got := corefileops_read(t, cfg); string(got) != string(good) {
		t.Fatalf("Restore() config = %q; want %q", got, good)
	}
}

// Restore errors when there is no backup to restore from.
func TestCorefileops_RestoreErrorsWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	corefileops_writeFile(t, cfg, []byte("CURRENT"))
	// No .bak exists.

	s := New(corefileops_missingBin(t), cfg)
	err := s.Restore()
	if err == nil {
		t.Fatal("Restore() with no backup returned nil error; want an error")
	}
	if got := err.Error(); got != "no backup config to restore" {
		t.Fatalf("Restore() error = %q; want %q", got, "no backup config to restore")
	}
	// The active config must be left untouched by a failed Restore.
	if got := corefileops_read(t, cfg); string(got) != "CURRENT" {
		t.Fatalf("active config mutated by a failed Restore: = %q; want %q", got, "CURRENT")
	}
}

// ---- Commit -------------------------------------------------------------------

// Commit writes the <config>.good baseline from the active config.
func TestCorefileops_CommitWritesGoodBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	want := []byte("KNOWN-GOOD-BASELINE")
	corefileops_writeFile(t, cfg, want)

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit() error = %v; want nil", err)
	}
	good := cfg + ".good"
	if !corefileops_exists(good) {
		t.Fatalf("Commit() did not create %s", good)
	}
	if got := corefileops_read(t, good); string(got) != string(want) {
		t.Fatalf("Commit() .good contents = %q; want %q", got, want)
	}
}

// Commit is a no-op (nil error, no .good created) when the active config is absent.
func TestCorefileops_CommitIsNoOpWhenConfigAbsent(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json") // never created

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit() with no config error = %v; want nil (no-op)", err)
	}
	if corefileops_exists(cfg + ".good") {
		t.Fatal("Commit() created a .good even though the active config was absent")
	}
}

// ---- Backup -> Restore round trip ---------------------------------------------

// A full Backup then mutate then Restore must return the original bytes — the
// fail-safe rollback contract.
func TestCorefileops_BackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	original := []byte(`{"outbounds":[{"type":"direct"}]}`)
	corefileops_writeFile(t, cfg, original)

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Backup(); err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	// Apply a "new" (broken) config over the active one.
	corefileops_writeFile(t, cfg, []byte("THIS-IS-BROKEN"))
	// Roll back.
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if got := corefileops_read(t, cfg); string(got) != string(original) {
		t.Fatalf("after Backup+Restore round trip config = %q; want %q", got, original)
	}
}

// ---- copyFile -----------------------------------------------------------------

// copyFile must round-trip the exact bytes, including empty and binary payloads.
func TestCorefileops_CopyFileRoundTripsBytes(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"empty":     {},
		"text":      []byte("hello\nworld\n"),
		"binary":    {0x00, 0x01, 0xFF, 0xFE, 0x0A, 0x0D, 0x00},
		"unicode":   []byte("конфиг 配置 🛰"),
		"with-null": []byte("a\x00b\x00c"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(dir, "src-"+name)
			dst := filepath.Join(dir, "dst-"+name)
			corefileops_writeFile(t, src, data)

			if err := copyFile(src, dst); err != nil {
				t.Fatalf("copyFile error = %v; want nil", err)
			}
			got := corefileops_read(t, dst)
			if string(got) != string(data) {
				t.Fatalf("copyFile bytes = %q; want %q", got, data)
			}
		})
	}
}

// copyFile writes the destination with 0o600 perms. On Windows the Go runtime
// only honours the owner-write (read-only) bit, so we assert the mode in an
// OS-aware way: the exact 0o600 on Unix, and merely "not a directory and
// readable/writable by owner" on Windows.
func TestCorefileops_CopyFileSetsPerms(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	// Deliberately create the source world-readable so we can prove copyFile does
	// NOT inherit the source mode but always writes 0o600.
	if err := os.WriteFile(src, []byte("perm-check"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile error = %v; want nil", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if info.IsDir() {
		t.Fatal("copyFile produced a directory; want a regular file")
	}
	if runtime.GOOS == "windows" {
		// Windows: owner must at least be able to write (not read-only).
		if info.Mode().Perm()&0o200 == 0 {
			t.Fatalf("dst perms = %v; want owner-writable on Windows", info.Mode().Perm())
		}
	} else {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("dst perms = %v; want 0o600 (copyFile must not inherit the 0o644 source mode)", got)
		}
	}
}

// copyFile must error when the source does not exist.
func TestCorefileops_CopyFileErrorsOnMissingSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "does-not-exist")
	dst := filepath.Join(dir, "dst")

	if err := copyFile(src, dst); err == nil {
		t.Fatal("copyFile with a missing source returned nil error; want an error")
	}
	if corefileops_exists(dst) {
		t.Fatal("copyFile created a destination from a missing source; want none")
	}
}

// ---- Available ----------------------------------------------------------------

// Available() must be true for a binary that exists on disk (regular file),
// even if it is not on PATH — Available falls back to os.Stat.
func TestCorefileops_AvailableTrueForExistingBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sing-box"+corefileops_exeSuffix())
	// Mark it executable on Unix; on Windows the suffix is what matters.
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}

	s := New(bin, filepath.Join(dir, "config.json"))
	if !s.Available() {
		t.Fatalf("Available() = false for an existing on-disk binary %q; want true", bin)
	}
}

// Available() must be false when the bin path points at a directory (not a
// runnable file).
func TestCorefileops_AvailableFalseForDirectory(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	s := New(binDir, filepath.Join(dir, "config.json"))
	if s.Available() {
		t.Fatalf("Available() = true for a directory path %q; want false", binDir)
	}
}

// ---- CheckConfig --------------------------------------------------------------

// CheckConfig must error (without invoking any process) when the binary is
// missing, and the error must name the binary path.
func TestCorefileops_CheckConfigErrorsWhenBinaryMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	corefileops_writeFile(t, cfg, []byte("{}"))

	bin := corefileops_missingBin(t)
	s := New(bin, cfg)

	err := s.CheckConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("CheckConfig() with a missing binary returned nil error; want an error")
	}
	if got := err.Error(); !strings.Contains(got, "sing-box binary not found") {
		t.Fatalf("CheckConfig() error = %q; want it to mention the binary was not found", got)
	}
}

// Check() (which delegates to CheckConfig with the active config) must also error
// when the binary is missing.
func TestCorefileops_CheckErrorsWhenBinaryMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	corefileops_writeFile(t, cfg, []byte("{}"))

	s := New(corefileops_missingBin(t), cfg)
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("Check() with a missing binary returned nil error; want an error")
	}
}

// ---- helpers ------------------------------------------------------------------

// corefileops_missingBin returns a path inside t.TempDir() that does not exist.
func corefileops_missingBin(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-such-sing-box-binary")
}

func corefileops_exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
