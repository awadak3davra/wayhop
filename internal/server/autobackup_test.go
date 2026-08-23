package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAutoBackup_WriteRestorablePruneAndDefaultOff: writeAutoBackup produces a restore-
// compatible bundle, retains only the newest KeepN, and auto-backup is OFF by default.
func TestAutoBackup_WriteRestorablePruneAndDefaultOff(t *testing.T) {
	s, _ := backup_newServer(t)

	// Default: auto-backup disabled (opt-in). A fresh config must not schedule backups.
	if got := s.config().Backup.AutoHours; got != 0 {
		t.Fatalf("auto-backup must be OFF by default, got AutoHours=%d", got)
	}

	dir := filepath.Join(t.TempDir(), "backups")
	s.cfg.Backup.Dir = dir
	s.cfg.Backup.KeepN = 3

	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var paths []string
	for i := 0; i < 5; i++ {
		p, err := s.writeAutoBackup(base.Add(time.Duration(i) * time.Minute))
		if err != nil {
			t.Fatalf("writeAutoBackup[%d]: %v", i, err)
		}
		paths = append(paths, p)
	}

	// The newest file is a valid, restore-compatible bundle (right schema marker).
	data, err := os.ReadFile(paths[4])
	if err != nil {
		t.Fatalf("read newest backup: %v", err)
	}
	var b backupBundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("newest backup is not a valid bundle: %v", err)
	}
	if b.Schema != backupSchemaVersion {
		t.Errorf("bundle schema = %d, want %d", b.Schema, backupSchemaVersion)
	}

	// Retention: only the newest KeepN=3 survive; the 2 oldest are pruned.
	remaining, _ := filepath.Glob(filepath.Join(dir, "wayhop-backup-*.json"))
	if len(remaining) != 3 {
		t.Fatalf("after prune: %d backups, want 3", len(remaining))
	}
	for _, gone := range paths[:2] {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("expected pruned backup to be gone: %s (err=%v)", gone, err)
		}
	}
	for _, kept := range paths[2:] {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("expected retained backup to exist: %s (err=%v)", kept, err)
		}
	}
}

// TestPruneBackups_NeverDeletesJustWritten: a backward wall-clock step (NTP correction)
// can make the just-written backup have both the oldest timestamp NAME and the oldest
// modtime. pruneBackups must still keep it — pruning it would delete the freshest,
// most-restorable snapshot while retaining stale ones.
func TestPruneBackups_NeverDeletesJustWritten(t *testing.T) {
	dir := t.TempDir()
	justWritten := filepath.Join(dir, "wayhop-backup-20260101T110000Z.json") // name + modtime OLDEST
	middle := filepath.Join(dir, "wayhop-backup-20260101T120000Z.json")
	newest := filepath.Join(dir, "wayhop-backup-20260101T130000Z.json")
	for _, p := range []string{justWritten, middle, newest} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	// justWritten is the oldest by modtime too (the clock was stepped back before it was written).
	_ = os.Chtimes(justWritten, base, base)
	_ = os.Chtimes(middle, base.Add(time.Hour), base.Add(time.Hour))
	_ = os.Chtimes(newest, base.Add(2*time.Hour), base.Add(2*time.Hour))

	pruneBackups(dir, 1, justWritten) // keep only 1 (+ always the just-written)

	if _, err := os.Stat(justWritten); err != nil {
		t.Errorf("just-written backup was pruned despite the exemption: %v", err)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Errorf("newest-by-modtime backup should be the kept slot: %v", err)
	}
	if _, err := os.Stat(middle); !os.IsNotExist(err) {
		t.Errorf("middle backup should have been pruned (keep=1, not the just-written), stat err = %v", err)
	}
}
