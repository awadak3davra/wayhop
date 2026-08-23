package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Backup writes the fail-safe's ONLY rollback target. handleApply reacts carefully to a Backup
// error — it records it, logs that the fail-safe may be unable to restore, and surfaces it — but
// Backup used to return nil whenever os.Stat failed for ANY reason, so none of that could fire.
// A router that could not be snapshotted reported the same as one that was.

func backupCore(t *testing.T) (*SingBox, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "singbox.json")
	return New(filepath.Join(dir, "no-such-binary"), cfg), cfg
}

// The legitimate case: no live config yet, so there is genuinely nothing to snapshot.
func TestBackup_NoConfigYetIsNotAnError(t *testing.T) {
	sb, _ := backupCore(t)
	if err := sb.Backup(); err != nil {
		t.Fatalf("a first apply has nothing to back up; that is not a failure: %v", err)
	}
}

func TestBackup_SnapshotsAndVerifies(t *testing.T) {
	sb, cfg := backupCore(t)
	if err := os.WriteFile(cfg, []byte(`{"log":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sb.Backup(); err != nil {
		t.Fatalf("backup of a readable config should succeed: %v", err)
	}
	st, err := os.Stat(cfg + ".bak")
	if err != nil {
		t.Fatalf("backup reported success but no snapshot exists: %v", err)
	}
	if st.Size() == 0 {
		t.Error("backup reported success but the snapshot is empty")
	}
	// And it must actually be restorable — the whole point of taking it.
	if err := sb.Restore(); err != nil {
		t.Errorf("restore of the snapshot Backup just took failed: %v", err)
	}
}

// A stat failure that is NOT "the file does not exist" means we could not tell whether a snapshot
// is possible. That must reach the caller, not be reported as a completed backup.
//
// Tested through the pure verdict rather than the filesystem: EACCES/EIO cannot be produced on the
// Windows dev box, and the earlier version of this test SKIPPED there — proving nothing on the
// machine actually running it.
func TestBackupStatVerdict_SeparatesAbsentFromUnreadable(t *testing.T) {
	if err := backupStatVerdict(nil); err != nil {
		t.Errorf("a successful stat is not a failure: %v", err)
	}
	if err := backupStatVerdict(os.ErrNotExist); err != nil {
		t.Errorf("no config yet means nothing to snapshot, not an error: %v", err)
	}
	if err := backupStatVerdict(fmt.Errorf("wrapped: %w", os.ErrNotExist)); err != nil {
		t.Errorf("a wrapped ErrNotExist must still read as absent: %v", err)
	}
	for _, e := range []error{os.ErrPermission, errors.New("input/output error"), syscall.EACCES} {
		if err := backupStatVerdict(e); err == nil {
			t.Errorf("%v means the snapshot could not be verified — it must not report success", e)
		}
	}
}

// The path that matters most: after a successful Backup, Restore must bring the ORIGINAL bytes
// back, so a rollback lands on the config the user actually had.
func TestBackup_RestoreReturnsTheOriginalBytes(t *testing.T) {
	sb, cfg := backupCore(t)
	original := []byte(`{"log":{"level":"info"},"marker":"original"}`)
	if err := os.WriteFile(cfg, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sb.Backup(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(`{"marker":"replaced"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sb.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("rollback landed on the wrong config:\n got %s\nwant %s", got, original)
	}
}

// Restoring with no snapshot must fail loudly: silently leaving the bad config in place is how a
// router stays on a configuration nobody chose.
func TestRestore_WithNoSnapshotFails(t *testing.T) {
	sb, _ := backupCore(t)
	if err := sb.Restore(); err == nil {
		t.Fatal("restore with no backup reported success")
	}
}
