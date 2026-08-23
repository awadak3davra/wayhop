package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pruneBackups used to order candidates by file MTIME. That is the wrong key twice over: its
// granularity on a router's jffs2/overlayfs is one second, so two backups written in the same
// second compared equal and sort.Slice — which is not stable — made "newest" arbitrary; and mtime
// tracks the last write rather than the backup's content, so restoring or copying an old file makes
// it look newest. Either way prune could delete the NEWEST backup and keep an older one.

func writeBackup(t *testing.T, dir, stamp string, mod time.Time) string {
	t.Helper()
	p := filepath.Join(dir, "wayhop-backup-"+stamp+".json")
	if err := os.WriteFile(p, []byte(`{"stamp":"`+stamp+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPruneBackups_KeepsTheNewestByNameNotByMtime(t *testing.T) {
	dir := t.TempDir()
	// Every file shares ONE mtime — exactly what a coarse-granularity filesystem produces.
	same := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	oldest := writeBackup(t, dir, "20260102T030405Z", same)
	middle := writeBackup(t, dir, "20260102T030505Z", same)
	newest := writeBackup(t, dir, "20260102T030605Z", same)

	pruneBackups(dir, 2, "")

	if _, err := os.Stat(newest); err != nil {
		t.Errorf("the newest backup was pruned: %v", err)
	}
	if _, err := os.Stat(middle); err != nil {
		t.Errorf("the second-newest backup was pruned: %v", err)
	}
	if _, err := os.Stat(oldest); err == nil {
		t.Error("the oldest backup should have been pruned")
	}
}

// mtime that CONTRADICTS the name must not win: an old backup that was touched or copied is still
// an old backup.
func TestPruneBackups_IgnoresAMisleadingMtime(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	oldest := writeBackup(t, dir, "20260102T030405Z", fresh) // touched recently, still the oldest
	newest := writeBackup(t, dir, "20260102T030605Z", old)   // written first, still the newest

	pruneBackups(dir, 1, "")

	if _, err := os.Stat(newest); err != nil {
		t.Errorf("the newest backup by name was pruned because an older one had a fresher mtime: %v", err)
	}
	if _, err := os.Stat(oldest); err == nil {
		t.Error("the oldest backup by name should have been pruned")
	}
}

// The file just written is always kept, whatever the ordering says.
func TestPruneBackups_AlwaysKeepsTheFileJustWritten(t *testing.T) {
	dir := t.TempDir()
	same := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	justWritten := writeBackup(t, dir, "20260101T000000Z", same) // deliberately the OLDEST name
	writeBackup(t, dir, "20260102T030505Z", same)
	writeBackup(t, dir, "20260102T030605Z", same)

	pruneBackups(dir, 1, justWritten)

	if _, err := os.Stat(justWritten); err != nil {
		t.Errorf("the file just written must never be pruned: %v", err)
	}
}

// A name the pattern does not recognise must still sort sanely rather than being pruned first.
func TestPruneBackups_UnparseableNameFallsBackToMtime(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	odd := filepath.Join(dir, "wayhop-backup-custom.json")
	if err := os.WriteFile(odd, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(odd, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	writeBackup(t, dir, "20260102T030405Z", old)

	pruneBackups(dir, 1, "")

	if _, err := os.Stat(odd); err != nil {
		t.Errorf("an unrecognised name with the freshest mtime should have been kept: %v", err)
	}
}
