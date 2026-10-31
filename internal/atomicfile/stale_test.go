package atomicfile

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func stale_names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// WriteOutsideDir is for a directory another program consumes entry by entry (NDM executes every
// file in netfilter.d, dnsmasq loads every file in its conf-dir). Its temp must never appear in that
// directory, not even for the duration of the write: it is staged in the parent under a dot name.
func TestWriteOutsideDir_NeverStagesInTheConsumedDirectory(t *testing.T) {
	root := t.TempDir()
	consumed := filepath.Join(root, "netfilter.d")
	if err := os.Mkdir(consumed, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(consumed, "50-hook.sh")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stagedAt string
	beforeRename = func(tmp string) {
		stagedAt = tmp
		if got := stale_names(t, consumed); len(got) != 1 || got[0] != "50-hook.sh" {
			t.Errorf("the consumed directory held %v while the write was staged", got)
		}
	}
	defer func() { beforeRename = nil }()

	if err := WriteOutsideDir(path, []byte("new"), 0o755); err != nil {
		t.Fatalf("WriteOutsideDir: %v", err)
	}
	if filepath.Dir(stagedAt) != root || !strings.HasPrefix(filepath.Base(stagedAt), ".50-hook.sh.") {
		t.Fatalf("staged at %q, want a dot name in %q", stagedAt, root)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte("new")) {
		t.Fatalf("content = %q", got)
	}
	if got := stale_names(t, root); len(got) != 1 || got[0] != "netfilter.d" {
		t.Fatalf("the staging directory kept %v", got)
	}
}

// The consumed directory belongs to the program that reads it. Creating it would make a hook look
// installed for an NDM that never runs one, so a missing directory is an error, as it was before.
func TestWriteOutsideDir_DoesNotCreateTheTargetDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "netfilter.d", "50-hook.sh")
	if err := WriteOutsideDir(path, []byte("x"), 0o755); err == nil {
		t.Fatal("WriteOutsideDir into a missing directory must fail")
	}
	if got := stale_names(t, root); len(got) != 0 {
		t.Fatalf("a failed write left %v behind", got)
	}
}

// RemoveStale deletes exactly the temps a crashed Write or WriteOutsideDir of the path can leave, and
// nothing else: not the target, not another file's temp, not a directory that happens to match.
func TestRemoveStale(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "wayhop")
	if err := os.MkdirAll(filepath.Join(dir, "profile.json.9.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	remove := []string{
		filepath.Join(dir, "profile.json.123.tmp"),
		filepath.Join(dir, "profile.json.4567.tmp"),
		filepath.Join(root, ".profile.json.123.tmp"),
	}
	keep := []string{
		filepath.Join(dir, "profile.json"),
		filepath.Join(dir, "profile.json.bak"),
		filepath.Join(dir, "profile.json.tmp"),
		filepath.Join(dir, "servers.json.123.tmp"),
		filepath.Join(root, "profile.json.123.tmp"),
	}
	for _, p := range append(append([]string{}, remove...), keep...) {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	RemoveStale(filepath.Join(dir, "profile.json"))
	for _, p := range remove {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
	for _, p := range append(keep, filepath.Join(dir, "profile.json.9.tmp")) {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must be kept: %v", p, err)
		}
	}

	// A family of targets (timestamped backups) is named by a pattern.
	backups := filepath.Join(root, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(backups, "wayhop-backup-20260101T000000Z.json.42.tmp")
	done := filepath.Join(backups, "wayhop-backup-20260101T000000Z.json")
	for _, p := range []string{orphan, done} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// RemoveStale takes its target literally: a glob character in a name never widens what it deletes.
	RemoveStale(filepath.Join(backups, "wayhop-backup-*.json"))
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("RemoveStale read its target as a pattern: %v", err)
	}
	RemoveStaleMatching(backups, "wayhop-backup-*.json.*.tmp")
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("backup temp survived: %v", err)
	}
	if _, err := os.Stat(done); err != nil {
		t.Errorf("finished backup removed: %v", err)
	}

	// A directory that does not exist yet is simply nothing to sweep.
	RemoveStale(filepath.Join(root, "absent", "x.json"))
}
