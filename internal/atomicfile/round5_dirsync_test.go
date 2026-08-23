package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirsMissing: the helper reports exactly the not-yet-existing ancestor levels (leaf-first),
// stopping at the first existing ancestor — the levels whose parents must be fsynced for durability.
func TestDirsMissing(t *testing.T) {
	base := t.TempDir() // exists
	target := filepath.Join(base, "a", "b", "c")
	want := []string{
		filepath.Join(base, "a", "b", "c"),
		filepath.Join(base, "a", "b"),
		filepath.Join(base, "a"),
	}
	got := dirsMissing(target)
	if len(got) != len(want) {
		t.Fatalf("dirsMissing = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dirsMissing[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if m := dirsMissing(base); len(m) != 0 {
		t.Errorf("dirsMissing(existing dir) = %v, want empty", m)
	}
}

// TestWrite_CreatesNestedTreeDurably: a first write into a not-yet-existing directory tree creates
// every level and writes the file — exercising the new per-level fsync path without breaking the
// functional result.
func TestWrite_CreatesNestedTreeDurably(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "x", "y", "z", "config.json")
	data := []byte(`{"ok":true}`)
	if err := Write(target, data, 0o600); err != nil {
		t.Fatalf("Write into a new tree: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(data) {
		t.Fatalf("read back = %q err=%v, want %q", got, err, data)
	}
	for _, d := range []string{"x", filepath.Join("x", "y"), filepath.Join("x", "y", "z")} {
		if fi, err := os.Stat(filepath.Join(base, d)); err != nil || !fi.IsDir() {
			t.Errorf("expected created dir %s: %v", d, err)
		}
	}
}
