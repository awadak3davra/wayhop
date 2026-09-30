package keenetic

import (
	"os"
	"path/filepath"
	"testing"
)

// --- bug #13: an existing-but-UNREADABLE original config.json must ABORT staging, not be overwritten
// without a rollback snapshot (which would make RestoreSingboxConfig a permanent no-op). ---

func TestStageSingboxConfig_UnreadableOriginalAborts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// Make config.json a DIRECTORY: os.Stat succeeds (it exists) but os.ReadFile fails with a
	// non-ENOENT error, exercising the "original exists but is unreadable" branch portably.
	if err := os.Mkdir(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	err := StageSingboxConfig(map[string]any{"inbounds": []any{}}, SingboxStageOptions{ConfigPath: cfgPath})
	if err == nil {
		t.Fatal("staging must ABORT when the original config exists but is unreadable (else it overwrites with no rollback snapshot)")
	}
	if _, serr := os.Stat(cfgPath + ".wr-orig"); !os.IsNotExist(serr) {
		t.Errorf("no snapshot must be written when the original is unreadable")
	}
}
