package server

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestStageExactCoreConfigWritesPrivateTemporaryFile(t *testing.T) {
	content := []byte(`{"route":{"rules":[]}}`)
	stagedPath, cleanup, err := stageExactCoreConfig(t.TempDir(), content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(stagedPath)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("staged config=%q error=%v", got, err)
	}
	info, err := os.Stat(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports the synthetic mode derived from ACLs; the router permission contract is Unix.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode=%v", info.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(stagedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup left staged config: %v", err)
	}
}
