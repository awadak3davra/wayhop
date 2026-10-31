package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"wayhop/internal/core"
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

// coreStep must replace the live sing-box config by rename, never truncate it and write in place: a
// power cut or kill between the truncate and the fsync left a zero-length or torn config, and an
// ENOSPC partway through destroyed the only on-disk copy while the old core kept running from memory,
// so the next scheduled restart read a broken file.
func TestCoreStep_ReplacesTheLiveConfigInsteadOfTruncatingIt(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(bin, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "singbox.json")
	if err := os.WriteFile(cfgPath, []byte(`{"log":{"level":"warn"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := pbrhook_identity(t, cfgPath)

	s := &Server{singbox: core.New(bin, cfgPath)}
	// A cancelled context stops coreStep right after the write, before it would start the stub binary.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	next := []byte(`{"log":{"level":"info"}}`)
	err := s.coreStep(ctx, executionCoreArtifactV1{
		Action: ExecutionEnsurePresent, BinaryPath: bin, ConfigPath: cfgPath, Config: next,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("coreStep = %v, want it to stop at the cancelled context after writing", err)
	}
	if got, _ := os.ReadFile(cfgPath); !bytes.Equal(got, next) {
		t.Fatalf("live config = %q, want %q", got, next)
	}
	if os.SameFile(before, pbrhook_identity(t, cfgPath)) {
		t.Fatal("the live config was truncated and rewritten in place, not replaced by rename")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("the write left something beside the config: %v", entries)
	}
}

// A power cut or kill while a config was being staged leaves its temp beside the live config for good:
// `sing-box check`'s candidate, or a half-written replacement of the config or its fail-safe copies,
// each a full config with endpoint keys. Boot sweeps them before anything can write there again.
func TestStartApply_SweepsCoreConfigTempsACrashLeftBehind(t *testing.T) {
	s, _ := applytest_server(t)
	dir := filepath.Dir(s.cfg.SingBox.Config)
	orphans := []string{
		".wayhop-core-check-123456",
		"singbox.json.123456.tmp",
		"singbox.json.bak.123456.tmp",
		"singbox.json.good.123456.tmp",
	}
	keep := []string{"singbox.json", "singbox.json.bak", "other.json.123456.tmp"}
	for _, name := range append(append([]string{}, orphans...), keep...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // only the synchronous part of StartApply runs
	s.StartApply(ctx, filepath.Join(s.applyStateDir, "config.json"))

	for _, name := range orphans {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived boot: %v", name, err)
		}
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is not a temp and must be kept: %v", name, err)
		}
	}
}
