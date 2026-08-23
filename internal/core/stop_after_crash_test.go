package core

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStopAndReloadAfterCrash is the regression for the lifecycle bug where
// Stop() returned the Kill()-on-already-dead-process error after a crash, which
// made Reload() abort without relaunching sing-box (leaving the core down — e.g.
// a failsafe rollback's reload would silently fail). Reuses the stub helpers from
// lifecycle_real_test.go.
func TestStopAndReloadAfterCrash(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// (1) Stop() after a self-crash must report success — the process is gone.
	os.Setenv("CORELIFECYCLE_CRASH", "1")
	s := New(stub, cfg)
	if err := s.Start(); err != nil {
		os.Unsetenv("CORELIFECYCLE_CRASH")
		t.Fatalf("Start() (crashing) error = %v", err)
	}
	corelifecycle_waitFor(t, "crashed process to flip Alive()=false", func() bool { return !s.Alive() })
	if err := s.Stop(); err != nil {
		os.Unsetenv("CORELIFECYCLE_CRASH")
		t.Fatalf("Stop() after crash = %v; want nil", err)
	}

	// (2) Reload() after a crash must reach Start() and relaunch a healthy process.
	s2 := New(stub, cfg)
	if err := s2.Start(); err != nil { // still crashing
		os.Unsetenv("CORELIFECYCLE_CRASH")
		t.Fatalf("Start() (crashing) error = %v", err)
	}
	corelifecycle_waitFor(t, "crashed process to flip Alive()=false", func() bool { return !s2.Alive() })
	os.Unsetenv("CORELIFECYCLE_CRASH") // the relaunch must be healthy
	if err := s2.Reload(); err != nil {
		t.Fatalf("Reload() after crash = %v; want nil (it must relaunch, not abort on Stop's Kill error)", err)
	}
	corelifecycle_waitFor(t, "Reload to relaunch Alive()=true", func() bool { return s2.Alive() })
	if !s2.Alive() {
		t.Fatal("Alive() = false after Reload() post-crash — the reload did not relaunch")
	}
	if err := s2.Stop(); err != nil {
		t.Fatalf("final Stop() = %v", err)
	}
}
