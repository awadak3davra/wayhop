package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// shutdown_gate_test.go covers Shutdown(), the daemon-teardown gate that closes the
// apply-vs-shutdown orphan race: after Shutdown() marks the supervisor "closed", no
// later Start()/StartIfDesiredDead() (e.g. from an HTTP apply handler that outlived
// httpSrv.Shutdown's deadline) may spawn a fresh core that would orphan a process
// holding the listen ports + cache.db flock.

// TestShutdown_RefusesLaterStart: once Shutdown() has run, Start() returns an error
// and spawns nothing, and StartIfDesiredDead() is a no-op.
func TestShutdown_RefusesLaterStart(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	if err := s.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)

	if err := s.Shutdown(); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if s.Alive() {
		t.Fatal("core still alive after Shutdown()")
	}

	// A late Start (the in-flight apply handler) must be refused, not spawn a new core.
	if err := s.Start(); err == nil {
		t.Fatal("Start() after Shutdown() returned nil; want a refusal error")
	}
	if s.Alive() {
		t.Fatal("Start() after Shutdown() resurrected the core — orphan not prevented")
	}

	// StartIfDesiredDead must likewise not spawn (desired was cleared by Stop, and even
	// if it were desired the closed gate in startLocked would refuse).
	started, err := s.StartIfDesiredDead()
	if err != nil {
		t.Fatalf("StartIfDesiredDead() after Shutdown() error = %v", err)
	}
	if started || s.Alive() {
		t.Fatalf("StartIfDesiredDead() after Shutdown() spawned a core (started=%v, alive=%v)", started, s.Alive())
	}
}

// TestShutdown_RaceWithStartNeverOrphans is the apply-vs-shutdown regression, run
// with -race: many iterations where a live core has Shutdown() race a concurrent
// Start() (modelling the in-flight apply handler). Both contend on s.mu, so the
// outcome is atomic — either the Start spawns first and the trailing Stop inside
// Shutdown kills it, or Shutdown's closed flag is set first and startLocked refuses.
// Either way the core must be DEAD afterwards: never an orphan survivor.
func TestShutdown_RaceWithStartNeverOrphans(t *testing.T) {
	stub := corelifecycle_buildStub(t)

	const iters = 200
	for i := 0; i < iters; i++ {
		cfg := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(stub, cfg)

		if err := s.Start(); err != nil {
			t.Fatalf("iter %d: Start() error = %v", i, err)
		}
		corelifecycle_waitFor(t, "process Alive", s.Alive)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = s.Shutdown() }()
		go func() { defer wg.Done(); _ = s.Start() }() // the racing apply handler
		wg.Wait()

		if s.Alive() {
			t.Fatalf("iter %d: core still alive after Shutdown()/Start() race — orphaned", i)
		}
	}
}
