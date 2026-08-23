package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// start_if_desired_dead_test.go covers StartIfDesiredDead, the atomic
// restart-decision primitive that closes the watchdog TOCTOU: a concurrent
// intentional Stop() (which clears desired and kills the process, e.g. a
// native-only apply) must never be overtaken by a stale "dead" observation that
// resurrects a redundant sing-box TUN core over the kernel-PBR datapath.

// TestStartIfDesiredDead_NoopWhenNotDesired: with desired=false (e.g. never
// started, or after Stop), it must NOT start and must NOT promote desired.
func TestStartIfDesiredDead_NoopWhenNotDesired(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	if s.Desired() {
		t.Fatal("Desired() = true before any Start; want false")
	}
	started, err := s.StartIfDesiredDead()
	if err != nil {
		t.Fatalf("StartIfDesiredDead() error = %v; want nil", err)
	}
	if started {
		t.Fatal("StartIfDesiredDead() started a non-desired core; want started=false")
	}
	if s.Desired() {
		t.Fatal("StartIfDesiredDead() promoted desired false->true; must never do that")
	}
	if s.Alive() {
		t.Fatal("Alive() = true after a no-op StartIfDesiredDead; want false")
	}
}

// TestStartIfDesiredDead_NoopWhenAlive: when the core is already up, it must be a
// no-op (no relaunch, started=false).
func TestStartIfDesiredDead_NoopWhenAlive(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	if err := s.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	first := s.StartedAt()

	started, err := s.StartIfDesiredDead()
	if err != nil {
		t.Fatalf("StartIfDesiredDead() error = %v; want nil", err)
	}
	if started {
		t.Fatal("StartIfDesiredDead() relaunched an already-alive core; want started=false")
	}
	if got := s.StartedAt(); !got.Equal(first) {
		t.Fatalf("StartedAt() changed across no-op StartIfDesiredDead: %v -> %v", first, got)
	}
}

// TestStartIfDesiredDead_RestartsGenuineCrash: desired=true but the process died
// (a real crash) — StartIfDesiredDead must relaunch it (started=true) and the
// core becomes alive again. This is the genuine-crash path the watchdog relies on.
func TestStartIfDesiredDead_RestartsGenuineCrash(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	s := New(stub, cfg)
	t.Cleanup(func() { _ = s.Stop() })

	// First launch crashes immediately; desired stays true after the crash.
	t.Setenv("CORELIFECYCLE_CRASH", "1")
	if err := s.Start(); err != nil {
		t.Fatalf("crashing Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "crashed process to flip Alive()=false", func() bool { return !s.Alive() })
	if !s.Desired() {
		t.Fatal("Desired() = false after crash; want true (watchdog must still want it up)")
	}

	// Clear the crash env so the relaunch is healthy (what the watchdog does).
	if err := os.Unsetenv("CORELIFECYCLE_CRASH"); err != nil {
		t.Fatalf("unset crash env: %v", err)
	}
	started, err := s.StartIfDesiredDead()
	if err != nil {
		t.Fatalf("StartIfDesiredDead() error = %v; want nil", err)
	}
	if !started {
		t.Fatal("StartIfDesiredDead() did not restart a genuine crash; want started=true")
	}
	corelifecycle_waitFor(t, "recovered process Alive", s.Alive)
	if !s.Alive() || !s.Desired() {
		t.Fatal("after StartIfDesiredDead the core must be Alive() and Desired()")
	}
}

// TestStartIfDesiredDead_RaceWithStopNeverResurrects is the core-level TOCTOU
// regression. Many iterations: a crashed-but-desired core has Stop() race
// StartIfDesiredDead(). Both contend on the SAME core mutex, so the decision is
// atomic — once Stop() clears desired (and kills the proc), the core must NOT be
// resurrected: it stays not-desired and not-alive. Run with -race.
func TestStartIfDesiredDead_RaceWithStopNeverResurrects(t *testing.T) {
	stub := corelifecycle_buildStub(t)

	const iters = 200
	for i := 0; i < iters; i++ {
		cfg := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(stub, cfg)

		// Put the core into "desired but dead" by crashing the launch — the exact
		// state in which a stale watchdog tick would try to restart.
		t.Setenv("CORELIFECYCLE_CRASH", "1")
		if err := s.Start(); err != nil {
			t.Fatalf("iter %d: crashing Start() error = %v", i, err)
		}
		corelifecycle_waitFor(t, "crashed process dead", func() bool { return !s.Alive() })
		// From here the relaunch (if any) would be HEALTHY (blocks forever), so a
		// wrongful resurrection is observable as a live process after Stop.
		os.Unsetenv("CORELIFECYCLE_CRASH")

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = s.StartIfDesiredDead() }()
		go func() { defer wg.Done(); _ = s.Stop() }()
		wg.Wait()

		// Whatever the interleaving, Stop and StartIfDesiredDead are serialized on
		// s.mu. If StartIfDesiredDead won, it spawned while desired was still true,
		// and the trailing Stop() then cleared desired AND killed it. If Stop won,
		// StartIfDesiredDead saw desired=false and refused. Either way: a core that
		// is NOT desired must NOT be alive.
		if !s.Desired() && s.Alive() {
			t.Fatalf("iter %d: core resurrected over an intentional Stop() — desired=false but alive=true", i)
		}

		// Belt-and-braces: a final Stop must leave it down regardless.
		if err := s.Stop(); err != nil {
			t.Fatalf("iter %d: final Stop() = %v", i, err)
		}
		if s.Alive() {
			t.Fatalf("iter %d: core still alive after final Stop()", i)
		}
	}
}
