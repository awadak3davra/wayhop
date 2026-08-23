package watchdog

import (
	"sync"
	"testing"
	"time"
)

// toctou_race_test.go is the regression for the SAFETY-CRITICAL TOCTOU where the
// watchdog read Desired()=true, Alive()=false, then Start() as three separate
// acquisitions of the core lock. An intentional native-only Stop() (which clears
// desired and kills the process so the kernel-PBR plane is the sole datapath)
// could be straddled by a tick and have a stale Alive()=false resurrect a
// redundant sing-box TUN core over the native datapath — a routing black-hole.
//
// The fix routes the restart through StartIfDesiredDead(), which makes the
// desired+alive check and the spawn atomic under the core's own lock. These
// tests assert (a) a Stop() racing a restart decision never resurrects the core,
// and (b) a genuine crash still restarts.

// TestStopRacingRestartNeverResurrects spins many iterations of a watchdog tick
// (which decides to crash-restart) racing a concurrent Stop() that clears
// desired. The invariant: once a Stop has happened, the core must NOT be
// resurrected — desired stays false and it is not alive. Run with -race.
func TestStopRacingRestartNeverResurrects(t *testing.T) {
	const iters = 2000
	for i := 0; i < iters; i++ {
		now := time.Unix(0, 0)
		// The core is desired + dead (a crash, from the watchdog's point of view)
		// — exactly the state in which a stale tick would call Start(). onStart
		// flips alive=true so that a WRONG resurrection (spawn after the Stop
		// cleared desired) is OBSERVABLE as desired=false + alive=true. The flip
		// happens under f.mu (spawnLocked holds it), so it's atomic w.r.t. the
		// concurrent Stop's setDesired.
		f := &fakeSup{desired: true, alive: false}
		f.onStart = func() { f.alive = true }
		w := newAt(f, &now)

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine A: the watchdog ticks (sees desired+dead, tries to restart).
		go func() {
			defer wg.Done()
			w.tick()
		}()

		// Goroutine B: an intentional native-only Stop() — atomically clears
		// desired AND kills the process (alive=false), modeling core.Stop().
		go func() {
			defer wg.Done()
			f.stop()
		}()

		wg.Wait()

		// The hard safety invariant: if the core ended up NOT desired (the Stop
		// won the race), it must NOT be alive — the watchdog must never resurrect
		// a deliberately-stopped core. Because Stop() and StartIfDesiredDead() are
		// serialized on the same lock and Stop clears desired+alive atomically, a
		// spawn can only occur while desired was still true; if Stop ran last,
		// alive is back to false. So !desired && alive is impossible unless the
		// TOCTOU resurrected the core.
		if !f.isDesired() && f.isAlive() {
			t.Fatalf("iter %d: core was resurrected after Stop() — desired=false but alive=true (started=%d)", i, f.startCount())
		}
	}
}

// TestStopBeforeTickIsNotACrashRestart models the deterministic ordering where
// the deliberate Stop() has fully completed before the tick runs. The tick must
// treat the core as intentionally down: no restart, no notify, and the backoff
// must NOT be charged (it's not a crash).
func TestStopBeforeTickIsNotACrashRestart(t *testing.T) {
	now := time.Unix(0, 0)
	// desired=false models a completed Stop(); alive=false models the killed proc.
	f := &fakeSup{desired: false, alive: false}
	w := newAt(f, &now)

	notifies := 0
	w.SetNotify(func(string) { notifies++ })

	w.tick()

	if f.startCount() != 0 {
		t.Fatalf("stopped core was (re)started %d times; want 0", f.startCount())
	}
	if notifies != 0 {
		t.Fatalf("notify fired %d times for a deliberately-stopped core; want 0", notifies)
	}
	if st := w.Stats(); st.Restarts != 0 || st.BackoffMS != 0 {
		t.Fatalf("deliberately-stopped core charged restart/backoff: %+v", st)
	}
}

// TestDeliberateStopRollsBackBackoff covers the race outcome where the tick has
// already passed the Desired() gate (saw desired=true) and the Alive() gate (saw
// dead) but the core is Stopped between then and the atomic restart decision. The
// atomic StartIfDesiredDead returns started=false, and the tick must roll back
// the backoff it optimistically charged so the stop costs nothing: no restart
// counted, no notify, backoff unchanged.
func TestDeliberateStopRollsBackBackoff(t *testing.T) {
	now := time.Unix(0, 0)
	// Pass the Desired() gate (true) and Alive() gate (false), but make the
	// atomic decision observe a Stop by clearing desired the instant the watchdog
	// is about to decide. We emulate the straddle by clearing desired inside the
	// tick via a custom supervisor wrapper.
	f := &straddleStopSup{fakeSup: fakeSup{desired: true, alive: false}}
	w := newAt(f, &now)

	notifies := 0
	w.SetNotify(func(string) { notifies++ })

	before := w.Stats()
	w.tick()
	after := w.Stats()

	if f.startCount() != 0 {
		t.Fatalf("straddled Stop still restarted the core %d times; want 0", f.startCount())
	}
	if notifies != 0 {
		t.Fatalf("straddled Stop fired %d notifies; want 0", notifies)
	}
	if after.Restarts != before.Restarts {
		t.Fatalf("restart counted for a straddled Stop: %d -> %d", before.Restarts, after.Restarts)
	}
	if after.BackoffMS != before.BackoffMS {
		t.Fatalf("backoff charged for a straddled Stop: %d -> %d ms (must roll back)", before.BackoffMS, after.BackoffMS)
	}
}

// straddleStopSup passes the Desired()/Alive() gates as desired+dead, then clears
// desired exactly when the atomic restart decision runs — modeling a Stop() that
// lands in the TOCTOU window. StartIfDesiredDead then observes desired=false and
// returns (false, nil): the deliberate-stop signal.
type straddleStopSup struct {
	fakeSup
}

func (s *straddleStopSup) StartIfDesiredDead() (bool, error) {
	s.setDesired(false) // Stop lands precisely in the decision window
	return s.fakeSup.StartIfDesiredDead()
}

// TestGenuineCrashStillRestarts is the companion invariant: a genuine crash
// (desired==true, not alive) DOES restart via the atomic path (started=true),
// recovers to alive, and is counted + notified exactly once — identical to the
// pre-fix behavior.
func TestGenuineCrashStillRestarts(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false}
	f.onStart = func() { f.alive = true } // genuine recovery on restart

	w := newAt(f, &now)
	var msgs []string
	w.SetNotify(func(m string) { msgs = append(msgs, m) })

	w.tick()

	if f.startCount() != 1 {
		t.Fatalf("genuine crash: started %d times; want exactly 1", f.startCount())
	}
	if !f.isAlive() {
		t.Fatal("genuine crash: core not alive after restart")
	}
	if !f.isDesired() {
		t.Fatal("genuine crash: core lost desired across restart")
	}
	if st := w.Stats(); st.Restarts != 1 || st.BackoffMS != 1000 {
		t.Fatalf("genuine crash: restart/backoff not recorded: %+v", st)
	}
	if len(msgs) != 1 {
		t.Fatalf("genuine crash: notify fired %d times; want 1 (%v)", len(msgs), msgs)
	}
}
