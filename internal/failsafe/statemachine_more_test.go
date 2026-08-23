package failsafe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// failsafe_newMgr builds a Manager with short, deterministic durations for
// driving tick() directly. Times below are expressed in the same units the
// state machine uses internally (RollbackAfter etc. are converted to ms, while
// tick() is called with explicit "now" values also interpreted as ms).
func failsafe_newMgr() *Manager {
	return New(Durations{
		Grace:         0,
		Interval:      time.Millisecond,
		RollbackAfter: 1000 * time.Millisecond,
		RebootAfter:   3000 * time.Millisecond,
		KeepWindow:    2000 * time.Millisecond,
	})
}

// failsafe_armForTick puts a freshly-built manager into the pending/armed state
// without spawning the background run() goroutine, so tick() can be driven
// deterministically. deadline is a "now" value (ms) past which a healthy router
// is left live-unsaved.
func failsafe_armForTick(m *Manager, deadline int64, rb func() error) {
	m.mu.Lock()
	m.pending = true
	m.phase = "armed"
	m.rolledBack = false
	m.bad = false
	m.badSince = 0
	m.deadline = deadline
	m.rollback = rb
	m.mu.Unlock()
}

// failsafe_counter is a tiny concurrency-safe call counter.
type failsafe_counter struct{ n int32 }

func (c *failsafe_counter) inc()       { atomic.AddInt32(&c.n, 1) }
func (c *failsafe_counter) get() int32 { return atomic.LoadInt32(&c.n) }

// --- Confirm cancels a pending rollback -------------------------------------

func TestFailsafe_ConfirmCancelsRollback(t *testing.T) {
	m := failsafe_newMgr()
	var rb failsafe_counter
	failsafe_armForTick(m, 100000, func() error { rb.inc(); return nil })

	// One bad tick (degraded, but well before RollbackAfter).
	if a := m.tick(0, false); a != ActNone {
		t.Fatalf("first bad tick -> %v, want ActNone", a)
	}
	if got := m.Status().Phase; got != "degraded" {
		t.Fatalf("phase after first bad -> %q, want degraded", got)
	}

	// User confirms the config works -> window is cancelled.
	m.Confirm()
	if s := m.Status(); s.Pending || s.Phase != "committed" {
		t.Fatalf("after Confirm: pending=%v phase=%q, want false/committed", s.Pending, s.Phase)
	}

	// Even if connectivity stays bad long past RollbackAfter, no rollback fires
	// because the window is no longer pending.
	if a := m.tick(5000, false); a != ActNone {
		t.Fatalf("tick after Confirm -> %v, want ActNone", a)
	}
	if rb.get() != 0 {
		t.Fatalf("rollback called %d times after Confirm, want 0", rb.get())
	}
}

// --- Bad past the window triggers rollback exactly once ----------------------

func TestFailsafe_BadTriggersRollbackExactlyOnce(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 100000, nil)

	// Before the window: no rollback.
	if a := m.tick(0, false); a != ActNone {
		t.Fatalf("t=0 first bad -> %v, want ActNone", a)
	}
	if a := m.tick(500, false); a != ActNone {
		t.Fatalf("t=500 badFor=500 (<1000) -> %v, want ActNone", a)
	}
	if a := m.tick(999, false); a != ActNone {
		t.Fatalf("t=999 badFor=999 (<1000) -> %v, want ActNone", a)
	}
	if m.Status().Phase != "degraded" {
		t.Fatalf("phase before rollback -> %q, want degraded", m.Status().Phase)
	}

	// Exactly at the boundary: rollback fires.
	if a := m.tick(1000, false); a != ActRollback {
		t.Fatalf("t=1000 badFor=1000 -> %v, want ActRollback", a)
	}
	if !m.rolledBack {
		t.Fatal("expected rolledBack=true after ActRollback")
	}
	if m.Status().Phase != "rolled_back" {
		t.Fatalf("phase after rollback -> %q, want rolled_back", m.Status().Phase)
	}

	// Still bad afterwards: must NOT roll back a second time (only ActNone until
	// the reboot threshold).
	if a := m.tick(1500, false); a != ActNone {
		t.Fatalf("t=1500 post-rollback still bad -> %v, want ActNone (no 2nd rollback)", a)
	}
	if a := m.tick(2999, false); a != ActNone {
		t.Fatalf("t=2999 badFor<reboot -> %v, want ActNone", a)
	}
}

// --- No rollback fires before the window ------------------------------------

func TestFailsafe_NoRollbackBeforeWindow(t *testing.T) {
	m := failsafe_newMgr()
	var rb failsafe_counter
	failsafe_armForTick(m, 100000, func() error { rb.inc(); return nil })

	// Drive many bad ticks that all stay just under RollbackAfter via a fresh
	// badSince each time would be wrong; instead keep a continuous bad streak
	// but stop one tick short of the boundary.
	for _, now := range []int64{0, 200, 400, 600, 800, 999} {
		if a := m.tick(now, false); a != ActNone {
			t.Fatalf("tick(now=%d, bad) -> %v, want ActNone (before window)", now, a)
		}
	}
	if rb.get() != 0 {
		t.Fatalf("rollback fired before window: %d times, want 0", rb.get())
	}
}

// --- A recovering router resets the bad streak ------------------------------

func TestFailsafe_RecoveryResetsBadStreak(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 100000, nil)

	if a := m.tick(0, false); a != ActNone { // bad starts at t=0
		t.Fatalf("t=0 -> %v", a)
	}
	if a := m.tick(900, true); a != ActNone { // recovers just before rollback
		t.Fatalf("t=900 recovered -> %v, want ActNone", a)
	}
	if m.bad || m.badSince != 0 {
		t.Fatalf("recovery did not reset streak: bad=%v badSince=%d", m.bad, m.badSince)
	}
	// Bad again: the badFor clock restarts from t=1000, so 1900 (=900 elapsed)
	// is still under RollbackAfter and must NOT roll back.
	if a := m.tick(1000, false); a != ActNone {
		t.Fatalf("t=1000 bad restart -> %v", a)
	}
	if a := m.tick(1900, false); a != ActNone {
		t.Fatalf("t=1900 badFor=900 after restart -> %v, want ActNone", a)
	}
	// Crossing the new boundary rolls back.
	if a := m.tick(2000, false); a != ActRollback {
		t.Fatalf("t=2000 badFor=1000 after restart -> %v, want ActRollback", a)
	}
}

// --- RollbackNow is immediate -----------------------------------------------

func TestFailsafe_RollbackNowImmediate(t *testing.T) {
	m := failsafe_newMgr()
	var rb failsafe_counter
	failsafe_armForTick(m, 100000, func() error { rb.inc(); return nil })

	if err := m.RollbackNow(); err != nil {
		t.Fatalf("RollbackNow returned err: %v", err)
	}
	if rb.get() != 1 {
		t.Fatalf("RollbackNow called rollback %d times, want 1", rb.get())
	}
	s := m.Status()
	if s.Pending {
		t.Fatalf("RollbackNow left pending=true, want false")
	}
	if s.Phase != "rolled_back" {
		t.Fatalf("RollbackNow phase=%q, want rolled_back", s.Phase)
	}
	if !m.rolledBack {
		t.Fatal("RollbackNow did not set rolledBack=true")
	}
}

func TestFailsafe_RollbackNowNilRollbackIsSafe(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 100000, nil) // no rollback func installed
	if err := m.RollbackNow(); err != nil {
		t.Fatalf("RollbackNow with nil rollback -> err %v, want nil", err)
	}
	if s := m.Status(); s.Pending || s.Phase != "rolled_back" {
		t.Fatalf("RollbackNow(nil): pending=%v phase=%q", s.Pending, s.Phase)
	}
}

// --- Status reflects armed / disarmed / remaining ---------------------------

func TestFailsafe_StatusRemainingWhilePending(t *testing.T) {
	m := failsafe_newMgr()
	// Deadline ~30s in the future (Status uses real wall clock via nowMS()).
	failsafe_armForTick(m, nowMS()+30000, nil)
	s := m.Status()
	if !s.Pending {
		t.Fatal("Status.Pending=false while armed, want true")
	}
	if s.SecondsLeft <= 0 || s.SecondsLeft > 30 {
		t.Fatalf("SecondsLeft=%d, want in (0,30]", s.SecondsLeft)
	}
}

func TestFailsafe_StatusNoRemainingPastDeadline(t *testing.T) {
	m := failsafe_newMgr()
	// Deadline already in the past -> no positive countdown.
	failsafe_armForTick(m, nowMS()-5000, nil)
	if s := m.Status(); s.SecondsLeft != 0 {
		t.Fatalf("past-deadline SecondsLeft=%d, want 0", s.SecondsLeft)
	}
}

func TestFailsafe_StatusNoRemainingAfterRollback(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, nowMS()+30000, nil)
	_ = m.RollbackNow()
	s := m.Status()
	// After rollback the window is no longer pending and SecondsLeft must be 0.
	if s.SecondsLeft != 0 {
		t.Fatalf("after rollback SecondsLeft=%d, want 0", s.SecondsLeft)
	}
	if s.Pending {
		t.Fatalf("after rollback Pending=%v, want false", s.Pending)
	}
}

func TestFailsafe_StatusFreshManagerIdle(t *testing.T) {
	m := failsafe_newMgr()
	s := m.Status()
	if s.Pending {
		t.Fatalf("fresh manager Pending=%v, want false", s.Pending)
	}
	if s.Phase != "idle" {
		t.Fatalf("fresh manager phase=%q, want idle", s.Phase)
	}
	if s.SecondsLeft != 0 {
		t.Fatalf("fresh manager SecondsLeft=%d, want 0", s.SecondsLeft)
	}
}

func TestFailsafe_StatusTracksLastCheck(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 100000, nil)
	m.tick(4242, false)
	s := m.Status()
	if s.LastCheckOk {
		t.Fatalf("LastCheckOk=%v after bad tick, want false", s.LastCheckOk)
	}
	if s.LastCheckAt != 4242 {
		t.Fatalf("LastCheckAt=%d, want 4242", s.LastCheckAt)
	}
	m.tick(5555, true)
	s = m.Status()
	if !s.LastCheckOk {
		t.Fatalf("LastCheckOk=%v after good tick, want true", s.LastCheckOk)
	}
	if s.LastCheckAt != 5555 {
		t.Fatalf("LastCheckAt=%d, want 5555", s.LastCheckAt)
	}
}

// --- Auto-reboot path is OFF unless explicitly enabled ----------------------

// tick() itself returns ActReboot once the reboot threshold passes regardless of
// allowReboot; the GATE lives in run(). These two tests verify both halves: the
// pure decision, and that run() only invokes reboot() when allowReboot is true.

func TestFailsafe_TickReturnsRebootAtThreshold(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 100000, nil)
	m.tick(0, false)
	m.tick(1000, false) // rollback
	if a := m.tick(3000, false); a != ActReboot {
		t.Fatalf("t=3000 badFor=3000 -> %v, want ActReboot", a)
	}
	if m.Status().Phase != "reboot" {
		t.Fatalf("phase after reboot threshold -> %q, want reboot", m.Status().Phase)
	}
}

func TestFailsafe_RebootSuppressedWhenDisabled(t *testing.T) {
	// Drive the real Arm/run loop with connectivity permanently bad and
	// allowReboot=false. The loop must rollback (if any) and reach the reboot
	// decision, but reboot() must never be invoked.
	d := Durations{
		Grace:         0,
		Interval:      time.Millisecond,
		RollbackAfter: 5 * time.Millisecond,
		RebootAfter:   20 * time.Millisecond,
		KeepWindow:    time.Hour, // never goes live on its own
	}
	m := New(d)

	var rebootCalls failsafe_counter
	var rollbackCalls failsafe_counter
	check := func() bool { return false } // always bad

	m.Arm(
		check,
		func() error { rollbackCalls.inc(); return nil },
		func() { rebootCalls.inc() },
		false, // allowReboot OFF
	)

	// Wait until the loop terminates (pending=false) by polling Status. The
	// reboot branch in run() returns after the decision, clearing nothing else,
	// so we detect completion via phase=="reboot".
	deadline := time.Now().Add(2 * time.Second)
	for {
		if m.Status().Phase == "reboot" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run() did not reach reboot phase in time; phase=%q", m.Status().Phase)
		}
		time.Sleep(time.Millisecond)
	}
	// Give the loop a moment to have returned past the (suppressed) reboot call.
	time.Sleep(20 * time.Millisecond)

	if rebootCalls.get() != 0 {
		t.Fatalf("reboot() called %d times with allowReboot=false, want 0", rebootCalls.get())
	}
	if rollbackCalls.get() == 0 {
		t.Fatal("expected at least one rollback before the reboot decision")
	}
}

func TestFailsafe_RebootInvokedWhenEnabled(t *testing.T) {
	// Same loop but allowReboot=true: reboot() must be invoked exactly once.
	d := Durations{
		Grace:         0,
		Interval:      time.Millisecond,
		RollbackAfter: 5 * time.Millisecond,
		RebootAfter:   20 * time.Millisecond,
		KeepWindow:    time.Hour,
	}
	m := New(d)

	var rebootCalls failsafe_counter
	done := make(chan struct{})
	var once sync.Once
	check := func() bool { return false }

	m.Arm(
		check,
		func() error { return nil },
		func() { rebootCalls.inc(); once.Do(func() { close(done) }) },
		true, // allowReboot ON
	)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("reboot() not invoked with allowReboot=true; phase=%q", m.Status().Phase)
	}
	// Allow any spurious extra invocation to surface, then assert exactly one.
	time.Sleep(20 * time.Millisecond)
	if got := rebootCalls.get(); got != 1 {
		t.Fatalf("reboot() called %d times, want exactly 1", got)
	}
}

// --- Healthy router left live-unsaved after the keep window -----------------

func TestFailsafe_HealthyGoesLiveUnsavedExactlyOnce(t *testing.T) {
	m := failsafe_newMgr()
	failsafe_armForTick(m, 2000, nil) // deadline at now=2000

	if a := m.tick(500, true); a != ActNone {
		t.Fatalf("t=500 healthy pre-deadline -> %v, want ActNone", a)
	}
	if a := m.tick(1999, true); a != ActNone {
		t.Fatalf("t=1999 healthy pre-deadline -> %v, want ActNone", a)
	}
	if a := m.tick(2000, true); a != ActDone {
		t.Fatalf("t=2000 healthy at deadline -> %v, want ActDone", a)
	}
	if m.Status().Phase != "live_unsaved" {
		t.Fatalf("phase -> %q, want live_unsaved", m.Status().Phase)
	}
	// Window is closed now; further ticks are no-ops.
	if a := m.tick(2500, true); a != ActNone {
		t.Fatalf("post-close tick -> %v, want ActNone", a)
	}
}

// --- A non-pending manager ignores ticks ------------------------------------

func TestFailsafe_TickIgnoredWhenNotPending(t *testing.T) {
	m := failsafe_newMgr() // never armed, pending=false
	if a := m.tick(1000, false); a != ActNone {
		t.Fatalf("tick on idle manager -> %v, want ActNone", a)
	}
	if a := m.tick(9999, true); a != ActNone {
		t.Fatalf("tick on idle manager (ok) -> %v, want ActNone", a)
	}
}

// --- DefaultDurations sanity ------------------------------------------------

func TestFailsafe_DefaultDurationsOrdering(t *testing.T) {
	d := DefaultDurations()
	if !(d.Grace > 0 && d.Interval > 0) {
		t.Fatalf("grace/interval must be positive: %+v", d)
	}
	if !(d.RollbackAfter < d.RebootAfter) {
		t.Fatalf("RollbackAfter(%v) must be < RebootAfter(%v)", d.RollbackAfter, d.RebootAfter)
	}
	if d.KeepWindow <= 0 {
		t.Fatalf("KeepWindow must be positive, got %v", d.KeepWindow)
	}
}

// The keep window is how long a new configuration must stay healthy before the fail-safe stops
// watching it. Every other tick test sets m.deadline by hand, so nothing exercised the one place it
// is computed — Arm — and a mutation setting it to `now` (disarming on the first healthy tick)
// passed the whole suite. A config that looks fine for one second and dies after ten would then be
// declared live with the rollback already given up.
func TestArm_KeepWindowIsAppliedAndHonoured(t *testing.T) {
	d := Durations{
		Grace:         0,
		Interval:      time.Hour, // the background loop must not tick during this test
		RollbackAfter: time.Second,
		RebootAfter:   3 * time.Second,
		KeepWindow:    30 * time.Second,
	}
	// Arm sets its fields before spawning the watcher, so reading them straight back is
	// deterministic. Driving tick() on this same manager afterwards is NOT: the watcher is running,
	// and a first version of this test did exactly that — it passed twice locally and failed in the
	// suite, which is a flake I introduced into the one package whose job is to be trustworthy.
	// The consequence is checked below on a manager with no watcher at all.
	m := New(d)
	m.Arm(func() bool { return true }, func() error { return nil }, nil, false)

	m.mu.Lock()
	armedAt, deadline := m.armedAt, m.deadline
	m.mu.Unlock()

	if got := deadline - armedAt; got != int64(d.KeepWindow/time.Millisecond) {
		t.Fatalf("keep window is %dms after arming, want %dms", got, int64(d.KeepWindow/time.Millisecond))
	}

	// And the consequence, which is what actually matters: healthy INSIDE the window keeps watching,
	// healthy at the end of it concludes. Driven on a manager armed by hand, so nothing else ticks.
	q := failsafe_newMgr()
	failsafe_armForTick(q, 30000, func() error { return nil })
	if a := q.tick(1, true); a != ActNone {
		t.Errorf("a healthy check one millisecond in returned %v; the window had 30s left and the "+
			"fail-safe should still be watching", a)
	}
	if a := q.tick(30000, true); a != ActDone {
		t.Errorf("a healthy check at the end of the keep window returned %v, want ActDone", a)
	}
}
