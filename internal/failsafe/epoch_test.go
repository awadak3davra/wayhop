package failsafe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// quietDurations keeps a run() goroutine parked in its grace timer for the duration of
// a test, so Arm's goroutines never fire on their own — we exercise the epoch primitives
// directly. Confirm()/a superseding Arm cancels the ctx, so the parked goroutine exits.
func quietDurations() Durations {
	return Durations{Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour}
}

// TestEpochSupersedeGating locks the primitives behind the stale-fire fix: every Arm bumps
// the epoch, IsCurrent tracks only the latest window, and a superseded window can win
// neither claimRollback nor claimReboot — while the current window claims its rollback
// exactly once (fire-once preserved).
func TestEpochSupersedeGating(t *testing.T) {
	m := New(quietDurations())
	noop := func() bool { return true }
	noRb := func() error { return nil }

	eA := m.Arm(noop, noRb, func() {}, false)
	if !m.IsCurrent(eA) {
		t.Fatalf("freshly-armed epoch %d should be current", eA)
	}
	eB := m.Arm(noop, noRb, func() {}, false)
	if eB <= eA {
		t.Fatalf("a re-Arm must advance the epoch: got %d, prior %d", eB, eA)
	}
	if m.IsCurrent(eA) {
		t.Fatal("a superseded window must not be current")
	}
	if !m.IsCurrent(eB) {
		t.Fatal("the latest window should be current")
	}
	// A superseded window's run() can claim neither side effect.
	if m.claimRollback(eA) {
		t.Fatal("a superseded window must not win claimRollback")
	}
	if m.claimReboot(eA) {
		t.Fatal("a superseded window must not win claimReboot")
	}
	// The current window claims its rollback once, then never again (fire-once).
	if !m.claimRollback(eB) {
		t.Fatal("the current window should win the first claimRollback")
	}
	if m.claimRollback(eB) {
		t.Fatal("claimRollback must fire at most once per window")
	}
	m.Confirm()
}

// TestStaleRollbackSkipsAfterSupersede drives the exact clobber interleaving deterministically:
// window B applies and re-Arms (under applyMu, as the server's handleApply does) BEFORE window
// A's already-decided rollback acquires applyMu. With the epoch gate, A's rollback observes
// !IsCurrent and skips — so it cannot restore A's predecessor on top of B's freshly-applied,
// now-live config. Without the gate (see the toggle in the commit message) this clobbers.
func TestStaleRollbackSkipsAfterSupersede(t *testing.T) {
	m := New(quietDurations())
	var applyMu sync.Mutex
	noop := func() bool { return true }
	noRb := func() error { return nil }

	eA := m.Arm(noop, noRb, func() {}, false)

	// handleApply(B): apply the new config and re-Arm, all while holding applyMu.
	bLive := false
	applyMu.Lock()
	bLive = true
	m.Arm(noop, noRb, func() {}, false)
	applyMu.Unlock()

	// Window A's stale rollback now runs — mimics server/failsafe.go's closure: take
	// applyMu, then skip if superseded.
	clobbered := false
	func() {
		applyMu.Lock()
		defer applyMu.Unlock()
		if !m.IsCurrent(eA) {
			return
		}
		if bLive {
			clobbered = true
		}
	}()
	if clobbered {
		t.Fatal("a superseded window's rollback clobbered the freshly-applied config")
	}
	m.Confirm()
}

// TestStaleRollbackRaceUnderApplyMu stresses the same gate concurrently (run under -race):
// A's stale rollback races handleApply(B) on applyMu in both orderings. Either A wins the
// lock first (still current, B not yet live → no clobber) or B wins first (epoch bumped →
// A skips). The fresh Apply is never clobbered.
func TestStaleRollbackRaceUnderApplyMu(t *testing.T) {
	noop := func() bool { return true }
	noRb := func() error { return nil }
	for iter := 0; iter < 300; iter++ {
		m := New(quietDurations())
		var applyMu sync.Mutex
		eA := m.Arm(noop, noRb, func() {}, false)
		var bLive, clobbered int32
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // window A's stale rollback (decided before this Arm)
			defer wg.Done()
			applyMu.Lock()
			defer applyMu.Unlock()
			if !m.IsCurrent(eA) {
				return
			}
			if atomic.LoadInt32(&bLive) == 1 {
				atomic.StoreInt32(&clobbered, 1)
			}
		}()
		go func() { // handleApply(B)
			defer wg.Done()
			applyMu.Lock()
			atomic.StoreInt32(&bLive, 1)
			m.Arm(noop, noRb, func() {}, false)
			applyMu.Unlock()
		}()
		wg.Wait()
		if atomic.LoadInt32(&clobbered) == 1 {
			t.Fatalf("iter %d: a stale rollback clobbered the fresh Apply", iter)
		}
		m.Confirm()
	}
}
