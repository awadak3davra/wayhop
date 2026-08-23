package watchdog

import (
	"errors"
	"testing"
	"time"
)

// Restarts counts ATTEMPTS. On its own it cannot distinguish a core that keeps recovering from one
// that never starts — the number climbs identically either way — so "12 restarts" on a
// crash-looping router read as twelve recoveries when there may have been none. Failed separates
// them; LastError only ever carries the most recent one.

func failedNewAt(sup Supervisor, now *time.Time) *Watchdog {
	w := New("test", sup)
	w.now = func() time.Time { return *now }
	w.rng = nil // no jitter, so advancing the clock past the backoff is exact
	return w
}

func TestStats_FailedAttemptsAreCountedSeparately(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: errors.New("exec format error")}
	w := failedNewAt(f, &now)

	for i := 0; i < 3; i++ {
		now = now.Add(time.Hour) // past any backoff window
		w.tick()
	}

	st := w.Stats()
	if st.Restarts == 0 {
		t.Fatal("no attempts were recorded — the test exercised nothing")
	}
	if st.Failed != st.Restarts {
		t.Errorf("every attempt failed, so Failed must equal Restarts: Failed=%d Restarts=%d",
			st.Failed, st.Restarts)
	}
	if st.LastError == "" {
		t.Error("a failing restart must leave its error behind")
	}
}

// A supervisor that starts cleanly records attempts and NO failures, so the two counters cannot
// simply be tracking each other.
func TestStats_SuccessfulAttemptsAreNotCountedAsFailed(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false}
	f.onStart = func() { f.alive = true } // the restart works
	w := failedNewAt(f, &now)

	now = now.Add(time.Hour)
	w.tick()

	st := w.Stats()
	if st.Restarts == 0 {
		t.Fatal("no attempt was recorded — the test exercised nothing")
	}
	if st.Failed != 0 {
		t.Errorf("the attempt succeeded, expected Failed=0, got %d", st.Failed)
	}
	if st.LastError != "" {
		t.Errorf("a successful restart must clear the last error, got %q", st.LastError)
	}
}

// The two are independent: a run that fails, then succeeds, must report one of each.
func TestStats_MixedOutcomesAreDistinguishable(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: errors.New("nope")}
	w := failedNewAt(f, &now)

	now = now.Add(time.Hour)
	w.tick() // fails

	f.mu.Lock()
	f.startErr = nil
	f.onStart = func() { f.alive = true }
	f.mu.Unlock()

	now = now.Add(time.Hour)
	w.tick() // succeeds

	st := w.Stats()
	if st.Restarts != 2 {
		t.Fatalf("expected 2 attempts, got %d", st.Restarts)
	}
	if st.Failed != 1 {
		t.Errorf("expected exactly 1 failed attempt, got %d", st.Failed)
	}
}
