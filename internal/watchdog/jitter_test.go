package watchdog

import (
	"testing"
	"time"
)

// TestJitteredEqualJitter proves the equal-jitter window: with a real rng the jittered backoff is
// always in [d/2, d] (never zero, never more than the nominal window), and rng==nil disables it.
func TestJitteredEqualJitter(t *testing.T) {
	w := New("test", &fakeSup{})

	// nil rng ⇒ no jitter (deterministic full window).
	w.rng = nil
	if got := w.jittered(4 * time.Second); got != 4*time.Second {
		t.Fatalf("nil rng: jittered=%v, want full 4s", got)
	}

	// rng at the extremes bounds the window to [half, full].
	d := 4 * time.Second
	w.rng = func(int64) int64 { return 0 } // minimum draw
	if got := w.jittered(d); got != d/2 {
		t.Fatalf("min draw: jittered=%v, want half %v", got, d/2)
	}
	w.rng = func(n int64) int64 { return n - 1 } // maximum draw
	if got := w.jittered(d); got < d/2 || got > d {
		t.Fatalf("max draw: jittered=%v, want within [%v,%v]", got, d/2, d)
	}

	// A real random source always stays inside the window and above half.
	w = New("test", &fakeSup{}) // real rng
	for i := 0; i < 200; i++ {
		got := w.jittered(d)
		if got < d/2 || got > d {
			t.Fatalf("random draw %d out of band: %v not in [%v,%v]", i, got, d/2, d)
		}
	}
}

// TestJitterKeepsBackoffFieldNominal confirms jitter affects only nextAttempt timing, not the
// reported/doubling backoff window (Stats.BackoffMS stays the clean nominal value).
func TestJitterKeepsBackoffFieldNominal(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: nil}
	f.onStart = func() {} // stays dead → keeps "crashing"
	w := New("test", f)
	w.now = func() time.Time { return now }
	w.rng = func(n int64) int64 { return n / 2 } // deterministic mid-jitter

	w.tick() // restart #1
	if st := w.Stats(); st.BackoffMS != 1000 {
		t.Fatalf("BackoffMS=%d, want nominal 1000 despite jitter", st.BackoffMS)
	}
	// nextAttempt is jittered strictly below the nominal 1s window.
	if !w.nextAttempt.After(now) || !w.nextAttempt.Before(now.Add(time.Second)) {
		t.Fatalf("nextAttempt=%v, want jittered within (now, now+1s)", w.nextAttempt)
	}
}
