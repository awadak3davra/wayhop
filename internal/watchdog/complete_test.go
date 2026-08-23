package watchdog

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// watchdogcomplete_newAt builds a watchdog with a controllable clock starting at
// the value pointed to by t. Mirrors newAt in watchdog_test.go but is given a
// unique prefix to avoid clashing with that helper while keeping these tests
// self-contained.
func watchdogcomplete_newAt(sup Supervisor, t *time.Time) *Watchdog {
	w := New("test", sup)
	w.now = func() time.Time { return *t }
	w.rng = nil // deterministic backoff (no jitter) for exact nextAttempt timing assertions
	return w
}

// TestSetNotifyFiresOnCrashRestart asserts the notify hook receives the
// "crashed — restart #N" message when a managed process is dead and gets
// (successfully) restarted. Reuses the package-local fakeSup.
func TestSetNotifyFiresOnCrashRestart(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false}
	f.onStart = func() { f.alive = true } // restart succeeds
	w := watchdogcomplete_newAt(f, &now)

	var msgs []string
	w.SetNotify(func(m string) { msgs = append(msgs, m) })

	w.tick() // dead -> restart #1 -> notify

	if f.starts != 1 {
		t.Fatalf("expected 1 restart, got %d", f.starts)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 notify, got %d: %v", len(msgs), msgs)
	}
	got := msgs[0]
	if !strings.Contains(got, "crashed") || !strings.Contains(got, "restart #1") {
		t.Fatalf("crash-restart notify missing expected text: %q", got)
	}
	if strings.Contains(got, "FAILED") {
		t.Fatalf("successful restart wrongly reported as FAILED: %q", got)
	}
	if !strings.Contains(got, "next backoff") {
		t.Fatalf("successful restart notify should mention next backoff: %q", got)
	}
}

// TestSetNotifyFiresOnRestartFailure asserts the notify hook receives the
// "FAILED" message (with the error) when Start returns an error, and that Stats
// surfaces the same last_error.
func TestSetNotifyFiresOnRestartFailure(t *testing.T) {
	now := time.Unix(0, 0)
	startErr := errors.New("exec format error")
	f := &fakeSup{desired: true, alive: false, startErr: startErr}
	w := watchdogcomplete_newAt(f, &now)

	var msgs []string
	w.SetNotify(func(m string) { msgs = append(msgs, m) })

	w.tick() // dead -> restart attempt fails -> notify(FAILED)

	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 notify, got %d: %v", len(msgs), msgs)
	}
	got := msgs[0]
	if !strings.Contains(got, "FAILED") {
		t.Fatalf("restart-failure notify should say FAILED: %q", got)
	}
	if !strings.Contains(got, startErr.Error()) {
		t.Fatalf("restart-failure notify should include the error %q: %q", startErr.Error(), got)
	}
	if !strings.Contains(got, "restart #1") {
		t.Fatalf("restart-failure notify should mention restart #1: %q", got)
	}

	st := w.Stats()
	if st.LastError != startErr.Error() {
		t.Fatalf("Stats.LastError = %q, want %q", st.LastError, startErr.Error())
	}
	if st.BackoffMS != 1000 {
		t.Fatalf("Stats.BackoffMS = %d, want 1000 (minBackoff)", st.BackoffMS)
	}
}

// TestNotifyNotFiredWhenAlive confirms the notify hook stays silent while the
// process is healthy (no crash, no restart, no message).
func TestNotifyNotFiredWhenAlive(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: true}
	w := watchdogcomplete_newAt(f, &now)

	fired := 0
	w.SetNotify(func(string) { fired++ })

	for i := 0; i < 3; i++ {
		w.tick()
		now = now.Add(w.interval)
	}
	if fired != 0 {
		t.Fatalf("notify fired %d times while alive, want 0", fired)
	}
}

// TestRunCancelsPromptly asserts Run(ctx) returns once ctx is cancelled rather
// than blocking forever on the ticker. The watchdog uses a short interval so an
// already-cancelled context is observed immediately.
func TestRunCancelsPromptly(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: true}
	w := watchdogcomplete_newAt(f, &now)
	w.interval = time.Millisecond // keep the ticker cheap

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// returned promptly after cancel
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancellation")
	}
}

// TestRunStopsTickingAfterCancel drives Run with a real (short) interval, lets
// it perform some real ticks supervising the plugin callback, then cancels and
// asserts no further ticks happen. This exercises the case <-t.C path and the
// case <-ctx.Done() return in Run together.
func TestRunStopsTickingAfterCancel(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: true}
	w := watchdogcomplete_newAt(f, &now)
	w.interval = 5 * time.Millisecond

	var mu sync.Mutex
	pluginCalls := 0
	w.SetPluginSupervisor(func() {
		mu.Lock()
		pluginCalls++
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Wait until the plugin callback has run at least a couple of times,
	// proving Run is actually ticking (case <-t.C -> w.tick()).
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		c := pluginCalls
		mu.Unlock()
		if c >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("Run did not tick: pluginCalls=%d", c)
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// Record the count at cancel time, wait well beyond several intervals,
	// and confirm ticking has stopped.
	mu.Lock()
	atCancel := pluginCalls
	mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	after := pluginCalls
	mu.Unlock()
	if after != atCancel {
		t.Fatalf("plugin supervisor kept firing after cancel: %d -> %d", atCancel, after)
	}
}

// TestStatsReflectsLastErrorAndBackoff drives a crash loop (Start always fails)
// and asserts Stats tracks last_error and a growing backoff_ms across attempts.
func TestStatsReflectsLastErrorAndBackoff(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: errors.New("nope")}
	w := watchdogcomplete_newAt(f, &now)

	w.tick() // attempt #1, backoff 1s
	st := w.Stats()
	if st.LastError != "nope" {
		t.Fatalf("attempt 1: LastError = %q, want %q", st.LastError, "nope")
	}
	if st.BackoffMS != 1000 {
		t.Fatalf("attempt 1: BackoffMS = %d, want 1000", st.BackoffMS)
	}
	if st.Restarts != 1 {
		t.Fatalf("attempt 1: Restarts = %d, want 1", st.Restarts)
	}
	if st.LastRestart == "" {
		t.Fatal("attempt 1: LastRestart not recorded")
	}

	// Jump exactly to the allowed next attempt and tick again -> backoff doubles.
	w.mu.Lock()
	now = w.nextAttempt
	w.mu.Unlock()
	w.tick() // attempt #2, backoff 2s
	st = w.Stats()
	if st.BackoffMS != 2000 {
		t.Fatalf("attempt 2: BackoffMS = %d, want 2000", st.BackoffMS)
	}
	if st.Restarts != 2 {
		t.Fatalf("attempt 2: Restarts = %d, want 2", st.Restarts)
	}
}

// TestStatsClearsLastErrorOnSuccessfulRestart confirms a failing restart sets
// last_error and a later successful restart clears it (the else branch in tick).
func TestStatsClearsLastErrorOnSuccessfulRestart(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: errors.New("transient")}
	w := watchdogcomplete_newAt(f, &now)

	w.tick() // fails -> last_error set
	if st := w.Stats(); st.LastError != "transient" {
		t.Fatalf("expected last_error 'transient', got %+v", st)
	}

	// Next attempt succeeds: clear the error, flip alive.
	f.startErr = nil
	f.onStart = func() { f.alive = true }
	w.mu.Lock()
	now = w.nextAttempt
	w.mu.Unlock()
	w.tick() // succeeds -> last_error cleared

	if st := w.Stats(); st.LastError != "" {
		t.Fatalf("last_error not cleared after successful restart: %+v", st)
	}
}
