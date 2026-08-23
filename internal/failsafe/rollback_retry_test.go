package failsafe

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRollbackNow_RetriesAfterFailedAutoRollback: after the AUTO rollback path has fired and FAILED,
// a manual RollbackNow must NOT report a false success (nor disarm the still-armed reboot fallback).
// It re-invokes the idempotent rollback; when that now succeeds the state becomes a genuine
// "rolled_back" with the prior error cleared. The old code returned nil + phase="rolled_back" WITHOUT
// ever re-running the rollback, over a still-broken config, and cancelled the reboot last resort.
func TestRollbackNow_RetriesAfterFailedAutoRollback(t *testing.T) {
	var calls int32
	rb := func() error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return errors.New("boom") // the auto attempt fails
		}
		return nil // the manual retry succeeds
	}
	d := Durations{Grace: time.Millisecond, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	m.Arm(func() bool { return false }, rb, func() {}, false)
	defer m.Confirm()

	// Wait for the auto path to dispatch and FAIL.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Status().Phase != "rollback_failed" {
		time.Sleep(2 * time.Millisecond)
	}
	if m.Status().Phase != "rollback_failed" {
		t.Fatalf("setup: want phase rollback_failed after a failing auto-rollback, got %q", m.Status().Phase)
	}

	// The manual retry must actually RE-RUN rb() and, on success, report a genuine rolled_back.
	if err := m.RollbackNow(); err != nil {
		t.Fatalf("manual retry after a failed auto-rollback should succeed, got err: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n < 2 {
		t.Fatalf("manual RollbackNow must RE-INVOKE the rollback after a failed auto attempt; calls=%d (false success = 1)", n)
	}
	s := m.Status()
	if s.Phase != "rolled_back" {
		t.Fatalf("phase=%q, want rolled_back after a successful retry", s.Phase)
	}
	if s.LastError != "" {
		t.Fatalf("LastError must be cleared on genuine success, got %q", s.LastError)
	}
}

// TestRollbackNow_FailedRetryKeepsRebootArmed: if the manual retry ALSO fails, RollbackNow must
// surface the error and keep the window pending (so the reboot fallback can still escalate) rather
// than reporting success and cancelling it.
func TestRollbackNow_FailedRetryKeepsRebootArmed(t *testing.T) {
	d := Durations{Grace: time.Millisecond, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	m.Arm(func() bool { return false }, func() error { return errors.New("still broken") }, func() {}, false)
	defer m.Confirm()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Status().Phase != "rollback_failed" {
		time.Sleep(2 * time.Millisecond)
	}
	if m.Status().Phase != "rollback_failed" {
		t.Fatalf("setup: want rollback_failed, got %q", m.Status().Phase)
	}

	if err := m.RollbackNow(); err == nil {
		t.Fatal("a still-failing manual retry must return the error, not a false success")
	}
	s := m.Status()
	if s.Phase != "rollback_failed" {
		t.Fatalf("phase=%q, want rollback_failed (config still broken)", s.Phase)
	}
	if !s.Pending {
		t.Fatal("the window must stay pending after a failed retry so the reboot fallback stays armed")
	}
}

// TestRollbackNow_InFlightDispatchIsNotSuccess: a manual RollbackNow issued while the AUTO
// rollback closure is still EXECUTING (claimed, not yet returned) must not report success or
// finalize the window — the in-flight rollback's outcome is unknown, and if it then FAILS the
// reboot fallback must still be armed. Previously dispatched&&!rollbackFailed misread the
// in-flight dispatch as a completed success: the operator got "rolled_back", the ctx was
// cancelled, and the subsequent failure could never escalate to reboot.
func TestRollbackNow_InFlightDispatchIsNotSuccess(t *testing.T) {
	d := Durations{Grace: 0, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	started := make(chan struct{})
	release := make(chan struct{})
	m.Arm(
		func() bool { return false }, // always bad → the auto path dispatches the rollback
		func() error {
			close(started)
			<-release // hold the dispatch IN FLIGHT
			return errors.New("restore failed")
		},
		func() {}, false,
	)
	<-started // the auto rollback is now mid-execution

	if err := m.RollbackNow(); err == nil {
		t.Fatal("RollbackNow during an in-flight dispatch must not report success (that dispatch may still fail)")
	}
	if st := m.Status(); !st.Pending {
		t.Error("the window must stay armed while the dispatch outcome is unknown — else the reboot fallback is disarmed")
	}

	close(release) // let the in-flight rollback FAIL
	deadline := time.Now().Add(time.Second)
	for {
		st := m.Status()
		if st.Phase == "rollback_failed" {
			if !st.Pending {
				t.Error("after the in-flight rollback fails the window must stay pending (reboot fallback armed)")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight failure never surfaced: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
	m.Confirm() // cleanup: cancel the run() goroutine
}

// TestRollbackNow_AfterCompletedAutoSuccessFinalizes: a COMPLETED successful auto dispatch must
// still finalize as success on a later manual RollbackNow (idempotent, no re-invoke) — pins that
// the in-flight guard keys off completion, not dispatch.
func TestRollbackNow_AfterCompletedAutoSuccessFinalizes(t *testing.T) {
	d := Durations{Grace: 0, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	var calls int32
	m := New(d)
	m.Arm(func() bool { return false }, func() error { atomic.AddInt32(&calls, 1); return nil }, func() {}, false)

	deadline := time.Now().Add(time.Second)
	var err error
	for {
		if err = m.RollbackNow(); err == nil {
			break // the completed auto dispatch finalized as success
		}
		if time.Now().After(deadline) {
			t.Fatalf("RollbackNow never finalized after the auto rollback completed: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("rollback closure invoked %d times, want exactly 1", n)
	}
	if st := m.Status(); st.Pending || st.Phase != "rolled_back" {
		t.Errorf("finalized window: phase=%q pending=%v, want rolled_back + not pending", st.Phase, st.Pending)
	}
}

// TestStaleRollbackDoneDoesNotContaminateNewWindow: a SUPERSEDED window's rb() returning nil
// (the production closure skips via IsCurrent and returns nil) must not mark the NEW window's
// dispatch done — otherwise a later manual RollbackNow on the new window finalizes as a success
// that never actually ran its rollback.
func TestStaleRollbackDoneDoesNotContaminateNewWindow(t *testing.T) {
	d := Durations{Grace: 0, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	started := make(chan struct{})
	release := make(chan struct{})
	// Window A: its rollback is claimed, then held in flight; it returns nil (a skipped stale
	// closure) only AFTER window B supersedes it.
	m.Arm(func() bool { return false }, func() error { close(started); <-release; return nil }, func() {}, false)
	<-started

	var calls int32
	m.Arm(func() bool { return true }, func() error { atomic.AddInt32(&calls, 1); return nil }, func() {}, false)
	close(release)                    // A's rb returns nil after the supersede
	time.Sleep(20 * time.Millisecond) // let A's run() reach its (epoch-gated) done-mark

	if err := m.RollbackNow(); err != nil {
		t.Fatalf("manual rollback on the new window: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("the new window's rollback must actually run (stale done-mark leaked in): calls=%d", n)
	}
}
