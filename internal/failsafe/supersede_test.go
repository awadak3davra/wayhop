package failsafe

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// A manual Roll back can be clicked while a Test Apply holds the server's applyMu. The rollback then
// parks on that lock, the Apply arms its OWN window and unlocks, and the stale closure skips. Its
// skip used to read as success: RollbackNow closed the window it found on return — the new one —
// cancelled its run() and reported "rolled back", leaving the untested configuration live with no
// auto-rollback and no reboot.

// staleSafeRollback mirrors the server's closure: serialize on applyMu, skip when superseded. skip is
// what the skip returns — ErrSuperseded as the server does now, nil as it used to — and the new
// window's state must not depend on which.
func staleSafeRollback(m *Manager, applyMu *sync.Mutex, epoch *int64, entered chan<- struct{}, skip error) func() error {
	return func() error {
		if entered != nil {
			entered <- struct{}{}
		}
		applyMu.Lock()
		defer applyMu.Unlock()
		if !m.IsCurrent(*epoch) {
			return skip
		}
		return nil
	}
}

func TestRollbackNow_SupersededByANewApplyLeavesTheNewWindowArmed(t *testing.T) {
	for _, skip := range []error{ErrSuperseded, nil} {
		m := New(quietDurations())
		var applyMu sync.Mutex
		var epochA int64
		entered := make(chan struct{}, 1)
		epochA = m.Arm(func() bool { return true }, staleSafeRollback(m, &applyMu, &epochA, entered, skip), func() {}, false)

		applyMu.Lock() // Test Apply B is running
		done := make(chan error, 1)
		go func() { done <- m.RollbackNow() }()
		// The manual rollback claimed window A and is now waiting for applyMu; B arms its window.
		<-entered
		m.Arm(func() bool { return true }, func() error { return nil }, func() {}, false)
		applyMu.Unlock()

		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("RollbackNow did not return")
		}
		// The closure is the one that knows it skipped; with the old nil the report is wrong but the
		// state below must hold either way.
		if skip != nil && !errors.Is(err, ErrSuperseded) {
			t.Fatalf("a rollback that a newer Apply superseded must not report success, got err=%v", err)
		}
		s := m.Status()
		if !s.Pending || s.Phase != "armed" {
			t.Fatalf("skip=%v: the new window must stay armed: pending=%v phase=%q", skip, s.Pending, s.Phase)
		}
		// B's window must still be able to roll back on its own: its run() was not cancelled and its
		// fire-once claim is untouched.
		if err := m.RollbackNow(); err != nil {
			t.Fatalf("skip=%v: B's own rollback = %v", skip, err)
		}
		m.Confirm()
	}
}

// Keep can land while a manual rollback waits for applyMu. Confirm bumps the epoch, the closure
// skips, and the window must stay "committed" rather than be relabelled "rolled_back".
func TestRollbackNow_SupersededByKeepKeepsCommitted(t *testing.T) {
	m := New(quietDurations())
	var applyMu sync.Mutex
	var epochA int64
	entered := make(chan struct{}, 1)
	epochA = m.Arm(func() bool { return true }, staleSafeRollback(m, &applyMu, &epochA, entered, ErrSuperseded), func() {}, false)

	applyMu.Lock()
	done := make(chan error, 1)
	go func() { done <- m.RollbackNow() }()
	<-entered
	m.Confirm()
	applyMu.Unlock()

	if err := <-done; !errors.Is(err, ErrSuperseded) {
		t.Fatalf("err=%v, want ErrSuperseded", err)
	}
	if s := m.Status(); s.Pending || s.Phase != "committed" {
		t.Fatalf("Keep's verdict was overwritten: pending=%v phase=%q", s.Pending, s.Phase)
	}
}

// A failed Apply that rolled the router back to the committed configuration finished the rollback a
// window was holding on: left as it was, the window would close later announcing that failure (or
// reboot) for a router that runs the committed configuration.
func TestMarkRolledBack_ClosesAWindowHeldOnAFailedRollback(t *testing.T) {
	m := New(quietDurations())
	defer m.Confirm()
	ep := m.Arm(func() bool { return true }, func() error { return errors.New("restore failed") }, func() {}, false)
	if err := m.RollbackNow(); err == nil {
		t.Fatal("setup: the rollback should fail")
	}
	if s := m.Status(); !s.Pending || s.Phase != "rollback_failed" {
		t.Fatalf("setup: %+v", s)
	}
	m.MarkRolledBack()
	if s := m.Status(); s.Pending || s.Phase != "rolled_back" || s.LastError != "" {
		t.Fatalf("after MarkRolledBack: %+v", s)
	}
	if m.IsCurrent(ep) {
		t.Fatal("a rollback parked on the caller's lock must find its window replaced and skip")
	}

	// A verdict other than the failed rollback is not the caller's to change.
	kept := New(quietDurations())
	kept.Arm(func() bool { return true }, nil, func() {}, false)
	kept.Confirm()
	kept.MarkRolledBack()
	if s := kept.Status(); s.Phase != "committed" {
		t.Fatalf("a kept window was relabelled %q", s.Phase)
	}
}

// A superseded window's auto rollback that errors must not mark the NEW window failed.
func TestMarkRollbackFailed_IgnoresASupersededWindow(t *testing.T) {
	m := New(quietDurations())
	defer m.Confirm()
	old := m.Arm(func() bool { return true }, nil, func() {}, false)
	m.Arm(func() bool { return true }, nil, func() {}, false)
	m.markRollbackFailed(old, errors.New("stale window's rollback failed"))
	if s := m.Status(); s.Phase != "armed" || s.LastError != "" {
		t.Fatalf("a stale window's failure leaked into the new one: phase=%q lastErr=%q", s.Phase, s.LastError)
	}
}
