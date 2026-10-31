package failsafe

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestDisarmClosesTheWindowWithoutAVerdict: Disarm ends a pending window with neither a commit nor
// a rollback, supersedes its epoch so a rollback parked on the caller's lock skips, and reports
// whether there was a window at all.
func TestDisarmClosesTheWindowWithoutAVerdict(t *testing.T) {
	m := New(quietDurations())
	var rolled atomic.Int32
	epoch := m.Arm(func() bool { return true }, func() error { rolled.Add(1); return nil }, func() {}, false)
	if !m.Disarm() {
		t.Fatal("Disarm over an armed window must report that one was pending")
	}
	st := m.Status()
	if st.Pending || st.Phase != "idle" {
		t.Fatalf("after Disarm the window is closed and idle, got pending=%v phase=%q", st.Pending, st.Phase)
	}
	if m.IsCurrent(epoch) {
		t.Fatal("Disarm must supersede the window's epoch, or a dispatched rollback would still fire")
	}
	if m.claimRollback(epoch) || m.claimReboot(epoch) {
		t.Fatal("a disarmed window must win neither its rollback nor its reboot")
	}
	if rolled.Load() != 0 {
		t.Fatal("Disarm must not roll anything back")
	}
	if m.Disarm() {
		t.Fatal("a second Disarm has no window to close")
	}
}

// TestDisarmStopsAFailingWindow: a window whose checks keep failing would roll back and then reboot.
// Once disarmed, neither happens however long the failure lasts.
func TestDisarmStopsAFailingWindow(t *testing.T) {
	m := New(Durations{Grace: 5 * time.Millisecond, Interval: 5 * time.Millisecond,
		RollbackAfter: 40 * time.Millisecond, RebootAfter: 80 * time.Millisecond, KeepWindow: time.Hour})
	var rolled, rebooted atomic.Int32
	m.Arm(func() bool { return false }, func() error { rolled.Add(1); return nil }, func() { rebooted.Add(1) }, true)
	m.Disarm()
	time.Sleep(200 * time.Millisecond)
	if rolled.Load() != 0 || rebooted.Load() != 0 {
		t.Fatalf("a disarmed window acted anyway: %d rollbacks, %d reboots", rolled.Load(), rebooted.Load())
	}
}
