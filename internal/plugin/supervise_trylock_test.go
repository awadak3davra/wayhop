package plugin

import (
	"testing"
	"time"
)

// TestSuperviseNonBlockingUnderLock verifies Supervise() uses TryLock: while a Sync()
// is in flight (simulated by holding m.mu — Sync holds it across blocking ip/awg execs
// and the process reap), a watchdog tick's Supervise() must return IMMEDIATELY rather
// than block. The watchdog drives Supervise on the same tick that crash-restarts
// sing-box, so blocking here would stall the core's recovery (concurrency-review fix).
func TestSuperviseNonBlockingUnderLock(t *testing.T) {
	m := New("", "")
	m.mu.Lock()
	done := make(chan struct{})
	go func() { m.Supervise(); close(done) }()
	select {
	case <-done: // good: TryLock skipped, Supervise returned without acquiring the lock
	case <-time.After(2 * time.Second):
		t.Fatal("Supervise blocked while m.mu was held — TryLock regression")
	}
	m.mu.Unlock()
	// Once the lock is free, Supervise runs normally (no-op on an empty proc set).
	m.Supervise()
}
