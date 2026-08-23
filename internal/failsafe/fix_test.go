package failsafe

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #7: a manual rollback that fails must report phase "rollback_failed" (and the
// error), not the false "rolled_back" — so the UI/operator knows the config was
// NOT reverted.
func TestRollbackNowFailureSurfaces(t *testing.T) {
	m := New(DefaultDurations())
	m.Arm(func() bool { return true }, func() error { return errors.New("no backup config to restore") }, func() {}, false)
	if err := m.RollbackNow(); err == nil {
		t.Fatal("RollbackNow should return the rollback error")
	}
	s := m.Status()
	if s.Phase != "rollback_failed" {
		t.Fatalf("phase=%q, want rollback_failed", s.Phase)
	}
	if s.LastError == "" {
		t.Fatal("LastError should surface why the rollback failed")
	}
}

// #7: an auto-rollback (run loop) whose rollback errors must also end in
// "rollback_failed", not "rolled_back".
func TestAutoRollbackFailureSurfaces(t *testing.T) {
	d := Durations{Grace: time.Millisecond, Interval: 2 * time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	m.Arm(func() bool { return false }, func() error { return errors.New("boom") }, func() {}, false)
	defer m.Confirm()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Phase == "rollback_failed" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("phase=%q, want rollback_failed after a failing auto-rollback", m.Status().Phase)
}

// #5: re-Arming must supersede the prior window's goroutine so they don't leak
// (each would otherwise live for the whole keep window and double-drive the
// state machine, including a possible double reboot()).
func TestArmSupersedesPriorGoroutine(t *testing.T) {
	d := Durations{Grace: time.Millisecond, Interval: time.Millisecond, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	check := func() bool { return true } // always ok -> window stays pending to the 1h deadline
	base := runtime.NumGoroutine()
	for i := 0; i < 25; i++ {
		m.Arm(check, func() error { return nil }, func() {}, false)
	}
	time.Sleep(40 * time.Millisecond) // let the 24 superseded run()s exit
	m.Confirm()                       // end the last window's goroutine
	time.Sleep(40 * time.Millisecond)
	if g := runtime.NumGoroutine(); g > base+6 {
		t.Fatalf("fail-safe goroutines leaked: base=%d now=%d (re-Arm must cancel the prior run())", base, g)
	}
}

// #3: a manual RollbackNow racing the auto-rollback dispatched by tick()'s run
// loop must not invoke the rollback closure rb() twice (double rollback of the
// LIVE routing). check()=false + RollbackAfter=0 drives the run loop into
// ActRollback while RollbackNow fires concurrently; rb must run EXACTLY once.
func TestRollbackFiresExactlyOnce_AutoVsManual(t *testing.T) {
	d := Durations{Grace: 0, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	for i := 0; i < 200; i++ {
		var calls int32
		m := New(d)
		m.Arm(
			func() bool { return false }, // always bad -> auto path wants to roll back
			func() error { atomic.AddInt32(&calls, 1); return nil },
			func() {}, false,
		)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.RollbackNow() }()
		wg.Wait()
		// give the run loop a moment to also reach its ActRollback branch
		time.Sleep(2 * time.Millisecond)
		m.Confirm()
		if n := atomic.LoadInt32(&calls); n != 1 {
			t.Fatalf("iter %d: rollback fired %d times, want exactly 1", i, n)
		}
	}
}

// #3: two concurrent RollbackNow calls must also collapse to a single rb()
// invocation (fire-once per window), not two.
func TestRollbackFiresExactlyOnce_TwoManual(t *testing.T) {
	for i := 0; i < 200; i++ {
		var calls int32
		m := New(DefaultDurations())
		m.Arm(
			func() bool { return true },
			func() error { atomic.AddInt32(&calls, 1); return nil },
			func() {}, false,
		)
		var wg sync.WaitGroup
		wg.Add(2)
		for j := 0; j < 2; j++ {
			go func() { defer wg.Done(); _ = m.RollbackNow() }()
		}
		wg.Wait()
		if n := atomic.LoadInt32(&calls); n != 1 {
			t.Fatalf("iter %d: rollback fired %d times, want exactly 1", i, n)
		}
	}
}

// #4: run() must not read the rollback/reboot/allowReboot fields lock-free while
// a concurrent re-Arm writes them. check()=false + RollbackAfter=0 drives run()
// into the ActRollback branch every tick, racing the re-Arm writes. Run with -race.
func TestArmConcurrentRollbackNoRace(t *testing.T) {
	d := Durations{Grace: 0, Interval: time.Millisecond, RollbackAfter: 0, RebootAfter: time.Hour, KeepWindow: time.Hour}
	m := New(d)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.Arm(func() bool { return false }, func() error { return nil }, func() {}, false)
		}
	}()
	time.Sleep(60 * time.Millisecond) // run() goroutines hit ActRollback while Arm rewrites the fields
	close(stop)
	wg.Wait()
	m.Confirm()
}
