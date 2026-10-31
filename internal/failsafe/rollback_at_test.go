package failsafe

import (
	"errors"
	"testing"
)

// A Roll back checked against test Apply A (the bot's button names it) reached RollbackNow after Test
// B had armed: RollbackNow runs the current window's closure, so it rolled back B, which nobody had
// been asked about. RollbackNowAt names the window it was checked against and leaves a newer one alone.
func TestRollbackNowAtLeavesANewerWindowAlone(t *testing.T) {
	m := New(quietDurations())
	ranA, ranB := 0, 0
	epochA := m.Arm(func() bool { return true }, func() error { ranA++; return nil }, func() {}, false)
	if m.Epoch() != epochA {
		t.Fatalf("Epoch %d, armed %d", m.Epoch(), epochA)
	}
	m.Arm(func() bool { return true }, func() error { ranB++; return nil }, func() {}, false)

	if err := m.RollbackNowAt(epochA); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("a Roll back of the replaced window: %v", err)
	}
	if ranA != 0 || ranB != 0 {
		t.Fatalf("rollbacks run: A %d, B %d", ranA, ranB)
	}
	if s := m.Status(); !s.Pending || s.Phase != "armed" {
		t.Fatalf("the newer window was touched: %+v", s)
	}

	// The window it names is rolled back as RollbackNow would.
	if err := m.RollbackNowAt(m.Epoch()); err != nil || ranB != 1 {
		t.Fatalf("err %v, B rolled back %d times", err, ranB)
	}
	if s := m.Status(); s.Pending || s.Phase != "rolled_back" {
		t.Fatalf("after the rollback: %+v", s)
	}
}
