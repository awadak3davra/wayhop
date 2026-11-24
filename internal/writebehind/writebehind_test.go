package writebehind

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wayhop/internal/ramdir"
)

type recorder struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *recorder) write(_ string, data []byte, _ os.FileMode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), data...))
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

// A burst of changes inside the rate-limit window is written once, on shutdown, with the last value.
func TestWriter_CoalescesAndFlushesOnShutdown(t *testing.T) {
	rec := &recorder{}
	w := New(filepath.Join(t.TempDir(), "f"), 0o600, Options{Debounce: time.Hour, MinInterval: 24 * time.Hour, Write: rec.write})
	defer w.Close()
	for i := 0; i < 50; i++ {
		v := []byte{byte('a' + i%26)}
		w.Mark(func() ([]byte, error) { return v, nil })
	}
	if rec.count() != 0 {
		t.Fatalf("wrote %d times before the debounce", rec.count())
	}
	FlushAll() // what main does on SIGTERM
	if rec.count() != 1 || string(rec.writes[0]) != "x" {
		t.Fatalf("writes = %q", rec.writes)
	}
	if w.Pending() {
		t.Fatal("still pending after flush")
	}
	FlushAll()
	if rec.count() != 1 {
		t.Fatal("clean writer wrote again")
	}
}

// Identical content (vs the seeded file or the last write) is never rewritten.
func TestWriter_SkipsUnchanged(t *testing.T) {
	rec := &recorder{}
	w := New(filepath.Join(t.TempDir(), "f"), 0o600, Options{Write: rec.write})
	defer w.Close()
	w.Seed([]byte("same"), time.Now().Add(-48*time.Hour))
	w.Mark(func() ([]byte, error) { return []byte("same"), nil })
	if rec.count() != 0 {
		t.Fatal("identical content rewritten")
	}
	w.Mark(func() ([]byte, error) { return []byte("new"), nil })
	w.Mark(func() ([]byte, error) { return []byte("new"), nil })
	if rec.count() != 1 {
		t.Fatalf("writes = %d, want 1", rec.count())
	}
}

// Write-through (zero options) writes synchronously; the rate limit defers a second write.
func TestWriter_RateLimit(t *testing.T) {
	rec := &recorder{}
	now := time.Unix(1_000_000, 0)
	w := New(filepath.Join(t.TempDir(), "f"), 0o600, Options{MinInterval: 24 * time.Hour, Write: rec.write, Now: func() time.Time { return now }})
	defer w.Close()
	w.Mark(func() ([]byte, error) { return []byte("1"), nil })
	if rec.count() != 1 {
		t.Fatalf("first write not immediate: %d", rec.count())
	}
	now = now.Add(time.Hour)
	w.Mark(func() ([]byte, error) { return []byte("2"), nil })
	if rec.count() != 1 || !w.Pending() {
		t.Fatal("second write inside the interval was not deferred")
	}
	if err := w.Flush(); err != nil || rec.count() != 2 {
		t.Fatalf("flush: %v, writes %d", err, rec.count())
	}
}

// Set holds a copy against the budget; a refused reservation writes through instead of buffering.
func TestWriter_SetRespectsBudget(t *testing.T) {
	rec := &recorder{}
	b := ramdir.NewBudget(8, 1)
	w := New(filepath.Join(t.TempDir(), "f"), 0o600, Options{Debounce: time.Hour, Budget: b, Write: rec.write})
	defer w.Close()
	if err := w.Set([]byte("small")); err != nil || rec.count() != 0 {
		t.Fatalf("small Set: %v, writes %d", err, rec.count())
	}
	if used, _, _ := b.Usage(); used != 5 {
		t.Fatalf("budget used = %d, want 5", used)
	}
	if err := w.Set([]byte("much too large")); err != nil || rec.count() != 1 {
		t.Fatalf("over-budget Set did not write through: %v, writes %d", err, rec.count())
	}
	if used, _, _ := b.Usage(); used != 0 {
		t.Fatalf("budget not released: %d", used)
	}
}
