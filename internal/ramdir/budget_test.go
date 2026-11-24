package ramdir

import "testing"

func TestBudget_CapAndRelease(t *testing.T) {
	b := NewBudget(100, 1)
	b.memAvailable = func() (int64, bool) { return 1 << 30, true }
	if !b.Reserve(60) || b.Reserve(41) || !b.Reserve(40) {
		t.Fatal("cap not enforced")
	}
	b.Release(60)
	if used, peak, c := b.Usage(); used != 40 || peak != 100 || c != 100 {
		t.Fatalf("usage = %d/%d/%d", used, peak, c)
	}
}

// Low free memory refuses even a reservation well under the cap.
func TestBudget_LowMemoryRefuses(t *testing.T) {
	b := NewBudget(4<<20, 32<<20)
	b.memAvailable = func() (int64, bool) { return 33 << 20, true }
	if b.Reserve(2 << 20) {
		t.Fatal("reservation that would leave < MinFree was accepted")
	}
	if !b.Reserve(512 << 10) {
		t.Fatal("small reservation refused")
	}
	b.memAvailable = func() (int64, bool) { return 0, false } // unknown → only the cap applies
	if !b.Reserve(1 << 20) {
		t.Fatal("unknown free memory must not block")
	}
}

func TestParseMemAvailable(t *testing.T) {
	raw := []byte("MemTotal:  250000 kB\nMemFree:   10000 kB\nMemAvailable:   40960 kB\n")
	if n, ok := parseMemAvailable(raw); !ok || n != 40960*1024 {
		t.Fatalf("got %d %v", n, ok)
	}
	if _, ok := parseMemAvailable([]byte("MemTotal: 1 kB\n")); ok {
		t.Fatal("missing field parsed")
	}
}
