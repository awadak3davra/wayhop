package traffic

import "testing"

// After the ring wraps around many times, Recent() must still return exactly the last
// `size` samples in oldest-first order — this exercises the modular index arithmetic that
// the old slice-shift implementation didn't have.
func TestRingManyWraps(t *testing.T) {
	const size = 5
	h := NewHub(size)
	// Push 3.4x capacity so start has wrapped past 0 several times.
	const total = 17
	for i := 1; i <= total; i++ {
		h.Push(traffic_mkSample(int64(i)))
	}
	got := h.Recent()
	if len(got) != size {
		t.Fatalf("Recent() len = %d; want %d", len(got), size)
	}
	// Expect the last `size` T values: total-size+1 .. total.
	for i, s := range got {
		want := int64(total - size + 1 + i)
		if s.T != want {
			t.Fatalf("Recent()[%d].T = %d; want %d (full window %v)", i, s.T, want, tvals(got))
		}
	}
}

// RecentN after a wrap must return the last n samples, oldest-first, spanning the ring seam.
func TestRingRecentNAfterWrap(t *testing.T) {
	const size = 5
	h := NewHub(size)
	for i := 1; i <= 12; i++ { // wraps: retained window is T = 8..12
		h.Push(traffic_mkSample(int64(i)))
	}
	// last 3 → T 10,11,12
	got := h.RecentN(3)
	if len(got) != 3 || got[0].T != 10 || got[1].T != 11 || got[2].T != 12 {
		t.Fatalf("RecentN(3) = %v; want [10 11 12]", tvals(got))
	}
	// n larger than retained → clamp to the whole window (T 8..12)
	all := h.RecentN(100)
	if len(all) != size || all[0].T != 8 || all[size-1].T != 12 {
		t.Fatalf("RecentN(100) = %v; want the 5-sample window 8..12", tvals(all))
	}
	// n <= 0 → all retained
	if z := h.RecentN(0); len(z) != size {
		t.Fatalf("RecentN(0) len = %d; want %d", len(z), size)
	}
}

func tvals(ss []Sample) []int64 {
	out := make([]int64, len(ss))
	for i, s := range ss {
		out[i] = s.T
	}
	return out
}
