package server

import "testing"

// The ribbon is read as "when was this router busy", so every way a bucket can be wrong is a shape
// somebody would act on: a spike at the daemon's start, a gap that closes up, or a burst invented by
// a counter that wrapped.

// Named oneMin, not min: a package-level const called oneMin shadows the builtin, and another test in
// this package calls min() on integers.
const oneMin = int64(60000)

func ifs(rx, tx int64) []Iface {
	return []Iface{{Name: "eth0", RxBytes: rx, TxBytes: tx, Up: true}}
}

// The first snapshot has no predecessor, so there is no delta. Counting the cumulative totals as one
// minute's traffic would draw a spike at every daemon restart — on a box that has been up for weeks,
// the first bucket would dwarf everything real.
func TestDayRing_FirstSampleIsOnlyABaseline(t *testing.T) {
	r := newDayRing()
	r.observe(oneMin*10, ifs(5_000_000, 3_000_000))
	for _, b := range r.snapshot() {
		if b.Bytes != 0 {
			t.Fatalf("the first sample established a baseline, not %d bytes of traffic", b.Bytes)
		}
	}
}

func TestDayRing_AccumulatesDeltasWithinAMinute(t *testing.T) {
	r := newDayRing()
	r.observe(oneMin*10, ifs(1000, 500))
	r.observe(oneMin*10+5000, ifs(1500, 700))  // +500 rx +200 tx
	r.observe(oneMin*10+10000, ifs(1600, 900)) // +100 rx +200 tx
	b := r.snapshot()
	if len(b) != 1 {
		t.Fatalf("three samples inside one minute is one bucket, got %d", len(b))
	}
	if b[0].Bytes != 1000 {
		t.Errorf("want 1000 bytes accumulated, got %d", b[0].Bytes)
	}
	if b[0].Samples != 2 {
		t.Errorf("two deltas were folded in, got %d samples", b[0].Samples)
	}
	if b[0].T != oneMin*10 {
		t.Errorf("bucket should be stamped at the start of its minute, got %d", b[0].T)
	}
}

// A minute with no sample must still exist. Closing the gap would slide later activity earlier on
// the ribbon, which is worse than an empty slot: it moves an event to a time it did not happen.
func TestDayRing_GapsAreKeptAsGaps(t *testing.T) {
	r := newDayRing()
	r.observe(oneMin*10, ifs(0, 0))
	r.observe(oneMin*10+5000, ifs(100, 0))
	// Nothing for three minutes, then a sample again.
	r.observe(oneMin*14, ifs(200, 0))
	b := r.snapshot()
	if len(b) != 5 {
		t.Fatalf("minutes 10..14 inclusive is 5 buckets, got %d: %+v", len(b), b)
	}
	for i := 0; i < len(b); i++ {
		want := oneMin*10 + int64(i)*oneMin
		if b[i].T != want {
			t.Fatalf("bucket %d should be stamped %d, got %d", i, want, b[i].T)
		}
	}
	if b[1].Bytes != 0 || b[2].Bytes != 0 || b[3].Bytes != 0 {
		t.Errorf("the silent minutes must read as silent, got %d/%d/%d", b[1].Bytes, b[2].Bytes, b[3].Bytes)
	}
}

// A counter that goes backwards is a reset or a 32-bit wrap. Subtracting would go negative and
// counting the new total would invent a burst; skipping the interval claims nothing at all.
func TestDayRing_CounterResetInventsNoTraffic(t *testing.T) {
	r := newDayRing()
	r.observe(oneMin*10, ifs(4_000_000_000, 0))
	r.observe(oneMin*10+5000, ifs(1200, 0)) // wrapped
	b := r.snapshot()
	if b[0].Bytes != 0 {
		t.Errorf("a wrapped counter is not %d bytes of traffic", b[0].Bytes)
	}
	// The next interval measures normally from the new baseline.
	r.observe(oneMin*10+10000, ifs(1700, 0))
	if got := r.snapshot()[0].Bytes; got != 500 {
		t.Errorf("after the wrap the next delta should be 500, got %d", got)
	}
}

// An interface that appears mid-run has no previous reading, so its cumulative total is not traffic
// that happened in this minute.
func TestDayRing_NewInterfaceContributesNoBacklog(t *testing.T) {
	r := newDayRing()
	r.observe(oneMin*10, ifs(100, 100))
	r.observe(oneMin*10+5000, []Iface{
		{Name: "eth0", RxBytes: 200, TxBytes: 100},
		{Name: "wg0", RxBytes: 9_000_000, TxBytes: 9_000_000},
	})
	if got := r.snapshot()[0].Bytes; got != 100 {
		t.Errorf("only eth0's 100-byte delta is measurable, got %d", got)
	}
}

// The ring must hold a day and then drop the oldest, keeping the newest — a ribbon that discarded
// the newest minute would show the router as idle exactly when it is busiest.
func TestDayRing_KeepsTheNewestDay(t *testing.T) {
	r := newDayRing()
	base := oneMin * 1000
	r.observe(base, ifs(0, 0))
	total := dayBuckets + 30
	for i := 1; i <= total; i++ {
		r.observe(base+int64(i)*oneMin, ifs(int64(i)*10, 0))
	}
	b := r.snapshot()
	if len(b) != dayBuckets {
		t.Fatalf("the ring holds %d buckets, got %d", dayBuckets, len(b))
	}
	if b[len(b)-1].T != base+int64(total)*oneMin {
		t.Errorf("the newest bucket must be the last minute observed; got %d want %d",
			b[len(b)-1].T, base+int64(total)*oneMin)
	}
	for i := 1; i < len(b); i++ {
		if b[i].T <= b[i-1].T {
			t.Fatalf("buckets must be oldest-first and strictly increasing at index %d", i)
		}
	}
}
