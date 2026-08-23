package traffic

import (
	"sync"
	"testing"
	"time"
)

// traffic_mkSample builds a Sample whose fields all derive from i, so a slice of
// them is easy to assert on by index/value.
func traffic_mkSample(i int64) Sample {
	return Sample{T: i, Up: i * 10, Down: i * 100}
}

// traffic_drain reads up to n samples from ch, returning what it actually got
// within the deadline. It stops early if the channel closes.
func traffic_drain(t *testing.T, ch <-chan Sample, n int, within time.Duration) []Sample {
	t.Helper()
	out := make([]Sample, 0, n)
	deadline := time.After(within)
	for len(out) < n {
		select {
		case s, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, s)
		case <-deadline:
			return out
		}
	}
	return out
}

// Recent on a brand-new hub must return a non-nil, empty, zero-length slice and
// must not panic.
func TestRecentEmptyHub(t *testing.T) {
	h := NewHub(8)
	got := h.Recent()
	if got == nil {
		t.Fatalf("Recent() on empty hub = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Recent() on empty hub len = %d; want 0", len(got))
	}
}

// NewHub with a non-positive size must fall back to the documented default of
// 300 (verified indirectly via the rolling-window behavior).
func TestNewHubDefaultSize(t *testing.T) {
	for _, size := range []int{0, -1, -100} {
		h := NewHub(size)
		// Push one more than the default cap; oldest must be evicted, newest kept.
		for i := int64(0); i < 301; i++ {
			h.Push(traffic_mkSample(i))
		}
		got := h.Recent()
		if len(got) != 300 {
			t.Fatalf("NewHub(%d): Recent() len = %d; want default cap 300", size, len(got))
		}
		// Oldest retained should be sample 1 (sample 0 evicted), newest 300.
		if got[0].T != 1 {
			t.Fatalf("NewHub(%d): oldest retained T = %d; want 1", size, got[0].T)
		}
		if got[len(got)-1].T != 300 {
			t.Fatalf("NewHub(%d): newest retained T = %d; want 300", size, got[len(got)-1].T)
		}
	}
}

// Pushing fewer samples than capacity keeps them all, oldest first.
func TestRecentUnderCapacity(t *testing.T) {
	h := NewHub(10)
	for i := int64(0); i < 4; i++ {
		h.Push(traffic_mkSample(i))
	}
	got := h.Recent()
	if len(got) != 4 {
		t.Fatalf("Recent() len = %d; want 4", len(got))
	}
	for i, s := range got {
		want := traffic_mkSample(int64(i))
		if s != want {
			t.Fatalf("Recent()[%d] = %+v; want %+v", i, s, want)
		}
	}
}

// The rolling buffer must never exceed capacity, and after overflow Recent()
// returns exactly the most-recent N in chronological (oldest-first) order.
func TestRollingBufferEvictsOldest(t *testing.T) {
	const cap = 5
	const total = 20
	h := NewHub(cap)
	for i := int64(0); i < total; i++ {
		h.Push(traffic_mkSample(i))
		if got := len(h.Recent()); got > cap {
			t.Fatalf("after push %d: Recent() len = %d; exceeds cap %d", i, got, cap)
		}
	}
	got := h.Recent()
	if len(got) != cap {
		t.Fatalf("Recent() len = %d; want cap %d", len(got), cap)
	}
	// The retained window must be the last `cap` samples: total-cap .. total-1.
	for i, s := range got {
		wantT := int64(total - cap + i)
		want := traffic_mkSample(wantT)
		if s != want {
			t.Fatalf("Recent()[%d] = %+v; want %+v (oldest-first window)", i, s, want)
		}
	}
}

// Recent must return an independent copy: mutating the returned slice must not
// corrupt the hub's internal buffer.
func TestRecentReturnsCopy(t *testing.T) {
	h := NewHub(4)
	for i := int64(0); i < 3; i++ {
		h.Push(traffic_mkSample(i))
	}
	first := h.Recent()
	first[0] = Sample{T: 9999, Up: 9999, Down: 9999}
	second := h.Recent()
	if second[0].T == 9999 {
		t.Fatalf("Recent() returned a view into internal buffer; mutation leaked back")
	}
	if second[0] != traffic_mkSample(0) {
		t.Fatalf("second Recent()[0] = %+v; want %+v", second[0], traffic_mkSample(0))
	}
}

// A subscriber receives samples pushed after it subscribes, in order. Samples
// pushed before Subscribe are not delivered on the channel (they live only in
// Recent()).
func TestSubscribeReceivesPushedSamples(t *testing.T) {
	h := NewHub(100)
	// Pre-existing sample: should NOT arrive on the subscription channel.
	h.Push(traffic_mkSample(-1))

	ch, cancel := h.Subscribe()
	defer cancel()

	const n = 8
	for i := int64(0); i < n; i++ {
		h.Push(traffic_mkSample(i))
	}

	got := traffic_drain(t, ch, n, 2*time.Second)
	if len(got) != n {
		t.Fatalf("subscriber received %d samples; want %d", len(got), n)
	}
	for i, s := range got {
		want := traffic_mkSample(int64(i))
		if s != want {
			t.Fatalf("subscriber sample[%d] = %+v; want %+v", i, s, want)
		}
	}
}

// cancel() removes the subscriber and closes its channel; a closed channel reads
// as not-ok and a second cancel must be a safe no-op (no double-close panic).
func TestSubscribeCancelClosesChannel(t *testing.T) {
	h := NewHub(10)
	ch, cancel := h.Subscribe()

	cancel()

	// Channel must be closed: a receive returns the zero value with ok=false.
	select {
	case s, ok := <-ch:
		if ok {
			t.Fatalf("after cancel, channel delivered a value %+v; want closed", s)
		}
	case <-time.After(time.Second):
		t.Fatalf("after cancel, receive blocked; channel not closed")
	}

	// Second cancel must not panic (double-close guard).
	cancel()

	// Pushing after cancel must not deliver to the cancelled channel nor panic.
	h.Push(traffic_mkSample(1))
}

// Multiple subscribers each get an independent copy of every broadcast sample.
func TestSubscribeMultipleSubscribers(t *testing.T) {
	h := NewHub(50)
	chA, cancelA := h.Subscribe()
	defer cancelA()
	chB, cancelB := h.Subscribe()
	defer cancelB()

	const n = 5
	for i := int64(0); i < n; i++ {
		h.Push(traffic_mkSample(i))
	}

	for _, pair := range []struct {
		name string
		ch   <-chan Sample
	}{{"A", chA}, {"B", chB}} {
		got := traffic_drain(t, pair.ch, n, 2*time.Second)
		if len(got) != n {
			t.Fatalf("subscriber %s received %d; want %d", pair.name, len(got), n)
		}
		for i, s := range got {
			if s != traffic_mkSample(int64(i)) {
				t.Fatalf("subscriber %s sample[%d] = %+v; want %+v", pair.name, i, s, traffic_mkSample(int64(i)))
			}
		}
	}
}

// A slow subscriber (one that never drains its 16-deep buffer) must not block
// the Push path: extra samples are dropped, but Push always returns promptly and
// Recent() still reflects every push.
func TestPushNonBlockingForSlowSubscriber(t *testing.T) {
	h := NewHub(1000)
	_, cancel := h.Subscribe() // subscriber that never reads
	defer cancel()

	const n = 500 // far more than the 16-slot subscriber buffer
	done := make(chan struct{})
	go func() {
		for i := int64(0); i < n; i++ {
			h.Push(traffic_mkSample(i))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Push blocked on a slow/non-draining subscriber; deadlock")
	}

	// Despite dropped broadcasts, every sample must be retained in the buffer.
	if got := len(h.Recent()); got != n {
		t.Fatalf("Recent() len = %d; want %d (drops must not affect retention)", got, n)
	}
}

// Concurrency: many goroutines Push while one goroutine continuously reads
// Recent(). Verifies there are no data races (run with -race) and no panics, and
// that the final buffer never exceeds capacity and is internally consistent.
func TestConcurrentPushAndRecent(t *testing.T) {
	const cap = 64
	const writers = 8
	const perWriter = 500
	h := NewHub(cap)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader: hammer Recent() until writers finish.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			got := h.Recent()
			if len(got) > cap {
				t.Errorf("Recent() len = %d exceeds cap %d", len(got), cap)
				return
			}
		}
	}()

	// Also keep a subscriber churning so the broadcast path runs concurrently.
	ch, cancel := h.Subscribe()
	subDone := make(chan struct{})
	go func() {
		defer close(subDone)
		for {
			select {
			case <-stop:
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
			}
		}
	}()

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(base int64) {
			defer wg.Done()
			for i := int64(0); i < perWriter; i++ {
				h.Push(traffic_mkSample(base*perWriter + i))
			}
		}(int64(w))
	}

	wg.Wait()
	close(stop)
	cancel()
	<-readerDone
	<-subDone

	final := h.Recent()
	if len(final) != cap {
		t.Fatalf("after %d pushes, Recent() len = %d; want cap %d",
			writers*perWriter, len(final), cap)
	}
}
