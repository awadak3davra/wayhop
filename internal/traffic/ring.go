// Package traffic keeps a rolling buffer of up/down samples and fans them out
// to subscribers (used by the SSE traffic stream that drives the live graph).
package traffic

import "sync"

// Sample is one second of throughput, in bytes per second, with a unix-ms timestamp.
type Sample struct {
	T    int64 `json:"t"`    // unix milliseconds
	Up   int64 `json:"up"`   // bytes/s uploaded
	Down int64 `json:"down"` // bytes/s downloaded
}

// Hub stores recent samples in a fixed-size ring and broadcasts new ones to subscribers.
// The ring makes Push O(1): buf has a constant length == size, start indexes the oldest
// retained sample, and count is how many are valid (0..size). The write position is
// (start+count)%size until full, after which each Push overwrites the oldest and advances
// start. (The previous slice-shift Push was O(size) — a 300-element memmove every second.)
type Hub struct {
	mu    sync.Mutex
	buf   []Sample // fixed length == size
	size  int
	start int // index of the oldest retained sample
	count int // number of valid samples (0..size)
	subs  map[chan Sample]struct{}
}

// NewHub returns a Hub retaining up to size recent samples.
func NewHub(size int) *Hub {
	if size <= 0 {
		size = 300
	}
	return &Hub{
		size: size,
		buf:  make([]Sample, size),
		subs: make(map[chan Sample]struct{}),
	}
}

// Push records a sample and broadcasts it to subscribers (non-blocking;
// samples are dropped for consumers that cannot keep up).
func (h *Hub) Push(s Sample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count < h.size {
		h.buf[(h.start+h.count)%h.size] = s
		h.count++
	} else {
		// Full ring: overwrite the oldest and advance the window — no shift.
		h.buf[h.start] = s
		h.start = (h.start + 1) % h.size
	}
	// Broadcast under the lock. The sends are non-blocking (buffered channel +
	// select default), so holding the lock can't deadlock — and it prevents a
	// subscriber's cancel() from closing a channel between our snapshot and the
	// send, which would panic with "send on closed channel".
	for ch := range h.subs {
		select {
		case ch <- s:
		default:
		}
	}
}

// Recent returns a copy of the retained samples, oldest first.
func (h *Hub) Recent() []Sample { return h.RecentN(0) }

// RecentN returns a copy of up to the last n retained samples, oldest first.
// n <= 0 returns all retained samples. The UI only renders the last ~90, so it
// asks for n=90 to avoid shipping the full 300-sample buffer every second.
func (h *Hub) RecentN(n int) []Sample {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.count
	if n > 0 && c > n {
		c = n
	}
	out := make([]Sample, c)
	// The last c samples end at (start+count-1); begin c back from there and walk
	// forward, wrapping around the ring, so the result is oldest-first.
	begin := h.start + h.count - c
	for i := 0; i < c; i++ {
		out[i] = h.buf[(begin+i)%h.size]
	}
	return out
}

// Subscribe returns a channel of future samples plus an unsubscribe func.
func (h *Hub) Subscribe() (<-chan Sample, func()) {
	ch := make(chan Sample, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, cancel
}
