package traffic

import (
	"sync"
	"testing"
)

// Regression for the "send on closed channel" panic: a subscriber that cancels
// (closing its channel) mid-broadcast must not crash Push. Run with -race.
func TestHubPushSubscribeCancelNoPanic(t *testing.T) {
	h := NewHub(64)
	var wg sync.WaitGroup

	// Pushers.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				h.Push(Sample{T: int64(j), Up: 1, Down: 1})
			}
		}()
	}
	// Subscribers that churn: subscribe, drain a little, cancel (closes the chan).
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				ch, cancel := h.Subscribe()
				select {
				case <-ch:
				default:
				}
				cancel()
			}
		}()
	}
	wg.Wait() // a panic in any Push goroutine would crash the test
}
