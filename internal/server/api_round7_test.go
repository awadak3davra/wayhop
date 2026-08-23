package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/traffic"
)

// flushErrWriter is a flushable ResponseWriter whose Write starts failing after
// failAt successful writes — modelling a stalled-but-open reader whose socket send
// buffer is full. http.NewResponseController(w).SetWriteDeadline is unsupported on
// it (returns ErrNotSupported, which handleTrafficStream ignores), so the write
// error itself is what must unblock the handler.
type flushErrWriter struct {
	hdr    http.Header
	writes int
	failAt int
}

func (f *flushErrWriter) Header() http.Header {
	if f.hdr == nil {
		f.hdr = http.Header{}
	}
	return f.hdr
}
func (f *flushErrWriter) WriteHeader(int) {}
func (f *flushErrWriter) Flush()          {}
func (f *flushErrWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAt {
		return 0, errors.New("peer stalled: write would block")
	}
	return len(p), nil
}

// TestTrafficStream_WriteErrorReturns is the regression for the unbounded-write
// goroutine-park DoS: handleTrafficStream must return when an SSE frame write fails
// (as it would once a stalled peer's send buffer fills and the per-write deadline
// elapses), rather than parking the request goroutine forever. The pre-fix code
// swallowed the write error (fmt.Fprintf) and then blocked in the select loop with
// no ctx cancellation, hanging until the process died.
func TestTrafficStream_WriteErrorReturns(t *testing.T) {
	s := &Server{hub: traffic.NewHub(10)}
	s.hub.Push(traffic.Sample{T: 1, Up: 10, Down: 20})

	w := &flushErrWriter{failAt: 0} // fail on the very first (backfill) frame
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/stream", nil)

	done := make(chan struct{})
	go func() { s.handleTrafficStream(w, req); close(done) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleTrafficStream did not return on a write error — the goroutine parked")
	}
}

// TestTrafficStream_ContextCancelReturns confirms the normal path still works: the
// backfill frame is written and the handler returns promptly when the request
// context is cancelled (a real client disconnect Go can observe).
func TestTrafficStream_ContextCancelReturns(t *testing.T) {
	s := &Server{hub: traffic.NewHub(10)}
	s.hub.Push(traffic.Sample{T: 1, Up: 10, Down: 20})

	w := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/stream", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() { s.handleTrafficStream(w, req); close(done) }()

	// Give the backfill loop a moment, then simulate a disconnect.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleTrafficStream did not return after context cancel")
	}
	if !strings.Contains(w.Body.String(), `"up":10`) {
		t.Errorf("backfill frame not written before cancel; body=%q", w.Body.String())
	}
}
