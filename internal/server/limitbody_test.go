package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLimitBody verifies the request-body cap: a read within maxRequestBody
// succeeds and delivers the bytes intact, while a body larger than the cap makes
// the handler's read fail (so a JSON decoder returns its usual 400 instead of
// buffering unbounded memory and risking an OOM on the RAM-constrained router).
func TestLimitBody(t *testing.T) {
	// The wrapped handler drains the body and records whether the read errored
	// and how many bytes it got.
	var gotErr bool
	var gotN int
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		gotErr = err != nil
		gotN = len(b)
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name     string
		size     int
		wantErr  bool
		wantRead int // bytes the handler should have read before any error
	}{
		{"well under cap", 1024, false, 1024},
		{"just under cap", maxRequestBody - 1, false, maxRequestBody - 1},
		{"at cap", maxRequestBody, false, maxRequestBody},
		{"over cap errors", maxRequestBody + 1024, true, maxRequestBody},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotErr, gotN = false, 0
			body := strings.NewReader(strings.Repeat("a", c.size))
			req := httptest.NewRequest(http.MethodPost, "http://192.168.2.1:8088/api/import", body)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if gotErr != c.wantErr {
				t.Errorf("read error = %v, want %v (size %d)", gotErr, c.wantErr, c.size)
			}
			// On an over-cap body the reader yields exactly maxRequestBody bytes
			// before failing; within the cap it yields the whole body.
			if gotN != c.wantRead {
				t.Errorf("bytes read = %d, want %d (size %d)", gotN, c.wantRead, c.size)
			}
		})
	}
}

// TestLimitBodyNilBodySafe ensures the middleware doesn't panic when there is no
// body (e.g. a bodyless POST like /api/service/restart).
func TestLimitBodyNilBodySafe(t *testing.T) {
	reached := false
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://192.168.2.1:8088/api/service/restart", nil)
	req.Body = nil // explicit: no body at all
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !reached {
		t.Fatal("handler not reached with a nil body")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestLimitBody_BoundsSlowTrickleBody is the LOOP-040 proof. MaxBytesReader caps how MANY bytes a
// body may carry but not how LONG they may take to arrive, so a client that trickles a body forever
// pins a goroutine + descriptor per connection — a slowloris the byte cap is blind to. limitBody now
// sets a read deadline on body-bearing methods, so a body slower than the window is cut off, while a
// prompt body (any legitimate one) still goes through. Run against a REAL httptest server, since the
// deadline needs a socket — httptest.NewRecorder has none, which is why the size tests above still
// exercise only the byte cap.
//
// Proven to FAIL when the SetReadDeadline line in limitBody is removed: the slow body is then read to
// completion and answered 200.
func TestLimitBody_BoundsSlowTrickleBody(t *testing.T) {
	orig := slowBodyReadTimeout
	slowBodyReadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { slowBodyReadTimeout = orig })

	// Reads the whole body; answers 200 only if the read completed, 408 if it timed out.
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "body read did not complete in time", http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// A prompt body sails through — the deadline never fires for legitimate traffic.
	t.Run("prompt body is accepted", func(t *testing.T) {
		resp, err := http.Post(ts.URL+"/api/import", "application/json", strings.NewReader(`{"ok":true}`))
		if err != nil {
			t.Fatalf("prompt POST failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("prompt body got %d, want 200 — the deadline is too aggressive for legitimate traffic", resp.StatusCode)
		}
	})

	// A body that opens, then stalls PAST the deadline before finishing, is cut off. io.Pipe drives
	// the request body: the client sends "{", sleeps well past 200ms, then "}". The server's read
	// hits the deadline during the stall.
	t.Run("trickled body is cut off", func(t *testing.T) {
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write([]byte("{"))
			time.Sleep(1 * time.Second) // >> slowBodyReadTimeout
			// By now the server has timed out and closed the body; this Write returns ErrClosedPipe
			// rather than blocking, so the goroutine does not leak.
			_, _ = pw.Write([]byte("}"))
			_ = pw.Close()
		}()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/import", pr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return // the server reset the connection mid-body — a valid "rejected" outcome
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a body trickled slower than the read deadline was accepted (200) — the slowloris is not bounded")
		}
	})
}
