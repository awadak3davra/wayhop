package clash

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClashDelayMalformed200 guards the fix for a 200 response with an unparseable body:
// it must surface an error (→ probe maps it to Unknown) rather than silently returning
// (0, nil) which the monitor treats as Alive(0) — masking a real failure.
func TestClashDelayMalformed200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>captcha, not json</html>"))
	}))
	defer ts.Close()
	c := newClient(t, ts)

	_, err := c.Delay(context.Background(), "p", "http://x", 1000)
	if err == nil {
		t.Fatal("Delay returned nil for a malformed 200 body — would be marked Alive(0)")
	}
	// It must NOT be ErrProxyDown (that means the test ran and failed → Down); a malformed
	// body is an unreachable/indeterminate result → Unknown.
	if errors.Is(err, ErrProxyDown) {
		t.Errorf("malformed 200 should be a generic error (→ Unknown), not ErrProxyDown: %v", err)
	}
}
