package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHealthCheckBattery exercises the whole "Run all checks" battery end-to-end (handleHealthCheck):
// every check runs, returns a well-formed row (non-empty id + a valid status), and none panic. A
// short request context makes the network sub-checks (clock-skew / DNS / reachability) fail fast
// instead of taking the handler's 15s — we're asserting wiring + row shape, not probe outcomes. Also
// locks that the recently-added checks are actually wired into the battery.
func TestHealthCheckBattery(t *testing.T) {
	s, _ := sharehandlers_server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/healthcheck", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	s.handleHealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Checks []healthRow `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body.String())
	}
	if len(resp.Checks) == 0 {
		t.Fatal("battery returned no checks")
	}
	seen := map[string]bool{}
	for _, c := range resp.Checks {
		if c.ID == "" {
			t.Errorf("a check has an empty id: %+v", c)
		}
		switch c.Status {
		case "pass", "warn", "fail":
		default:
			t.Errorf("check %q has invalid status %q", c.ID, c.Status)
		}
		seen[c.ID] = true
	}
	for _, id := range []string{"conntrack", "subscription", "disk-space"} {
		if !seen[id] {
			t.Errorf("battery is missing wired check %q (got %v)", id, keysOf(seen))
		}
	}
}
