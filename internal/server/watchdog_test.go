package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"velinx/internal/watchdog"
)

// stoppedSup is a Supervisor that is never running (demo-like).
type stoppedSup struct{}

func (stoppedSup) Desired() bool { return false }
func (stoppedSup) Alive() bool   { return false }
func (stoppedSup) Start() error  { return nil }

func TestHandleWatchdog(t *testing.T) {
	s := &Server{watchdog: watchdog.New("sing-box", stoppedSup{})}
	req := httptest.NewRequest(http.MethodGet, "/api/watchdog", nil)
	w := httptest.NewRecorder()
	s.handleWatchdog(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	// The JSON must carry the documented keys with the expected demo values.
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, k := range []string{"supervised", "alive", "restarts"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("watchdog stats missing key %q (body=%s)", k, w.Body.String())
		}
	}
	var st watchdog.Stats
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Supervised || st.Alive || st.Restarts != 0 {
		t.Fatalf("unexpected demo stats: %+v", st)
	}
}

func TestWebhookNotifier(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		got <- m
	}))
	defer srv.Close()

	makeWebhookNotifier(srv.URL)("sing-box crashed — restart #1")

	select {
	case m := <-got:
		if m["text"] != "sing-box crashed — restart #1" {
			t.Fatalf("unexpected webhook payload: %v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not delivered")
	}
}
