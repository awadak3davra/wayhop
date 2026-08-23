package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestServerAlert verifies s.alert: when a Watchdog.NotifyURL is configured it POSTs
// {"text":msg} (async), reading the CURRENT config so a Settings change is honored; with
// no URL it is a silent no-op. This is the shared notifier path for crash-restart +
// fail-safe rollback/reboot alerts.
func TestServerAlert(t *testing.T) {
	got := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- body.Text
	}))
	defer ts.Close()

	s := serverjobs_newServer(t)
	s.allowInternalFetch = true // this test delivers to a loopback httptest server; bypass the SSRF dial guard

	// URL configured → alert POSTs the message.
	s.cfgMu.Lock()
	s.cfg.Watchdog.NotifyURL = ts.URL
	s.cfgMu.Unlock()
	s.alert("rolled back")
	select {
	case msg := <-got:
		if msg != "rolled back" {
			t.Errorf("alert posted %q, want %q", msg, "rolled back")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("alert did not POST to the configured webhook")
	}

	// No URL → alert is a no-op (no POST).
	s.cfgMu.Lock()
	s.cfg.Watchdog.NotifyURL = ""
	s.cfgMu.Unlock()
	s.alert("ignored")
	select {
	case msg := <-got:
		t.Errorf("alert posted %q with no NotifyURL set", msg)
	case <-time.After(300 * time.Millisecond):
		// good: nothing posted
	}
}
