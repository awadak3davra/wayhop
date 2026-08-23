package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"wayhop/internal/watchdog"
)

// handleWatchdog reports the crash-restart supervisor state (restarts, last restart, backoff) for
// the Dashboard / Diagnostics.
func (s *Server) handleWatchdog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.supervisionStats())
}

// supervisionStats is the watchdog's view, empty (unsupervised) when the daemon has none.
func (s *Server) supervisionStats() watchdog.Stats {
	if s == nil || s.watchdog == nil {
		return watchdog.Stats{}
	}
	return s.watchdog.Stats()
}

// makeWebhookNotifier returns an alert hook that POSTs {"text":"…"} to url on
// each crash-restart (e.g. a Telegram bot webhook). Fire-and-forget with a short timeout.
// The caller supplies the http.Client: production passes the SSRF-guarded
// subscriptionFetchClient (blockInternalDial + capped redirects) so an operator-
// supplied — or 302-redirected — internal NotifyURL can't reach loopback/RFC1918/
// CGNAT/link-local/metadata targets, the same guard the subscription-fetch path uses.
func makeWebhookNotifier(url string, client *http.Client) func(string) {
	return func(msg string) {
		body, _ := json.Marshal(map[string]string{"text": msg})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
}

// alert fires a fire-and-forget webhook notification for an operational event
// (sing-box crash-restart, fail-safe rollback/reboot) when a NotifyURL is configured.
// It reads the CURRENT config — so a Settings change to the URL is honored, unlike a
// notifier frozen at startup — and runs async so it never blocks the caller (the
// fail-safe rollback path holds applyMu; a slow webhook must not stall it). No-op when
// no URL is set.
func (s *Server) alert(msg string) {
	if u := s.config().Watchdog.NotifyURL; u != "" {
		go makeWebhookNotifier(u, s.subscriptionFetchClient())(msg)
	}
}
