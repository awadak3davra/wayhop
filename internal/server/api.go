package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"wayhop/internal/version"
)

const (
	// sseWriteTimeout bounds a single SSE frame write. Without it a stalled-but-open
	// reader (e.g. one advertising a zero TCP receive window and never reading) blocks
	// the request goroutine forever: r.Context() is cancelled only when the connection's
	// background read observes a client close/RST, which never happens for a peer that
	// keeps the socket open, and there is no http.Server WriteTimeout either.
	sseWriteTimeout = 10 * time.Second
	// sseHeartbeat emits a comment frame during quiet periods so a dead/stalled peer
	// surfaces a write error even when no samples are flowing.
	sseHeartbeat = 15 * time.Second
)

type healthResp struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	// Build is the identity of the running binary: which commit, built when, and whether the tree
	// was clean. Carries no secrets — it is the same information `wayhop --version` prints — and it
	// is here because "which code is actually running on this router" had no answer from outside.
	Build   version.Info `json:"build"`
	Demo    bool         `json:"demo"`
	SingBox struct {
		Available  bool `json:"available"`
		Running    bool `json:"running"`
		NativeOnly bool `json:"native_only"`
	} `json:"singbox"`
}

// handleHealth reports daemon + core status (used by the UI header pill).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Health is live operational truth used for reconnect and status decisions. A browser or LAN
	// proxy must never reuse an earlier "ok" response after the daemon/core state or build changed.
	w.Header().Set("Cache-Control", "no-store")
	var resp healthResp
	resp.Status = "ok"
	resp.Version = version.Version
	resp.Build = version.Get()
	resp.Demo = s.config().Demo
	if s.singbox != nil {
		resp.SingBox.Available = s.singbox.Available()
		resp.SingBox.Running = s.singbox.Running()
	}
	// Monitor mode: the daemon doesn't manage sing-box, so Running() stays false even
	// when sing-box is up independently and serving the Clash API (the same API that
	// feeds the live traffic / top-talkers). If we can reach it, the core IS running —
	// report that so the UI stops showing a false "core not running" while live stats flow.
	if !resp.SingBox.Running && s.clash != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		if _, err := s.clash.Proxies(ctx); err == nil {
			resp.SingBox.Running = true
			resp.SingBox.Available = true
		}
	}
	// Native-only: the live profile needs no sing-box (generator.DatapathNativeOnly — "fast"
	// mode + all egresses kernel-native), so an absent core is BY DESIGN. The UI reads this
	// to show "native-only mode" instead of a false "core down". Conservative by construction.
	if s.store != nil {
		resp.SingBox.NativeOnly = s.nativeOnlyCached()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTrafficRecent returns the retained samples so a fresh tab backfills
// instantly. ?n=N caps the response to the last N samples (the UI renders only
// the last ~90, so it asks for n=90 instead of pulling the whole 300 buffer).
func (s *Server) handleTrafficRecent(w http.ResponseWriter, r *http.Request) {
	n := 0
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, s.hub.RecentN(n))
}

// handleTrafficStream pushes samples to the browser as Server-Sent Events.
func (s *Server) handleTrafficStream(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	rc := http.NewResponseController(w)
	ch, cancel := s.hub.Subscribe()
	defer cancel()

	// send writes one frame under a bounded write deadline and flushes; it returns
	// false when the write fails (deadline exceeded on a stalled peer, or a real
	// disconnect) so the caller returns and the goroutine is freed. SetWriteDeadline
	// may be unsupported by the underlying writer (e.g. in tests) — that is best-effort
	// and never fatal.
	send := func(frame string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := io.WriteString(w, frame); err != nil {
			return false
		}
		_ = rc.Flush()
		return true
	}

	// Backfill the rolling buffer before streaming live samples.
	for _, sample := range s.hub.Recent() {
		if !send(sseFrame(sample)) {
			return
		}
	}

	// A heartbeat comment frame during quiet periods makes a dead/stalled peer surface
	// a write error even when no samples are flowing (EventSource ignores ":" comments).
	ping := time.NewTicker(sseHeartbeat)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if !send(": ping\n\n") {
				return
			}
		case sample, ok := <-ch:
			if !ok {
				return
			}
			if !send(sseFrame(sample)) {
				return
			}
		}
	}
}

// sseFrame renders v as an SSE "data:" frame, or "" if it cannot be marshalled.
func sseFrame(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("data: %s\n\n", data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
