package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"wayhop/internal/version"
)

type healthResp struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Demo    bool   `json:"demo"`
	SingBox struct {
		Available  bool `json:"available"`
		Running    bool `json:"running"`
		NativeOnly bool `json:"native_only"`
	} `json:"singbox"`
}

// handleHealth reports daemon + core status (used by the UI header pill).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var resp healthResp
	resp.Status = "ok"
	resp.Version = version.Version
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.hub.Subscribe()
	defer cancel()

	// Backfill the rolling buffer before streaming live samples.
	for _, sample := range s.hub.Recent() {
		writeSSE(w, sample)
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case sample, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, sample)
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
