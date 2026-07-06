package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/speedtest"
)

// handleSpeedtest runs a throughput test. Body: {via, bytes, id}. When id is
// set and it belongs to a selector group, that endpoint is temporarily selected
// (then restored) so the test measures *that* tunnel; otherwise the test runs
// through the active route.
func (s *Server) handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Via   string `json:"via"`
		Bytes int    `json:"bytes"`
		ID    string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	bytes := body.Bytes
	if bytes <= 0 {
		bytes = 10_000_000
	}
	if bytes > 100_000_000 {
		bytes = 100_000_000
	}

	viaProxy := s.singbox != nil && s.singbox.Running()
	switch body.Via {
	case "proxy":
		viaProxy = true
	case "direct":
		viaProxy = false
	}

	pinned := false
	if body.ID != "" && s.clash != nil {
		if restore := s.selectEndpoint(r.Context(), body.ID); restore != nil {
			pinned, viaProxy = true, true
			defer restore()
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	res, err := speedtest.New(s.config().Ports.Mixed).Run(ctx, viaProxy, bytes)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		speedtest.Result
		Pinned bool   `json:"pinned"`
		ID     string `json:"id,omitempty"`
	}{res, pinned, body.ID})
}

// selectEndpoint temporarily selects id in any selector group that contains it,
// returning a restore func (or nil if it can't be pinned, e.g. urltest groups).
func (s *Server) selectEndpoint(ctx context.Context, id string) func() {
	for _, g := range s.store.Profile().Groups {
		if g.Type != model.GroupSelector {
			continue
		}
		for _, m := range g.Members {
			if m != id {
				continue
			}
			prev := ""
			if px, err := s.clash.Proxies(ctx); err == nil {
				prev = px[g.ID].Now
			}
			if err := s.clash.Select(ctx, g.ID, id); err != nil {
				return nil
			}
			return func() {
				if prev != "" {
					rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = s.clash.Select(rctx, g.ID, prev)
				}
			}
		}
	}
	return nil
}
