package server

import (
	"context"
	"net/http"
	"time"
)

// handleHealthEndpoints returns the accumulated per-target health snapshot
// (state, latency, success rate, avg latency, reconnections, uptime).
func (s *Server) handleHealthEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.Snapshot())
}

// handleFailoverState returns the REAL failover state for the Failover UI: the actually-elected
// member of each group — sing-box's live pick, read from Clash `now`, NOT the client-side
// lowest-latency guess the page otherwise shows as "BEST" — plus the monitor's local-fault flag
// (every exit down at once ⇒ a likely local-uplink problem, not N independent exit failures).
// Read-only + best-effort: a missing Clash (native-only / stopped core) yields an empty elected
// map, and the UI falls back to its latency guess.
func (s *Server) handleFailoverState(w http.ResponseWriter, r *http.Request) {
	elected := map[string]string{}
	localFault := false
	if s.monitor != nil {
		localFault = s.monitor.LocalFault()
	}
	if s.clash != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if proxies, err := s.clash.Proxies(ctx); err == nil {
			for _, g := range s.store.Profile().Groups {
				if p, ok := proxies[g.ID]; ok && p.Now != "" {
					elected[g.ID] = p.Now
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"elected": elected, "local_fault": localFault})
}

// handleHealthTest probes a single target immediately ("Test now").
func (s *Server) handleHealthTest(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitor not running")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.monitor.ProbeOne(ctx, r.PathValue("id")))
}
