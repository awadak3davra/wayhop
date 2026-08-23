package server

import (
	"context"
	"net/http"
	"strconv"
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
	writeJSON(w, http.StatusOK, map[string]any{
		"elected": elected, "local_fault": localFault,
		// Which groups the daemon itself re-points when a member dies. Without this the Failover page
		// had to guess, and guessed the old answer: it told a native group backing routing lists that
		// it "does not switch by itself", which stopped being true when the routing-list failover owner
		// landed (listfailover.go) — measured on a live router, nwg3 down to nwg5 in 15s. A
		// page that under-promises here is as wrong as one that over-promises: it sends the operator
		// looking for a manual switch the daemon has already made.
		"self_switching_groups": s.selfSwitchingGroups(),
		// Which members of those groups the KERNEL plane can route to. A group that mixes a native
		// tunnel with an engine-carried one has fewer exits than it has members, and only the daemon
		// knows which: see kernelElectableMembers.
		"kernel_members": s.kernelElectableMembers(),
	})
}

// selfSwitchingGroups names the groups whose routing-list tables this daemon owns and re-points on
// health changes. Empty where that owner does not run — it is the answer for THIS platform, not a
// claim about what the feature could do elsewhere.
func (s *Server) selfSwitchingGroups() []string {
	// Same precondition as the loop itself — this must report what that loop will actually do, on any
	// platform where it runs.
	if s == nil || !iprouteAvailable() {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range s.listFailoverTargets() {
		if t.Group != "" && !seen[t.Group] {
			seen[t.Group] = true
			out = append(out, t.Group)
		}
	}
	return out
}

// handleFailoverEvents returns the failover log: confirmed exit outages and recoveries, plus the
// switches the proxy core actually made. See internal/health/events.go for what it can and cannot
// contain — notably it starts empty on every daemon restart, which the UI states rather than
// letting an empty list read as "nothing has ever gone wrong".
func (s *Server) handleFailoverEvents(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "known": false})
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 256 {
			limit = n
		}
	}
	events := s.monitor.Events(limit)
	// The stated window must contain everything shown. The monitor starts ticking before this server
	// is constructed, so a window beginning at server start would exclude entries it is displaying.
	since := s.startedAt.UnixMilli()
	if oldest := s.monitor.OldestEventAt(); oldest != 0 && oldest < since {
		since = oldest
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		// known=false means the log could not be read at all, which is a different answer from an
		// empty log and the page renders it differently.
		"known":    true,
		"since_ms": since,
		"total":    s.monitor.EventCount(),
		// Whether entries were left out — not whether the caller happened to ask for fewer than the
		// ring can hold, which is what comparing the limit to the capacity actually measured.
		"truncated": len(events) < s.monitor.EventCount(),
	})
}

// handleHealthHistory returns each exit's rolling probe window for the Diagnostics availability
// bands. Served on its own route rather than folded into /api/health/endpoints, which the dashboard
// polls every few seconds — the bands are read once when a page opens and do not belong on that path.
func (s *Server) handleHealthHistory(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeJSON(w, http.StatusOK, map[string]any{"windows": []any{}, "known": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"windows": s.monitor.RecentWindows(),
		"known":   true,
	})
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
