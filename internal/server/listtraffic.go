package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"wayhop/internal/platform"
)

// Per-routing-list traffic: how many connections actually landed in each list, and how many bytes
// went with them.
//
// The Routing page shows an ordered rule-set, and the one thing it could never answer was whether a
// rule was doing anything. A list that matches nothing looks exactly like a list that matches
// everything important, so people keep dead rules forever and cannot tell which of two overlapping
// lists is winning.
//
// The numbers come from the connections the PROXY CORE reports, which bounds what they can mean, and
// that bound is the point:
//
//   - Kernel-routed traffic is invisible here. In hybrid/fast mode a pure-IP list pointed at a kernel
//     egress never reaches sing-box at all, so its counters stay zero however busy it is. Reporting
//     that zero as "nothing matched" would be a lie about the busiest lists on a kernel-first router,
//     so each list is marked with whether the running core can even see it — read from the config the
//     core is ACTUALLY running, not guessed from what the generator would emit.
//   - A connection that opens and closes between two polls is missed entirely.
//   - Counters live in RAM and start at zero on every restart.
//
// Sampling piggybacks on the existing per-outbound poll (see ifacehistory.go), so this costs no extra
// request to the core.

// listStats is one routing list's observed traffic.
type listStats struct {
	Live  int   `json:"live"`  // connections open right now
	Conns int64 `json:"conns"` // connections first seen since the daemon started
	Bytes int64 `json:"bytes"` // up+down attributed to this list since the daemon started
}

// listIDFromRulePayload maps a Clash rulePayload to the routing list it belongs to.
//
// A list contributes up to two rule-sets: "rs-<id>" for its remote source and "rsm-<id>" for its
// manual entries. sing-box may report several tags at once for a rule that references both, so the
// payload is split and the first recognised tag wins — both halves belong to the same list, and
// counting the connection twice would double its bytes.
func listIDFromRulePayload(payload string) string {
	for _, raw := range strings.FieldsFunc(payload, func(r rune) bool {
		return r == ',' || r == ' ' || r == '[' || r == ']' || r == '"'
	}) {
		if id := strings.TrimPrefix(raw, "rsm-"); id != raw && id != "" {
			return id
		}
		if id := strings.TrimPrefix(raw, "rs-"); id != raw && id != "" {
			return id
		}
	}
	return ""
}

// coreVisibleLists reads the sing-box config the core is running and returns the routing-list IDs it
// carries a rule-set for.
//
// Reading the file rather than re-deriving it from the profile matters: the running config is what
// attributes connections, and it can lag the profile by an unapplied change. Deriving would answer
// "what would the core see if we applied", which is a different question and would mark a list
// visible while the running core has never heard of it.
//
// An unreadable config returns ok=false, and the caller must NOT then treat every list as invisible —
// "could not check" is not "not there".
func coreVisibleLists(path string) (ids map[string]bool, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cfg struct {
		Route struct {
			RuleSet []struct {
				Tag string `json:"tag"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, false
	}
	ids = map[string]bool{}
	for _, rs := range cfg.Route.RuleSet {
		if id := listIDFromRulePayload(rs.Tag); id != "" {
			ids[id] = true
		}
	}
	return ids, true
}

// handleRoutingTraffic reports per-list observed traffic plus everything needed to read it honestly.
func (s *Server) handleRoutingTraffic(w http.ResponseWriter, r *http.Request) {
	prof := s.store.Profile()
	if s.config().Demo {
		// A disabled list is never emitted into the core config, so the demo must report it invisible
		// too — otherwise the one path that distinguishes "switched off" from "kernel-routed" is the
		// only path the demo can never exercise, which is where UI bugs go to hide.
		ids := make([]string, 0, len(prof.RoutingLists))
		vis := map[string]bool{}
		for _, rl := range prof.RoutingLists {
			ids = append(ids, rl.ID)
			vis[rl.ID] = rl.Enabled
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"lists": demoListTraffic(ids, time.Now()), "since_ms": s.startedAt.UnixMilli(),
			"visible_known": true, "core_visible": vis, "sampled": true, "demo": true,
		})
		return
	}
	stats := map[string]listStats{}
	if s.outbound != nil {
		s.outbound.mu.Lock()
		for id, b := range s.outbound.listBytes {
			st := stats[id]
			st.Bytes = b
			stats[id] = st
		}
		for id, c := range s.outbound.listConns {
			st := stats[id]
			st.Conns = c
			stats[id] = st
		}
		for id, l := range s.outbound.listLive {
			st := stats[id]
			st.Live = l
			stats[id] = st
		}
		s.outbound.mu.Unlock()
	}
	// On a kernel-routed router the core has nothing to report, and reporting ITS silence as the
	// list's activity is what made every row read "nothing yet" while the mangle chain was matching.
	// Read the plane that is actually carrying the traffic. Core numbers win when both exist: they
	// are per-connection and live, where these are cumulative since the rules were installed.
	kernelStats := map[string]listStats{}
	if s.detectedPlatform() == platform.Keenetic || s.routingMode(s.config()) == "fast" ||
		s.routingMode(s.config()) == "hybrid" {
		ids := make([]string, 0, len(prof.RoutingLists))
		for _, rl := range prof.RoutingLists {
			ids = append(ids, rl.ID)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		kernelStats = s.kernelListCounters(ctx, ids)
		cancel()
	}
	// Every list appears, including the ones with nothing — a missing row would read as a missing
	// list rather than an idle one.
	out := make(map[string]listStats, len(prof.RoutingLists))
	for _, rl := range prof.RoutingLists {
		st := stats[rl.ID]
		if st.Bytes == 0 && st.Conns == 0 && st.Live == 0 {
			if k, ok := kernelStats[rl.ID]; ok {
				st = k
			}
		}
		out[rl.ID] = st
	}
	visible, visibleKnown := coreVisibleLists(s.config().SingBox.Config)
	vis := map[string]bool{}
	if visibleKnown {
		for _, rl := range prof.RoutingLists {
			vis[rl.ID] = visible[rl.ID]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lists":    out,
		"since_ms": s.startedAt.UnixMilli(),
		// visible_known=false means the running config could not be read, so a zero is
		// "not measured", not "not matched". The page words those two differently.
		"visible_known": visibleKnown,
		"core_visible":  vis,
		"sampled":       s.outbound != nil && s.clash != nil,
	})
}

// demoListTraffic synthesises plausible per-list numbers so the page can be developed and reviewed
// without a running core. Marked demo by the caller; never mixed with real samples.
func demoListTraffic(ids []string, now time.Time) map[string]listStats {
	out := make(map[string]listStats, len(ids))
	elapsed := int64(now.Unix() % 3600)
	for i, id := range ids {
		seed := int64(len(id)*37 + i*11)
		out[id] = listStats{
			Live:  int(seed % 9),
			Conns: seed*3 + elapsed/7,
			Bytes: (seed + 3) * 1_100_000 * (elapsed/60 + 1),
		}
	}
	return out
}
