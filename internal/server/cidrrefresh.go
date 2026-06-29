package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"velinx/internal/cidrfeed"
	"velinx/internal/model"
)

// handleRoutingRefresh (POST /api/routing/refresh) re-fetches every routing list that has a
// CIDRSource and updates its CIDRCache (last-good kept on a per-feed failure). It does NOT
// apply — the refreshed CIDRs activate on the next /api/apply (the normal, fail-safe-
// protected path), matching the app's stage-then-Apply model and avoiding a second apply
// path. Returns per-list cache sizes + any per-feed errors so the UI can report
// "refreshed N, M failed".
func (s *Server) handleRoutingRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	changed, errs := s.refreshAll(ctx)
	errStrs := make([]string, 0, len(errs))
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}
	type listInfo struct {
		ID     string `json:"id"`
		Source string `json:"cidr_source"`
		CIDRs  int    `json:"cidrs"`
	}
	lists := []listInfo{}
	p := s.store.Profile()
	for i := range p.RoutingLists {
		if rl := p.RoutingLists[i]; rl.CIDRSource != "" {
			lists = append(lists, listInfo{ID: rl.ID, Source: rl.CIDRSource, CIDRs: len(rl.CIDRCache)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changed": changed,
		"errors":  errStrs,
		"lists":   lists,
		"note":    "CIDRs refreshed into each list's cache — click Apply to activate.",
	})
}

// refreshOne fetches a routing list's CIDRSource and, when the result differs from the
// list's current CIDRCache, persists the new cache. Returns (changed, error). It does NOT
// re-apply — a batch refresh applies once after updating all changed lists (the ticker
// loop, auto-refresh phase 4b). Safety: a fetch error OR a zero-entry result LEAVES the
// existing cache intact (last-good) and returns an error, so a transient feed/RIPEstat
// failure or a format change never empties a live carve-out.
func (s *Server) refreshOne(ctx context.Context, rl model.RoutingList) (changed bool, err error) {
	if rl.CIDRSource == "" {
		return false, nil
	}
	cidrs, skipped, err := cidrfeed.Fetch(ctx, s.subscriptionFetchClient(), rl.CIDRSource)
	if err != nil {
		return false, fmt.Errorf("refresh %q: %w", rl.ID, err)
	}
	if len(cidrs) == 0 {
		return false, fmt.Errorf("refresh %q: source returned 0 valid entries (%d skipped) — keeping last-good", rl.ID, skipped)
	}
	sort.Strings(cidrs)
	if equalStrings(cidrs, rl.CIDRCache) {
		return false, nil // unchanged — don't churn the store / trigger a re-apply
	}
	if err := s.store.SetRoutingListCache(rl.ID, cidrs); err != nil {
		return false, fmt.Errorf("refresh %q: %w", rl.ID, err)
	}
	return true, nil
}

// refreshAll refreshes every ENABLED routing list that has a CIDRSource (refreshOne each),
// returning whether ANY list's cache changed plus the per-list errors — one feed failing
// does NOT stop the others (each keeps its own last-good). The caller (the refresh ticker
// / a manual "refresh now") re-applies once when changed. Lists with no CIDRSource, or
// disabled, are skipped.
func (s *Server) refreshAll(ctx context.Context) (changed bool, errs []error) {
	p := s.store.Profile()
	for i := range p.RoutingLists {
		rl := p.RoutingLists[i]
		if rl.CIDRSource == "" || !rl.Enabled {
			continue
		}
		ch, err := s.refreshOne(ctx, rl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ch {
			changed = true
		}
	}
	return changed, errs
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
