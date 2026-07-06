package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"time"

	"wayhop/internal/cidrfeed"
	"wayhop/internal/model"
	"wayhop/internal/store"
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

// fetchOne fetches rl.CIDRSource and returns the new SORTED CIDR set plus whether it DIFFERS from
// rl.CIDRCache — WITHOUT writing the store. The caller decides how to persist: refreshOne writes one
// list; the auto-refresh ticker coalesces many changed lists into a single write (flash protection).
// Safety: a fetch error OR a zero-entry result returns changed=false + an error and leaves the cache
// untouched (last-good), so a transient feed/RIPEstat failure never empties a live carve-out. Empty
// CIDRSource → (nil,false,nil).
func (s *Server) fetchOne(ctx context.Context, rl model.RoutingList) (cidrs []string, changed bool, err error) {
	if rl.CIDRSource == "" {
		return nil, false, nil
	}
	got, skipped, err := cidrfeed.Fetch(ctx, s.subscriptionFetchClient(), rl.CIDRSource)
	if err != nil {
		return nil, false, fmt.Errorf("refresh %q: %w", rl.ID, err)
	}
	if len(got) == 0 {
		return nil, false, fmt.Errorf("refresh %q: source returned 0 valid entries (%d skipped) — keeping last-good", rl.ID, skipped)
	}
	sort.Strings(got)
	if slices.Equal(got, rl.CIDRCache) {
		return got, false, nil // unchanged — don't churn the store / trigger a re-apply
	}
	return got, true, nil
}

// refreshOne fetches a routing list's CIDRSource and, when the result differs from the list's current
// CIDRCache, persists the new cache (a single-list write, source-guarded: a mid-fetch re-source of
// the list drops the now-stale result instead of resurrecting the old feed's CIDRs). Used by the
// MANUAL refreshAll path. It does NOT re-apply — the manual button follows the stage-then-Apply
// model (the auto-refresh ticker is what re-applies). Last-good is preserved on a fetch error /
// zero-entry result via fetchOne.
func (s *Server) refreshOne(ctx context.Context, rl model.RoutingList) (changed bool, err error) {
	cidrs, changed, err := s.fetchOne(ctx, rl)
	if err != nil || !changed {
		return false, err
	}
	n, err := s.store.SetRoutingListCaches(map[string]store.CacheUpdate{rl.ID: {Source: rl.CIDRSource, CIDRs: cidrs}})
	if err != nil {
		return false, fmt.Errorf("refresh %q: %w", rl.ID, err)
	}
	return n > 0, nil
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

// cidrIntervalHours is a routing list's effective auto-refresh cadence in hours: 0 → 24h default,
// and anything below the flash-protecting floor is clamped up (defends against a hand-edited
// profile.json that bypassed the API validator), anything above the ceiling clamped down.
func cidrIntervalHours(rl model.RoutingList) int {
	h := rl.RefreshHours
	if h == 0 {
		return 24
	}
	if h < model.MinCIDRRefreshHours {
		return model.MinCIDRRefreshHours
	}
	if h > model.MaxCIDRRefreshHours {
		return model.MaxCIDRRefreshHours
	}
	return h
}

// CIDRRefreshLoop auto-refreshes every enabled routing list's CIDRSource on that list's own
// RefreshHours cadence (0 → 24h default). It ticks hourly and re-reads config/profile each tick so a
// Settings or list change takes effect without a restart. FLASH SAFETY, in layers: (1) fetchOne's
// dedup — an unchanged feed writes nothing; (2) a whole tick's changed lists are coalesced into ONE
// store write via SetRoutingListCaches; (3) each list's cadence is clamped up to
// model.MinCIDRRefreshHours even if a hand-edited profile set it lower (cidrIntervalHours), and the
// hourly ticker is a hard sub-hourly floor at the mechanism level; (4) the first tick only SEEDS
// per-list timers (refreshing nothing) so a reboot/crash-loop never makes all lists due at once.
// After a batch it re-applies the KERNEL plane ONCE under applyMu — no sing-box reload, no fail-safe
// window (the CIDR carve-out is kernel-only in hybrid/fast mode; applyPBR is DeepEqual-idempotent).
// No-op in demo mode. Cancels with ctx (the process signal context), like the sibling loops.
func (s *Server) CIDRRefreshLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	due := map[string]time.Time{} // per-list next-ATTEMPT time (in-memory; seeded from CIDRRefreshed)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.cidrRefreshTick(ctx, due, time.Now())
	}
}

// cidrRefreshTick performs one auto-refresh tick (extracted from CIDRRefreshLoop so tests can drive
// time). Scheduling: each eligible list's first due time seeds from its PERSISTED CIDRRefreshed
// (+interval), so a router that restarts more often than a list's interval still refreshes on
// schedule (a never-refreshed list is due immediately). After every ATTEMPT — success, unchanged,
// or error — the in-memory due time advances a full interval, so an unchanged feed (which by design
// writes no flash and thus never advances CIDRRefreshed) is refetched once per interval per daemon
// life, not every tick. Deleted/disabled lists are dropped from the schedule; a shortened interval
// takes effect by clamping. Fetches run serially under per-list 60s timeouts; all changed caches
// coalesce into ONE source-guarded store write. The kernel plane is then re-applied ONLY when it is
// safe (see the block below). No-op in demo mode.
func (s *Server) cidrRefreshTick(ctx context.Context, due map[string]time.Time, now time.Time) {
	c := s.config()
	if c.Demo { // must not touch host state / make network calls in demo mode
		return
	}
	p := s.store.Profile()
	eligible := map[string]bool{}
	var dueList []model.RoutingList
	for _, rl := range p.RoutingLists {
		if rl.CIDRSource == "" || !rl.Enabled {
			continue
		}
		eligible[rl.ID] = true
		interval := time.Duration(cidrIntervalHours(rl)) * time.Hour
		nd, ok := due[rl.ID]
		if !ok {
			// First sighting (boot, or a newly added/re-enabled list): schedule from the persisted
			// last-refresh so restarts don't push refreshes forever; never refreshed -> due now.
			nd = now
			if rl.CIDRRefreshed > 0 {
				nd = time.Unix(rl.CIDRRefreshed, 0).Add(interval)
			}
			due[rl.ID] = nd
		}
		if nd.After(now.Add(interval)) {
			// The list's interval was shortened (or its id was recreated) — don't sit out the old,
			// longer schedule.
			nd = now.Add(interval)
			due[rl.ID] = nd
		}
		if !now.Before(nd) {
			dueList = append(dueList, rl)
		}
	}
	for id := range due { // drop deleted/disabled lists from the schedule
		if !eligible[id] {
			delete(due, id)
		}
	}
	if len(dueList) == 0 {
		return
	}
	// Fetch each due list under its OWN bounded timeout so a slow multi-ASN feed can't stall the loop
	// goroutine for minutes; accumulate changed caches; reschedule each attempt regardless of outcome.
	caches := map[string]store.CacheUpdate{}
	oldCache := map[string][]string{}
	for _, rl := range dueList {
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		cidrs, changed, err := s.fetchOne(fctx, rl)
		cancel()
		due[rl.ID] = now.Add(time.Duration(cidrIntervalHours(rl)) * time.Hour)
		if err != nil {
			log.Printf("cidr auto-refresh: %v", err)
			continue
		}
		if changed {
			caches[rl.ID] = store.CacheUpdate{Source: rl.CIDRSource, CIDRs: cidrs}
			oldCache[rl.ID] = rl.CIDRCache
		}
	}
	if len(caches) == 0 {
		return // nothing changed — no write, no re-apply
	}
	matched, err := s.store.SetRoutingListCaches(caches)
	if err != nil {
		log.Printf("cidr auto-refresh: persist %d list(s): %v", len(caches), err)
		return
	}
	if matched == 0 {
		log.Printf("cidr auto-refresh: %d list(s) changed but were deleted/re-sourced mid-fetch — skipped", len(caches))
		return
	}
	log.Printf("cidr auto-refresh: updated %d list(s)", matched)
	s.cidrAutoApply(oldCache)
}

// cidrAutoApply activates just-refreshed CIDR caches in the kernel plane when — and only when — it
// is safe to do so without an operator:
//
//   - FAST mode only. In hybrid the carve-out has a second half inside the running sing-box (the
//     TUN's route_exclude_address, one compile with the kernel plan by design): re-applying only the
//     kernel side would desync them — a CIDR *removed* from a feed would stay excluded from the TUN
//     and leak out the WAN. Hybrid/tun stay stage-then-Apply (the refreshed caches persist and
//     activate on the next Apply). Fast mode has no TUN, so the kernel plane is the whole story.
//   - NO STAGED DRIFT. The store profile is also the STAGING area: applying a plan compiled from it
//     would silently activate a user's staged-but-never-Applied routing edits with no fail-safe
//     window. Gate: a plan compiled from the pre-refresh profile (old caches) must equal the
//     installed plane — then the ONLY change the re-apply introduces is the refreshed CIDRs.
//   - RESTORE ON FAILURE. applyPBR tears down the old plane before installing the new one; if the
//     install fails the ticker restores the pre-refresh plan (best-effort) instead of leaving the
//     carve-outs dead until the next Apply.
//
// Holds applyMu end-to-end so it can't interleave with a concurrent manual Apply. (The refreshed
// caches themselves are already persisted — the profile read below carries them; only oldCache is
// needed, to reconstruct the pre-refresh profile for the drift gate.)
func (s *Server) cidrAutoApply(oldCache map[string][]string) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	c := s.config()
	if c.Demo {
		return
	}
	if mode := s.routingMode(c); mode != "fast" {
		log.Printf("cidr auto-refresh: staged only (mode=%s keeps kernel+sing-box in one Apply) — activate via Apply", mode)
		return
	}
	// ONE store snapshot: pOld is DERIVED from pNew (cloned list slice, old caches patched in), not
	// a second Profile() read — two reads could straddle a concurrent profile write, making the two
	// plans differ in more than the refreshed CIDRs, which is exactly what the drift gate must rule
	// out. Profile() already deep-clones the top-level slices; the compile below is read-only.
	pNew := s.store.Profile()
	pOld := pNew
	pOld.RoutingLists = append([]model.RoutingList(nil), pNew.RoutingLists...)
	for i := range pOld.RoutingLists {
		if old, ok := oldCache[pOld.RoutingLists[i].ID]; ok {
			pOld.RoutingLists[i].CIDRCache = old
		}
	}
	_, planOld := s.genOptionsWithPlan(&pOld, c)
	_, planNew := s.genOptionsWithPlan(&pNew, c)
	s.pbrMu.Lock()
	cur := s.pbrPlan
	s.pbrMu.Unlock()
	if !reflect.DeepEqual(planOld, cur) {
		log.Printf("cidr auto-refresh: staged changes pending (installed plane differs from the pre-refresh profile) — refreshed CIDRs will activate on the next Apply")
		return
	}
	if err := s.applyPBR(planNew); err != nil {
		log.Printf("cidr auto-refresh: kernel re-apply failed: %v — restoring the previous plane", err)
		if rerr := s.applyPBR(planOld); rerr != nil {
			log.Printf("cidr auto-refresh: RESTORE FAILED too (%v) — kernel carve-outs may be down until the next Apply", rerr)
		}
		return
	}
	log.Printf("cidr auto-refresh: kernel plane re-applied")
}
