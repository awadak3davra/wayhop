package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
		// A feed's address can carry its credential (a token in the path or query, a user in it),
		// and these strings end up in screenshots and bug reports.
		errStrs = append(errStrs, redactSubscriptionError(e.Error()))
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
	// The fetch happened, whatever it found. Recorded here rather than at the call sites so the two
	// can never disagree, and BEFORE the unchanged shortcut below — that shortcut is exactly the case
	// where nothing else records that anything was checked.
	s.noteCIDRChecked(rl.ID)
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
	cidrs, cidrChanged, cidrErr := s.fetchOne(ctx, rl)
	domains, domainChanged, domainErr := s.fetchDomainsOne(ctx, rl)
	// One list can carry both feeds. Each keeps its own last-good on failure, and a list where one
	// feed fails and the other succeeds still persists the half that worked — reporting both errors.
	err = errors.Join(cidrErr, domainErr)
	if !cidrChanged && !domainChanged {
		return false, err
	}
	up := store.CacheUpdate{}
	if cidrChanged {
		up.Source, up.CIDRs = rl.CIDRSource, cidrs
	}
	if domainChanged {
		up.DomainSource, up.Domains = rl.DomainSource, domains
	}
	n, werr := s.store.SetRoutingListCaches(map[string]store.CacheUpdate{rl.ID: up})
	if werr != nil {
		return false, errors.Join(err, fmt.Errorf("refresh %q: %w", rl.ID, werr))
	}
	return n > 0, err
}

// fetchDomainsOne is fetchOne for a list's DomainSource: same last-good contract, same "unchanged
// writes nothing" rule. A feed over the resolver's carrying capacity errors here (see
// cidrfeed.MaxDomains) rather than being trimmed, because a silently truncated domain list routes
// some of its names and leaks the rest.
func (s *Server) fetchDomainsOne(ctx context.Context, rl model.RoutingList) (domains []string, changed bool, err error) {
	if rl.DomainSource == "" {
		return nil, false, nil
	}
	got, skipped, err := cidrfeed.FetchDomains(ctx, s.subscriptionFetchClient(), rl.DomainSource)
	if err != nil {
		return nil, false, fmt.Errorf("refresh %q domains: %w", rl.ID, err)
	}
	if len(got) == 0 {
		return nil, false, fmt.Errorf("refresh %q domains: source returned 0 usable names (%d skipped) — keeping last-good", rl.ID, skipped)
	}
	sort.Strings(got)
	if slices.Equal(got, rl.DomainCache) {
		return got, false, nil
	}
	return got, true, nil
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
		if (rl.CIDRSource == "" && rl.DomainSource == "") || !rl.Enabled {
			continue
		}
		if ctx.Err() != nil {
			// Out of time: the rest were not asked, so they neither failed nor changed.
			errs = append(errs, fmt.Errorf("refresh %q: %w", rl.ID, errFeedNotTried))
			continue
		}
		ch, err := s.refreshOne(ctx, rl)
		if err != nil && ctx.Err() != nil {
			// The time ran out while this one was being asked: no answer from its feed either way.
			errs = append(errs, fmt.Errorf("refresh %q: %w", rl.ID, errFeedNotTried))
			continue
		}
		s.noteFeedRefresh(rl, time.Now(), err)
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

// feedNeverLoaded reports a list with a feed whose content has never been written: its timestamp is
// zero, as the store leaves it for a new list and resets it when that feed's source changes.
func feedNeverLoaded(rl model.RoutingList) bool {
	return (rl.CIDRSource != "" && rl.CIDRRefreshed == 0) || (rl.DomainSource != "" && rl.DomainRefreshed == 0)
}

// lastLoaded is when the list's feeds were last written, the older of the two where it has both, so a
// restart schedules the list by the more overdue one. Unchanged content is not written, so this can
// be older than the last fetch that worked; that only brings the first refresh after a restart
// forward.
func lastLoaded(rl model.RoutingList) int64 {
	var last int64
	for _, f := range []struct {
		src string
		at  int64
	}{{rl.CIDRSource, rl.CIDRRefreshed}, {rl.DomainSource, rl.DomainRefreshed}} {
		if f.src != "" && (last == 0 || f.at < last) {
			last = f.at
		}
	}
	return last
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
		if (rl.CIDRSource == "" && rl.DomainSource == "") || !rl.Enabled {
			continue
		}
		eligible[rl.ID] = true
		interval := time.Duration(cidrIntervalHours(rl)) * time.Hour
		nd, ok := due[rl.ID]
		switch {
		case feedNeverLoaded(rl):
			// A feed that has never loaded is due on every tick until it does: a new list, one whose
			// source was just changed in the panel (the store clears that feed's timestamp, and the
			// new source must not wait out the old one's schedule), or one whose feed has not
			// answered yet. Until it loads the list has nothing of it, and Apply refuses it.
			nd = now
			due[rl.ID] = nd
		case !ok:
			// First sighting (boot, or a newly added/re-enabled list): schedule from the persisted
			// last-refresh so restarts don't push refreshes forever.
			nd = time.Unix(lastLoaded(rl), 0).Add(interval)
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
	s.forgetFeeds(eligible)
	if len(dueList) == 0 {
		return
	}
	// Fetch each due list under its OWN bounded timeout so a slow multi-ASN feed can't stall the loop
	// goroutine for minutes; accumulate changed caches; reschedule each attempt regardless of outcome.
	caches := map[string]store.CacheUpdate{}
	for _, rl := range dueList {
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		cidrs, cidrChanged, cidrErr := s.fetchOne(fctx, rl)
		// A list's two feeds are fetched under the same budget and persisted in the same batch, so a
		// list carrying both still costs one write. One failing does not discard the other's result.
		domains, domainChanged, domainErr := s.fetchDomainsOne(fctx, rl)
		cancel()
		due[rl.ID] = now.Add(time.Duration(cidrIntervalHours(rl)) * time.Hour)
		s.noteFeedRefresh(rl, now, errors.Join(cidrErr, domainErr))
		for _, err := range []error{cidrErr, domainErr} {
			if err != nil {
				log.Printf("list auto-refresh: %s", redactSubscriptionError(err.Error()))
			}
		}
		if !cidrChanged && !domainChanged {
			continue
		}
		up := store.CacheUpdate{}
		if cidrChanged {
			up.Source, up.CIDRs = rl.CIDRSource, cidrs
		}
		if domainChanged {
			up.DomainSource, up.Domains = rl.DomainSource, domains
		}
		caches[rl.ID] = up
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
	log.Printf("cidr auto-refresh: staged for strict reviewed Apply")
}
