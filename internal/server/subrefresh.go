package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"velinx/internal/importer"
)

// subRefreshStatus records the outcome of the most recent REAL refresh attempt
// (auto loop or manual "refresh now") so the UI can show whether auto-refresh is
// actually working. A no-op refresh (no URL stored) does not touch it. Safe for
// concurrent loop-writer / handler-reader use; lives as a value field on Server
// (never copied — Server is always used by pointer).
type subRefreshStatus struct {
	mu    sync.Mutex
	last  time.Time // time of the last real attempt (zero = never)
	added int       // endpoints added on that attempt
	err   string    // that attempt's error ("" = success)
}

// record stores the outcome of a refresh attempt at time.Now().
func (st *subRefreshStatus) record(added int, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.last = time.Now()
	st.added = added
	if err != nil {
		st.err = err.Error()
	} else {
		st.err = ""
	}
}

// snapshot returns a consistent copy of the last-attempt status for the API.
func (st *subRefreshStatus) snapshot() (last time.Time, added int, errStr string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.last, st.added, st.err
}

// errSubConfig marks a refreshSubscriptionOnce failure caused by the stored
// configuration itself (empty/invalid URL, bad scheme) rather than an upstream
// fetch failure. handleSubRefreshNow maps it to 400 (client/config error) while
// genuine fetch/Do/non-200 failures stay 502 (bad gateway). Wrapped so callers
// can distinguish via errors.Is.
var errSubConfig = errors.New("subscription config error")

// refreshSubscriptionOnce re-fetches the stored subscription URL and ADDS any
// newly-rotated endpoints to the profile. It is purely additive: an endpoint the
// provider dropped is intentionally NEVER deleted (preserve-all-functionality), and
// a re-fetch of unchanged content adds nothing (importer.DedupeNew). Returns the
// number of new endpoints saved. A "" URL is a no-op (0, nil). Never panics.
func (s *Server) refreshSubscriptionOnce(ctx context.Context) (added int, err error) {
	c := s.config()
	raw := c.Subscription.URL
	if raw == "" {
		return 0, nil // nothing stored to refresh — not a real attempt, don't record status
	}
	// Record the outcome of this real attempt (named returns are read at return time)
	// so the UI can show last-refreshed time / added count / last error.
	defer func() { s.subStatus.record(added, err) }()

	// Re-check the scheme even though import already did: the stored value could
	// have been edited in config.json, and the SSRF guard runs at dial time only.
	u, perr := url.Parse(raw)
	if perr != nil {
		return 0, fmt.Errorf("%w: parse subscription url: %v", errSubConfig, perr)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return 0, fmt.Errorf("%w: subscription url must be an http(s) URL, got %q", errSubConfig, u.Scheme)
	}

	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: build subscription request: %v", errSubConfig, err)
	}
	req.Header.Set("User-Agent", "velinx")

	resp, err := s.subscriptionFetchClient().Do(req) // SSRF-guarded (blockInternalDial)
	if err != nil {
		return 0, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("subscription returned status %s", resp.Status)
	}

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap, matches handleSubscription
	parsed, _ := importer.ParseSubscription(string(b))   // parse errors per-line are non-fatal here

	// Add only endpoints whose CONTENT is genuinely new. A refresh re-parses the SAME
	// links (ParseSubscription gives them stable IDs), so DedupeNew's "an ID match is an
	// in-place update, keep it" rule (built for bulk import) would re-add them on every
	// refresh. For refresh we want content-new ONLY, and we must never overwrite an
	// endpoint the user has since edited — so filter purely by ContentKey.
	existing := s.store.Profile().Endpoints
	seen := make(map[string]bool, len(existing))
	for i := range existing {
		seen[importer.ContentKey(existing[i])] = true
	}
	for _, e := range parsed {
		if e.ID == "" {
			continue
		}
		ck := importer.ContentKey(e)
		if seen[ck] {
			continue // already present by content — additive, never duplicate or overwrite
		}
		seen[ck] = true // also dedupe within this batch
		if uerr := s.store.UpsertEndpoint(e); uerr != nil {
			// Non-fatal: keep going so one bad endpoint doesn't drop the rest.
			log.Printf("subscription refresh: skipped %s: %v", e.ID, uerr)
			continue
		}
		added++
	}
	return added, nil
}

// SubscriptionRefreshLoop periodically re-fetches the stored subscription URL and
// adds newly-rotated endpoints, when the user has opted in (Subscription.RefreshHours
// > 0 and a URL is set). It ticks hourly and re-reads config each tick so a Settings
// change takes effect without a restart; an actual refresh runs only once the configured
// interval has elapsed (and once promptly on the first eligible tick). No-op in demo mode.
func (s *Server) SubscriptionRefreshLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	var lastRefresh time.Time // zero until the first refresh runs
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c := s.config()
		if c.Demo { // must not touch host state / make network calls in demo mode
			continue
		}
		sub := c.Subscription
		if sub.RefreshHours <= 0 || sub.URL == "" {
			continue // refresh disabled or nothing to refresh
		}
		now := time.Now()
		interval := time.Duration(sub.RefreshHours) * time.Hour
		if !lastRefresh.IsZero() && now.Sub(lastRefresh) < interval {
			continue // not due yet
		}
		n, err := s.refreshSubscriptionOnce(ctx)
		lastRefresh = now
		if err != nil {
			log.Printf("subscription refresh: %v", err)
			continue
		}
		log.Printf("subscription refresh: +%d endpoints", n)
	}
}

// handleSubAutoRefresh sets the subscription auto-refresh interval (hours; 0 = off,
// max 168 = one week). Same-origin-guarded (a panel action). Opt-in: it does not
// start refreshing until a positive interval is set and a URL has been imported.
func (s *Server) handleSubAutoRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hours int `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Hours < 0 || body.Hours > 168 {
		writeErr(w, http.StatusBadRequest, "hours must be between 0 (off) and 168 (one week)")
		return
	}
	s.cfgMu.Lock()
	s.cfg.Subscription.RefreshHours = body.Hours
	url := s.cfg.Subscription.URL
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"refresh_hours": body.Hours, "url": url})
}

// handleSubRefreshNow re-fetches the stored subscription URL immediately ("refresh
// now") and reports how many new endpoints were added. Same-origin-guarded.
func (s *Server) handleSubRefreshNow(w http.ResponseWriter, r *http.Request) {
	added, err := s.refreshSubscriptionOnce(r.Context())
	if err != nil {
		// A config/validation error (empty/invalid URL, bad scheme) is the client's
		// fault → 400. Only an actual upstream fetch/Do/non-200 failure is a 502.
		if errors.Is(err, errSubConfig) {
			writeErr(w, http.StatusBadRequest, "refresh failed: "+err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, "refresh failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added})
}
