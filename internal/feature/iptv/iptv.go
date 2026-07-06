// Package iptv is the IPTV feature MODULE: it wires the pure playlist core (wayhop/internal/iptv,
// imported as iptvcore) to the plugin system — the country catalog, the user's []List of aggregated
// per-country playlists (persisted in the featurestore), and the HTTP routes to manage them. The
// fetch→aggregate→serve→refresh machinery lands in later slices (I7 serve, I8 refresh); this slice
// (I6) is the catalog endpoint + the list CRUD + persistence.
//
// Installed via a blank import in cmd/wayhop (`_ "wayhop/internal/feature/iptv"`); enabling it is a
// config.Features["iptv"].Enabled flip. Every route gates on that flag, so a disabled plugin 404s.
package iptv

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/feature"
	iptvcore "wayhop/internal/iptv"
)

const moduleID = "iptv"

// Bounds keep a low-RAM router safe: a bounded number of lists, countries per list, and blocklist
// entries, and a capped name/body.
const (
	maxLists            = 50
	maxCountriesPerList = 40
	maxBlocklist        = 500
	maxCategories       = 200
	maxNameLen          = 100
	maxBody             = 1 << 18 // 256 KiB request body cap

	defaultRefreshHours = 12      // IPTV lists change more than CIDR feeds → shorter default than 24h
	minRefreshHours     = 6       // flash-wear floor (a hand-edited settings blob is clamped up)
	maxRefreshHours     = 24 * 14 // 2 weeks ceiling
)

func init() { feature.Register(&module{}) }

// module is the singleton IPTV feature. mu serializes the read-modify-write of the persisted list
// collection (featurestore.Set is itself atomic, but load→mutate→save across concurrent requests is
// not — the mutex makes each mutation a critical section). building single-flights a list's refresh:
// only one build (scheduled OR manual) runs per list at a time, which bounds the RAM/FD amplification
// of concurrent "Update now" clicks and stops two builds racing on the same output playlist.
type module struct {
	mu       sync.Mutex
	building sync.Map // list ID -> struct{} while a build is in flight
	probers  sync.Map // list ID -> *iptvcore.Prober (persistent so its rotation cursor advances across builds)
	aggCache sync.Map // preview aggregate cache: aggKey -> *aggCacheEntry (short TTL, self-evicting)
}

// probeBatch caps how many channels a single build health-checks, so a probing build finishes well
// under buildTimeout (sem=8 × ~6s each). The per-list Prober's rotation cursor advances across builds,
// so a large list is covered over several refreshes rather than all-at-once (which would time out).
const probeBatch = 300

// tryBuild marks a list as building; returns false if a build is already in flight for it.
func (m *module) tryBuild(id string) bool {
	_, loaded := m.building.LoadOrStore(id, struct{}{})
	return !loaded
}

func (m *module) doneBuild(id string) { m.building.Delete(id) }

// proberFor returns the list's persistent Prober (the single-flight build guard makes it safe to reuse
// without extra locking — only one build touches it at a time).
func (m *module) proberFor(l List) *iptvcore.Prober {
	cfg := iptvcore.ProbeConfig{BatchSize: probeBatch}
	if l.ID == "" {
		return iptvcore.NewProber(cfg)
	}
	if p, ok := m.probers.Load(l.ID); ok {
		return p.(*iptvcore.Prober)
	}
	p, _ := m.probers.LoadOrStore(l.ID, iptvcore.NewProber(cfg))
	return p.(*iptvcore.Prober)
}

func (m *module) Descriptor() feature.Descriptor {
	return feature.Descriptor{
		ID:   moduleID,
		Name: "IPTV",
		Icon: "📺",
		Tip:  "Aggregate open per-country channel lists into one auto-updating, deduped M3U",
	}
}

// Start is the module's refresh loop: it ticks hourly and refreshes every list that is due on its
// own cadence, re-reading state each tick so CRUD changes take effect without a restart. It no-ops
// entirely while the plugin is disabled (refreshTick re-checks the flag). Cancels with ctx.
func (m *module) Start(ctx context.Context, d *feature.Deps) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	due := map[string]time.Time{} // per-list next-attempt time (in-memory; seeded from Stats.LastRefresh)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.refreshTick(ctx, d, due, time.Now())
	}
}

func (m *module) Stop() {}

// refreshTick performs one refresh pass (extracted from Start so tests drive time). Scheduling mirrors
// the CIDR feed loop: each list's first due time seeds from its persisted Stats.LastRefresh (+interval)
// so restarts don't defer refreshes forever, a never-refreshed list is due immediately, and a
// shortened cadence is picked up by clamping. After every ATTEMPT (ok/error) the due time advances a
// full interval. Each due list is fetched+built under its own bounded timeout; the resulting playlist
// is written atomically (last-good kept on error); Stats are coalesced into ONE store write at the
// end. No-op while the plugin is disabled.
func (m *module) refreshTick(ctx context.Context, d *feature.Deps, due map[string]time.Time, now time.Time) {
	c := d.Cfg()
	if c.Demo { // demo mode: never fetch/probe (no network calls, no host state), like the CIDR loop
		return
	}
	if fc, ok := c.Features[moduleID]; !ok || !fc.Enabled {
		return
	}
	st := m.load(d)
	eligible := make(map[string]bool, len(st.Lists))
	var dueLists []List
	for _, l := range st.Lists {
		eligible[l.ID] = true
		if l.Paused { // paused: no auto-refresh (token still serves last-good; manual "Update now" still works)
			continue
		}
		interval := time.Duration(clampRefreshHours(l.RefreshHours)) * time.Hour
		nd, seen := due[l.ID]
		if !seen {
			nd = now
			if l.Stats.LastRefresh > 0 {
				nd = time.Unix(l.Stats.LastRefresh, 0).Add(interval)
			}
			due[l.ID] = nd
		}
		if nd.After(now.Add(interval)) { // cadence shortened / id recreated — don't sit out the old schedule
			nd = now.Add(interval)
			due[l.ID] = nd
		}
		if !now.Before(nd) {
			dueLists = append(dueLists, l)
		}
	}
	for id := range due { // drop deleted lists from the schedule
		if !eligible[id] {
			delete(due, id)
		}
	}
	if len(dueLists) == 0 {
		return
	}

	updates := make(map[string]buildOutcome, len(dueLists))
	for _, l := range dueLists {
		due[l.ID] = now.Add(time.Duration(clampRefreshHours(l.RefreshHours)) * time.Hour)
		if !m.tryBuild(l.ID) { // a manual "Update now" is already building this list — skip this tick
			continue
		}
		func() {
			defer m.doneBuild(l.ID)
			bctx, cancel := context.WithTimeout(ctx, buildTimeout(l))
			rendered, stats, cats, err := m.buildList(bctx, d, l, now.Unix())
			cancel()
			if err != nil { // keep the last-good file; record the error but preserve the previous counts
				updates[l.ID] = buildOutcome{stats: failStats(l.Stats, err, now.Unix())}
				log.Printf("iptv refresh %q: %v", l.ID, err)
				return
			}
			if werr := atomicfile.Write(m.playlistPath(d, l.Token), rendered, 0o644); werr != nil {
				updates[l.ID] = buildOutcome{stats: failStats(l.Stats, werr, now.Unix())}
				log.Printf("iptv refresh %q: write playlist: %v", l.ID, werr)
				return
			}
			updates[l.ID] = buildOutcome{stats: stats, cats: cats}
		}()
	}

	// Persist stats + category tracking (coalesced) under the mutex, re-reading so a concurrent CRUD
	// isn't clobbered — a list deleted/updated mid-build simply doesn't receive its (now-stale) update.
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.load(d)
	for i := range cur.Lists {
		if o, ok := updates[cur.Lists[i].ID]; ok {
			cur.Lists[i].Stats = o.stats
			if o.cats != nil { // successful build → update the seen/new category tracking
				recordCategories(&cur.Lists[i], o.cats)
			}
		}
	}
	if err := m.save(d, cur); err != nil {
		log.Printf("iptv refresh: persist stats: %v", err)
	}
}

// buildOutcome carries a build's persisted result: the fresh stats and (on success) the upstream
// category set for the review tracking (nil on a failed build so seen/new stay untouched).
type buildOutcome struct {
	stats ListStats
	cats  []string
}

// buildList runs the full pipeline for one list: fetch each allowlisted country's iptv-org playlist
// (via the SSRF-guarded Deps.Fetch), aggregate, filter (adult default-OFF + blocklist), dedup, sort,
// optionally health-probe (dropping dead channels when Probe is on — Tier-1), and render a clean
// M3U. A per-country fetch error is tolerated (its channels are skipped, noted in Stats.LastError) as
// long as at least one country yields channels; zero channels overall is an error (keeps last-good).
func (m *module) buildList(ctx context.Context, d *feature.Deps, l List, now int64) ([]byte, ListStats, []string, error) {
	client := d.Fetch()
	all, urlTvg, fetchErrs := fetchAll(ctx, client, l.Countries, l.Catalogs, l.SourceURLs, l.XtreamSources)
	if len(all) == 0 {
		return nil, ListStats{}, nil, fmt.Errorf("no channels fetched (%s)", strings.Join(fetchErrs, "; "))
	}

	block := make(map[string]bool, len(l.Blocklist))
	for _, b := range l.Blocklist {
		block[b] = true
	}
	filtered, fc := iptvcore.Filter(all, iptvcore.FilterOptions{AdultAllow: l.Adult, Blocklist: block})
	deduped, dups := iptvcore.Dedup(filtered)
	// The full upstream category vocabulary (pre-exclusion) feeds the "new category" review tracking.
	upstreamCats := categoryNames(iptvcore.Categorize(deduped))
	// Category curation: drop the categories the user opted OUT of, except channels rescued by tvg-id
	// (ChannelInclude). Applied post-dedup so the counts shown by the preview endpoint (also post-dedup)
	// match exactly what gets removed here.
	keep := make(map[string]bool, len(l.ChannelInclude))
	for _, k := range l.ChannelInclude {
		if s := strings.TrimSpace(k); s != "" {
			keep[s] = true
		}
	}
	excl := iptvcore.NormCategories(l.ExcludeCategories)
	// strict_new: hold a newly-appeared category out of THIS build too (not one refresh later). The
	// persist step (recordCategories) then adds it to ExcludeCategories durably. Skipped on the baseline
	// refresh (empty SeenCategories), where nothing is "new".
	if l.StrictNew && len(l.SeenCategories) > 0 {
		if excl == nil {
			excl = map[string]bool{}
		}
		seen := lowerSet(l.SeenCategories)
		for _, c := range upstreamCats {
			if lc := strings.ToLower(strings.TrimSpace(c)); lc != "" && !seen[lc] {
				excl[lc] = true
			}
		}
	}
	deduped, catCut := iptvcore.FilterCategoriesKeep(deduped, excl, keep)
	iptvcore.SortWithPins(deduped, l.PinnedCategories) // pinned categories lead the served M3U

	probeDropped := 0
	if l.Probe {
		m.proberFor(l).Probe(ctx, client, deduped, now)
		kept := deduped[:0] // filter-in-place: kept index never overtakes the read index
		for _, ch := range deduped {
			// Drop ONLY channels that were actually probed and found dead. A channel left unprobed
			// (ctx expired mid-pass, or beyond this build's rotation window) has Status=="" and is KEPT —
			// otherwise a big list under buildTimeout would lose every un-probed channel as "dead".
			if ch.Status == "" || ch.Live {
				kept = append(kept, ch)
			}
		}
		probeDropped = len(deduped) - len(kept)
		deduped = kept
	}

	stats := ListStats{
		Channels:    len(deduped),
		Pruned:      fc.Blocked + fc.Junk + catCut + probeDropped,
		AdultCut:    fc.Adult,
		CategoryCut: catCut,
		Duplicates:  dups,
		LastRefresh: now,
		LastAttempt: now,
		LastError:   strings.Join(fetchErrs, "; "), // "" on a full success; a note when some countries failed
	}
	return iptvcore.Render(deduped, urlTvg), stats, upstreamCats, nil
}

// categoryNames extracts the (display-cased) names from a Categorize result.
func categoryNames(cats []iptvcore.Category) []string {
	out := make([]string, len(cats))
	for i, c := range cats {
		out[i] = c.Name
	}
	return out
}

// recordCategories folds a successful build's upstream category set into a list's review tracking:
// the FIRST successful refresh (empty SeenCategories) just establishes the baseline (nothing is
// "new"); afterwards a category that is present now yet not previously seen, not excluded, and not
// already pending is queued in NewCategories. All current categories are absorbed into SeenCategories
// so they aren't re-flagged next time. Mutates l.
func recordCategories(l *List, cats []string) {
	baseline := len(l.SeenCategories) == 0
	seen := lowerSet(l.SeenCategories)
	excl := lowerSet(l.ExcludeCategories)
	pending := lowerSet(l.NewCategories)
	for _, c := range cats {
		lc := strings.ToLower(strings.TrimSpace(c))
		if lc == "" || seen[lc] {
			continue
		}
		if !baseline && !excl[lc] && !pending[lc] {
			l.NewCategories = append(l.NewCategories, c)
			pending[lc] = true
			if l.StrictNew { // hold it out of the served list until the user reviews/keeps it
				l.ExcludeCategories = append(l.ExcludeCategories, c)
				excl[lc] = true
			}
		}
		l.SeenCategories = append(l.SeenCategories, c)
		seen[lc] = true
	}
}

func lowerSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		if lc := strings.ToLower(strings.TrimSpace(s)); lc != "" {
			m[lc] = true
		}
	}
	return m
}

// buildTimeout bounds one list's fetch+build. A probing (Tier-1) list needs headroom to health-check
// every channel; a trust-iptv-org (Tier-0) list only fetches + transforms.
func buildTimeout(l List) time.Duration {
	if l.Probe {
		return 5 * time.Minute
	}
	return 90 * time.Second
}

// clampRefreshHours resolves a list's cadence: 0 → default, below the flash-wear floor clamps up,
// above the ceiling clamps down (defends against a hand-edited settings blob).
func clampRefreshHours(h int) int {
	if h == 0 {
		return defaultRefreshHours
	}
	if h < minRefreshHours {
		return minRefreshHours
	}
	if h > maxRefreshHours {
		return maxRefreshHours
	}
	return h
}

// Routes mounts the module's endpoints UNCONDITIONALLY (the mux is built once). Every handler is
// wrapped by gate, which 404s while the plugin is disabled, so toggling needs no restart/rebuild.
func (m *module) Routes(mux *http.ServeMux, d *feature.Deps) {
	mux.HandleFunc("GET /api/iptv/catalog", m.gate(d, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, iptvcore.Catalog())
	}))
	mux.HandleFunc("GET /api/iptv/catalogs", m.gate(d, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, iptvcore.CatalogKinds()) // language + category lists (the picker beyond countries)
	}))
	mux.HandleFunc("GET /api/iptv/lists", m.gate(d, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.load(d).Lists)
	}))
	mux.HandleFunc("GET /api/iptv/exits", m.gate(d, m.handleExits(d)))
	mux.HandleFunc("POST /api/iptv/preview", m.gate(d, m.handlePreview(d)))
	mux.HandleFunc("POST /api/iptv/preview/channels", m.gate(d, m.handlePreviewChannels(d)))
	mux.HandleFunc("POST /api/iptv/preview/health", m.gate(d, m.handlePreviewHealth(d)))
	mux.HandleFunc("POST /api/iptv/lists", m.gate(d, m.handleCreate(d)))
	mux.HandleFunc("PUT /api/iptv/lists/{id}", m.gate(d, m.handleUpdate(d)))
	mux.HandleFunc("DELETE /api/iptv/lists/{id}", m.gate(d, m.handleDelete(d)))
	mux.HandleFunc("POST /api/iptv/lists/{id}/refresh", m.gate(d, m.handleRefreshNow(d)))
	mux.HandleFunc("POST /api/iptv/lists/{id}/pause", m.gate(d, m.handlePause(d)))
	mux.HandleFunc("GET /api/iptv/lists/{id}/export", m.gate(d, m.handleExport(d)))
	mux.HandleFunc("GET /api/iptv/lists/{id}/review", m.gate(d, m.handleReviewGet(d)))
	mux.HandleFunc("POST /api/iptv/lists/{id}/review", m.gate(d, m.handleReviewResolve(d)))
	// Token-gated serve: a player GETs the aggregated .m3u; a browser GET (or ?web=1) gets a
	// landing page. The URL ends in .m3u for player compatibility — a Go 1.22 wildcard must be a
	// whole segment, so the token is its own segment and "tv.m3u" is a literal trailer.
	mux.HandleFunc("GET /api/iptv/{token}/tv.m3u", m.gate(d, m.handleServe(d)))
}

// List is one user-defined aggregated playlist: a set of allowlisted countries, per-list options, a
// stable serve token (used by the I7 serve route), and the last refresh stats (filled by I8).
type List struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Countries         []string       `json:"countries"`                    // allowlisted ISO codes to aggregate
	Catalogs          []string       `json:"catalogs,omitempty"`           // iptv-org "kind:code" lists beyond country (language:rus, category:news)
	SourceURLs        []string       `json:"source_urls,omitempty"`        // owner-supplied provider/custom M3U URLs (SSRF-guarded fetch)
	XtreamSources     []XtreamSource `json:"xtream_sources,omitempty"`     // Xtream Codes accounts → get.php M3U, fetched like a custom source
	Adult             bool           `json:"adult"`                        // include adult channels — opt-in, default OFF
	Probe             bool           `json:"probe"`                        // health-check channels — opt-in (Tier-0 default trusts iptv-org)
	RefreshHours      int            `json:"refresh_hours"`                // auto-refresh cadence (0 → 12h default; clamped)
	Blocklist         []string       `json:"blocklist,omitempty"`          // per-list blocklist (tvg-id or exact stream URL)
	ExcludeCategories []string       `json:"exclude_categories,omitempty"` // group-titles to drop (exclude-list = auto-update safe)
	ChannelInclude    []string       `json:"channel_include,omitempty"`    // tvg-ids to KEEP even if their category is cut (rescue)
	PinnedCategories  []string       `json:"pinned_categories,omitempty"`  // categories floated to the top of the served M3U (pin order)
	SeenCategories    []string       `json:"seen_categories,omitempty"`    // categories seen on past refreshes (baseline for "new" detection)
	NewCategories     []string       `json:"new_categories,omitempty"`     // categories that appeared upstream and await review (Phase 3)
	StrictNew         bool           `json:"strict_new"`                   // hold newly-appeared categories (auto-exclude) until reviewed
	Paused            bool           `json:"paused,omitempty"`             // skip auto-refresh (token keeps serving last-good; manual refresh still works)
	Token             string         `json:"token"`                        // serve token for GET /api/iptv/{token}/tv.m3u (I7)
	Stats             ListStats      `json:"stats"`                        // last refresh outcome (I8)
}

// XtreamSource is an Xtream Codes account (the credential form most paid providers hand out instead of
// a ready-made M3U link). URL is the provider base (host, host:port, or a full URL — only scheme+host
// are used); Username/Password build the standard get.php playlist URL, which is then fetched through
// the same SSRF-guarded client + pipeline as any custom source. Credentials never appear in a
// user-facing error (the fetch label is the host only) nor in logs (the URL is query-stripped).
type XtreamSource struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ListStats is the refresh outcome shown in the UI (populated by the I8 refresh loop).
type ListStats struct {
	Channels    int    `json:"channels"`
	Pruned      int    `json:"pruned"`
	AdultCut    int    `json:"adult_cut"`
	CategoryCut int    `json:"category_cut"`
	Duplicates  int    `json:"duplicates"`
	LastRefresh int64  `json:"last_refresh,omitempty"` // unix time of the last SUCCESSFUL build (0 = never)
	LastAttempt int64  `json:"last_attempt,omitempty"` // unix time of the last build ATTEMPT, success or fail
	LastError   string `json:"last_error,omitempty"`
}

// listInput is the create/update request body.
type listInput struct {
	Name              string         `json:"name"`
	Countries         []string       `json:"countries"`
	Catalogs          []string       `json:"catalogs"`
	SourceURLs        []string       `json:"source_urls"`
	XtreamSources     []XtreamSource `json:"xtream_sources"`
	Adult             bool           `json:"adult"`
	Probe             bool           `json:"probe"`
	StrictNew         bool           `json:"strict_new"`
	RefreshHours      int            `json:"refresh_hours"`
	Blocklist         []string       `json:"blocklist"`
	ExcludeCategories []string       `json:"exclude_categories"`
	ChannelInclude    []string       `json:"channel_include"`
	PinnedCategories  []string       `json:"pinned_categories"`
}

// state is the module's persisted blob (featurestore key "iptv").
type state struct {
	Lists []List `json:"lists"`
}

func (m *module) load(d *feature.Deps) state {
	var st state
	if d.Store != nil {
		_ = d.Store.GetJSON(moduleID, &st)
	}
	return st
}

func (m *module) save(d *feature.Deps, st state) error {
	if d.Store == nil {
		return errors.New("no feature store")
	}
	return d.Store.SetJSON(moduleID, st)
}

func (m *module) handleCreate(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in, err := decodeInput(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		countries, catalogs, sources, xtream, err := validateSources(in.Countries, in.Catalogs, in.SourceURLs, in.XtreamSources)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.load(d)
		if len(st.Lists) >= maxLists {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("too many lists (max %d)", maxLists))
			return
		}
		id, err1 := randHex(8)
		token, err2 := randHex(16)
		if err1 != nil || err2 != nil {
			writeErr(w, http.StatusInternalServerError, "id generation failed")
			return
		}
		l := List{
			ID:                id,
			Name:              listName(in.Name, countries, sources),
			Countries:         countries,
			Catalogs:          catalogs,
			SourceURLs:        sources,
			XtreamSources:     xtream,
			Adult:             in.Adult,
			Probe:             in.Probe,
			StrictNew:         in.StrictNew,
			RefreshHours:      clampRefreshHours(in.RefreshHours),
			Blocklist:         cleanBlocklist(in.Blocklist),
			ExcludeCategories: cleanCategories(in.ExcludeCategories),
			ChannelInclude:    cleanBlocklist(in.ChannelInclude),
			PinnedCategories:  cleanCategories(in.PinnedCategories),
			Token:             token,
		}
		st.Lists = append(st.Lists, l)
		if err := m.save(d, st); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, l)
	}
}

func (m *module) handleUpdate(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		in, err := decodeInput(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		countries, catalogs, sources, xtream, err := validateSources(in.Countries, in.Catalogs, in.SourceURLs, in.XtreamSources)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.load(d)
		idx := indexByID(st.Lists, id)
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		l := &st.Lists[idx] // preserve ID/Token/Stats; refresh (I8) recomputes stats.
		l.Name = listName(in.Name, countries, sources)
		l.Countries = countries
		l.Catalogs = catalogs
		l.SourceURLs = sources
		l.XtreamSources = xtream
		l.Adult = in.Adult
		l.Probe = in.Probe
		l.StrictNew = in.StrictNew
		l.RefreshHours = clampRefreshHours(in.RefreshHours)
		l.Blocklist = cleanBlocklist(in.Blocklist)
		l.ExcludeCategories = cleanCategories(in.ExcludeCategories)
		l.ChannelInclude = cleanBlocklist(in.ChannelInclude)
		l.PinnedCategories = cleanCategories(in.PinnedCategories)
		if err := m.save(d, st); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.Lists[idx])
	}
}

// handlePause (POST /api/iptv/lists/{id}/pause) sets a list's Paused flag from {"paused": bool}. A
// paused list is skipped by the auto-refresh loop — its token keeps serving the last-good playlist so
// provisioned players are unaffected, and "Update now" still forces a manual rebuild — so a flaky
// source or flash-wear can be stopped without deleting the list (which would mint a new token and
// break every player/QR already set up).
func (m *module) handlePause(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var in struct {
			Paused bool `json:"paused"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.load(d)
		idx := indexByID(st.Lists, id)
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		st.Lists[idx].Paused = in.Paused
		if err := m.save(d, st); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st.Lists[idx])
	}
}

// handleRefreshNow (POST /api/iptv/lists/{id}/refresh) forces an immediate rebuild of one list instead
// of waiting for its auto-refresh cadence — the card's "Update now". Because a build fetches (and, if
// Probe is on, health-checks) many channels and can take up to buildTimeout, it runs in the BACKGROUND
// and the handler returns 202 immediately; the card shows fresh stats on its next load. User-initiated,
// so it runs even in demo mode (unlike the scheduled loop, which must stay offline in demo).
func (m *module) handleRefreshNow(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		st := m.load(d)
		idx := indexByID(st.Lists, id)
		m.mu.Unlock()
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		if !m.tryBuild(id) { // a build is already in flight for this list — coalesce, don't pile on
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "already refreshing", "id": id})
			return
		}
		go func(l List) { defer m.doneBuild(l.ID); m.rebuildOne(d, l) }(st.Lists[idx])
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "refreshing", "id": id})
	}
}

// failStats records a build failure onto the previous stats: LastError set, LastAttempt stamped, but
// the previous counts (incl. LastRefresh) preserved — so a failed build keeps the last-good numbers and
// shows an honest "failed <ago>" without ever claiming a successful refresh. ListStats is a value, so
// prev is a copy.
func failStats(prev ListStats, err error, now int64) ListStats {
	prev.LastError = err.Error()
	prev.LastAttempt = now
	return prev
}

// rebuildOne fetches + rebuilds a single list now and persists the result (last-good file kept on a
// build error, which is recorded in Stats.LastError). Uses context.Background (NOT the request ctx,
// which is cancelled once handleRefreshNow returns 202) bounded by buildTimeout. Stats are re-read
// under the mutex before writing so a concurrent CRUD isn't clobbered; a list deleted mid-build is a
// no-op (its index is gone).
func (m *module) rebuildOne(d *feature.Deps, l List) {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout(l))
	defer cancel()
	now := time.Now().Unix()
	rendered, stats, cats, err := m.buildList(ctx, d, l, now)
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.load(d)
	i := indexByID(cur.Lists, l.ID)
	if i < 0 {
		return // deleted mid-build
	}
	if err != nil {
		cur.Lists[i].Stats = failStats(cur.Lists[i].Stats, err, now)
		_ = m.save(d, cur)
		log.Printf("iptv manual refresh %q: %v", l.ID, err)
		return
	}
	if werr := atomicfile.Write(m.playlistPath(d, l.Token), rendered, 0o644); werr != nil {
		log.Printf("iptv manual refresh %q: write playlist: %v", l.ID, werr)
		return
	}
	cur.Lists[i].Stats = stats
	recordCategories(&cur.Lists[i], cats)
	_ = m.save(d, cur)
}

// curationExport is a list's PORTABLE curation — everything the user configured, and nothing
// instance-specific (no token, stats, or seen/new tracking). Its json field names match listInput
// exactly, so an exported blob re-imports verbatim through POST /api/iptv/lists (the extra "version"
// is ignored on decode). Lets a user back up or share a curated list.
type curationExport struct {
	Version           int            `json:"version"`
	Name              string         `json:"name"`
	Countries         []string       `json:"countries,omitempty"`
	Catalogs          []string       `json:"catalogs,omitempty"`
	SourceURLs        []string       `json:"source_urls,omitempty"`
	XtreamSources     []XtreamSource `json:"xtream_sources,omitempty"`
	Adult             bool           `json:"adult"`
	Probe             bool           `json:"probe"`
	StrictNew         bool           `json:"strict_new"`
	RefreshHours      int            `json:"refresh_hours,omitempty"`
	ExcludeCategories []string       `json:"exclude_categories,omitempty"`
	ChannelInclude    []string       `json:"channel_include,omitempty"`
	PinnedCategories  []string       `json:"pinned_categories,omitempty"`
	Blocklist         []string       `json:"blocklist,omitempty"`
}

// handleExport (GET /api/iptv/lists/{id}/export) returns a list's portable curation JSON.
func (m *module) handleExport(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := m.load(d)
		idx := indexByID(st.Lists, r.PathValue("id"))
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		l := st.Lists[idx]
		writeJSON(w, http.StatusOK, curationExport{
			Version:           1,
			Name:              l.Name,
			Countries:         l.Countries,
			Catalogs:          l.Catalogs,
			SourceURLs:        l.SourceURLs,
			XtreamSources:     l.XtreamSources,
			Adult:             l.Adult,
			Probe:             l.Probe,
			StrictNew:         l.StrictNew,
			RefreshHours:      l.RefreshHours,
			ExcludeCategories: l.ExcludeCategories,
			ChannelInclude:    l.ChannelInclude,
			PinnedCategories:  l.PinnedCategories,
			Blocklist:         l.Blocklist,
		})
	}
}

// handleReviewGet (GET /api/iptv/lists/{id}/review) returns the categories that appeared upstream
// since the list's baseline and haven't been resolved — the pending review queue (Phase 3 C2). Names
// only (a count would need a fresh fetch); the card badge just needs the length.
func (m *module) handleReviewGet(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := m.load(d)
		idx := indexByID(st.Lists, r.PathValue("id"))
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		cats := st.Lists[idx].NewCategories
		if cats == nil {
			cats = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"categories": cats})
	}
}

// handleReviewResolve (POST /api/iptv/lists/{id}/review, body {keep:[],cut:[]}) resolves pending-new
// categories: cut → added to exclude_categories (dropped from now on), keep → just acknowledged
// (stays in — already in SeenCategories). Both are removed from NewCategories. Idempotent + safe:
// unknown names are simply cleared; empty body is a no-op.
func (m *module) handleReviewResolve(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var in struct {
			Keep []string `json:"keep"`
			Cut  []string `json:"cut"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.load(d)
		idx := indexByID(st.Lists, id)
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		l := &st.Lists[idx]
		// cut → exclude_categories (deduped, case-insensitive).
		excl := lowerSet(l.ExcludeCategories)
		for _, c := range in.Cut {
			s := strings.TrimSpace(c)
			if lc := strings.ToLower(s); s != "" && !excl[lc] {
				l.ExcludeCategories = append(l.ExcludeCategories, s)
				excl[lc] = true
			}
		}
		// keep → un-exclude (strict_new may have held it out; keeping means let it flow in).
		keepSet := lowerSet(in.Keep)
		if len(keepSet) > 0 {
			ex := l.ExcludeCategories[:0]
			for _, c := range l.ExcludeCategories {
				if !keepSet[strings.ToLower(strings.TrimSpace(c))] {
					ex = append(ex, c)
				}
			}
			l.ExcludeCategories = ex
		}
		// Remove every resolved (kept OR cut) name from the pending queue.
		resolved := lowerSet(append(append([]string{}, in.Keep...), in.Cut...))
		if len(resolved) > 0 {
			kept := l.NewCategories[:0]
			for _, c := range l.NewCategories {
				if !resolved[strings.ToLower(strings.TrimSpace(c))] {
					kept = append(kept, c)
				}
			}
			l.NewCategories = kept
		}
		// Re-normalize through the same cap create/update use, so the review route can't grow
		// ExcludeCategories past maxCategories (a client POSTing large all-distinct cut arrays).
		l.ExcludeCategories = cleanCategories(l.ExcludeCategories)
		if err := m.save(d, st); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pending": len(l.NewCategories)})
	}
}

func (m *module) handleDelete(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.load(d)
		idx := indexByID(st.Lists, id)
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "list not found")
			return
		}
		token := st.Lists[idx].Token
		st.Lists = append(st.Lists[:idx], st.Lists[idx+1:]...)
		if err := m.save(d, st); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Best-effort remove the generated playlist so a deleted list's token stops serving stale
		// channels (absent file is a harmless no-op).
		_ = os.Remove(m.playlistPath(d, token))
		m.probers.Delete(id) // drop the per-list prober state
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	}
}

// previewInput asks "what's inside a list built from these countries?" — used before saving so the
// user can choose categories. Countries are validated against the allowlist; adult mirrors the list's
// setting so the counts match what will actually be served.
type previewInput struct {
	Countries  []string `json:"countries"`
	Catalogs   []string `json:"catalogs"`
	SourceURLs []string `json:"source_urls"`
	Adult      bool     `json:"adult"`
}

// previewResult is the channel breakdown of a would-be list: the total (post-filter, post-dedup) and
// the per-category counts, biggest first — everything the curation UI needs to offer category picking.
type previewResult struct {
	Total      int                 `json:"total"`
	Categories []iptvcore.Category `json:"categories"`
	Errors     []string            `json:"errors,omitempty"` // per-country fetch failures (partial results still returned)
}

// handlePreview (POST /api/iptv/preview) fetches the requested countries, aggregates + adult-filters +
// dedupes exactly as a real build would (minus the health probe, for speed), and returns the category
// breakdown so the user can pick which categories to keep BEFORE saving/publishing. It does NOT touch
// stored state — a pure read. Bounded by validateSources; a per-source fetch error is tolerated.
func (m *module) handlePreview(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in previewInput
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		countries, catalogs, sources, _, err := validateSources(in.Countries, in.Catalogs, in.SourceURLs, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		deduped, errs := m.aggregateCached(r.Context(), d, countries, catalogs, sources, in.Adult)
		writeJSON(w, http.StatusOK, previewResult{
			Total:      len(deduped),
			Categories: iptvcore.Categorize(deduped),
			Errors:     errs,
		})
	}
}

// aggregate is the shared read path behind both preview endpoints: fetch each allowlisted country (via
// the SSRF-guarded client), adult-filter, and dedup — exactly what a build does minus the health
// probe. Per-country fetch errors are tolerated and returned (partial results still stand). Bounded by
// a 90s timeout. The FULL channel slice lives only transiently server-side; callers ship a summary or
// a capped page, never the whole aggregate (router-safe).
func aggregate(ctx context.Context, d *feature.Deps, countries, catalogs, sourceURLs []string, adult bool) ([]iptvcore.Channel, []string) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	all, _, errs := fetchAll(ctx, d.Fetch(), countries, catalogs, sourceURLs, nil) // preview reflects countries/catalogs/URLs; Xtream flows in at build
	filtered, _ := iptvcore.Filter(all, iptvcore.FilterOptions{AdultAllow: adult})
	deduped, _ := iptvcore.Dedup(filtered)
	return deduped, errs
}

// aggCacheTTL is how long a preview aggregate is reused. A drill-down session (preview → expand many
// categories → health-check) otherwise re-fetches ALL countries per request; this collapses those into
// one fetch. Builds NEVER use this cache — they always fetch fresh.
const aggCacheTTL = 45 * time.Second

type aggCacheEntry struct {
	chs  []iptvcore.Channel
	errs []string
	at   time.Time
}

func aggKey(countries, catalogs, sourceURLs []string, adult bool) string {
	c := append([]string(nil), countries...)
	k := append([]string(nil), catalogs...)
	s := append([]string(nil), sourceURLs...)
	sort.Strings(c)
	sort.Strings(k)
	sort.Strings(s)
	// Join with NUL (0x00, which can't appear in a URL or an ISO/kind:code token) between elements and
	// 0x01 between groups, so distinct inputs can't collide — fmt "%v" space-joins slices, which two
	// different source-URL sets (e.g. one URL with an interior space vs two URLs) can render identically.
	return strings.Join(c, "\x00") + "\x01" + strings.Join(k, "\x00") + "\x01" + strings.Join(s, "\x00") + "\x01" + fmt.Sprintf("%t", adult)
}

// aggregateCached wraps aggregate with a short-lived cache keyed by the normalized inputs, so the three
// preview endpoints share one fetch across a drill-down session. Opportunistically evicts expired
// entries so distinct preview combos don't accumulate on a low-RAM router. now is time.Now (the module
// runs in the live daemon; the pure package stays clock-free).
func (m *module) aggregateCached(ctx context.Context, d *feature.Deps, countries, catalogs, sourceURLs []string, adult bool) ([]iptvcore.Channel, []string) {
	key := aggKey(countries, catalogs, sourceURLs, adult)
	now := time.Now()
	if v, ok := m.aggCache.Load(key); ok {
		if e := v.(*aggCacheEntry); now.Sub(e.at) < aggCacheTTL {
			return e.chs, e.errs
		}
	}
	chs, errs := aggregate(ctx, d, countries, catalogs, sourceURLs, adult)
	if len(chs) > 0 { // don't cache an all-failed fetch
		m.aggCache.Range(func(k, v any) bool {
			if now.Sub(v.(*aggCacheEntry).at) >= aggCacheTTL {
				m.aggCache.Delete(k)
			}
			return true
		})
		m.aggCache.Store(key, &aggCacheEntry{chs: chs, errs: errs, at: now})
	}
	return chs, errs
}

// xtreamM3UURL builds the get.php playlist URL for an Xtream Codes account. The base may be a bare
// host, host:port, or a full URL — only scheme+host are used (any path/query is dropped). username +
// password are query-escaped; type=m3u_plus & output=m3u8 request the full HLS playlist. Returns an
// error (which never contains the password) for an unusable account.
func xtreamM3UURL(x XtreamSource) (string, error) {
	base := strings.TrimSpace(x.URL)
	if base == "" {
		return "", fmt.Errorf("xtream: host required")
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("xtream: invalid host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("xtream: host must be http(s)")
	}
	user, pass := strings.TrimSpace(x.Username), strings.TrimSpace(x.Password)
	if user == "" || pass == "" {
		return "", fmt.Errorf("xtream: username and password required")
	}
	q := url.Values{"username": {user}, "password": {pass}, "type": {"m3u_plus"}, "output": {"m3u8"}}
	return u.Scheme + "://" + u.Host + "/get.php?" + q.Encode(), nil
}

// xtreamHost returns just the host of an Xtream account, for user-facing labels — never the credentials.
func xtreamHost(x XtreamSource) string {
	base := strings.TrimSpace(x.URL)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return "xtream"
}

// sanitizeURL strips the query string and userinfo from a URL for logging, so a token or Xtream
// credential in a source URL never lands in the daemon log. Returns the input unchanged if it doesn't
// parse.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// credQueryRe matches the query string of an http(s) URL OR a quoted absolute-path (relative) URL — a
// redirect Location can be relative ("/live?token=…"), which has no scheme, so scrubErr must strip the
// query (credential/token) from both forms, not just absolute URLs.
var credQueryRe = regexp.MustCompile(`(https?://[^\s"'?]+|"/[^\s"'?]*)\?[^\s"']*`)

// scrubErr renders a fetch error safe to log: it replaces the exact source URL with its query-stripped
// form and defensively removes the query from any other URL in the message. FetchPlaylist wraps errors
// with the full URL and Go's *url.Error stringifies it too, so without this an Xtream password (or a
// subscription token in a custom source URL) would reach the daemon log via the error text.
func scrubErr(err error, raw string) string {
	s := err.Error()
	if raw != "" {
		s = strings.ReplaceAll(s, raw, sanitizeURL(raw))
	}
	return credQueryRe.ReplaceAllString(s, "$1")
}

// fetchAll fetches every source of a list — each allowlisted country's iptv-org playlist, each
// iptv-org "kind:code" catalog (language/category), each owner-supplied custom URL, and each Xtream
// Codes account (resolved to its get.php M3U) — via the SSRF-guarded client, returning the aggregated
// channels, the merged EPG (url-tvg) header, and per-source error strings. A single source failing is
// tolerated (skipped + noted); the caller decides what an all-empty result means.
func fetchAll(ctx context.Context, client *http.Client, countries, catalogs, sourceURLs []string, xtream []XtreamSource) (chs []iptvcore.Channel, urlTvg string, errs []string) {
	// Collect the EPG (url-tvg) guide URL from EVERY source, deduped in first-seen order. A WayHop list
	// is a MERGE of many countries + custom URLs, so keeping only the first source's guide left every
	// other channel with "No Information" in the player. Emitting all of them comma-joined (the de-facto
	// M3U convention TiviMate/Kodi/OTT Navigator merge) covers the whole list. A single source's url-tvg
	// may itself be comma-separated, so split those too.
	var epgs []string
	seenEpg := map[string]bool{}
	addEPG := func(s string) {
		for _, u := range strings.Split(s, ",") {
			if u = strings.TrimSpace(u); u != "" && !seenEpg[u] {
				seenEpg[u] = true
				epgs = append(epgs, u)
			}
		}
	}
	// fetch tries each candidate URL in order and stops at the first that yields channels. A country
	// carries mirrors (identical content) so a DPI-blocked primary falls through to a CDN; a custom
	// source is a single URL. The client-facing error is generic (detail logged server-side only) so
	// the unauthenticated preview endpoints can't be turned into an internal host/DNS scanner (the SSRF
	// dial guard distinguishes "internal address" from "no such host", which we must not leak).
	fetch := func(label string, urls []string) {
		for _, u := range urls {
			pl, err := iptvcore.FetchPlaylist(ctx, client, u, 0)
			if err != nil {
				log.Printf("iptv fetch %s: %s", sanitizeURL(u), scrubErr(err, u)) // both args creds-stripped
				continue                                                          // try the next mirror
			}
			if len(pl.Channels) == 0 {
				// A 200 with no channels is almost always a censorship/error interstitial — a DPI block
				// page parses as an empty M3U — so fall through to the next mirror rather than accept it.
				log.Printf("iptv fetch %s: no channels (treating as unavailable)", sanitizeURL(u)) // creds-stripped
				continue
			}
			addEPG(pl.URLTvg)
			chs = append(chs, pl.Channels...)
			return
		}
		errs = append(errs, label+": unavailable")
	}
	for _, cc := range countries {
		if urls, ok := iptvcore.CountryM3Us(cc); ok { // defensive: codes already allowlist-validated
			fetch(cc, urls)
		}
	}
	for _, tok := range catalogs {
		if urls, ok := iptvcore.CatalogM3Us(tok); ok { // language:rus / category:news, allowlist-validated
			label := iptvcore.CatalogLabel(tok)
			if label == "" {
				label = tok
			}
			fetch(label, urls)
		}
	}
	for _, u := range sourceURLs {
		// Label with the query-stripped URL: the label feeds the user-facing errs slice (→ Stats.LastError,
		// shown in the UI, and the "no channels fetched" build error in the log), so a token/credential in
		// the URL's query must not ride along. The full URL is still what's fetched.
		fetch(sanitizeURL(u), []string{u})
	}
	for _, x := range xtream {
		u, err := xtreamM3UURL(x)
		if err != nil {
			// err is credential-free; label is the host only — the get.php URL (with the password) never
			// reaches the user-facing errors.
			errs = append(errs, xtreamHost(x)+": "+strings.TrimPrefix(err.Error(), "xtream: "))
			continue
		}
		fetch(xtreamHost(x), []string{u})
	}
	return chs, strings.Join(epgs, ","), errs
}

// previewChannelsInput drills into ONE category (or all, when Category is empty) of a would-be list,
// optionally name-filtered by Q, returning a capped page — so the browser never receives the full
// aggregate (a country can be >1000 channels).
type previewChannelsInput struct {
	Countries  []string `json:"countries"`
	Catalogs   []string `json:"catalogs"`
	SourceURLs []string `json:"source_urls"`
	Adult      bool     `json:"adult"`
	Category   string   `json:"category"`
	Q          string   `json:"q"`
	Offset     int      `json:"offset"`
	Limit      int      `json:"limit"`
}

// channelRow is one channel in the drill-down (identity + logo for the pick list). tvg-id is the stable
// key the UI stores in the per-channel blocklist; URL is the fallback when tvg-id is absent.
type channelRow struct {
	TvgID  string `json:"tvg_id,omitempty"`
	Name   string `json:"name"`
	Logo   string `json:"logo,omitempty"`
	URL    string `json:"url"`
	Group  string `json:"group,omitempty"`
	Status string `json:"status,omitempty"` // "" = not probed; "alive"|"geo"|"dead" from preview/health
}

type previewChannelsResult struct {
	Items  []channelRow `json:"items"`
	Total  int          `json:"total"` // matches BEFORE pagination (category + search applied)
	Offset int          `json:"offset"`
	Errors []string     `json:"errors,omitempty"`
}

const previewPageMax = 200

// handlePreviewChannels (POST /api/iptv/preview/channels) returns a capped, paginated page of the
// channels in one category (case-insensitive; empty Category = all) of a would-be list, optionally
// filtered by a name/tvg-id substring — the lazy drill-down behind per-channel picking. Router-safe:
// only the requested page crosses the wire; the full aggregate stays server-side.
func (m *module) handlePreviewChannels(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in previewChannelsInput
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		countries, catalogs, sources, _, err := validateSources(in.Countries, in.Catalogs, in.SourceURLs, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		offset, limit := pageBounds(in.Offset, in.Limit, previewPageMax)
		deduped, errs := m.aggregateCached(r.Context(), d, countries, catalogs, sources, in.Adult)
		page, total := selectChannels(deduped, in.Category, in.Q, offset, limit)
		items := make([]channelRow, 0, len(page))
		for _, ch := range page {
			items = append(items, channelRow{TvgID: ch.TvgID, Name: ch.Name, Logo: ch.Logo, URL: ch.URL, Group: iptvcore.CategoryOf(ch)})
		}
		writeJSON(w, http.StatusOK, previewChannelsResult{Items: items, Total: total, Offset: offset, Errors: errs})
	}
}

// pageBounds normalizes an offset/limit pair: offset floored at 0, limit defaulted+capped to max.
func pageBounds(offset, limit, max int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > max {
		limit = max
	}
	return offset, limit
}

// selectChannels applies the drill-down filters (category, case-insensitive; name/tvg-id substring)
// then returns the requested page plus the total match count (before pagination). offset/limit must
// be normalized (see pageBounds).
func selectChannels(chs []iptvcore.Channel, category, q string, offset, limit int) ([]iptvcore.Channel, int) {
	cat := strings.TrimSpace(category)
	ql := strings.ToLower(strings.TrimSpace(q))
	matched := make([]iptvcore.Channel, 0, len(chs))
	for _, ch := range chs {
		if cat != "" && !strings.EqualFold(iptvcore.CategoryOf(ch), cat) {
			continue
		}
		if ql != "" && !strings.Contains(strings.ToLower(ch.Name), ql) && !strings.Contains(strings.ToLower(ch.TvgID), ql) {
			continue
		}
		matched = append(matched, ch)
	}
	if offset >= len(matched) {
		return nil, len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], len(matched)
}

// previewHealthMax caps a live health-probe page: probing is sem=8 × up-to-6s, so a big page would
// stall the interactive "expand a category" action — the UI requests health for the visible page.
const previewHealthMax = 50

// handlePreviewHealth (POST /api/iptv/preview/health) probes ONE capped page of a would-be list's
// channels LIVE via the bounded prober and returns each channel's status (alive|geo|dead) — the
// source of the per-channel green ✓ / red ✗ in the drill-down. Same input as preview/channels; only
// the requested page is probed + returned (router-safe). now=0 so a first probe commits immediately.
func (m *module) handlePreviewHealth(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in previewChannelsInput
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		countries, catalogs, sources, _, err := validateSources(in.Countries, in.Catalogs, in.SourceURLs, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		offset, limit := pageBounds(in.Offset, in.Limit, previewHealthMax)
		deduped, errs := m.aggregateCached(r.Context(), d, countries, catalogs, sources, in.Adult)
		page, total := selectChannels(deduped, in.Category, in.Q, offset, limit)

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		iptvcore.NewProber(iptvcore.ProbeConfig{}).Probe(ctx, d.Fetch(), page, 0) // mutates page[i].Status in place
		items := make([]channelRow, 0, len(page))
		for _, ch := range page {
			items = append(items, channelRow{TvgID: ch.TvgID, Name: ch.Name, Logo: ch.Logo, URL: ch.URL, Group: iptvcore.CategoryOf(ch), Status: ch.Status})
		}
		writeJSON(w, http.StatusOK, previewChannelsResult{Items: items, Total: total, Offset: offset, Errors: errs})
	}
}

// exitRow is one enabled proxy endpoint with its inferred exit country (R1). Country/Flag/Name are
// empty when the country can't be inferred offline from the endpoint's label/host.
type exitRow struct {
	ID          string `json:"id"`
	Endpoint    string `json:"endpoint"`
	Country     string `json:"country,omitempty"`      // ISO code
	CountryName string `json:"country_name,omitempty"` // display name
	Flag        string `json:"flag,omitempty"`
}

// handleExits (GET /api/iptv/exits) reports the user's enabled exits and, for each, the country it
// likely exits in — inferred OFFLINE from the endpoint's name/server (no geo-IP, no network). The UI
// (and later R2/R3) use it to tell a user "you have an exit in the country this playlist needs", so a
// geo-locked national stream can be routed through a matching exit. Live-geo refinement is R2/R3.
func (m *module) handleExits(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var eps []feature.EndpointMeta
		if d.Endpoints != nil {
			eps = d.Endpoints()
		}
		rows := make([]exitRow, 0, len(eps))
		for _, e := range eps {
			row := exitRow{ID: e.ID, Endpoint: e.Name}
			if code, ok := iptvcore.InferExitCountry(e.Name, e.Server); ok {
				row.Country = code
				row.CountryName = iptvcore.CountryName(code)
				row.Flag = iptvcore.CountryFlag(code)
			}
			rows = append(rows, row)
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// gate wraps a handler so a disabled plugin 404s (mirrors the server's featureEnabled check, but read
// through the module's Deps.Cfg so the module stays decoupled from *Server).
func (m *module) gate(d *feature.Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fc, ok := d.Cfg().Features[moduleID]
		if !ok || !fc.Enabled {
			writeErr(w, http.StatusNotFound, "plugin not installed")
			return
		}
		h(w, r)
	}
}

func decodeInput(r *http.Request) (listInput, error) {
	var in listInput
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
		return in, errors.New("invalid JSON body")
	}
	return in, nil
}

// normCountries validates the country codes against the compiled-in allowlist (unknown → error),
// de-dupes + lowercases, and caps the count. Empty input is allowed (returns nil, nil) — the "≥1
// source" requirement is enforced by validateSources so a list can be countries OR a custom URL.
func normCountries(in []string) ([]string, error) {
	if len(in) > maxCountriesPerList {
		return nil, fmt.Errorf("too many countries (max %d)", maxCountriesPerList)
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		code := strings.ToLower(strings.TrimSpace(c))
		if code == "" {
			continue
		}
		if !iptvcore.KnownCountry(code) {
			return nil, fmt.Errorf("unknown country code %q", c)
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out, nil
}

// validateSourceURLs accepts owner-supplied provider/custom M3U URLs. Each must be an absolute
// http(s) URL with a host; de-duped and capped. The SSRF dial guard on the shared fetch client
// (blockInternalDial) still blocks loopback/private/link-local targets at connect time, so a custom
// URL can never be turned into an internal-network probe — the reason free-text URLs were held back
// in v1. Links-only: WayHop fetches the M3U and serves its links, it never proxies the streams.
func validateSourceURLs(in []string) ([]string, error) {
	const maxSources = 20
	if len(in) > maxSources {
		return nil, fmt.Errorf("too many custom sources (max %d)", maxSources)
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid playlist URL %q (must start with http:// or https://)", raw)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// cleanXtream validates + trims a list's Xtream accounts (each must resolve to a get.php URL — host +
// username + password), caps the count, and drops wholly-empty rows. Error messages are
// credential-free.
func cleanXtream(in []XtreamSource) ([]XtreamSource, error) {
	const maxXtream = 10
	if len(in) > maxXtream {
		return nil, fmt.Errorf("too many Xtream accounts (max %d)", maxXtream)
	}
	out := make([]XtreamSource, 0, len(in))
	for _, x := range in {
		x.URL, x.Username, x.Password = strings.TrimSpace(x.URL), strings.TrimSpace(x.Username), strings.TrimSpace(x.Password)
		if x.URL == "" && x.Username == "" && x.Password == "" {
			continue // an empty row from the UI
		}
		if _, err := xtreamM3UURL(x); err != nil { // validates host + creds; the message never leaks the password
			return nil, fmt.Errorf("Xtream account: %s", strings.TrimPrefix(err.Error(), "xtream: "))
		}
		out = append(out, x)
	}
	return out, nil
}

// cleanCatalogs validates + dedups a list's iptv-org catalog tokens ("language:rus", "category:news").
// An unknown token is an ERROR (a typo surfaces rather than silently dropping), matching the country
// allowlist's strictness. The tokens resolve, via the compiled-in allowlist, to iptv-org URLs only.
func cleanCatalogs(in []string) ([]string, error) {
	const maxCatalogs = 40
	if len(in) > maxCatalogs {
		return nil, fmt.Errorf("too many lists (max %d)", maxCatalogs)
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		tok := strings.ToLower(strings.TrimSpace(raw))
		if tok == "" {
			continue
		}
		if !iptvcore.KnownCatalog(tok) {
			return nil, fmt.Errorf("unknown list %q", raw)
		}
		if seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out, nil
}

// validateSources validates the four source types together and enforces that a list has at least one
// of them (a country, an iptv-org catalog list, a custom URL, OR an Xtream account) — so no field alone
// is "required", but the set can't be empty.
func validateSources(countries, catalogs, urls []string, xtream []XtreamSource) (cc, cat, src []string, xt []XtreamSource, err error) {
	if cc, err = normCountries(countries); err != nil {
		return nil, nil, nil, nil, err
	}
	if cat, err = cleanCatalogs(catalogs); err != nil {
		return nil, nil, nil, nil, err
	}
	if src, err = validateSourceURLs(urls); err != nil {
		return nil, nil, nil, nil, err
	}
	if xt, err = cleanXtream(xtream); err != nil {
		return nil, nil, nil, nil, err
	}
	if len(cc) == 0 && len(cat) == 0 && len(src) == 0 && len(xt) == 0 {
		return nil, nil, nil, nil, errors.New("add at least one country, list, custom URL, or Xtream account")
	}
	return cc, cat, src, xt, nil
}

// listName picks the display name: the user's (trimmed, capped) label, else a default built from the
// countries' catalog names.
func listName(name string, countries, sources []string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		if r := []rune(name); len(r) > maxNameLen { // truncate on a rune boundary, not mid-UTF-8
			name = string(r[:maxNameLen])
		}
		return name
	}
	parts := make([]string, 0, len(countries)+len(sources))
	for _, c := range countries {
		if n := iptvcore.CountryName(c); n != "" {
			parts = append(parts, n)
		}
	}
	// A URL-only list defaults its name to the source host(s) so it isn't blank.
	for _, s := range sources {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			parts = append(parts, u.Host)
		}
	}
	if len(parts) == 0 {
		return "Custom list"
	}
	return strings.Join(parts, ", ")
}

// cleanStrings trims, de-dupes (case-insensitive, first-seen display casing preserved), and caps a
// user-supplied string list; nil for empty input.
func cleanStrings(in []string, limit int) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > limit {
		in = in[:limit]
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		key := strings.ToLower(s)
		if s == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// cleanBlocklist / cleanCategories are cleanStrings at their respective caps (tvg-id/URL blocklist,
// excluded category names).
func cleanBlocklist(in []string) []string  { return cleanStrings(in, maxBlocklist) }
func cleanCategories(in []string) []string { return cleanStrings(in, maxCategories) }

func indexByID(ls []List, id string) int {
	for i := range ls {
		if ls[i].ID == id {
			return i
		}
	}
	return -1
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleServe serves a list's aggregated playlist. The token (a whole path segment) is matched
// constant-time against every list; a human browser gets the landing page, a player gets the .m3u.
func (m *module) handleServe(d *feature.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		l, ok := m.listByToken(d, token)
		if !ok {
			writeErr(w, http.StatusForbidden, "invalid playlist token")
			return
		}
		if wantsHTML(r) {
			m.serveLanding(w, r, d, l)
			return
		}
		serveM3UFile(w, m.playlistPath(d, token))
	}
}

// playlistPath is the on-disk location of a list's generated M3U (written by the I8 refresh loop,
// read here). Keyed by the token so the file name carries no user input.
func (m *module) playlistPath(d *feature.Deps, token string) string {
	return filepath.Join(d.DataDir, "iptv", token+".m3u")
}

// listByToken finds the list whose serve token matches, comparing constant-time and without an early
// return so neither the token value nor which list matched leaks through response timing.
func (m *module) listByToken(d *feature.Deps, token string) (List, bool) {
	if token == "" {
		return List{}, false
	}
	tb := []byte(token)
	var found List
	ok := false
	for _, l := range m.load(d).Lists {
		if l.Token != "" && subtle.ConstantTimeCompare(tb, []byte(l.Token)) == 1 {
			found, ok = l, true
		}
	}
	return found, ok
}

// serveM3UFile streams the generated playlist. A missing file (list never refreshed, or its file was
// pruned) yields an empty-but-valid #EXTM3U with 200 so a player import doesn't hard-fail before the
// first refresh populates it. io.Copy streams (never ReadAll) — router-safe on a large playlist.
func serveM3UFile(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "application/x-mpegurl; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	f, err := os.Open(path)
	if err != nil {
		_, _ = io.WriteString(w, "#EXTM3U\n")
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}

// wantsHTML decides browser-landing vs raw-playlist. Conservative so a player never gets HTML: an
// explicit ?raw=1 forces the playlist; ?web=1 forces the page; otherwise HTML only when the request
// both advertises text/html AND carries a browser (mozilla) UA. IPTV players send neither.
func wantsHTML(r *http.Request) bool {
	q := r.URL.Query()
	if v := strings.ToLower(q.Get("raw")); v == "1" || v == "true" {
		return false
	}
	if v := strings.ToLower(q.Get("web")); v == "1" || v == "true" {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(accept, "text/html") && strings.Contains(ua, "mozilla")
}

// serveLanding renders a self-contained, CSP-clean install page: the (already token-gated) playlist
// URL + QR + copy button (via the shared static /subcopy.js reading #u, so no inline script), the
// refresh status, and the mandatory legal disclaimer (links-only, public per-country sources).
func (m *module) serveLanding(w http.ResponseWriter, r *http.Request, d *feature.Deps, l List) {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	playURL := scheme + "://" + r.Host + r.URL.Path

	var qrTag string
	if d.QR != nil {
		if png, err := d.QR(playURL, 320); err == nil {
			qrTag = `<img class="qr" width="240" height="240" alt="Playlist QR code" src="data:image/png;base64,` +
				base64.StdEncoding.EncodeToString(png) + `">`
		}
	}

	urlHTML := html.EscapeString(playURL)
	dlHref := html.EscapeString(r.URL.Path + "?raw=1")
	countries := make([]string, 0, len(l.Countries))
	for _, c := range l.Countries {
		if n := iptvcore.CountryName(c); n != "" {
			countries = append(countries, html.EscapeString(iptvcore.CountryFlag(c)+" "+n))
		}
	}
	status := "Not refreshed yet"
	if l.Stats.LastRefresh > 0 {
		status = strconv.Itoa(l.Stats.Channels) + " channels"
		if l.Stats.Pruned > 0 {
			status += " · " + strconv.Itoa(l.Stats.Pruned) + " pruned"
		}
		if l.Stats.AdultCut > 0 {
			status += " · " + strconv.Itoa(l.Stats.AdultCut) + " adult-filtered"
		}
	}
	_ = url.QueryEscape // reserved for future deep-link import helpers

	page := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>` + html.EscapeString(l.Name) + ` — WayHop IPTV</title>
<style>
:root{--bg:#0e1116;--card:#161b22;--border:#262d36;--fg:#e6edf3;--muted:#9aa7b4;--accent:#3fb950;--accent-d:#2ea043;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:28px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{margin:0 0 4px;font-size:22px}
.sub{margin:0 0 14px;color:var(--muted);font-size:14px}
.count{display:inline-block;margin-bottom:14px;padding:3px 10px;border:1px solid var(--border);border-radius:999px;
  color:var(--accent);font-size:12px}
.flags{margin:0 0 16px;color:var(--muted);font-size:13px}
.qr{display:block;margin:0 auto 18px;border-radius:10px;background:#fff;padding:10px}
.urlrow{display:flex;gap:8px;align-items:stretch;margin:0 0 12px}
code#u{flex:1;min-width:0;overflow:auto;white-space:nowrap;background:#0b0e13;border:1px solid var(--border);
  border-radius:8px;padding:9px 11px;font-size:12px;color:var(--fg);text-align:left}
button,.btn{cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:9px 13px;font-size:13px;
  font-weight:600;text-decoration:none;display:inline-block}
#copy{background:var(--accent);border-color:var(--accent);color:#06120a}
#copy:hover{background:var(--accent-d)}
.imports{display:flex;gap:8px;margin:0 0 16px}
.imports .btn{flex:1;background:#0b0e13;color:var(--fg)}
.imports .btn:hover{border-color:var(--accent)}
.disclaimer{margin:14px 0 0;padding-top:14px;border-top:1px solid var(--border);color:var(--muted);font-size:11px;text-align:left}
</style>
</head>
<body>
<div class="card">
  <h1>` + html.EscapeString(l.Name) + `</h1>
  <p class="sub">Add this playlist to your IPTV player</p>
  <div class="count">` + html.EscapeString(status) + `</div>
  <div class="flags">` + strings.Join(countries, " · ") + `</div>
  ` + qrTag + `
  <div class="urlrow">
    <code id="u">` + urlHTML + `</code>
    <button id="copy" type="button">Copy</button>
  </div>
  <div class="imports">
    <a class="btn" href="` + dlHref + `" download>Download .m3u</a>
  </div>
  <p class="works" style="margin:0;color:var(--muted);font-size:12px">Works with: TiviMate, IPTV Smarters, VLC, Kodi, OTT Navigator</p>
  <p class="disclaimer">Links to publicly-listed free-to-air streams aggregated from the open
  <b>iptv-org</b> per-country catalogs. WayHop does not host, cache, or re-stream any content — it
  only serves a list of links. Availability is not guaranteed. Respect the broadcasters' terms and
  your local laws.</p>
</div>
<script src="/subcopy.js" defer></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
