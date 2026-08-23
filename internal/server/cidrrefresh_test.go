package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"wayhop/internal/model"
)

func feedServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// getList returns a copy of a routing list (Profile() returns a value, and RoutingListByID
// is a pointer method, so we snapshot through an addressable local).
func getList(t *testing.T, s *Server, id string) model.RoutingList {
	t.Helper()
	p := s.store.Profile()
	rl := p.RoutingListByID(id)
	if rl == nil {
		t.Fatalf("routing list %q missing", id)
	}
	return *rl
}

func cacheOf(t *testing.T, s *Server, id string) []string { return getList(t, s, id).CIDRCache }

// TestRefreshOne: a CIDRSource feed populates CIDRCache (sorted); an unchanged feed is a
// no-op; a genuinely different result updates the cache.
func TestRefreshOne(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true // let the SSRF-guarded client reach the loopback httptest

	a := feedServer(t, "2.2.2.0/24\n1.1.1.0/24\n") // unsorted on purpose
	rl := model.RoutingList{ID: "ru", Name: "RU", CIDRSource: a.URL, Outbound: "direct", Enabled: true}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}

	changed, err := s.refreshOne(context.Background(), rl)
	if err != nil || !changed {
		t.Fatalf("first refresh: changed=%v err=%v, want true/nil", changed, err)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Fatalf("cache = %v, want sorted [1.1.1.0/24 2.2.2.0/24]", c)
	}

	// same feed again → no change.
	if changed, err := s.refreshOne(context.Background(), getList(t, s, "ru")); err != nil || changed {
		t.Errorf("second refresh: changed=%v err=%v, want false/nil", changed, err)
	}

	// a different result → cache updates. The write is source-guarded, so the new source must be
	// PERSISTED first (a fetch against a source the store no longer has is a stale write — dropped).
	b := feedServer(t, "3.3.3.0/24\n")
	rl3 := getList(t, s, "ru")
	rl3.CIDRSource = b.URL
	if err := s.store.UpsertRoutingList(rl3); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.refreshOne(context.Background(), getList(t, s, "ru")); err != nil || !changed {
		t.Fatalf("changed-result refresh: changed=%v err=%v", changed, err)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"3.3.3.0/24"}) {
		t.Errorf("cache after change = %v, want [3.3.3.0/24]", c)
	}

	// The guard itself: a fetch performed against a source the store has since moved away from
	// must NOT write (no resurrecting the old feed's CIDRs).
	stale := getList(t, s, "ru")
	stale.CIDRSource = a.URL // pretend the fetch ran against the old source
	if changed, err := s.refreshOne(context.Background(), stale); err != nil || changed {
		t.Errorf("stale-source refresh must be dropped: changed=%v err=%v", changed, err)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"3.3.3.0/24"}) {
		t.Errorf("cache must survive a stale-source refresh: %v", c)
	}
}

// TestRefreshOne_KeepsLastGoodOnFailure: a fetch error or an all-empty result must NOT wipe
// the existing carve-out — it returns an error and leaves CIDRCache intact.
func TestRefreshOne_KeepsLastGoodOnFailure(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true

	good := feedServer(t, "9.9.9.0/24\n")
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: good.URL, Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.refreshOne(context.Background(), getList(t, s, "ru")); err != nil {
		t.Fatal(err)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"9.9.9.0/24"}) {
		t.Fatalf("seed cache = %v", c)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	empty := feedServer(t, "# only comments, no CIDRs\n")

	for _, src := range []string{bad.URL, empty.URL} {
		rlf := getList(t, s, "ru")
		rlf.CIDRSource = src
		if _, err := s.refreshOne(context.Background(), rlf); err == nil {
			t.Errorf("source %q should error", src)
		}
		if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"9.9.9.0/24"}) {
			t.Errorf("cache must survive a failed refresh from %q: %v", src, c)
		}
	}
}

// TestRefreshAll: batch refresh updates each enabled sourced list, isolates a failing feed
// (one error, others still refresh), and skips disabled / non-sourced lists.
func TestRefreshAll(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true

	a := feedServer(t, "1.1.1.0/24\n")
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	disabledFeed := feedServer(t, "8.8.8.0/24\n")

	lists := []model.RoutingList{
		{ID: "l1", Name: "ok", CIDRSource: a.URL, Outbound: "direct", Enabled: true},
		{ID: "l2", Name: "fails", CIDRSource: bad.URL, Outbound: "direct", Enabled: true},
		{ID: "l3", Name: "manual", Manual: []string{"9.9.9.0/24"}, Outbound: "direct", Enabled: true},
		{ID: "l4", Name: "disabled", CIDRSource: disabledFeed.URL, Outbound: "direct", Enabled: false},
	}
	for _, rl := range lists {
		if err := s.store.UpsertRoutingList(rl); err != nil {
			t.Fatal(err)
		}
	}

	changed, errs := s.refreshAll(context.Background())
	if !changed {
		t.Error("want changed=true (l1 fetched a new cache)")
	}
	if len(errs) != 1 {
		t.Errorf("want exactly 1 error (l2 failed), got %d: %v", len(errs), errs)
	}
	if c := cacheOf(t, s, "l1"); !slices.Equal(c, []string{"1.1.1.0/24"}) {
		t.Errorf("l1 cache = %v, want [1.1.1.0/24]", c)
	}
	if c := cacheOf(t, s, "l2"); len(c) != 0 {
		t.Errorf("l2 (failed) cache should stay empty: %v", c)
	}
	if c := cacheOf(t, s, "l4"); len(c) != 0 {
		t.Errorf("l4 (disabled) must not be refreshed: %v", c)
	}
}

// TestHandleRoutingRefresh: POST /api/routing/refresh refreshes each sourced list's cache
// and reports it, WITHOUT applying (the user Applies separately).
func TestHandleRoutingRefresh(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed := feedServer(t, "1.1.1.0/24\n2.2.2.0/24\n")
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "ru", Name: "RU", CIDRSource: feed.URL, Outbound: "direct", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleRoutingRefresh(rec, httptest.NewRequest("POST", "/api/routing/refresh", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Changed bool     `json:"changed"`
		Errors  []string `json:"errors"`
		Lists   []struct {
			ID    string `json:"id"`
			CIDRs int    `json:"cidrs"`
		} `json:"lists"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v (%s)", err, rec.Body.String())
	}
	if !resp.Changed {
		t.Errorf("changed=false, want true; body=%s", rec.Body.String())
	}
	if len(resp.Errors) != 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}
	if len(resp.Lists) != 1 || resp.Lists[0].ID != "ru" || resp.Lists[0].CIDRs != 2 {
		t.Errorf("lists=%+v, want one ru list with 2 cidrs", resp.Lists)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Errorf("cache not persisted: %v", c)
	}
}

// TestCIDRIntervalHours: 0 → 24h default; sub-floor clamps up to 6; above the ceiling clamps to 720.
func TestCIDRIntervalHours(t *testing.T) {
	for _, c := range []struct{ in, want int }{
		{0, 24}, {1, 6}, {5, 6}, {6, 6}, {12, 12}, {24, 24}, {168, 168}, {720, 720}, {1000, 720},
	} {
		if got := cidrIntervalHours(model.RoutingList{RefreshHours: c.in}); got != c.want {
			t.Errorf("cidrIntervalHours(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestCIDRRefreshTick_NeverRefreshedIsDueNow: a list with no CIDRRefreshed history fetches on the
// FIRST tick (sorted persist + timestamp recorded); after that it isn't due again until its
// interval elapses, and a due re-fetch of an UNCHANGED feed writes nothing (dedup).
func TestCIDRRefreshTick_NeverRefreshedIsDueNow(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed := feedServer(t, "2.2.2.0/24\n1.1.1.0/24\n") // unsorted on purpose
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: feed.URL, Outbound: "direct", Enabled: true, RefreshHours: 6}); err != nil {
		t.Fatal(err)
	}
	due := map[string]time.Time{}
	base := time.Now()

	s.cidrRefreshTick(context.Background(), due, base)
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Fatalf("never-refreshed list must fetch on the first tick (sorted); cache=%v", c)
	}
	if ts := getList(t, s, "ru").CIDRRefreshed; ts == 0 {
		t.Error("a successful cache write must record CIDRRefreshed")
	}

	// Not due again within the interval; due (and deduped — no content change) after it.
	s.cidrRefreshTick(context.Background(), due, base.Add(1*time.Hour))
	if nd := due["ru"]; !nd.After(base.Add(5 * time.Hour)) {
		t.Errorf("next attempt must be a full interval out, got %v", nd.Sub(base))
	}
	s.cidrRefreshTick(context.Background(), due, base.Add(7*time.Hour))
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Errorf("unchanged feed re-fetch must keep the cache; cache=%v", c)
	}
}

// TestCIDRRefreshTick_SeedsFromPersistedTimestamp: across a daemon restart (fresh due map) the
// schedule comes from CIDRRefreshed — a recently-refreshed list is NOT due, an overdue one is.
// This is the fix for "a router restarted more often than the interval never auto-refreshes".
func TestCIDRRefreshTick_SeedsFromPersistedTimestamp(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	fresh := feedServer(t, "1.1.1.0/24\n")
	stale := feedServer(t, "2.2.2.0/24\n")
	base := time.Now()
	for _, rl := range []model.RoutingList{
		{ID: "fresh", Name: "f", CIDRSource: fresh.URL, Outbound: "direct", Enabled: true, RefreshHours: 6,
			CIDRCache: []string{"9.9.9.0/24"}, CIDRRefreshed: base.Add(-2 * time.Hour).Unix()},
		{ID: "stale", Name: "s", CIDRSource: stale.URL, Outbound: "direct", Enabled: true, RefreshHours: 6,
			CIDRCache: []string{"8.8.8.0/24"}, CIDRRefreshed: base.Add(-7 * time.Hour).Unix()},
	} {
		if err := s.store.UpsertRoutingList(rl); err != nil {
			t.Fatal(err)
		}
	}
	due := map[string]time.Time{} // fresh map = daemon restart
	s.cidrRefreshTick(context.Background(), due, base)
	if c := cacheOf(t, s, "fresh"); !slices.Equal(c, []string{"9.9.9.0/24"}) {
		t.Errorf("refreshed 2h ago on a 6h interval must NOT refetch after restart; cache=%v", c)
	}
	if c := cacheOf(t, s, "stale"); !slices.Equal(c, []string{"2.2.2.0/24"}) {
		t.Errorf("overdue list must refetch right after restart; cache=%v", c)
	}
}

// TestCIDRRefreshTick_BatchesAndSkipsDisabled: two due lists that both change persist in one tick; a
// disabled list is never fetched; its schedule entry is dropped.
func TestCIDRRefreshTick_BatchesAndSkipsDisabled(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	f1, f2, f3 := feedServer(t, "1.1.1.0/24\n"), feedServer(t, "2.2.2.0/24\n"), feedServer(t, "3.3.3.0/24\n")
	for _, rl := range []model.RoutingList{
		{ID: "a", Name: "a", CIDRSource: f1.URL, Outbound: "direct", Enabled: true},
		{ID: "b", Name: "b", CIDRSource: f2.URL, Outbound: "direct", Enabled: true},
		{ID: "c", Name: "c", CIDRSource: f3.URL, Outbound: "direct", Enabled: false},
	} {
		if err := s.store.UpsertRoutingList(rl); err != nil {
			t.Fatal(err)
		}
	}
	due := map[string]time.Time{"c": time.Now().Add(-time.Hour)} // stale entry for the disabled list
	s.cidrRefreshTick(context.Background(), due, time.Now())

	if c := cacheOf(t, s, "a"); !slices.Equal(c, []string{"1.1.1.0/24"}) {
		t.Errorf("a cache=%v", c)
	}
	if c := cacheOf(t, s, "b"); !slices.Equal(c, []string{"2.2.2.0/24"}) {
		t.Errorf("b cache=%v", c)
	}
	if c := cacheOf(t, s, "c"); len(c) != 0 {
		t.Errorf("disabled c must not be refreshed: %v", c)
	}
	if _, ok := due["c"]; ok {
		t.Error("a disabled list's schedule entry must be dropped")
	}
}

// TestCIDRRefreshTick_FloorClampsDue: a hand-edited refresh_hours=1 (below the flash floor) is
// scheduled at the 6h floor by the ticker itself: after the first fetch, +2h is not due; +7h is.
func TestCIDRRefreshTick_FloorClampsDue(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed := feedServer(t, "1.1.1.0/24\n")
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: feed.URL, Outbound: "direct", Enabled: true, RefreshHours: 1}); err != nil {
		t.Fatal(err)
	}
	due := map[string]time.Time{}
	base := time.Now()
	s.cidrRefreshTick(context.Background(), due, base) // never-refreshed -> fetches now
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"1.1.1.0/24"}) {
		t.Fatalf("first fetch expected; cache=%v", c)
	}
	if nd := due["ru"]; nd.Before(base.Add(5 * time.Hour)) {
		t.Errorf("sub-floor refresh_hours must reschedule at the 6h floor, got +%v", nd.Sub(base))
	}
}

// TestCIDRRefreshTick_ShortenedIntervalTakesEffect: a list mid-way through a long schedule whose
// RefreshHours is edited down must not sit out the old schedule (the due time is clamped).
func TestCIDRRefreshTick_ShortenedIntervalTakesEffect(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed := feedServer(t, "1.1.1.0/24\n")
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: feed.URL, Outbound: "direct", Enabled: true, RefreshHours: 6}); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	due := map[string]time.Time{"ru": base.Add(500 * time.Hour)} // leftover from a former 720h setting
	s.cidrRefreshTick(context.Background(), due, base)
	if nd := due["ru"]; nd.After(base.Add(6*time.Hour + time.Minute)) {
		t.Errorf("shortened interval must clamp the due time to <= now+6h, got +%v", nd.Sub(base))
	}
}

// TestUpsertPreservesCIDRCache: a user edit that omits the system-managed cache keeps it
// (same source), but a changed source drops the now-stale cache.
func TestUpsertPreservesCIDRCache(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: "asn:13238", Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetRoutingListCache("ru", []string{"5.45.192.0/18"}); err != nil {
		t.Fatal(err)
	}
	// edit omitting CIDRCache, same source → preserved.
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU renamed", CIDRSource: "asn:13238", Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c := cacheOf(t, s, "ru"); !slices.Equal(c, []string{"5.45.192.0/18"}) {
		t.Errorf("cache should be preserved on same-source edit: %v", c)
	}
	// edit changing the source → stale cache dropped.
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", CIDRSource: "asn:47541", Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c := cacheOf(t, s, "ru"); len(c) != 0 {
		t.Errorf("cache should be dropped when source changes: %v", c)
	}

	// Round-trip case: a source change where the incoming struct STILL carries the old
	// cache (UI GET→edit source→PUT echoes cidr_cache) must also drop it — else stale CIDRs
	// route under the new source until the next refresh.
	if err := s.store.SetRoutingListCache("ru", []string{"95.213.0.0/17"}); err != nil { // seed cache for asn:47541
		t.Fatal(err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "ru", Name: "RU", CIDRSource: "asn:13238", // changed back
		CIDRCache: []string{"95.213.0.0/17"}, // stale cache echoed by the client
		Outbound:  "direct", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if c := cacheOf(t, s, "ru"); len(c) != 0 {
		t.Errorf("stale cache echoed on a source-change PUT must be dropped: %v", c)
	}
}
