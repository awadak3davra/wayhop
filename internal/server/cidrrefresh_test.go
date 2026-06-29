package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"velinx/internal/model"
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
	if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Fatalf("cache = %v, want sorted [1.1.1.0/24 2.2.2.0/24]", c)
	}

	// same feed again → no change.
	if changed, err := s.refreshOne(context.Background(), getList(t, s, "ru")); err != nil || changed {
		t.Errorf("second refresh: changed=%v err=%v, want false/nil", changed, err)
	}

	// a different result → cache updates.
	b := feedServer(t, "3.3.3.0/24\n")
	rl3 := getList(t, s, "ru")
	rl3.CIDRSource = b.URL
	if changed, err := s.refreshOne(context.Background(), rl3); err != nil || !changed {
		t.Fatalf("changed-result refresh: changed=%v err=%v", changed, err)
	}
	if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"3.3.3.0/24"}) {
		t.Errorf("cache after change = %v, want [3.3.3.0/24]", c)
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
	if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"9.9.9.0/24"}) {
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
		if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"9.9.9.0/24"}) {
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
	if c := cacheOf(t, s, "l1"); !equalStrings(c, []string{"1.1.1.0/24"}) {
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
	if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"1.1.1.0/24", "2.2.2.0/24"}) {
		t.Errorf("cache not persisted: %v", c)
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
	if c := cacheOf(t, s, "ru"); !equalStrings(c, []string{"5.45.192.0/18"}) {
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
