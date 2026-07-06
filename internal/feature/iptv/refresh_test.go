package iptv

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/feature"
	"wayhop/internal/featurestore"
)

// fakeRT intercepts BOTH the per-country iptv-org playlist fetch and the per-channel health probe, so
// the whole refresh pipeline runs offline with no real network. A path under /countries/{cc}.m3u
// returns that country's canned M3U (or a 404 / network error); any other URL is treated as a stream
// probe whose status is decided by streamCode.
type fakeRT struct {
	countries  map[string]string // cc -> M3U body
	urls       map[string]string // full custom URL -> M3U body (provider/custom source)
	failCC     map[string]bool   // cc -> simulated network error
	streamCode func(url string) int
}

func (f *fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if body, ok := f.urls[req.URL.String()]; ok { // owner-supplied custom source URL
		return mkResp(http.StatusOK, body), nil
	}
	p := req.URL.Path
	if strings.Contains(p, "/countries/") && strings.HasSuffix(p, ".m3u") {
		cc := strings.TrimSuffix(path.Base(p), ".m3u")
		if f.failCC[cc] {
			return nil, fmt.Errorf("simulated dial failure for %s", cc)
		}
		body, ok := f.countries[cc]
		if !ok {
			return mkResp(http.StatusNotFound, ""), nil
		}
		return mkResp(http.StatusOK, body), nil
	}
	code := http.StatusOK
	if f.streamCode != nil {
		code = f.streamCode(req.URL.String())
	}
	return mkResp(code, "#EXTM3U\n#EXT-X-VERSION:3\n"), nil
}

func mkResp(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func refreshSetup(t *testing.T, enabled *bool, rt *fakeRT) (*module, *feature.Deps) {
	t.Helper()
	fs, err := featurestore.Open(filepath.Join(t.TempDir(), "features.json"))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt}
	d := &feature.Deps{
		Cfg: func() config.Config {
			return config.Config{Features: map[string]config.FeatureConfig{moduleID: {Enabled: *enabled}}}
		},
		Fetch:   func() *http.Client { return client },
		Store:   fs,
		DataDir: t.TempDir(),
	}
	return &module{}, d
}

func seed(t *testing.T, d *feature.Deps, lists ...List) {
	t.Helper()
	if err := d.Store.SetJSON(moduleID, state{Lists: lists}); err != nil {
		t.Fatal(err)
	}
}

func readStats(t *testing.T, d *feature.Deps, id string) ListStats {
	t.Helper()
	var st state
	if err := d.Store.GetJSON(moduleID, &st); err != nil {
		t.Fatal(err)
	}
	i := indexByID(st.Lists, id)
	if i < 0 {
		t.Fatalf("list %s gone", id)
	}
	return st.Lists[i].Stats
}

func tick(m *module, d *feature.Deps, due map[string]time.Time, now time.Time) {
	m.refreshTick(context.Background(), d, due, now)
}

func TestRefreshBuildsPlaylist(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTM3U url-tvg=\"http://epg\"\n#EXTINF:-1 tvg-id=\"z\",Zeta\nhttp://s/z\n",
		"gb": "#EXTINF:-1 tvg-id=\"a\",Alpha\nhttp://s/a\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Name: "Mix", Countries: []string{"us", "gb"}, Token: "tok1"})

	tick(m, d, map[string]time.Time{}, time.Unix(1000, 0))

	out, err := os.ReadFile(m.playlistPath(d, "tok1"))
	if err != nil {
		t.Fatalf("playlist not written: %v", err)
	}
	body := string(out)
	// Sorted A-Z (Alpha before Zeta), EPG header carried through, both channels present.
	if !strings.HasPrefix(body, "#EXTM3U url-tvg=\"http://epg\"") {
		t.Fatalf("missing url-tvg header: %q", body)
	}
	if strings.Index(body, "Alpha") > strings.Index(body, "Zeta") {
		t.Fatalf("not sorted A-Z: %q", body)
	}
	s := readStats(t, d, "l1")
	if s.Channels != 2 || s.LastRefresh != 1000 || s.LastError != "" {
		t.Fatalf("stats wrong: %+v", s)
	}
}

// TestRefreshMergesEPGGuides: a multi-source list must carry the EPG (url-tvg) guide of EVERY source,
// comma-joined + deduped, so no channel is left guide-less (keeping only the first source's guide was
// the bug).
func TestRefreshMergesEPGGuides(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTM3U url-tvg=\"http://epg/us.xml\"\n#EXTINF:-1 tvg-id=\"a\",A\nhttp://s/a\n",
		"gb": "#EXTM3U url-tvg=\"http://epg/gb.xml\"\n#EXTINF:-1 tvg-id=\"b\",B\nhttp://s/b\n",
		"de": "#EXTM3U url-tvg=\"http://epg/us.xml\"\n#EXTINF:-1 tvg-id=\"c\",C\nhttp://s/c\n", // dup url-tvg → collapsed
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Name: "Mix", Countries: []string{"us", "gb", "de"}, Token: "tok"})

	tick(m, d, map[string]time.Time{}, time.Unix(1000, 0))

	body, err := os.ReadFile(m.playlistPath(d, "tok"))
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(string(body), "\n", 2)[0]
	if header != `#EXTM3U url-tvg="http://epg/us.xml,http://epg/gb.xml"` {
		t.Fatalf("EPG guides not merged/deduped, header = %q", header)
	}
}

// TestRefreshNowAlreadyRefreshing: a manual "Update now" while a build of the same list is already in
// flight must coalesce (202 "already refreshing") instead of spawning an overlapping fetch+probe build.
func TestRefreshNowAlreadyRefreshing(t *testing.T) {
	enabled := true
	m, d := refreshSetup(t, &enabled, &fakeRT{})
	seed(t, d, List{ID: "l1", Name: "X", Countries: []string{"us"}, Token: "t"})
	// Occupy the per-list single-flight (simulate a build in progress).
	if !m.tryBuild("l1") {
		t.Fatal("first tryBuild should win")
	}
	defer m.doneBuild("l1")

	req := httptest.NewRequest(http.MethodPost, "/api/iptv/lists/l1/refresh", nil)
	req.SetPathValue("id", "l1")
	w := httptest.NewRecorder()
	m.handleRefreshNow(d)(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already refreshing") {
		t.Fatalf("body = %q, want 'already refreshing'", w.Body.String())
	}
}

// TestRefreshFirstBuildFailStampsAttempt: when every source fails on a never-built list, the refresh
// must record LastError + LastAttempt (so the card shows an honest "first build failed") while leaving
// LastRefresh at 0 (no successful build ever happened).
func TestRefreshFirstBuildFailStampsAttempt(t *testing.T) {
	enabled := true
	rt := &fakeRT{failCC: map[string]bool{"us": true}} // both primary + mirror dial-fail (path-matched)
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Name: "X", Countries: []string{"us"}, Token: "tok"})

	tick(m, d, map[string]time.Time{}, time.Unix(5000, 0))

	s := readStats(t, d, "l1")
	if s.LastRefresh != 0 {
		t.Fatalf("a failed first build must not set LastRefresh, got %d", s.LastRefresh)
	}
	if s.LastAttempt != 5000 {
		t.Fatalf("a failed build must stamp LastAttempt=5000, got %d", s.LastAttempt)
	}
	if s.LastError == "" {
		t.Fatal("a failed build must record LastError")
	}
}

// TestRefreshSkipsPausedList: a paused list is never auto-built (no playlist written, no stats
// stamped) — its token keeps serving whatever was last written, and pausing is reversible.
func TestRefreshSkipsPausedList(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1 tvg-id=\"a\",Alpha\nhttp://s/a\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Name: "X", Countries: []string{"us"}, Token: "tok", Paused: true})

	tick(m, d, map[string]time.Time{}, time.Unix(1000, 0))

	if _, err := os.ReadFile(m.playlistPath(d, "tok")); err == nil {
		t.Fatal("a paused list must not be built/written")
	}
	if s := readStats(t, d, "l1"); s.LastRefresh != 0 || s.LastAttempt != 0 {
		t.Fatalf("a paused list must not be attempted by the auto-refresh loop: %+v", s)
	}
}

func TestRefreshAdultAndDedup(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		// "us" has an adult channel (group XXX) + a channel that duplicates "gb"'s by URL.
		"us": "#EXTINF:-1 group-title=\"XXX\",Naughty\nhttp://s/adult\n" +
			"#EXTINF:-1,Shared\nhttp://s/dup\n",
		"gb": "#EXTINF:-1,Shared\nhttp://s/dup\n#EXTINF:-1,Brit\nhttp://s/brit\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us", "gb"}, Token: "t", Adult: false})

	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	s := readStats(t, d, "l1")
	if s.AdultCut != 1 {
		t.Errorf("AdultCut = %d, want 1", s.AdultCut)
	}
	if s.Duplicates < 1 {
		t.Errorf("Duplicates = %d, want >=1", s.Duplicates)
	}
	// Adult default-OFF: the adult stream URL must not be in the output.
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	if strings.Contains(string(out), "s/adult") {
		t.Fatal("adult channel leaked into the playlist")
	}
}

func TestRefreshProbeDropsDead(t *testing.T) {
	enabled := true
	rt := &fakeRT{
		countries: map[string]string{
			"us": "#EXTINF:-1,Good\nhttp://stream/ok\n#EXTINF:-1,Bad\nhttp://stream/dead\n",
		},
		streamCode: func(u string) int {
			if strings.Contains(u, "/ok") {
				return http.StatusOK
			}
			return http.StatusInternalServerError
		},
	}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", Probe: true})

	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	s := readStats(t, d, "l1")
	if s.Channels != 1 || s.Pruned != 1 {
		t.Fatalf("probe: Channels=%d Pruned=%d, want 1/1", s.Channels, s.Pruned)
	}
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	if strings.Contains(string(out), "stream/dead") {
		t.Fatal("dead channel not pruned")
	}
}

func TestRefreshErrorKeepsLastGood(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,Chan\nhttp://s/1\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	due := map[string]time.Time{}

	// First refresh succeeds.
	tick(m, d, due, time.Unix(1, 0))
	good, err := os.ReadFile(m.playlistPath(d, "t"))
	if err != nil || !strings.Contains(string(good), "s/1") {
		t.Fatalf("first refresh failed: %v %q", err, good)
	}

	// Now the source fails; a later tick must keep the last-good file + record the error.
	rt.failCC = map[string]bool{"us": true}
	tick(m, d, due, time.Unix(1, 0).Add(24*time.Hour))
	after, _ := os.ReadFile(m.playlistPath(d, "t"))
	if string(after) != string(good) {
		t.Fatal("last-good playlist was overwritten on fetch failure")
	}
	if s := readStats(t, d, "l1"); s.LastError == "" {
		t.Fatal("fetch failure not recorded in stats")
	}
}

func TestRefreshScheduling(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,C\nhttp://s/1\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	// A list refreshed "just now" is not due until +interval.
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", RefreshHours: 12,
		Stats: ListStats{LastRefresh: 1000}})
	due := map[string]time.Time{}

	tick(m, d, due, time.Unix(1000, 0)) // not due yet
	if _, err := os.Stat(m.playlistPath(d, "t")); err == nil {
		t.Fatal("list refreshed before it was due")
	}
	tick(m, d, due, time.Unix(1000, 0).Add(13*time.Hour)) // now due
	if _, err := os.Stat(m.playlistPath(d, "t")); err != nil {
		t.Fatalf("list not refreshed after its interval: %v", err)
	}
}

func TestRefreshExcludeCategories(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 group-title=\"News\",A\nhttp://s/a\n" +
			"#EXTINF:-1 group-title=\"Shop\",B\nhttp://s/b\n" +
			"#EXTINF:-1 group-title=\"Shop\",C\nhttp://s/c\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", ExcludeCategories: []string{"shop"}})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	s := readStats(t, d, "l1")
	if s.Channels != 1 || s.CategoryCut != 2 {
		t.Fatalf("Channels=%d CategoryCut=%d, want 1/2", s.Channels, s.CategoryCut)
	}
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	if strings.Contains(string(out), "s/b") || strings.Contains(string(out), "s/c") {
		t.Fatal("excluded 'Shop' category leaked into the playlist")
	}
	if !strings.Contains(string(out), "s/a") {
		t.Fatal("kept 'News' category missing from the playlist")
	}
}

func TestRefreshCustomSourceURL(t *testing.T) {
	enabled := true
	rt := &fakeRT{
		countries: map[string]string{"us": "#EXTINF:-1,US One\nhttp://s/us1\n"},
		urls:      map[string]string{"http://provider.example/list.m3u": "#EXTINF:-1,Provider A\nhttp://s/pa\n#EXTINF:-1,Provider B\nhttp://s/pb\n"},
	}
	m, d := refreshSetup(t, &enabled, rt)
	// A list mixing a country AND a custom provider URL.
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, SourceURLs: []string{"http://provider.example/list.m3u"}, Token: "t"})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	s := readStats(t, d, "l1")
	if s.Channels != 3 {
		t.Fatalf("channels = %d, want 3 (1 country + 2 provider)", s.Channels)
	}
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	for _, want := range []string{"s/us1", "s/pa", "s/pb"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("playlist missing %q:\n%s", want, out)
		}
	}
}

func TestRefreshCustomSourceOnly(t *testing.T) {
	enabled := true
	rt := &fakeRT{urls: map[string]string{"https://prov.test/x.m3u": "#EXTINF:-1,Only\nhttp://s/only\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	// No countries — a URL-only list must still build.
	seed(t, d, List{ID: "l1", SourceURLs: []string{"https://prov.test/x.m3u"}, Token: "t"})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	if s := readStats(t, d, "l1"); s.Channels != 1 {
		t.Fatalf("URL-only list channels = %d, want 1", s.Channels)
	}
}

func TestRebuildOneManual(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,One\nhttp://s/1\n#EXTINF:-1,Two\nhttp://s/2\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	// rebuildOne is the synchronous core the background handler runs.
	m.rebuildOne(d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	if s := readStats(t, d, "l1"); s.Channels != 2 || s.LastRefresh == 0 {
		t.Fatalf("manual rebuild stats = %+v, want 2 channels + a refresh time", s)
	}
	if out, _ := os.ReadFile(m.playlistPath(d, "t")); !strings.Contains(string(out), "s/1") {
		t.Fatalf("manual rebuild did not write the playlist: %q", out)
	}
}

func TestRefreshNowHandler(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,One\nhttp://s/1\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	mux := http.NewServeMux()
	m.Routes(mux, d)
	// Unknown id → 404.
	req := httptest.NewRequest("POST", "/api/iptv/lists/nope/refresh", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-id refresh = %d, want 404", rec.Code)
	}
	// Known id → 202 accepted (build runs in the background).
	req = httptest.NewRequest("POST", "/api/iptv/lists/l1/refresh", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid refresh = %d, want 202", rec.Code)
	}
	// Await the background rebuild before returning, else its playlist write races the TempDir cleanup.
	done := false
	for i := 0; i < 300 && !done; i++ {
		if readList(t, d, "l1").Stats.LastRefresh != 0 {
			done = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !done {
		t.Fatal("background rebuild did not complete in time")
	}
}

func TestRefreshChannelIncludeRescue(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 tvg-id=\"cnn.us\" group-title=\"News\",CNN\nhttp://s/cnn\n" +
			"#EXTINF:-1 tvg-id=\"fox.us\" group-title=\"News\",Fox\nhttp://s/fox\n" +
			"#EXTINF:-1 group-title=\"Sports\",ESPN\nhttp://s/espn\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	// Cut News, but rescue CNN by its tvg-id.
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t",
		ExcludeCategories: []string{"News"}, ChannelInclude: []string{"cnn.us"}})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	s := readStats(t, d, "l1")
	if s.Channels != 2 || s.CategoryCut != 1 { // CNN (rescued) + ESPN kept; only Fox cut
		t.Fatalf("Channels=%d CategoryCut=%d, want 2/1 (Fox cut, CNN rescued)", s.Channels, s.CategoryCut)
	}
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	if !strings.Contains(string(out), "s/cnn") || strings.Contains(string(out), "s/fox") {
		t.Fatalf("rescue wrong — CNN must survive, Fox must be cut:\n%s", out)
	}
}

func readList(t *testing.T, d *feature.Deps, id string) List {
	t.Helper()
	var st state
	if err := d.Store.GetJSON(moduleID, &st); err != nil {
		t.Fatal(err)
	}
	i := indexByID(st.Lists, id)
	if i < 0 {
		t.Fatalf("list %s gone", id)
	}
	return st.Lists[i]
}

func TestRefreshTracksNewCategories(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 group-title=\"News\",A\nhttp://s/a\n#EXTINF:-1 group-title=\"Sports\",B\nhttp://s/b\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", RefreshHours: 12})
	due := map[string]time.Time{}

	// Refresh 1 = baseline: News + Sports become "seen", nothing is "new".
	tick(m, d, due, time.Unix(1000, 0))
	l := readList(t, d, "l1")
	if len(l.SeenCategories) != 2 || len(l.NewCategories) != 0 {
		t.Fatalf("baseline: seen=%v new=%v, want 2 seen / 0 new", l.SeenCategories, l.NewCategories)
	}

	// Upstream now adds a "Kids" category; the next refresh flags it as new (but not News/Sports).
	rt.countries["us"] += "#EXTINF:-1 group-title=\"Kids\",C\nhttp://s/c\n"
	tick(m, d, due, time.Unix(1000, 0).Add(13*time.Hour))
	l = readList(t, d, "l1")
	if len(l.NewCategories) != 1 || l.NewCategories[0] != "Kids" {
		t.Fatalf("new categories = %v, want [Kids]", l.NewCategories)
	}
	if len(l.SeenCategories) != 3 {
		t.Fatalf("seen after 2nd refresh = %v, want 3 (News/Sports/Kids)", l.SeenCategories)
	}
}

func TestRecordCategoriesStrictNew(t *testing.T) {
	// strict_new ON: a newly-appeared category is queued AND held (auto-excluded).
	l := &List{SeenCategories: []string{"News"}, StrictNew: true}
	recordCategories(l, []string{"News", "Kids"})
	if len(l.NewCategories) != 1 || l.NewCategories[0] != "Kids" {
		t.Fatalf("new = %v, want [Kids]", l.NewCategories)
	}
	if len(l.ExcludeCategories) != 1 || l.ExcludeCategories[0] != "Kids" {
		t.Fatalf("strict_new must hold Kids in exclude, got %v", l.ExcludeCategories)
	}

	// strict_new OFF: the new category flows in (queued but NOT excluded).
	l2 := &List{SeenCategories: []string{"News"}}
	recordCategories(l2, []string{"News", "Kids"})
	if len(l2.NewCategories) != 1 || len(l2.ExcludeCategories) != 0 {
		t.Fatalf("strict off: new=%v exclude=%v, want [Kids]/none", l2.NewCategories, l2.ExcludeCategories)
	}
}

func TestRecordCategoriesExcludedNotNew(t *testing.T) {
	// A category the user has already EXCLUDED must not resurface as "new" when it appears upstream.
	l := &List{SeenCategories: []string{"News"}, ExcludeCategories: []string{"Shop"}}
	recordCategories(l, []string{"News", "Shop", "Kids"})
	// News already seen; Shop excluded → not new; Kids is genuinely new.
	if len(l.NewCategories) != 1 || l.NewCategories[0] != "Kids" {
		t.Fatalf("new = %v, want [Kids] (Shop excluded, News seen)", l.NewCategories)
	}
}

func TestRefreshStrictNewHoldsSameBuild(t *testing.T) {
	has := func(ss []string, v string) bool {
		for _, s := range ss {
			if s == v {
				return true
			}
		}
		return false
	}
	enabled := true
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1 group-title=\"News\",A\nhttp://s/a\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	// strict_new ON, baseline already saw "News" (so it isn't "new").
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", StrictNew: true, SeenCategories: []string{"News"}})
	// Upstream adds a NEW "Kids" category → must be HELD out of the SAME build's playlist, not one refresh later.
	rt.countries["us"] += "#EXTINF:-1 group-title=\"Kids\",K\nhttp://s/kids\n"
	tick(m, d, map[string]time.Time{}, time.Unix(1000, 0))
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	if strings.Contains(string(out), "s/kids") {
		t.Fatal("strict_new: a newly-appeared category must be held out of the SAME build it first appears in")
	}
	if !strings.Contains(string(out), "s/a") {
		t.Fatal("an already-seen category (News) must still be served")
	}
	l := readList(t, d, "l1")
	if !has(l.ExcludeCategories, "Kids") || !has(l.NewCategories, "Kids") {
		t.Fatalf("Kids must be held (excluded) + queued for review: excl=%v new=%v", l.ExcludeCategories, l.NewCategories)
	}
}

func TestRefreshPinnedCategoriesLead(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 group-title=\"Arts\",A\nhttp://s/arts\n" +
			"#EXTINF:-1 group-title=\"Sports\",S\nhttp://s/sports\n" +
			"#EXTINF:-1 group-title=\"News\",N\nhttp://s/news\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", PinnedCategories: []string{"Sports"}})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	out, _ := os.ReadFile(m.playlistPath(d, "t"))
	body := string(out)
	// Sports (pinned) must appear before Arts and News in the served M3U.
	if idx := strings.Index(body, "s/sports"); idx < 0 || idx > strings.Index(body, "s/arts") || idx > strings.Index(body, "s/news") {
		t.Fatalf("pinned Sports must lead the playlist:\n%s", body)
	}
}

func TestRefreshDemoNoop(t *testing.T) {
	fs, err := featurestore.Open(filepath.Join(t.TempDir(), "features.json"))
	if err != nil {
		t.Fatal(err)
	}
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,C\nhttp://s/1\n"}}
	client := &http.Client{Transport: rt}
	d := &feature.Deps{
		Cfg: func() config.Config {
			return config.Config{Demo: true, Features: map[string]config.FeatureConfig{moduleID: {Enabled: true}}}
		},
		Fetch:   func() *http.Client { return client },
		Store:   fs,
		DataDir: t.TempDir(),
	}
	m := &module{}
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	m.refreshTick(context.Background(), d, map[string]time.Time{}, time.Unix(1, 0))
	if _, err := os.Stat(m.playlistPath(d, "t")); err == nil {
		t.Fatal("demo mode must not refresh (no network calls)")
	}
}

func TestRefreshDisabledNoop(t *testing.T) {
	enabled := false
	rt := &fakeRT{countries: map[string]string{"us": "#EXTINF:-1,C\nhttp://s/1\n"}}
	m, d := refreshSetup(t, &enabled, rt)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t"})
	tick(m, d, map[string]time.Time{}, time.Unix(1, 0))
	if _, err := os.Stat(m.playlistPath(d, "t")); err == nil {
		t.Fatal("disabled plugin must not refresh")
	}
}
