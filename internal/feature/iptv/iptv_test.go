package iptv

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"

	"wayhop/internal/config"
	"wayhop/internal/feature"
	"wayhop/internal/featurestore"
)

// testDeps builds a module + a mux wired to a temp featurestore. enabled is a pointer so a test can
// flip the install state to exercise the gate. The store file path is returned so a test can reopen
// it and assert on-disk persistence.
func testDeps(t *testing.T, enabled *bool) (*http.ServeMux, *feature.Deps, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "features.json")
	fs, err := featurestore.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	d := &feature.Deps{
		Cfg: func() config.Config {
			return config.Config{Features: map[string]config.FeatureConfig{moduleID: {Enabled: *enabled}}}
		},
		Store:   fs,
		DataDir: t.TempDir(),
		QR:      func(text string, size int) ([]byte, error) { return qrcode.Encode(text, qrcode.Medium, size) },
	}
	mux := http.NewServeMux()
	(&module{}).Routes(mux, d)
	return mux, d, path
}

func do(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPauseEndpoint(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	rec := do(t, mux, "POST", "/api/iptv/lists", `{"countries":["ru"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body)
	}
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if l.Paused {
		t.Fatal("a new list must not be paused")
	}
	// Pause.
	rec = do(t, mux, "POST", "/api/iptv/lists/"+l.ID+"/pause", `{"paused":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("pause = %d (%s)", rec.Code, rec.Body)
	}
	var got List
	if json.Unmarshal(rec.Body.Bytes(), &got); !got.Paused {
		t.Fatal("list must report paused after pause")
	}
	// Resume, and confirm token/curation are untouched (the whole point — no new token).
	rec = do(t, mux, "POST", "/api/iptv/lists/"+l.ID+"/pause", `{"paused":false}`)
	got = List{} // reset — "paused":false is omitted by omitempty, so a stale true would survive unmarshal
	if rec.Code != http.StatusOK {
		t.Fatalf("resume = %d (%s)", rec.Code, rec.Body)
	}
	if json.Unmarshal(rec.Body.Bytes(), &got); got.Paused || got.Token != l.Token {
		t.Fatalf("resume must clear paused and keep the token: %+v (orig token %s)", got, l.Token)
	}
	if rec := do(t, mux, "POST", "/api/iptv/lists/nope/pause", `{"paused":true}`); rec.Code != http.StatusNotFound {
		t.Fatalf("pause unknown id = %d, want 404", rec.Code)
	}
}

// TestReviewCapsExcludeCategories: the review route must not grow ExcludeCategories past the
// maxCategories cap create/update enforce (a client POSTing large all-distinct cut arrays can't bloat
// the persisted store).
func TestReviewCapsExcludeCategories(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	rec := do(t, mux, "POST", "/api/iptv/lists", `{"countries":["ru"]}`)
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	cuts := make([]string, 500)
	for i := range cuts {
		cuts[i] = "cat" + strconv.Itoa(i)
	}
	body, _ := json.Marshal(map[string][]string{"cut": cuts})
	if rec := do(t, mux, "POST", "/api/iptv/lists/"+l.ID+"/review", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("review = %d (%s)", rec.Code, rec.Body)
	}
	var st state
	if err := d.Store.GetJSON(moduleID, &st); err != nil {
		t.Fatal(err)
	}
	if n := len(st.Lists[indexByID(st.Lists, l.ID)].ExcludeCategories); n > 200 {
		t.Fatalf("ExcludeCategories not capped by review: %d (want <=200)", n)
	}
}

func TestGateBlocksWhenDisabled(t *testing.T) {
	enabled := false
	mux, _, _ := testDeps(t, &enabled)
	if rec := do(t, mux, "GET", "/api/iptv/catalog", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled catalog = %d, want 404", rec.Code)
	}
	enabled = true
	if rec := do(t, mux, "GET", "/api/iptv/catalog", ""); rec.Code != http.StatusOK {
		t.Fatalf("enabled catalog = %d, want 200", rec.Code)
	}
}

func TestCatalogEndpoint(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	rec := do(t, mux, "GET", "/api/iptv/catalog", "")
	var cat []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cat) < 100 {
		t.Fatalf("catalog too small: %d", len(cat))
	}
}

func TestListCRUD(t *testing.T) {
	enabled := true
	mux, _, storePath := testDeps(t, &enabled)

	// Create.
	rec := do(t, mux, "POST", "/api/iptv/lists", `{"countries":["ru","US","ru"],"probe":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body)
	}
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if l.ID == "" || l.Token == "" {
		t.Fatal("create must assign ID + token")
	}
	if len(l.Countries) != 2 || l.Countries[0] != "ru" || l.Countries[1] != "us" {
		t.Fatalf("countries not deduped/lowercased: %v", l.Countries)
	}
	if l.Adult {
		t.Fatal("adult must default OFF")
	}
	if l.Name == "" {
		t.Fatal("empty name should default from country names")
	}

	// List shows it.
	rec = do(t, mux, "GET", "/api/iptv/lists", "")
	var ls []List
	_ = json.Unmarshal(rec.Body.Bytes(), &ls)
	if len(ls) != 1 || ls[0].ID != l.ID {
		t.Fatalf("list after create = %v", ls)
	}

	// Update preserves ID + token, changes fields.
	rec = do(t, mux, "PUT", "/api/iptv/lists/"+l.ID, `{"name":"My TV","countries":["gb"],"adult":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d (%s)", rec.Code, rec.Body)
	}
	var u List
	_ = json.Unmarshal(rec.Body.Bytes(), &u)
	if u.ID != l.ID || u.Token != l.Token {
		t.Fatal("update must preserve ID + token")
	}
	if u.Name != "My TV" || len(u.Countries) != 1 || u.Countries[0] != "gb" || !u.Adult {
		t.Fatalf("update did not apply: %+v", u)
	}

	// Persistence: a fresh store reading the same file sees the list.
	fs2, err := featurestore.Open(storePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	var st state
	if err := fs2.GetJSON(moduleID, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Lists) != 1 || st.Lists[0].Name != "My TV" {
		t.Fatalf("persisted state wrong: %+v", st)
	}

	// Delete.
	rec = do(t, mux, "DELETE", "/api/iptv/lists/"+l.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	rec = do(t, mux, "GET", "/api/iptv/lists", "")
	if !bytes.Contains(rec.Body.Bytes(), []byte("[]")) && rec.Body.Len() > 4 {
		t.Fatalf("list not empty after delete: %s", rec.Body)
	}
}

func TestCreateValidation(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	cases := []string{
		`{"countries":[]}`,                  // none
		`{"countries":["zz"]}`,              // unknown code
		`{"countries":["us/../evil"]}`,      // injection
		`{"countries":["ru"` + "\x00" + `}`, // malformed JSON
	}
	for _, body := range cases {
		if rec := do(t, mux, "POST", "/api/iptv/lists", body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %q => %d, want 400", body, rec.Code)
		}
	}
}

func TestUpdateDeleteUnknown(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	if rec := do(t, mux, "PUT", "/api/iptv/lists/nope", `{"countries":["us"]}`); rec.Code != http.StatusNotFound {
		t.Errorf("update unknown = %d, want 404", rec.Code)
	}
	if rec := do(t, mux, "DELETE", "/api/iptv/lists/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete unknown = %d, want 404", rec.Code)
	}
}

// seedList creates one list and returns it (so serve tests have a token + DataDir to work with).
func seedList(t *testing.T, mux *http.ServeMux, body string) List {
	t.Helper()
	rec := do(t, mux, "POST", "/api/iptv/lists", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed create = %d (%s)", rec.Code, rec.Body)
	}
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestServePlaylist(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	l := seedList(t, mux, `{"countries":["us"]}`)
	servePath := "/api/iptv/" + l.Token + "/tv.m3u"

	// Before any refresh, the file is absent → empty-but-valid #EXTM3U (player import won't fail).
	rec := do(t, mux, "GET", servePath, "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "#EXTM3U") {
		t.Fatalf("pre-refresh serve = %d %q", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "mpegurl") {
		t.Fatalf("Content-Type = %q, want an m3u type", ct)
	}

	// Write the file the I8 refresh would produce; serve streams it back verbatim.
	m := &module{}
	path := m.playlistPath(d, l.Token)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	want := "#EXTM3U\n#EXTINF:-1,Chan\nhttp://s/1\n"
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = do(t, mux, "GET", servePath, "")
	if rec.Body.String() != want {
		t.Fatalf("serve body = %q, want %q", rec.Body, want)
	}
}

func TestServeTokenGate(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	seedList(t, mux, `{"countries":["us"]}`)
	if rec := do(t, mux, "GET", "/api/iptv/deadbeefdeadbeef/tv.m3u", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token = %d, want 403", rec.Code)
	}
}

func TestServeLandingForBrowser(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	l := seedList(t, mux, `{"countries":["ru","ua"]}`)
	req := httptest.NewRequest("GET", "/api/iptv/"+l.Token+"/tv.m3u", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (browser)")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("landing = %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	body := rec.Body.String()
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("landing Content-Type = %q", ct)
	}
	for _, must := range []string{l.Token, "iptv-org", "does not host", "data:image/png;base64,", "/subcopy.js"} {
		if !strings.Contains(body, must) {
			t.Errorf("landing missing %q", must)
		}
	}
	// ?raw=1 forces the playlist even for a browser UA.
	req2 := httptest.NewRequest("GET", "/api/iptv/"+l.Token+"/tv.m3u?raw=1", nil)
	req2.Header.Set("Accept", "text/html")
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if !strings.HasPrefix(rec2.Body.String(), "#EXTM3U") {
		t.Fatalf("?raw=1 should force the playlist, got %q", rec2.Body)
	}
}

func TestServeGatedWhenDisabled(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	l := seedList(t, mux, `{"countries":["us"]}`)
	enabled = false
	if rec := do(t, mux, "GET", "/api/iptv/"+l.Token+"/tv.m3u", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled serve = %d, want 404", rec.Code)
	}
}

func TestExitsEndpoint(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	d.Endpoints = func() []feature.EndpointMeta {
		return []feature.EndpointMeta{
			{ID: "e1", Name: "🇷🇺 Moscow", Server: "ru1.vps.net"},
			{ID: "e2", Name: "NL exit", Server: "nl-ams.vps.net"},
			{ID: "e3", Name: "mystery box", Server: "1.2.3.4"}, // uninferable
		}
	}
	rec := do(t, mux, "GET", "/api/iptv/exits", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("exits = %d", rec.Code)
	}
	var rows []exitRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0].Country != "ru" || rows[0].Flag == "" || rows[0].CountryName != "Russia" {
		t.Errorf("row0 (RU flag) = %+v", rows[0])
	}
	if rows[1].Country != "nl" {
		t.Errorf("row1 (NL code) = %+v", rows[1])
	}
	if rows[2].Country != "" {
		t.Errorf("row2 should be uninferable, got %+v", rows[2])
	}
}

func TestExitsNilEndpoints(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	d.Endpoints = nil // no accessor wired — must not panic, returns []
	rec := do(t, mux, "GET", "/api/iptv/exits", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("nil endpoints: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestPreviewCategories(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 group-title=\"News\",A\nhttp://s/a\n" +
			"#EXTINF:-1 group-title=\"News\",B\nhttp://s/b\n" +
			"#EXTINF:-1 group-title=\"Sports\",C\nhttp://s/c\n" +
			"#EXTINF:-1 group-title=\"XXX\",Adult\nhttp://s/x\n", // adult → filtered when adult=false
	}}
	m, d := refreshSetup(t, &enabled, rt)
	mux := http.NewServeMux()
	m.Routes(mux, d)

	req := httptest.NewRequest("POST", "/api/iptv/preview", strings.NewReader(`{"countries":["us"],"adult":false}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d (%s)", rec.Code, rec.Body)
	}
	var pr previewResult
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Total != 3 { // adult dropped
		t.Fatalf("total = %d, want 3", pr.Total)
	}
	if len(pr.Categories) != 2 || pr.Categories[0].Name != "News" || pr.Categories[0].Count != 2 {
		t.Fatalf("categories = %+v, want News(2) first then Sports(1)", pr.Categories)
	}
	// Unknown country → 400 (allowlist enforced at the preview boundary too).
	req2 := httptest.NewRequest("POST", "/api/iptv/preview", strings.NewReader(`{"countries":["zz"]}`))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("preview unknown country = %d, want 400", rec2.Code)
	}
}

func TestPreviewChannelsDrillDown(t *testing.T) {
	enabled := true
	rt := &fakeRT{countries: map[string]string{
		"us": "#EXTINF:-1 tvg-id=\"cnn.us\" group-title=\"News\",CNN\nhttp://s/cnn\n" +
			"#EXTINF:-1 tvg-id=\"fox.us\" group-title=\"News\",Fox News\nhttp://s/fox\n" +
			"#EXTINF:-1 tvg-id=\"abc.us\" group-title=\"News\",ABC News\nhttp://s/abc\n" +
			"#EXTINF:-1 group-title=\"Sports\",ESPN\nhttp://s/espn\n",
	}}
	m, d := refreshSetup(t, &enabled, rt)
	mux := http.NewServeMux()
	m.Routes(mux, d)
	post := func(body string) previewChannelsResult {
		req := httptest.NewRequest("POST", "/api/iptv/preview/channels", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("preview/channels = %d (%s)", rec.Code, rec.Body)
		}
		var pr previewChannelsResult
		if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
			t.Fatal(err)
		}
		return pr
	}

	// Category filter: only the 3 News channels.
	news := post(`{"countries":["us"],"category":"news"}`) // case-insensitive
	if news.Total != 3 || len(news.Items) != 3 {
		t.Fatalf("News drill-down total=%d items=%d, want 3/3", news.Total, len(news.Items))
	}
	if news.Items[0].TvgID == "" || news.Items[0].Group != "News" {
		t.Fatalf("channel row missing identity: %+v", news.Items[0])
	}
	// Search within category.
	cnn := post(`{"countries":["us"],"category":"News","q":"cnn"}`)
	if cnn.Total != 1 || cnn.Items[0].Name != "CNN" {
		t.Fatalf("search q=cnn => %+v", cnn)
	}
	// Pagination: limit 2 then offset 2.
	p1 := post(`{"countries":["us"],"category":"News","limit":2,"offset":0}`)
	p2 := post(`{"countries":["us"],"category":"News","limit":2,"offset":2}`)
	if len(p1.Items) != 2 || len(p2.Items) != 1 || p2.Total != 3 {
		t.Fatalf("pagination p1=%d p2=%d total=%d, want 2/1/3", len(p1.Items), len(p2.Items), p2.Total)
	}
	if p1.Items[0].Name == p2.Items[0].Name {
		t.Fatal("pages overlap — offset not applied")
	}
}

func TestCustomSourceValidation(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	// A URL-only list (no countries) is valid.
	if rec := do(t, mux, "POST", "/api/iptv/lists", `{"source_urls":["http://prov.test/a.m3u"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("URL-only create = %d (%s), want 201", rec.Code, rec.Body)
	}
	bad := []string{
		`{}`,                                     // neither country nor URL → 400
		`{"countries":[],"source_urls":[]}`,      // both empty → 400
		`{"source_urls":["ftp://x/a.m3u"]}`,      // non-http scheme → 400
		`{"source_urls":["not a url"]}`,          // no scheme/host → 400
		`{"source_urls":["http:///nohost.m3u"]}`, // missing host → 400
	}
	for _, body := range bad {
		if rec := do(t, mux, "POST", "/api/iptv/lists", body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %q => %d, want 400", body, rec.Code)
		}
	}
}

func TestPreviewHealth(t *testing.T) {
	enabled := true
	rt := &fakeRT{
		countries: map[string]string{
			"us": "#EXTINF:-1 tvg-id=\"a\" group-title=\"News\",Alive One\nhttp://stream/ok/a\n" +
				"#EXTINF:-1 tvg-id=\"b\" group-title=\"News\",Dead One\nhttp://stream/dead/b\n",
		},
		streamCode: func(u string) int {
			if strings.Contains(u, "/ok") {
				return http.StatusOK
			}
			return http.StatusInternalServerError
		},
	}
	m, d := refreshSetup(t, &enabled, rt)
	mux := http.NewServeMux()
	m.Routes(mux, d)

	req := httptest.NewRequest("POST", "/api/iptv/preview/health", strings.NewReader(`{"countries":["us"],"category":"News"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview/health = %d (%s)", rec.Code, rec.Body)
	}
	var pr previewChannelsResult
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Total != 2 || len(pr.Items) != 2 {
		t.Fatalf("health total=%d items=%d, want 2/2", pr.Total, len(pr.Items))
	}
	byName := map[string]string{}
	for _, it := range pr.Items {
		byName[it.Name] = it.Status
	}
	if byName["Alive One"] != "alive" || byName["Dead One"] != "dead" {
		t.Fatalf("per-channel status wrong: %+v", byName)
	}
}

func TestReviewEndpoint(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t",
		NewCategories: []string{"Kids", "Shop"}, SeenCategories: []string{"News", "Kids", "Shop"}})

	// GET → the two pending categories.
	rec := do(t, mux, "GET", "/api/iptv/lists/l1/review", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("review GET = %d", rec.Code)
	}
	var got struct {
		Categories []string `json:"categories"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Categories) != 2 {
		t.Fatalf("pending = %v, want 2", got.Categories)
	}

	// Resolve: keep Kids, cut Shop.
	rec = do(t, mux, "POST", "/api/iptv/lists/l1/review", `{"keep":["Kids"],"cut":["Shop"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("review POST = %d (%s)", rec.Code, rec.Body)
	}
	l := readList(t, d, "l1")
	if len(l.NewCategories) != 0 {
		t.Fatalf("NewCategories after resolve = %v, want empty", l.NewCategories)
	}
	if len(l.ExcludeCategories) != 1 || l.ExcludeCategories[0] != "Shop" {
		t.Fatalf("ExcludeCategories = %v, want [Shop] (cut), Kids kept-not-excluded", l.ExcludeCategories)
	}

	// Unknown id → 404.
	if rec := do(t, mux, "GET", "/api/iptv/lists/nope/review", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("review GET unknown = %d, want 404", rec.Code)
	}
}

func TestReviewKeepUnexcludes(t *testing.T) {
	// A strict_new-held category (in both new + exclude); keeping it via review must un-exclude it.
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	seed(t, d, List{ID: "l1", Countries: []string{"us"}, Token: "t", StrictNew: true,
		NewCategories: []string{"Kids"}, ExcludeCategories: []string{"Kids"}})
	rec := do(t, mux, "POST", "/api/iptv/lists/l1/review", `{"keep":["Kids"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("review keep = %d", rec.Code)
	}
	l := readList(t, d, "l1")
	if len(l.NewCategories) != 0 || len(l.ExcludeCategories) != 0 {
		t.Fatalf("keep must clear pending AND un-exclude: new=%v exclude=%v", l.NewCategories, l.ExcludeCategories)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	enabled := true
	mux, d, _ := testDeps(t, &enabled)
	seed(t, d, List{ID: "l1", Name: "Curated", Countries: []string{"us", "gb"}, Token: "tok",
		Adult: true, StrictNew: true, ExcludeCategories: []string{"Shop"}, ChannelInclude: []string{"cnn.us"},
		Blocklist: []string{"x.tv"}, RefreshHours: 24})

	// Export.
	rec := do(t, mux, "GET", "/api/iptv/lists/l1/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	blob := rec.Body.Bytes()
	// Instance-specific fields must NOT be exported.
	if bytes.Contains(blob, []byte("tok")) || bytes.Contains(blob, []byte("seen_categories")) {
		t.Fatalf("export leaked instance state: %s", blob)
	}

	// Re-import the blob verbatim via POST /lists → a fresh list with the same curation.
	rec = do(t, mux, "POST", "/api/iptv/lists", string(blob))
	if rec.Code != http.StatusCreated {
		t.Fatalf("import = %d (%s)", rec.Code, rec.Body)
	}
	var imported List
	_ = json.Unmarshal(rec.Body.Bytes(), &imported)
	if imported.ID == "l1" || imported.Token == "tok" {
		t.Fatal("import must mint a fresh ID + token, not reuse the exported list's")
	}
	if imported.Name != "Curated" || len(imported.Countries) != 2 || !imported.Adult || !imported.StrictNew ||
		len(imported.ExcludeCategories) != 1 || imported.ExcludeCategories[0] != "Shop" ||
		len(imported.ChannelInclude) != 1 || imported.RefreshHours != 24 {
		t.Fatalf("round-trip lost curation: %+v", imported)
	}
	// Unknown id → 404.
	if rec := do(t, mux, "GET", "/api/iptv/lists/nope/export", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("export unknown = %d, want 404", rec.Code)
	}
}

func TestModuleRegistered(t *testing.T) {
	found := false
	for _, m := range feature.All() {
		if m.Descriptor().ID == moduleID {
			found = true
		}
	}
	if !found {
		t.Fatal("iptv module did not self-register via init()")
	}
}
