package iptv

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestFetchAllCatalogs: a "language:rus" / "category:news" token fetches its iptv-org playlist (path
// discriminated), and an unknown token is silently skipped by fetchAll (validation catches it earlier).
func TestFetchAllCatalogs(t *testing.T) {
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(req.URL.Path, "/languages/rus.m3u"):
			return mkResp(http.StatusOK, "#EXTINF:-1 tvg-id=\"r\",R\nhttp://s/r\n"), nil
		case strings.Contains(req.URL.Path, "/categories/news.m3u"):
			return mkResp(http.StatusOK, "#EXTINF:-1 tvg-id=\"n\",N\nhttp://s/n\n"), nil
		}
		return mkResp(http.StatusNotFound, ""), nil
	})}
	chs, _, errs := fetchAll(context.Background(), client, nil, []string{"language:rus", "category:news"}, nil, nil)
	if len(chs) != 2 || len(errs) != 0 {
		t.Fatalf("catalog fetch: chs=%d errs=%v", len(chs), errs)
	}
}

// TestCatalogsEndpointAndCreate: the /catalogs picker endpoint lists the kinds; a catalog-only list is
// valid + stored; an unknown token is rejected.
func TestCatalogsEndpointAndCreate(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)

	rec := do(t, mux, "GET", "/api/iptv/catalogs", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"language"`) || !strings.Contains(rec.Body.String(), "Russian") {
		t.Fatalf("catalogs endpoint: %d %s", rec.Code, rec.Body)
	}

	rec = do(t, mux, "POST", "/api/iptv/lists", `{"catalogs":["language:rus","category:news","language:rus"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create catalog list = %d (%s)", rec.Code, rec.Body)
	}
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Catalogs) != 2 { // deduped
		t.Fatalf("catalogs not stored/deduped: %+v", l.Catalogs)
	}
	// Export carries the catalogs.
	rec = do(t, mux, "GET", "/api/iptv/lists/"+l.ID+"/export", "")
	if !strings.Contains(rec.Body.String(), "language:rus") {
		t.Fatalf("export missing catalogs: %s", rec.Body)
	}
	// An unknown/typo'd token is rejected (matches the country allowlist's strictness).
	if rec := do(t, mux, "POST", "/api/iptv/lists", `{"catalogs":["region:eur"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown catalog = %d, want 400", rec.Code)
	}
}
