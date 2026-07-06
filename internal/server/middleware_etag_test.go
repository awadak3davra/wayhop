package server

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestComputeUIETag: every embedded asset (name + content) folds into the ETag, so editing a file that
// a hardcoded list used to omit (iptv-i18n.js, subcopy.js) now busts the browser cache instead of
// returning a stale 304.
func TestComputeUIETag(t *testing.T) {
	base := fstest.MapFS{
		"index.html":   {Data: []byte("<html>")},
		"app.js":       {Data: []byte("app")},
		"i18n.js":      {Data: []byte("core-i18n")},
		"iptv-i18n.js": {Data: []byte("iptv-i18n")},
		"subcopy.js":   {Data: []byte("sub")},
		"styles.css":   {Data: []byte("css")},
	}
	e1 := computeUIETag(base)
	if !strings.HasPrefix(e1, `W/"wr-`) {
		t.Fatalf("unexpected etag format: %q", e1)
	}
	if computeUIETag(base) != e1 {
		t.Fatal("etag must be deterministic for identical input")
	}
	// Editing ANY asset — including the ones the old hardcoded list omitted — must change the ETag.
	for _, f := range []string{"iptv-i18n.js", "subcopy.js", "app.js", "index.html", "i18n.js", "styles.css"} {
		m := fstest.MapFS{}
		for k, v := range base {
			m[k] = v
		}
		m[f] = &fstest.MapFile{Data: []byte("CHANGED")}
		if computeUIETag(m) == e1 {
			t.Fatalf("ETag must change when %s changes (stale-cache bug)", f)
		}
	}
	// Adding a brand-new asset also busts it (so a future file can't be silently omitted).
	added := fstest.MapFS{}
	for k, v := range base {
		added[k] = v
	}
	added["new-widget.js"] = &fstest.MapFile{Data: []byte("new")}
	if computeUIETag(added) == e1 {
		t.Fatal("ETag must change when a new asset is added")
	}
}
