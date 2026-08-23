package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestDownloadNamesEveryPathItTried (L5): a failed download used to report only the LAST mirror.
//
// The shipped default list ends with https://mirror.ghproxy.com/, and that host no longer exists —
// it does not resolve from a live Keenetic (`nslookup: can't resolve`) or from the dev
// machine. Since download() returned lastErr, every failure on every router ended with
// "lookup mirror.ghproxy.com: no such host", whatever had actually gone wrong: measured on the demo,
// three paths were tried and the panel showed the third. The operator is then debugging the DNS of
// a mirror they never chose, while the failure that matters — the direct download — is not on screen.
func TestDownloadNamesEveryPathItTried(t *testing.T) {
	// Two servers with DIFFERENT failures, so a report that keeps only one is visibly incomplete.
	teapot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer teapot.Close()
	htmlPage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>blocked</title>"))
	}))
	defer htmlPage.Close()

	u := New(t.TempDir(), "amd64", []string{teapot.URL + "/", htmlPage.URL + "/"})
	_, err := u.download(context.Background(), "https://example.invalid/asset.tar.gz", 1<<20)
	if err == nil {
		t.Fatal("a download with no working path must fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "all 2 download paths failed") {
		t.Errorf("the report must say how many paths were tried, got %q", msg)
	}
	// Both distinct reasons have to survive: keeping one is the defect.
	if !strings.Contains(msg, "status 418") {
		t.Errorf("the first path's own failure is missing: %q", msg)
	}
	if !strings.Contains(msg, "HTML/error page") {
		t.Errorf("the second path's own failure is missing: %q", msg)
	}
	// Each reason must be attached to the path it belongs to, or the operator cannot tell which
	// mirror to stop using.
	if !strings.Contains(msg, teapot.URL) || !strings.Contains(msg, htmlPage.URL) {
		t.Errorf("every attempted path must be named: %q", msg)
	}
}

// TestDownloadNamesTheDirectPath (L5): "" is the direct download, and an error message that renders
// it as an empty string names nothing at all — on the default list it is the FIRST entry and the one
// whose failure usually explains the rest.
func TestDownloadNamesTheDirectPath(t *testing.T) {
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer gone.Close()

	u := New(t.TempDir(), "amd64", []string{"", gone.URL + "/"})
	_, err := u.download(context.Background(), gone.URL+"/asset.tar.gz", 1<<20)
	if err == nil {
		t.Fatal("both paths 404, so this must fail")
	}
	if !strings.Contains(err.Error(), "direct:") {
		t.Errorf("the direct download must be named as such, got %q", err.Error())
	}
}

// TestStreamAssetNamesEveryPathItTried (L5): the same claim for the loop an ENGINE INSTALL uses.
//
// download() serves small in-memory fetches; streamAssetToFile is what /api/updater/{id}/install
// goes through, and it had the same lastErr. Fixing only the first would have left the defect
// exactly where it was measured — the demo's sing-box install reporting mirror.ghproxy.com as the
// sole reason three paths failed.
func TestStreamAssetNamesEveryPathItTried(t *testing.T) {
	teapot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer teapot.Close()
	htmlPage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>blocked</title>"))
	}))
	defer htmlPage.Close()

	dir := t.TempDir()
	u := New(dir, "amd64", []string{teapot.URL + "/", htmlPage.URL + "/"})
	asset := Asset{Name: "sing-box-1.0.0-linux-amd64.tar.gz", URL: "https://example.invalid/a.tar.gz", Size: 1 << 10}
	err := u.streamAssetToFile(context.Background(), asset, "sing-box", filepath.Join(dir, "sing-box.new"), false)
	if err == nil {
		t.Fatal("no path can serve this asset, so the install must fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "all 2 download paths failed") {
		t.Errorf("the install failure must say how many paths were tried, got %q", msg)
	}
	if !strings.Contains(msg, "status 418") || !strings.Contains(msg, "HTML/error page") {
		t.Errorf("both distinct reasons must survive: %q", msg)
	}
}
