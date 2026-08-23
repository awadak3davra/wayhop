package updater

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDownloadMirrorFailover: download tries each mirror in order and falls through a failing mirror
// (HTTP 500) AND a mirror that answers 200 with an HTML/captcha page (a censored-region interstitial),
// returning the first real binary asset. This locks the self-update resilience that keeps a single
// bad mirror from breaking updates / installing a captcha page as the "binary".
func TestDownloadMirrorFailover(t *testing.T) {
	m1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer m1.Close()
	m2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>are you human?</body></html>"))
	}))
	defer m2.Close()
	want := []byte{0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04} // gzip magic — clearly not HTML
	m3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(want)
	}))
	defer m3.Close()

	u := &Updater{BinDir: t.TempDir(), Arch: "amd64", Mirrors: []string{m1.URL, m2.URL, m3.URL}, hc: &http.Client{}}
	got, err := u.download(context.Background(), "https://example.com/asset.tar.gz", 1<<20)
	if err != nil {
		t.Fatalf("download should have fallen through to the good mirror: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("download returned %v, want the third mirror's bytes %v", got, want)
	}
}

// TestDownloadRejectsHTMLOnly: when every mirror serves an HTML page, download must fail rather than
// install the page as the binary.
func TestDownloadRejectsHTMLOnly(t *testing.T) {
	m := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>blocked</html>"))
	}))
	defer m.Close()
	u := &Updater{BinDir: t.TempDir(), Arch: "amd64", Mirrors: []string{m.URL}, hc: &http.Client{}}
	if _, err := u.download(context.Background(), "https://x/asset", 1<<20); err == nil {
		t.Error("download must reject an HTML-only response, not install a captcha/error page as the binary")
	}
}
