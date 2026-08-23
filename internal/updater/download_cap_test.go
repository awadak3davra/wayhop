package updater

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDlCap(t *testing.T) {
	if got := dlCap(0); got != 96<<20 {
		t.Errorf("dlCap(0)=%d want 96MiB fallback (unknown size)", got)
	}
	if got := dlCap(10 << 20); got != (10<<20)+(1<<20) {
		t.Errorf("dlCap(10MiB)=%d want size+1MiB margin", got)
	}
}

// TestDownloadCapsOversizedResponse proves a mirror that streams far more than the expected
// asset size can't blow past the cap into the router's RAM.
func TestDownloadCapsOversizedResponse(t *testing.T) {
	big := bytes.Repeat([]byte{0xAB}, 5<<20) // 5 MiB of non-HTML bytes
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer ts.Close()

	u := &Updater{BinDir: t.TempDir(), Arch: "amd64", Mirrors: []string{""}, hc: &http.Client{}}
	data, err := u.download(context.Background(), ts.URL, 1<<20) // cap 1 MiB
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if int64(len(data)) > 1<<20 {
		t.Errorf("download returned %d bytes, want <= 1 MiB cap (LimitReader not applied)", len(data))
	}
}
