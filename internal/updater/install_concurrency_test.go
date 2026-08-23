package updater

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// concurrencyRT serves the release JSON, and for the asset it runs onAsset (which records
// how many downloads are in flight at once) while it holds the response open — so a test can
// prove two Installs never stream concurrently.
type concurrencyRT struct {
	relSuffix, assetSuffix string
	relJSON, asset         []byte
	onAsset                func()
}

func (rt *concurrencyRT) RoundTrip(req *http.Request) (*http.Response, error) {
	mk := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: req}, nil
	}
	u := req.URL.String()
	if strings.HasSuffix(u, rt.relSuffix) {
		return mk(http.StatusOK, rt.relJSON)
	}
	if strings.HasSuffix(u, rt.assetSuffix) {
		if rt.onAsset != nil {
			rt.onAsset()
		}
		return mk(http.StatusOK, rt.asset)
	}
	return mk(http.StatusNotFound, []byte("not found"))
}

// TestInstall_SerializedByMutex: two concurrent Install calls stage to the SAME <dst>.new path
// (opened O_TRUNC), so overlapping downloads would interleave into a corrupt binary that the
// per-stream SHA can't catch. The Updater mutex must serialize them — asserted by proving the
// asset download is never in flight from two goroutines at once. Remove the mutex and this fails.
func TestInstall_SerializedByMutex(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	payload := []byte("REAL-SINGBOX-BINARY-amd64-padding-to-take-a-beat-streaming")
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/sing-box-1.0.0-linux-amd64.tar.gz"
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, payload)
	assetSuffix := "/sing-box-1.0.0-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "sing-box-1.0.0-linux-amd64.tar.gz", URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})

	var cur, max int32
	rt := &concurrencyRT{
		relSuffix: "/releases/tags/" + tag, relJSON: rel,
		assetSuffix: assetSuffix, asset: tgz,
		onAsset: func() {
			n := atomic.AddInt32(&cur, 1)
			for {
				m := atomic.LoadInt32(&max)
				if n <= m || atomic.CompareAndSwapInt32(&max, m, n) {
					break
				}
			}
			time.Sleep(40 * time.Millisecond) // hold the "download" open; an unserialized peer would overlap here
			atomic.AddInt32(&cur, -1)
		},
	}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = u.Install(context.Background(), e, tag) }(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Install #%d failed: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&max); got != 1 {
		t.Errorf("max concurrent asset downloads = %d, want 1 — Install must be serialized (shared %s.new staging path)", got, e.BinName)
	}
}
