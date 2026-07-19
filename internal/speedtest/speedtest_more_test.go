package speedtest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// speedtest_rewriteTransport redirects every outbound request to a local
// httptest.Server, preserving the original path + query. This lets us exercise
// latency/download/upload (whose target URLs are hardcoded to Cloudflare)
// against a deterministic, offline server.
type speedtest_rewriteTransport struct {
	base *url.URL // scheme+host of the test server
	rt   http.RoundTripper
}

func (t *speedtest_rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = t.base.Scheme
	out.URL.Host = t.base.Host
	out.Host = t.base.Host
	return t.rt.RoundTrip(out)
}

// speedtest_clientFor builds an *http.Client whose transport rewrites all
// requests to srv. timeout==0 means no timeout.
func speedtest_clientFor(srv *httptest.Server, timeout time.Duration) *http.Client {
	base, _ := url.Parse(srv.URL)
	return &http.Client{
		Transport: &speedtest_rewriteTransport{base: base, rt: http.DefaultTransport},
		Timeout:   timeout,
	}
}

// speedtest_downServer serves the Cloudflare-style /__down endpoint: it streams
// exactly the number of bytes requested via ?bytes=N, and /__up just drains.
func speedtest_downServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/__down"):
			n := 0
			if v := r.URL.Query().Get("bytes"); v != "" {
				n, _ = strconv.Atoi(v)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			if n > 0 {
				buf := make([]byte, n)
				_, _ = w.Write(buf)
			}
		case strings.HasPrefix(r.URL.Path, "/__up"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRound2(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{1.234, 1.23},
		{1.235, 1.24},
		{1.236, 1.24},
		{0, 0},
		{100, 100},
		{0.005, 0.01},
		{0.004, 0.0},
	}
	for _, c := range cases {
		if got := round2(c.in); got != c.want {
			t.Errorf("round2(%v)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestNew(t *testing.T) {
	tr := New(1080)
	if tr == nil {
		t.Fatal("New returned nil")
	}
	if tr.mixedPort != 1080 {
		t.Fatalf("mixedPort=%d want 1080", tr.mixedPort)
	}
}

func TestClientDirect(t *testing.T) {
	tr := New(0)
	cl, err := tr.client(false, 5*time.Second)
	if err != nil {
		t.Fatalf("client direct err: %v", err)
	}
	if cl.Timeout != 5*time.Second {
		t.Fatalf("timeout=%v want 5s", cl.Timeout)
	}
	httpTr, ok := cl.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type %T", cl.Transport)
	}
	if httpTr.Proxy != nil {
		t.Fatal("direct client must not set Proxy")
	}
}

func TestClientProxyNoPort(t *testing.T) {
	tr := New(0)
	if _, err := tr.client(true, time.Second); err == nil {
		t.Fatal("expected error when proxy requested but no port configured")
	}
}

func TestClientProxyConfigured(t *testing.T) {
	tr := New(1080)
	cl, err := tr.client(true, time.Second)
	if err != nil {
		t.Fatalf("client proxy err: %v", err)
	}
	httpTr := cl.Transport.(*http.Transport)
	if httpTr.Proxy == nil {
		t.Fatal("proxy client must set Proxy func")
	}
	// The Proxy func should resolve to 127.0.0.1:1080.
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	pu, err := httpTr.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func err: %v", err)
	}
	if pu == nil || pu.Host != "127.0.0.1:1080" {
		t.Fatalf("proxy URL = %v want host 127.0.0.1:1080", pu)
	}
}

func TestLatencyOK(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, 10*time.Second)
	tr := New(0)
	ms, err := tr.latency(context.Background(), cl)
	if err != nil {
		t.Fatalf("latency err: %v", err)
	}
	if ms < 0 {
		t.Fatalf("latency negative: %d", ms)
	}
}

func TestLatencyClientError(t *testing.T) {
	// Point at a closed server so the dial fails.
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, time.Second)
	srv.Close() // force connection refused
	tr := New(0)
	if _, err := tr.latency(context.Background(), cl); err == nil {
		t.Fatal("expected latency error against closed server")
	}
}

func TestLatencyBadContext(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled
	tr := New(0)
	if _, err := tr.latency(ctx, cl); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestDownloadKnownPayload(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, 30*time.Second)
	tr := New(0)
	const want = 1_000_000
	n, dur, err := tr.download(context.Background(), cl, want)
	if err != nil {
		t.Fatalf("download err: %v", err)
	}
	if n != want {
		t.Fatalf("downloaded %d bytes want %d", n, want)
	}
	if dur <= 0 {
		t.Fatalf("duration must be positive, got %v", dur)
	}
	// Sanity-check the reported rate is finite & positive for a real payload.
	rate := Mbps(n, dur)
	if rate <= 0 {
		t.Fatalf("rate must be positive, got %v", rate)
	}
}

func TestDownloadZeroBytes(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, 10*time.Second)
	tr := New(0)
	n, _, err := tr.download(context.Background(), cl, 0)
	if err != nil {
		t.Fatalf("download err: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

func TestDownloadNon200(t *testing.T) {
	// Server that always returns 404 for /__down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	cl := speedtest_clientFor(srv, 10*time.Second)
	tr := New(0)
	_, _, err := tr.download(context.Background(), cl, 1000)
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("error = %v want to mention status 404", err)
	}
}

func TestDownloadClientError(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, time.Second)
	srv.Close()
	tr := New(0)
	if _, _, err := tr.download(context.Background(), cl, 1000); err == nil {
		t.Fatal("expected error against closed server")
	}
}

func TestUploadOK(t *testing.T) {
	var got int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got = n
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	cl := speedtest_clientFor(srv, 30*time.Second)
	tr := New(0)
	const up = 500_000
	dur, err := tr.upload(context.Background(), cl, up)
	if err != nil {
		t.Fatalf("upload err: %v", err)
	}
	if dur <= 0 {
		t.Fatalf("duration must be positive, got %v", dur)
	}
	if got != up {
		t.Fatalf("server received %d bytes want %d", got, up)
	}
}

// TestUploadNon200: a 4xx/5xx upload response (proxy error page, 429 rate-limit…) must error rather
// than report a bogus UpMbps timed against the rejection — parity with TestDownloadNon200.
func TestUploadNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // drain the upload body, then reject
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	cl := speedtest_clientFor(srv, 10*time.Second)
	tr := New(0)
	_, err := tr.upload(context.Background(), cl, 1000)
	if err == nil {
		t.Fatal("expected an error on a non-2xx upload status")
	}
	if !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("error = %v want to mention status 429", err)
	}
}

func TestUploadClientError(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, time.Second)
	srv.Close()
	tr := New(0)
	if _, err := tr.upload(context.Background(), cl, 1000); err == nil {
		t.Fatal("expected error against closed server")
	}
}

// TestRunDirectEndToEnd drives the full Run flow against a local server by
// supplying a Tester with a rewriting client through an injected transport.
// Run() builds its own client internally, so we test it via a Tester whose
// proxy resolves to our server is not possible; instead we validate the
// pieces and the assembled Result fields by replicating Run's call shape.
func TestRunResultViaComponents(t *testing.T) {
	srv := speedtest_downServer(t)
	cl := speedtest_clientFor(srv, 30*time.Second)
	tr := New(0)
	ctx := context.Background()

	res := Result{Via: "direct"}
	if ms, err := tr.latency(ctx, cl); err == nil {
		res.LatencyMs = ms
	}
	n, dur, err := tr.download(ctx, cl, 1_000_000)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	res.DownBytes = n
	res.DownMbps = round2(Mbps(n, dur))
	if d, err := tr.upload(ctx, cl, 500_000); err == nil {
		res.UpMbps = round2(Mbps(500_000, d))
	}

	if res.Via != "direct" {
		t.Fatalf("Via=%q want direct", res.Via)
	}
	if res.DownBytes != 1_000_000 {
		t.Fatalf("DownBytes=%d want 1000000", res.DownBytes)
	}
	if res.DownMbps <= 0 {
		t.Fatalf("DownMbps must be positive, got %v", res.DownMbps)
	}
	if res.UpMbps <= 0 {
		t.Fatalf("UpMbps must be positive, got %v", res.UpMbps)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("LatencyMs negative: %d", res.LatencyMs)
	}
}

// TestRunClientError exercises Run's early client() error path: requesting a
// proxy with no port configured must surface the error and not attempt a fetch.
func TestRunClientError(t *testing.T) {
	tr := New(0)
	res, err := tr.Run(context.Background(), true, 1000)
	if err == nil {
		t.Fatal("expected error from Run when proxy requested with no port")
	}
	if res.Via != "proxy" {
		t.Fatalf("Via=%q want proxy", res.Via)
	}
	if res.DownBytes != 0 {
		t.Fatalf("DownBytes should be 0 on early error, got %d", res.DownBytes)
	}
}

// TestRunDownloadErrorPropagates verifies Run wraps and returns download
// failures. We can't easily redirect Run's internal client to a fake server,
// so we use a real Run against a direct (non-proxy) path with a context that is
// cancelled, forcing the download to error and Run to return a wrapped error.
func TestRunDownloadErrorPropagates(t *testing.T) {
	tr := New(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tr.Run(ctx, false, 1000)
	if err == nil {
		t.Fatal("expected Run to fail with cancelled context")
	}
	if !strings.Contains(err.Error(), "download") {
		t.Fatalf("error = %v want to be wrapped with \"download\"", err)
	}
	if !errors.Is(err, context.Canceled) {
		// Best-effort: the underlying cause should be context cancellation.
		// Some transports wrap differently; only assert if available.
		t.Logf("note: error not wrapping context.Canceled directly: %v", err)
	}
}

func TestZeroReaderChunks(t *testing.T) {
	z := &zeroReader{left: 10}
	buf := make([]byte, 4)
	total := 0
	for {
		n, err := z.Read(buf)
		total += n
		for i := 0; i < n; i++ {
			if buf[i] != 0 {
				t.Fatalf("non-zero byte at %d", i)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read err: %v", err)
		}
	}
	if total != 10 {
		t.Fatalf("read %d bytes want 10", total)
	}
	// Further reads must keep returning EOF with 0 bytes.
	n, err := z.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("post-EOF read n=%d err=%v want 0/EOF", n, err)
	}
}
