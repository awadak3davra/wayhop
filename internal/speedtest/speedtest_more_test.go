package speedtest

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
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

// A direct run dials through Direct when it is set (the server's redirect-bypassing dialer); a run
// through the proxy never does, since its only connection is to the local mixed inbound.
func TestClientDirectDialer(t *testing.T) {
	srv := speedtest_downServer(t)
	var dialed []string
	tr := New(1080)
	tr.Direct = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	cl, err := tr.client(false, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get(srv.URL + "/__down?bytes=10")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cl.CloseIdleConnections()
	if len(dialed) != 1 || dialed[0] != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("dialed %v", dialed)
	}
	pc, err := tr.client(true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Transport.(*http.Transport).DialContext != nil {
		t.Fatal("a run through the proxy used the direct dialer")
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
	// Deliberately NOT asserting dur > 0: a localhost transfer can complete inside the clock's
	// resolution, so requiring a positive duration made this test fail intermittently on Windows for
	// reasons that had nothing to do with the code under test. What must hold is that the reported
	// rate is always FINITE — an +Inf here fails json.Marshal and takes out the whole response.
	if dur < 0 {
		t.Fatalf("duration must not be negative, got %v", dur)
	}
	rate := Mbps(n, dur)
	if math.IsInf(rate, 0) || math.IsNaN(rate) {
		t.Fatalf("rate must be finite (it is JSON-encoded), got %v", rate)
	}
	if rate < 0 {
		t.Fatalf("rate must not be negative, got %v", rate)
	}
	if dur > 0 && rate <= 0 {
		t.Fatalf("a measurable transfer must report a positive rate, got %v", rate)
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
	sent, dur, err := tr.upload(context.Background(), cl, up)
	if err != nil {
		t.Fatalf("upload err: %v", err)
	}
	// Not asserting dur > 0, for the reason TestDownloadKnownPayload gives: on Windows the clock moves
	// in timer ticks, and a localhost upload can finish inside one. It failed the scrub gate that way.
	if dur < 0 {
		t.Fatalf("duration must not be negative, got %v", dur)
	}
	if got != up || sent != up {
		t.Fatalf("server received %d bytes, sent %d, want %d", got, sent, up)
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
	_, _, err := tr.upload(context.Background(), cl, 1000)
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
	if _, _, err := tr.upload(context.Background(), cl, 1000); err == nil {
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
	if sent, d, err := tr.upload(ctx, cl, 500_000); err == nil {
		res.UpMbps = round2(Mbps(sent, d))
	}

	if res.Via != "direct" {
		t.Fatalf("Via=%q want direct", res.Via)
	}
	if res.DownBytes != 1_000_000 {
		t.Fatalf("DownBytes=%d want 1000000", res.DownBytes)
	}
	// Rates are asserted FINITE and non-negative rather than strictly positive. Against a localhost
	// server a transfer can complete inside the clock's resolution, so Mbps correctly reports 0
	// ("no measurement") — requiring a positive number made this fail intermittently on Windows for
	// reasons unrelated to the code under test. The property that actually matters is that the value
	// is JSON-encodable: +Inf or NaN here would fail json.Marshal and take out the whole response.
	for _, m := range []struct {
		name string
		v    float64
	}{{"DownMbps", res.DownMbps}, {"UpMbps", res.UpMbps}} {
		if math.IsInf(m.v, 0) || math.IsNaN(m.v) {
			t.Fatalf("%s must be finite (it is JSON-encoded), got %v", m.name, m.v)
		}
		if m.v < 0 {
			t.Fatalf("%s must not be negative, got %v", m.name, m.v)
		}
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

// With a budget, a transfer still running when it runs out stops there and counts what moved: a
// download trickling in for seconds and an upload with no end both come back in about the budget,
// with a rate rather than an error.
func TestBudgetBoundsEachTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__up") {
			_, _ = io.Copy(io.Discard, r.Body)
			return
		}
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 1024)
		for i := 0; i < 400; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	cl := speedtest_clientFor(srv, 30*time.Second)
	tr := New(0)
	tr.Budget = 150 * time.Millisecond

	start := time.Now()
	n, dur, err := tr.download(context.Background(), cl, 400*1024)
	if err != nil || n <= 0 || n >= 400*1024 || dur < tr.Budget || time.Since(start) > 2*time.Second {
		t.Fatalf("download: %d bytes in %v, err %v", n, dur, err)
	}
	sent, dur, err := tr.upload(context.Background(), cl, 1<<40)
	if err != nil || sent <= 0 || sent >= 1<<40 || dur < tr.Budget || dur > 5*time.Second {
		t.Fatalf("upload: %d bytes in %v, err %v", sent, dur, err)
	}
}

// With a budget, waiting for an answer is bounded too: a path that takes a request and never
// answers (an MTU black hole stalling the handshake, a proxy whose upstream went silent) is "no
// answer" in about the budget, not the client's 90 s or the caller's deadline.
func TestBudgetBoundsTheWaitForAnAnswer(t *testing.T) {
	headersOnly := make(chan struct{})
	t.Cleanup(func() { close(headersOnly) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("bytes") == "7" {
			w.WriteHeader(http.StatusOK) // the headers, and then nothing
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-headersOnly:
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/__up") {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		<-r.Context().Done() // never answers
	}))
	t.Cleanup(srv.Close)
	cl := speedtest_clientFor(srv, 90*time.Second)
	tr := New(0)
	tr.Budget = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, c := range []struct {
		name string
		run  func() error
		max  time.Duration
	}{
		{"latency", func() error { _, err := tr.latency(ctx, cl); return err }, time.Second},
		{"download", func() error { _, _, err := tr.download(ctx, cl, 1_000_000); return err }, time.Second},
		{"download body", func() error { _, _, err := tr.download(ctx, cl, 7); return err }, time.Second},
		{"upload", func() error { _, _, err := tr.upload(ctx, cl, 1<<40); return err }, 2 * time.Second},
	} {
		start := time.Now()
		err := c.run()
		if took := time.Since(start); !errors.Is(err, ErrNoAnswer) || took > c.max {
			t.Errorf("%s: %v after %v", c.name, err, took.Round(time.Millisecond))
		}
	}
}

// A budgeted run whose empty probe got no answer stops there: the transfers would only wait out
// their own budgets. The path here accepts the connection and never answers the TLS handshake.
func TestBudgetedRunStopsWhenTheProbeGetsNoAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		for len(accepted) > 0 {
			(<-accepted).Close()
		}
	})
	tr := New(0)
	tr.Budget = 150 * time.Millisecond
	tr.Direct = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	start := time.Now()
	_, err = tr.Run(context.Background(), false, 1_000_000)
	if took := time.Since(start); !errors.Is(err, ErrNoAnswer) || !strings.HasPrefix(err.Error(), "latency: ") || took > time.Second {
		t.Fatalf("%v after %v", err, took.Round(time.Millisecond))
	}
	if n := len(accepted); n != 1 {
		t.Fatalf("%d connections: the run went on past the probe", n)
	}
}

// sleepingPath answers every request after wait, like a path whose answer lands at the very end of
// the budget, with a body whose bytes never come: a read waits for the request's context.
type sleepingPath struct{ wait time.Duration }

func (p sleepingPath) RoundTrip(req *http.Request) (*http.Response, error) {
	time.Sleep(p.wait)
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: ctxBody{req.Context()}, Request: req}, nil
}

type ctxBody struct{ ctx context.Context }

func (b ctxBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b ctxBody) Close() error             { return nil }

// An answer that lands just as the budget runs out is no answer, every time. The budget's timer
// used to cancel the request after send had handed the answer back as on time, and the leg then
// failed with a bare "context canceled", which is neither a measurement nor "no answer". One P and
// an answer in the same timer batch as the budget made that happen within a few tries.
func TestAnAnswerAtTheBudgetsEdgeIsNoAnswer(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	const wait = 20 * time.Millisecond
	tr := New(0)
	tr.Budget = wait
	cl := &http.Client{Transport: sleepingPath{wait}}
	for i := 0; i < 100; i++ {
		if _, _, err := tr.download(context.Background(), cl, 1000); !errors.Is(err, ErrNoAnswer) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
}

// bufferedUplink models an upload behind buffers: the local path (the socket's send buffer, then
// the modem's queue) takes up to buf bytes more than the uplink has carried, the uplink carries rate
// bytes a second, and the far side answers once the last byte has crossed it.
type bufferedUplink struct {
	buf  int64
	rate float64
}

func (u bufferedUplink) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	crossed := func() float64 { return u.rate * time.Since(start).Seconds() }
	var got int64
	p := make([]byte, 4<<10)
	for {
		for float64(got)-crossed() > float64(u.buf) {
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			time.Sleep(time.Millisecond)
		}
		n, err := req.Body.Read(p)
		got += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	select {
	case <-time.After(time.Until(start.Add(time.Duration(float64(got) / u.rate * float64(time.Second))))):
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// A slow uplink behind deep buffers is still measured: what counts as sent includes what the
// buffers held when sending stopped, and the answer comes once that has crossed too. Scaled: a
// 0.8 Mbit/s uplink whose buffers hold three budgets of it.
func TestAnUploadBehindDeepBuffersIsStillMeasured(t *testing.T) {
	tr := New(0)
	tr.Budget = 200 * time.Millisecond
	sent, dur, err := tr.upload(context.Background(), &http.Client{Transport: bufferedUplink{buf: 60_000, rate: 100_000}}, 1_000_000)
	if mbps := Mbps(sent, dur); err != nil || mbps < 0.7 || mbps > 0.9 {
		t.Fatalf("%d bytes in %v (%.2f Mbit/s), %v", sent, dur, mbps, err)
	}
}
