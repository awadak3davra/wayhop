package clash

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/traffic"
)

// clash_newClient builds a Client pointing at ts with the given secret. It is a
// secret-aware sibling of the package's existing newClient helper.
func clash_newClient(t *testing.T, ts *httptest.Server, secret string) *Client {
	t.Helper()
	c, err := New(strings.TrimPrefix(ts.URL, "http://"), secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// clash_recorder captures the auth header and path seen by a stub controller.
type clash_recorder struct {
	mu     sync.Mutex
	auth   string
	path   string
	method string
	body   string
	query  string
}

func (r *clash_recorder) snapshot() (method, path, auth, body, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.auth, r.body, r.query
}

// --- New() ---------------------------------------------------------------

func TestClashNewBadController(t *testing.T) {
	// A control character in the host makes url.Parse fail, so New must error.
	if _, err := New("\x7f bad host", ""); err == nil {
		t.Fatal("expected error for bad controller, got nil")
	}
}

func TestClashNewValidController(t *testing.T) {
	c, err := New("127.0.0.1:9090", "sekret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.base == nil || c.base.Host != "127.0.0.1:9090" {
		t.Fatalf("base host = %q, want 127.0.0.1:9090", c.base.Host)
	}
	if c.base.Scheme != "http" {
		t.Fatalf("scheme = %q, want http", c.base.Scheme)
	}
	if c.secret != "sekret" {
		t.Fatalf("secret = %q, want sekret", c.secret)
	}
	if c.hc == nil {
		t.Fatal("http client is nil")
	}
	// No global timeout is intentional (long-lived /traffic stream).
	if c.hc.Timeout != 0 {
		t.Fatalf("hc.Timeout = %v, want 0", c.hc.Timeout)
	}
}

// --- auth header propagation --------------------------------------------

func TestClashProxiesSendsAuthHeader(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.auth = r.Header.Get("Authorization")
		rec.path = r.URL.Path
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"proxies":{}}`))
	}))
	defer ts.Close()

	if _, err := clash_newClient(t, ts, "topsecret").Proxies(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, path, auth, _, _ := rec.snapshot()
	if auth != "Bearer topsecret" {
		t.Fatalf("Authorization = %q, want %q", auth, "Bearer topsecret")
	}
	if path != "/proxies" {
		t.Fatalf("path = %q, want /proxies", path)
	}
}

func TestClashProxiesNoAuthWhenSecretEmpty(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.auth = r.Header.Get("Authorization")
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"proxies":{}}`))
	}))
	defer ts.Close()

	if _, err := clash_newClient(t, ts, "").Proxies(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, auth, _, _ := rec.snapshot(); auth != "" {
		t.Fatalf("Authorization = %q, want empty", auth)
	}
}

// --- Proxies error paths -------------------------------------------------

func TestClashProxiesNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Proxies(context.Background())
	if err == nil {
		t.Fatal("expected error on non-200")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("error = %v, want it to mention status 500", err)
	}
}

func TestClashProxiesBadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Proxies(context.Background())
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
}

func TestClashProxiesUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close() // controller now down

	c, _ := New(addr, "")
	if _, err := c.Proxies(context.Background()); err == nil {
		t.Fatal("expected error on unreachable controller")
	}
}

func TestClashProxiesEmptyMap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No "proxies" key at all -> nil map, no error.
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	px, err := clash_newClient(t, ts, "").Proxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(px) != 0 {
		t.Fatalf("want empty map, got %+v", px)
	}
}

// --- Delay: meanDelay fallback and message handling ---------------------

func TestClashDelayMeanDelayFallback(t *testing.T) {
	// delay==0 but meanDelay present -> client returns meanDelay.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"delay":0,"meanDelay":88}`))
	}))
	defer ts.Close()

	d, err := clash_newClient(t, ts, "").Delay(context.Background(), "p", "http://x", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d != 88 {
		t.Fatalf("delay = %d, want 88 (meanDelay fallback)", d)
	}
}

func TestClashDelayPrefersDelayOverMean(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"delay":11,"meanDelay":99}`))
	}))
	defer ts.Close()

	d, err := clash_newClient(t, ts, "").Delay(context.Background(), "p", "http://x", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d != 11 {
		t.Fatalf("delay = %d, want 11 (delay preferred)", d)
	}
}

func TestClashDelayBothZero(t *testing.T) {
	// 200 OK with both zero -> returns 0, nil (treated as alive per current code).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"delay":0,"meanDelay":0}`))
	}))
	defer ts.Close()

	d, err := clash_newClient(t, ts, "").Delay(context.Background(), "p", "http://x", 1000)
	if err != nil {
		t.Fatalf("want nil error, got %v", err)
	}
	if d != 0 {
		t.Fatalf("delay = %d, want 0", d)
	}
}

func TestClashDelayDownUsesStatusWhenNoMessage(t *testing.T) {
	// Non-200 with empty body/message -> error message falls back to resp.Status.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Delay(context.Background(), "p", "http://x", 1000)
	if !errors.Is(err, ErrProxyDown) {
		t.Fatalf("want ErrProxyDown, got %v", err)
	}
	if !strings.Contains(err.Error(), "504") {
		t.Fatalf("error %v should mention status 504", err)
	}
}

func TestClashDelaySendsQueryAndAuth(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		rec.query = r.URL.RawQuery
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"delay":5}`))
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "abc").Delay(context.Background(), "proxy-a", "http://t/generate_204", 3000)
	if err != nil {
		t.Fatal(err)
	}
	_, path, auth, _, query := rec.snapshot()
	if path != "/proxies/proxy-a/delay" {
		t.Fatalf("path = %q, want /proxies/proxy-a/delay", path)
	}
	if auth != "Bearer abc" {
		t.Fatalf("auth = %q, want Bearer abc", auth)
	}
	if !strings.Contains(query, "timeout=3000") {
		t.Fatalf("query %q missing timeout=3000", query)
	}
	if !strings.Contains(query, "url=http") {
		t.Fatalf("query %q missing url param", query)
	}
}

func TestClashDelayEscapesProxyName(t *testing.T) {
	// A name with characters needing escaping is url.PathEscape'd into the path.
	var escaped string
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		escaped = r.URL.EscapedPath()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"delay":1}`))
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Delay(context.Background(), "grp/sub", "http://x", 1000)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Regression: Delay sets the decoded Path + escaped RawPath so the name is
	// encoded EXACTLY ONCE — "grp/sub" must arrive on the wire as "grp%2Fsub"
	// (not the previously-double-encoded "grp%252Fsub"), so sing-box resolves the
	// real proxy name.
	if escaped != "/proxies/grp%2Fsub/delay" {
		t.Fatalf("escaped path = %q, want /proxies/grp%%2Fsub/delay", escaped)
	}
}

func TestClashDelayUnreachableNotProxyDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()

	c, _ := New(addr, "")
	_, err := c.Delay(context.Background(), "x", "http://y", 1000)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrProxyDown) {
		t.Fatal("unreachable must not be ErrProxyDown")
	}
}

// --- Connections ---------------------------------------------------------

func TestClashConnectionsParse(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"downloadTotal":1000,"uploadTotal":250,"connections":[{"upload":7,"download":9,"chains":["proxy","main"]}]}`))
	}))
	defer ts.Close()

	conns, err := clash_newClient(t, ts, "k").Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conns.DownloadTotal != 1000 || conns.UploadTotal != 250 {
		t.Fatalf("totals wrong: %+v", conns)
	}
	if len(conns.Connections) != 1 {
		t.Fatalf("want 1 connection, got %d", len(conns.Connections))
	}
	c0 := conns.Connections[0]
	if c0.Upload != 7 || c0.Download != 9 || len(c0.Chains) != 2 || c0.Chains[0] != "proxy" {
		t.Fatalf("connection parse wrong: %+v", c0)
	}
	_, path, auth, _, _ := rec.snapshot()
	if path != "/connections" {
		t.Fatalf("path = %q, want /connections", path)
	}
	if auth != "Bearer k" {
		t.Fatalf("auth = %q, want Bearer k", auth)
	}
}

func TestClashConnectionsNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Connections(context.Background())
	if err == nil {
		t.Fatal("expected error on non-200")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error %v should mention 502", err)
	}
}

func TestClashConnectionsBadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	_, err := clash_newClient(t, ts, "").Connections(context.Background())
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
}

// --- Select --------------------------------------------------------------

func TestClashSelectSendsPutBody(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		rec.body = string(buf)
		rec.mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad content-type", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	err := clash_newClient(t, ts, "tok").Select(context.Background(), "main", "proxy-a")
	if err != nil {
		t.Fatal(err)
	}
	method, path, auth, body, _ := rec.snapshot()
	if method != http.MethodPut {
		t.Fatalf("method = %q, want PUT", method)
	}
	if path != "/proxies/main" {
		t.Fatalf("path = %q, want /proxies/main", path)
	}
	if auth != "Bearer tok" {
		t.Fatalf("auth = %q, want Bearer tok", auth)
	}
	// Body must be {"name":"proxy-a"}.
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("body not JSON: %q (%v)", body, err)
	}
	if m["name"] != "proxy-a" {
		t.Fatalf("body name = %q, want proxy-a", m["name"])
	}
}

func TestClashSelectErrorOnBadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 300+ is treated as an error.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	err := clash_newClient(t, ts, "").Select(context.Background(), "g", "n")
	if err == nil {
		t.Fatal("expected error on status >= 300")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %v should mention 404", err)
	}
}

func TestClashSelectOKOn200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := clash_newClient(t, ts, "").Select(context.Background(), "g", "n"); err != nil {
		t.Fatalf("want nil error on 200, got %v", err)
	}
}

func TestClashSelectUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()

	c, _ := New(addr, "")
	if err := c.Select(context.Background(), "g", "n"); err == nil {
		t.Fatal("expected error on unreachable controller")
	}
}

// --- StreamTraffic -------------------------------------------------------

func TestClashStreamTrafficSamples(t *testing.T) {
	rec := &clash_recorder{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		rec.mu.Unlock()
		// Two concatenated JSON objects, as the Clash /traffic stream emits.
		_, _ = w.Write([]byte(`{"up":10,"down":20}{"up":30,"down":40}`))
	}))
	defer ts.Close()

	var (
		mu      sync.Mutex
		samples []traffic.Sample
	)
	// The stream ends after two objects -> Decode returns io.EOF -> StreamTraffic
	// returns that error. We assert the samples were delivered.
	_ = clash_newClient(t, ts, "streamtok").StreamTraffic(context.Background(), func(s traffic.Sample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	})

	mu.Lock()
	defer mu.Unlock()
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2: %+v", len(samples), samples)
	}
	if samples[0].Up != 10 || samples[0].Down != 20 {
		t.Fatalf("sample0 = %+v, want up=10 down=20", samples[0])
	}
	if samples[1].Up != 30 || samples[1].Down != 40 {
		t.Fatalf("sample1 = %+v, want up=30 down=40", samples[1])
	}
	if samples[0].T == 0 {
		t.Fatal("sample timestamp should be set")
	}
	_, path, auth, _, _ := rec.snapshot()
	if path != "/traffic" {
		t.Fatalf("path = %q, want /traffic", path)
	}
	if auth != "Bearer streamtok" {
		t.Fatalf("auth = %q, want Bearer streamtok", auth)
	}
}

func TestClashStreamTrafficNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	err := clash_newClient(t, ts, "").StreamTraffic(context.Background(), func(traffic.Sample) {
		t.Fatal("onSample must not be called on non-200")
	})
	if err == nil {
		t.Fatal("expected error on non-200")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error %v should mention 401", err)
	}
}

func TestClashStreamTrafficContextCancel(t *testing.T) {
	// Server keeps the connection open and sends one sample, then blocks.
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"up":1,"down":2}`))
		if fl != nil {
			fl.Flush()
		}
		<-release // hold the response open until the test is done
	}))
	defer ts.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan traffic.Sample, 1)
	done := make(chan error, 1)
	go func() {
		done <- clash_newClient(t, ts, "").StreamTraffic(ctx, func(s traffic.Sample) {
			select {
			case got <- s:
			default:
			}
			cancel() // cancel after first sample
		})
	}()

	select {
	case s := <-got:
		if s.Up != 1 || s.Down != 2 {
			t.Fatalf("sample = %+v, want up=1 down=2", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for first sample")
	}

	select {
	case err := <-done:
		// After cancel, the next Decode fails and ctx.Err() is returned.
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StreamTraffic did not return after cancel")
	}
}

func TestClashStreamTrafficUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()

	c, _ := New(addr, "")
	err := c.StreamTraffic(context.Background(), func(traffic.Sample) {
		t.Fatal("onSample must not be called when unreachable")
	})
	if err == nil {
		t.Fatal("expected error on unreachable controller")
	}
}

// --- Reverse proxy (Proxy) ----------------------------------------------

func TestClashReverseProxyStripsPrefixAndAddsAuth(t *testing.T) {
	rec := &clash_recorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		rec.query = r.URL.RawQuery
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`ok`))
	}))
	defer upstream.Close()

	c := clash_newClient(t, upstream, "proxytok")
	h := c.Proxy("/api/clash")

	// Front-end request under the mount prefix, with a query string.
	req := httptest.NewRequest(http.MethodGet, "/api/clash/proxies?foo=bar", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rw.Code, rw.Body.String())
	}
	_, path, auth, _, query := rec.snapshot()
	if path != "/proxies" {
		t.Fatalf("forwarded path = %q, want /proxies (prefix stripped)", path)
	}
	if auth != "Bearer proxytok" {
		t.Fatalf("forwarded auth = %q, want Bearer proxytok", auth)
	}
	if query != "foo=bar" {
		t.Fatalf("forwarded query = %q, want foo=bar", query)
	}
}

func TestClashReverseProxyRootPathBecomesSlash(t *testing.T) {
	rec := &clash_recorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.path = r.URL.Path
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`root`))
	}))
	defer upstream.Close()

	c := clash_newClient(t, upstream, "")
	h := c.Proxy("/api/clash")

	// Request hitting exactly the prefix -> stripped to "" -> rewritten to "/".
	req := httptest.NewRequest(http.MethodGet, "/api/clash", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if _, path, _, _, _ := rec.snapshot(); path != "/" {
		t.Fatalf("forwarded path = %q, want / (empty path rewritten)", path)
	}
}

func TestClashReverseProxyNoAuthWhenSecretEmpty(t *testing.T) {
	rec := &clash_recorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.auth = r.Header.Get("Authorization")
		rec.mu.Unlock()
	}))
	defer upstream.Close()

	c := clash_newClient(t, upstream, "")
	h := c.Proxy("/api/clash")

	req := httptest.NewRequest(http.MethodGet, "/api/clash/version", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if _, _, auth, _, _ := rec.snapshot(); auth != "" {
		t.Fatalf("forwarded auth = %q, want empty when secret unset", auth)
	}
}
