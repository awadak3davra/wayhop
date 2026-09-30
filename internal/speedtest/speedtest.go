// Package speedtest measures throughput through the active proxy (or directly).
// It routes via the sing-box "mixed" inbound's HTTP-proxy mode, so it needs no
// SOCKS client dependency — just http.Transport.Proxy.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	downURL = "https://speed.cloudflare.com/__down"
	upURL   = "https://speed.cloudflare.com/__up"
)

// Result is one speedtest measurement.
type Result struct {
	Via      string  `json:"via"` // "proxy" | "direct"
	DownMbps float64 `json:"down_mbps"`
	UpMbps   float64 `json:"up_mbps"`
	// LatencyMs is -1 when the latency probe did not complete, following the same convention as
	// netdiag's LossPct/AvgMs. It used to stay at its zero value, and the panel renders
	// `latency_ms ?? "?"` — which only substitutes for null/undefined — so a FAILED probe displayed
	// as "0 ms": not merely wrong but the best possible reading, so a broken measurement looked
	// like an excellent one.
	LatencyMs int   `json:"latency_ms"`
	DownBytes int64 `json:"down_bytes"`
	// UpErr is why the upload was not measured, "" when it was or was not tried. The upload is best
	// effort, so a run with one is still a result; the bot says "↑ not measured" rather than leaving
	// the figure out, and the panel's view is unchanged.
	UpErr string `json:"-"`
}

// Tester runs throughput tests, optionally through the local mixed inbound.
type Tester struct {
	mixedPort int
	// Direct, when set, dials the connections of a direct run. On a gateway router the engine's
	// transparent redirect carries a plain local socket into sing-box, which sends it out whichever
	// outbound its rules pick, so a "direct" test would measure a tunnel; the server passes a
	// dialer that marks the socket past the redirect.
	Direct func(ctx context.Context, network, addr string) (net.Conn, error)
	// Budget, when set, bounds each transfer: a download or an upload still under way when it runs
	// out stops there, and the rate is taken over what moved. Each request gets the budget to answer
	// as well (an upload's answer, which waits for what the buffers still hold, four more), and a run
	// whose empty probe got no answer stops there. The bot sets it, so a test on a slow or dead path
	// ends in seconds instead of running into the client's timeout; the panel leaves it zero.
	Budget time.Duration
}

// ErrNoAnswer is a budgeted request that got no answer in time: a path that takes the request and
// never answers, as over an MTU black hole that stalls the TLS handshake or through a proxy whose
// upstream went silent.
var ErrNoAnswer = errors.New("no answer")

// New returns a Tester that proxies via 127.0.0.1:<mixedPort> when asked.
func New(mixedPort int) *Tester { return &Tester{mixedPort: mixedPort} }

// Mbps converts a byte count + duration into megabits per second.
func Mbps(bytes int64, d time.Duration) float64 {
	// A non-positive duration cannot yield a rate and must never be divided by (Go returns +Inf,
	// which json.Marshal then rejects). 0 means "no measurement", not "0 Mbps".
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / (d.Seconds() * 1e6)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func (t *Tester) client(viaProxy bool, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{}
	if !viaProxy && t.Direct != nil {
		tr.DialContext = t.Direct
	}
	if viaProxy {
		if t.mixedPort == 0 {
			return nil, fmt.Errorf("no proxy port configured")
		}
		pu, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", t.mixedPort))
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// newResult is the starting point of every run: nothing measured yet.
//
// Split out so the "unknown" default is testable without a network. LatencyMs must start NEGATIVE:
// the panel renders it directly, and a zero would display as "0 ms" — the best possible reading —
// for a probe that never completed.
func newResult(viaProxy bool) Result {
	via := "direct"
	if viaProxy {
		via = "proxy"
	}
	return Result{Via: via, LatencyMs: -1}
}

// Run measures latency + download (and best-effort upload). downBytes is the
// download payload size; upload uses half that.
func (t *Tester) Run(ctx context.Context, viaProxy bool, downBytes int) (Result, error) {
	res := newResult(viaProxy)
	cl, err := t.client(viaProxy, 90*time.Second)
	if err != nil {
		return res, err
	}
	defer cl.CloseIdleConnections() // the per-Run Transport is never reused; don't leak its idle conns

	ms, err := t.latency(ctx, cl)
	switch {
	case err == nil:
		res.LatencyMs = ms
	case t.Budget > 0:
		// What cannot answer an empty request in the budget cannot carry a transfer either; trying
		// would only wait out the transfer's own budget twice.
		return res, fmt.Errorf("latency: %w", err)
	}

	n, dur, err := t.download(ctx, cl, downBytes)
	if err != nil {
		return res, fmt.Errorf("download: %w", err)
	}
	res.DownBytes = n
	res.DownMbps = round2(Mbps(n, dur))

	if upBytes := downBytes / 2; upBytes > 0 {
		if sent, dur, err := t.upload(ctx, cl, upBytes); err == nil {
			res.UpMbps = round2(Mbps(sent, dur))
		} else {
			res.UpErr = err.Error()
		}
	}
	return res, nil
}

// send makes a request whose answer may take, with a budget, no longer than wait; the dial, a
// proxy's CONNECT, the TLS handshake and the headers all count. cancel ends req.
func (t *Tester) send(cl *http.Client, req *http.Request, cancel context.CancelFunc, wait time.Duration) (*http.Response, error) {
	if t.Budget <= 0 {
		return cl.Do(req)
	}
	timer := time.AfterFunc(wait, cancel)
	resp, err := cl.Do(req)
	if !timer.Stop() {
		// The timer fired, so the request's context is cancelled or about to be: an answer that got
		// here at the edge can no longer be read, and it counts as none.
		if err == nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("%w in %s", ErrNoAnswer, wait)
	}
	return resp, err
}

func (t *Tester) latency(ctx context.Context, cl *http.Client) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downURL+"?bytes=0", nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := t.send(cl, req, cancel, t.Budget)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return int(time.Since(start).Milliseconds()), nil
}

func (t *Tester) download(ctx context.Context, cl *http.Client, bytes int) (int64, time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?bytes=%d", downURL, bytes), nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := t.send(cl, req, cancel, t.Budget)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	// Time ONLY the body transfer, not the request + response-header round-trip: the
	// connection is already warm from the preceding latency() probe, so including the header
	// RTT here would understate throughput on a high-latency tunnel.
	start := time.Now()
	var spent atomic.Bool
	if t.Budget > 0 {
		stop := time.AfterFunc(t.Budget, func() { spent.Store(true); cancel() })
		defer stop.Stop()
	}
	n, err := io.Copy(io.Discard, resp.Body)
	d := time.Since(start)
	switch {
	case err != nil && spent.Load() && n > 0:
		// The budget ran out mid-transfer: what arrived by then is the sample.
		return n, d, nil
	case err != nil && spent.Load():
		return 0, 0, fmt.Errorf("%w in %s", ErrNoAnswer, t.Budget)
	}
	return n, d, err
}

// upload sends up to bytes and reports how many it sent and how long that took, timed to the
// server's answer, which comes only once everything sent has arrived.
func (t *Tester) upload(ctx context.Context, cl *http.Client, bytes int) (int64, time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	body := &zeroReader{left: int64(bytes)}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, body)
	if err != nil {
		return 0, 0, err
	}
	req.ContentLength = int64(bytes)
	if t.Budget > 0 {
		// A slow uplink stops sending when the budget runs out, so the length is not known ahead.
		body.until = time.Now().Add(t.Budget)
		req.ContentLength = -1
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	// The answer comes once everything sent has arrived, and what was sent includes what still sits in
	// the socket's and the modem's buffers: on a slow uplink those can hold half a minute. So after
	// the budget for sending, the answer gets four more.
	resp, err := t.send(cl, req, cancel, 5*t.Budget)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	// Mirror download()'s status validation: a 4xx/5xx (proxy error page, 429 rate-limit, 413
	// too-large…) means the upload never landed, so timing against the rejection would report a
	// bogus UpMbps. Return an error instead — Run treats a non-nil upload error as "couldn't
	// measure" (UpMbps stays 0), best-effort, same as download. (>=400 not strict ==200, since a
	// successful upload may legitimately answer 204/2xx, unlike __down which returns 200.)
	if resp.StatusCode >= 400 {
		return 0, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body.sent.Load(), time.Since(start), nil
}

// zeroReader yields `left` zero bytes then EOF (cheap upload payload), or EOF sooner once until
// has passed. sent counts what it handed out; the transport may still be reading from its own
// goroutine when the caller looks, so it is atomic.
type zeroReader struct {
	left  int64
	until time.Time
	sent  atomic.Int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 || (!z.until.IsZero() && !time.Now().Before(z.until)) {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > z.left {
		n = int(z.left)
	}
	clear(p[:n])
	z.left -= int64(n)
	z.sent.Add(int64(n))
	return n, nil
}
