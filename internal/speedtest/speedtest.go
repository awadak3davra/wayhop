// Package speedtest measures throughput through the active proxy (or directly).
// It routes via the sing-box "mixed" inbound's HTTP-proxy mode, so it needs no
// SOCKS client dependency — just http.Transport.Proxy.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
)

const (
	downURL = "https://speed.cloudflare.com/__down"
	upURL   = "https://speed.cloudflare.com/__up"
)

// Result is one speedtest measurement.
type Result struct {
	Via       string  `json:"via"` // "proxy" | "direct"
	DownMbps  float64 `json:"down_mbps"`
	UpMbps    float64 `json:"up_mbps"`
	LatencyMs int     `json:"latency_ms"`
	DownBytes int64   `json:"down_bytes"`
}

// Tester runs throughput tests, optionally through the local mixed inbound.
type Tester struct {
	mixedPort int
}

// New returns a Tester that proxies via 127.0.0.1:<mixedPort> when asked.
func New(mixedPort int) *Tester { return &Tester{mixedPort: mixedPort} }

// Mbps converts a byte count + duration into megabits per second.
func Mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / (d.Seconds() * 1e6)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func (t *Tester) client(viaProxy bool, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{}
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

// Run measures latency + download (and best-effort upload). downBytes is the
// download payload size; upload uses half that.
func (t *Tester) Run(ctx context.Context, viaProxy bool, downBytes int) (Result, error) {
	res := Result{Via: "direct"}
	if viaProxy {
		res.Via = "proxy"
	}
	cl, err := t.client(viaProxy, 90*time.Second)
	if err != nil {
		return res, err
	}
	defer cl.CloseIdleConnections() // the per-Run Transport is never reused; don't leak its idle conns

	if ms, err := t.latency(ctx, cl); err == nil {
		res.LatencyMs = ms
	}

	n, dur, err := t.download(ctx, cl, downBytes)
	if err != nil {
		return res, fmt.Errorf("download: %w", err)
	}
	res.DownBytes = n
	res.DownMbps = round2(Mbps(n, dur))

	if upBytes := downBytes / 2; upBytes > 0 {
		if dur, err := t.upload(ctx, cl, upBytes); err == nil {
			res.UpMbps = round2(Mbps(int64(upBytes), dur))
		}
	}
	return res, nil
}

func (t *Tester) latency(ctx context.Context, cl *http.Client) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downURL+"?bytes=0", nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return int(time.Since(start).Milliseconds()), nil
}

func (t *Tester) download(ctx context.Context, cl *http.Client, bytes int) (int64, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?bytes=%d", downURL, bytes), nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := cl.Do(req)
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
	n, err := io.Copy(io.Discard, resp.Body)
	return n, time.Since(start), err
}

func (t *Tester) upload(ctx context.Context, cl *http.Client, bytes int) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, &zeroReader{left: int64(bytes)})
	if err != nil {
		return 0, err
	}
	req.ContentLength = int64(bytes)
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Mirror download()'s status validation: a 4xx/5xx (proxy error page, 429 rate-limit, 413
	// too-large…) means the upload never landed, so timing against the rejection would report a
	// bogus UpMbps. Return an error instead — Run treats a non-nil upload error as "couldn't
	// measure" (UpMbps stays 0), best-effort, same as download. (>=400 not strict ==200, since a
	// successful upload may legitimately answer 204/2xx, unlike __down which returns 200.)
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

// zeroReader yields `left` zero bytes then EOF (cheap upload payload).
type zeroReader struct{ left int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > z.left {
		n = int(z.left)
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	z.left -= int64(n)
	return n, nil
}
