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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func throughputWriteBytes(w io.Writer, bytes int64) {
	buffer := make([]byte, DownloadBufferSize)
	for bytes > 0 {
		n := int64(len(buffer))
		if n > bytes {
			n = bytes
		}
		written, err := w.Write(buffer[:int(n)])
		if err != nil {
			return
		}
		bytes -= int64(written)
	}
}

func throughputOptions(rawURL string, bytes int64) DownloadOptions {
	return DownloadOptions{
		MaxBytes:    bytes,
		MaxDuration: 5 * time.Second,
		Warmup:      10 * time.Millisecond,
		// The tests serve small objects on purpose; the size floor has its own tests.
		MinObjectBytes: 1,
		Sources:        []DownloadSource{{ID: "test", URL: rawURL}},
	}
}

func TestDefaultDownloadSources(t *testing.T) {
	sources := DefaultDownloadSources()
	if len(sources) != 4 {
		t.Fatalf("got %d sources, want 4", len(sources))
	}
	want := []DownloadSource{
		{ID: "cloudflare", URL: "https://speed.cloudflare.com/__down"},
		{ID: "ovh", URL: "https://proof.ovh.net/files/100Mb.dat"},
		{ID: "hetzner", URL: "https://fsn1-speed.hetzner.com/100MB.bin"},
		{ID: "google", URL: "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"},
	}
	for i := range want {
		if sources[i] != want[i] {
			t.Errorf("source %d = %#v, want %#v", i, sources[i], want[i])
		}
	}
	sources[0].ID = "changed"
	if DefaultDownloadSources()[0].ID != "cloudflare" {
		t.Fatal("default source slices share backing storage")
	}
}

func TestMeasureDownloadStopsAtSize(t *testing.T) {
	const maxBytes = 512 * 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		throughputWriteBytes(w, 4*maxBytes)
	}))
	defer server.Close()

	result, err := MeasureDownload(context.Background(), throughputOptions(server.URL, maxBytes))
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Bytes != maxBytes || result.TotalBytes != maxBytes {
		t.Fatalf("bytes=%d total=%d, want %d", result.Bytes, result.TotalBytes, maxBytes)
	}
	if result.Source != "test" || result.URL != server.URL {
		t.Fatalf("accepted source=%q URL=%q", result.Source, result.URL)
	}
	if result.Interrupted {
		t.Fatal("size-limited transfer marked interrupted")
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Status != http.StatusOK || result.Attempts[0].Bytes != maxBytes {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
}

func TestMeasureDownloadStopsAtTimeWithPartialSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		chunk := make([]byte, 4096)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}))
	defer server.Close()

	opts := throughputOptions(server.URL, 16*1024*1024)
	opts.MaxDuration = 120 * time.Millisecond
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("time-limited partial transfer failed: %v", err)
	}
	if result.Bytes <= 0 || result.Bytes >= opts.MaxBytes {
		t.Fatalf("partial bytes=%d", result.Bytes)
	}
	if result.TotalBytes != result.Bytes {
		t.Fatalf("total=%d bytes=%d", result.TotalBytes, result.Bytes)
	}
	if result.Interrupted {
		t.Fatal("time-limited partial transfer marked interrupted")
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Error != "" {
		t.Fatalf("time-limited attempt=%+v", result.Attempts)
	}
}

func TestMeasureDownloadRotatesAfterStatus(t *testing.T) {
	const maxBytes = 32 * 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/limited" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		throughputWriteBytes(w, maxBytes)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL+"/ok", maxBytes)
	opts.Sources = []DownloadSource{
		{ID: "limited", URL: server.URL + "/limited"},
		{ID: "ok", URL: server.URL + "/ok"},
	}
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "ok" || result.Bytes != maxBytes {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Attempts) != 2 {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
	if result.Attempts[0].Status != http.StatusTooManyRequests || result.Attempts[0].Error == "" {
		t.Fatalf("429 attempt=%+v", result.Attempts[0])
	}
	if result.Attempts[1].Status != http.StatusOK || result.Attempts[1].Error != "" {
		t.Fatalf("success attempt=%+v", result.Attempts[1])
	}
}

func TestMeasureDownloadRotatesAfterPrematureEOF(t *testing.T) {
	const (
		shortBytes = 1234
		maxBytes   = 64 * 1024
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/short" {
			// A body cut before its declared length: the connection breaks mid-object.
			w.Header().Set("Content-Length", strconv.Itoa(maxBytes))
			throughputWriteBytes(w, shortBytes)
			return
		}
		throughputWriteBytes(w, maxBytes)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL+"/full", maxBytes)
	opts.Sources = []DownloadSource{
		{ID: "short", URL: server.URL + "/short"},
		{ID: "full", URL: server.URL + "/full"},
	}
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "full" || result.Bytes != maxBytes {
		t.Fatalf("result=%+v", result)
	}
	if result.TotalBytes != maxBytes+shortBytes {
		t.Fatalf("total=%d, want %d", result.TotalBytes, maxBytes+shortBytes)
	}
	if result.Interrupted {
		t.Fatal("successful rotated measurement marked interrupted")
	}
	if len(result.Attempts) != 2 || !strings.Contains(result.Attempts[0].Error, "EOF") {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
}

func TestMeasureDownloadFinalErrorRetainsAccounting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		throughputWriteBytes(w, 100)
	}))
	defer server.Close()

	result, err := MeasureDownload(context.Background(), throughputOptions(server.URL, 1000))
	if err == nil {
		t.Fatal("premature EOF succeeded")
	}
	if !result.Interrupted {
		t.Fatal("premature EOF not marked interrupted")
	}
	if result.Bytes != 0 || result.TotalBytes != 100 {
		t.Fatalf("bytes=%d total=%d", result.Bytes, result.TotalBytes)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Bytes != 100 || result.Attempts[0].Error == "" {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
}

func TestMeasureDownloadEmptyBodyFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := MeasureDownload(context.Background(), throughputOptions(server.URL, 1024))
	if err == nil {
		t.Fatal("an empty body succeeded")
	}
	if result.TotalBytes != 0 || len(result.Attempts) != 1 || result.Attempts[0].Error == "" {
		t.Fatalf("result=%+v, want one failed attempt with no body bytes", result)
	}
}

func TestMeasureDownloadCloudflareCapAndQueryMerge(t *testing.T) {
	var mutex sync.Mutex
	var requested []int64
	var tokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil {
			t.Errorf("bytes query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mutex.Lock()
		requested = append(requested, bytes)
		tokens = append(tokens, r.URL.Query().Get("token"))
		mutex.Unlock()
		throughputWriteBytes(w, bytes)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL+"/__down?token=a%20b&bytes=7", DefaultDownloadBytes)
	opts.Sources = []DownloadSource{{ID: "cloudflare", URL: server.URL + "/__down?token=a%20b&bytes=7"}}
	opts.MaxDuration = 30 * time.Second
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	mutex.Lock()
	gotRequests := append([]int64(nil), requested...)
	gotTokens := append([]string(nil), tokens...)
	mutex.Unlock()
	if len(gotRequests) != 2 || gotRequests[0] != MaxCloudflareBytes || gotRequests[1] != 1 {
		t.Fatalf("Cloudflare request sizes=%v", gotRequests)
	}
	for _, bytes := range gotRequests {
		if bytes >= 100_000_000 {
			t.Fatalf("Cloudflare request was not capped: %d", bytes)
		}
	}
	if len(gotTokens) != 2 || gotTokens[0] != "a b" || gotTokens[1] != "a b" {
		t.Fatalf("merged tokens=%q", gotTokens)
	}
	if result.Bytes != DefaultDownloadBytes || result.TotalBytes != DefaultDownloadBytes {
		t.Fatalf("bytes=%d total=%d", result.Bytes, result.TotalBytes)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Bytes != DefaultDownloadBytes {
		t.Fatalf("a source asked twice must keep one attempt record: %+v", result.Attempts)
	}
	parsed, err := url.Parse(result.Attempts[0].URL)
	if err != nil || parsed.Query().Get("token") != "a b" {
		t.Fatalf("attempt URL did not preserve query: %q", result.Attempts[0].URL)
	}
}

func TestMeasureDownloadTelegramExtractionAndAccounting(t *testing.T) {
	const payloadBytes = 16 * 1024
	page := `<html><meta content="https:\/\/cdn4.telesco.pe\/file.mp4?x=1&amp;y=2"></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/channel":
			_, _ = io.WriteString(w, page)
		case "/payload":
			throughputWriteBytes(w, payloadBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dialer := &net.Dialer{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "cdn4.telesco.pe:") {
			return nil, errors.New("CDN reached; stopping test request")
		}
		return dialer.DialContext(ctx, network, addr)
	}
	opts := throughputOptions(server.URL+"/payload", payloadBytes)
	opts.DialContext = dial
	opts.Sources = []DownloadSource{
		{ID: "telegram", URL: server.URL + "/channel", Telegram: true},
		{ID: "fallback", URL: server.URL + "/payload"},
	}
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "fallback" || result.Bytes != payloadBytes {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Attempts) != 3 {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
	if result.Attempts[0].URL != server.URL+"/channel" || result.Attempts[0].Bytes != int64(len(page)) {
		t.Fatalf("page attempt=%+v", result.Attempts[0])
	}
	wantMedia := "https://cdn4.telesco.pe/file.mp4?x=1&y=2"
	if result.Attempts[1].URL != wantMedia || !strings.Contains(result.Attempts[1].Error, "CDN reached") {
		t.Fatalf("media attempt=%+v, want URL %q", result.Attempts[1], wantMedia)
	}
	if result.TotalBytes != int64(len(page))+payloadBytes {
		t.Fatalf("total=%d, want page %d + payload %d", result.TotalBytes, len(page), payloadBytes)
	}
}

func TestMeasureDownloadTelegramPageCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		throughputWriteBytes(w, maxTelegramPageBytes+DownloadBufferSize)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL, 1024)
	opts.Sources = []DownloadSource{{ID: "telegram", URL: server.URL, Telegram: true}}
	result, err := MeasureDownload(context.Background(), opts)
	if err == nil {
		t.Fatal("Telegram page without media succeeded")
	}
	if result.TotalBytes != maxTelegramPageBytes {
		t.Fatalf("page bytes=%d, want strict cap %d", result.TotalBytes, maxTelegramPageBytes)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Bytes != maxTelegramPageBytes {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
}

func TestDownloadURLValidation(t *testing.T) {
	valid := []string{"http://example.com/file", "https://example.com/file?x=1"}
	for _, raw := range valid {
		if _, err := validateDownloadURL(raw); err != nil {
			t.Errorf("valid URL %q rejected: %v", raw, err)
		}
	}
	invalid := []string{
		"ftp://example.com/file",
		"https://user@example.com/file",
		"https://example.com/file#fragment",
		"https:///missing-host",
	}
	for _, raw := range invalid {
		if _, err := validateDownloadURL(raw); err == nil {
			t.Errorf("invalid URL %q accepted", raw)
		}
	}
}

func TestMeasureDownloadSelectsNetworkFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		throughputWriteBytes(w, 1024)
	}))
	defer server.Close()

	networks := make(chan string, 1)
	dialer := &net.Dialer{}
	opts := throughputOptions(server.URL, 1024)
	opts.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		networks <- network
		return dialer.DialContext(ctx, network, addr)
	}
	if _, err := MeasureDownload(context.Background(), opts); err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	select {
	case network := <-networks:
		if network != "tcp4" {
			t.Fatalf("dialed network=%q, want tcp4", network)
		}
	default:
		t.Fatal("custom dialer was not called")
	}
}

func TestSourceMeasurementMetrics(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	measurement := sourceMeasurement{url: "https://example.com/payload"}
	measurement.startTransfer(start, 35*time.Millisecond)
	measurement.add(1_000_000, start.Add(100*time.Millisecond), time.Second)
	measurement.add(1_000_000, start.Add(1200*time.Millisecond), time.Second)
	measurement.add(500_000, start.Add(3200*time.Millisecond), time.Second)

	result := measurement.resultForElapsed(DownloadSource{ID: "metrics"}, time.Second, 3500*time.Millisecond)
	if result.Bytes != 2_500_000 || result.ElapsedMs != 3500 || result.TTFBMs != 35 {
		t.Fatalf("basic metrics=%+v", result)
	}
	if math.Abs(result.SteadyMbps-4.8) > 0.000001 {
		t.Fatalf("steady Mbps=%f, want 4.8", result.SteadyMbps)
	}
	if result.ZeroSecondsPct != 25 {
		t.Fatalf("zero seconds=%f, want 25", result.ZeroSecondsPct)
	}
	if result.MaxPauseMs != 2000 {
		t.Fatalf("max pause=%dms, want 2000ms", result.MaxPauseMs)
	}

	short := sourceMeasurement{}
	short.startTransfer(start, 0)
	short.add(1_000_000, start.Add(100*time.Millisecond), time.Second)
	fallback := short.resultForElapsed(DownloadSource{}, time.Second, 500*time.Millisecond)
	if math.Abs(fallback.SteadyMbps-16) > 0.000001 {
		t.Fatalf("short-sample Mbps=%f, want overall rate 16", fallback.SteadyMbps)
	}
}

func TestMeasureDownloadHeapGrowth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		throughputWriteBytes(w, DefaultDownloadBytes)
	}))
	defer server.Close()

	warmup := throughputOptions(server.URL, 256*1024)
	if _, err := MeasureDownload(context.Background(), warmup); err != nil {
		t.Fatalf("warmup measurement: %v", err)
	}

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	opts := throughputOptions(server.URL, DefaultDownloadBytes)
	opts.Warmup = DefaultWarmup
	opts.MaxDuration = 30 * time.Second
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("100,000,000-byte measurement: %v", err)
	}
	if result.Bytes != DefaultDownloadBytes {
		t.Fatalf("bytes=%d, want %d", result.Bytes, DefaultDownloadBytes)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if growth >= 1<<20 {
		t.Fatalf("retained heap grew by %d bytes (before=%d after=%d), want <1MiB", growth, before.HeapAlloc, after.HeapAlloc)
	}
}

// A source whose object is smaller than the volume (a Telegram media file) is asked again until the
// volume is reached, under one attempt record.
func TestMeasureDownloadRepeatsSmallObject(t *testing.T) {
	const object, want = 10_000, 64_000
	var requests atomic.Int64
	var agent atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		agent.Store(r.Header.Get("User-Agent"))
		throughputWriteBytes(w, object)
	}))
	defer server.Close()

	result, err := MeasureDownload(context.Background(), throughputOptions(server.URL, want))
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Bytes != want || result.Interrupted {
		t.Fatalf("result=%+v", result)
	}
	if got := requests.Load(); got != 7 {
		t.Fatalf("requests=%d, want 7", got)
	}
	if len(result.Attempts) != 1 || result.Attempts[0].Bytes != want {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
	if agent.Load() != downloadUserAgent {
		t.Fatalf("user agent %q", agent.Load())
	}
}

// A source that never answers costs SourceTimeout, not the transfer's time: the next one still gets
// its full MaxDuration.
func TestMeasureDownloadSilentSourceRotates(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/silent" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		throughputWriteBytes(w, 4096)
	}))
	defer server.Close()
	defer close(release)

	opts := throughputOptions(server.URL, 4096)
	opts.SourceTimeout = 100 * time.Millisecond
	opts.Sources = []DownloadSource{{ID: "silent", URL: server.URL + "/silent"}, {ID: "ok", URL: server.URL + "/ok"}}
	started := time.Now()
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "ok" || result.Bytes != 4096 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Attempts) != 2 || !strings.Contains(result.Attempts[0].Error, "did not answer") {
		t.Fatalf("attempts=%+v", result.Attempts)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("a silent source held the run for %v", took)
	}
}

// A transfer that breaks after the warm-up has measured something: it is kept, marked interrupted,
// rather than spending the next source's traffic too.
func TestMeasureDownloadLateBreakIsKept(t *testing.T) {
	var second atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/second" {
			second.Add(1)
			throughputWriteBytes(w, 1<<20)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(1<<20))
		throughputWriteBytes(w, 32<<10)
		w.(http.Flusher).Flush()
		time.Sleep(1200 * time.Millisecond)
		throughputWriteBytes(w, 32<<10)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL, 1<<20)
	opts.Sources = append(opts.Sources, DownloadSource{ID: "second", URL: server.URL + "/second"})
	var calls atomic.Int64
	opts.Progress = func(bytes int64, _ float64) {
		if bytes > 0 {
			calls.Add(1)
		}
	}
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "test" || !result.Interrupted || result.Bytes != 64<<10 {
		t.Fatalf("result=%+v", result)
	}
	if second.Load() != 0 {
		t.Fatal("a kept sample still spent the next source")
	}
	if calls.Load() == 0 {
		t.Fatal("no progress was reported")
	}
}

// The caller's cancellation is never turned into a figure.
func TestMeasureDownloadCancelledIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		throughputWriteBytes(w, 8192)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := MeasureDownload(ctx, throughputOptions(server.URL, 1<<20)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, want the caller's deadline", err)
	}
}
