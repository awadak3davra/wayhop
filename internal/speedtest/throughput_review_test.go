package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// telegramTestServer serves a channel page and its media; the media check is opened to the test
// server for the test's length.
func telegramTestServer(t *testing.T, page func(base string) string, sizes map[string]int64) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/channel" {
			_, _ = io.WriteString(w, page(server.URL))
			return
		}
		size, ok := sizes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(size))
		throughputWriteBytes(w, size)
	}))
	t.Cleanup(server.Close)
	old := telegramMediaAllowed
	telegramMediaAllowed = func(u *url.URL) bool { return "http://"+u.Host == server.URL }
	t.Cleanup(func() { telegramMediaAllowed = old })
	return server, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range hits {
			out[k] = v
		}
		return out
	}
}

// The first CDN URLs of a channel page are its avatar and thumbnails. The payload is a
// video large enough to measure with; a small video is refused by its announced size, unread.
func TestTelegramSourceSkipsAvatarAndSmallMedia(t *testing.T) {
	const big, want = 300_000, 600_000
	page := func(base string) string {
		return `<html><img src="` + base + `/avatar.jpg"><i style="background-image:url('` + base + `/thumb.jpg')"></i>` +
			`<video src="` + base + `/small.mp4?token=a&amp;b=1"></video><video src="` + base + `/big.mp4"></video></html>`
	}
	server, hits := telegramTestServer(t, page, map[string]int64{"/avatar.jpg": 6216, "/thumb.jpg": 22353, "/small.mp4": 2909, "/big.mp4": big})

	opts := throughputOptions(server.URL, want)
	opts.MinObjectBytes = 100_000
	opts.Sources = []DownloadSource{{ID: "telegram", URL: server.URL + "/channel", Telegram: true}}
	result, err := MeasureDownload(context.Background(), opts)
	if err != nil {
		t.Fatalf("MeasureDownload: %v", err)
	}
	if result.Source != "telegram" || !strings.HasSuffix(result.URL, "/big.mp4") || result.Bytes != want {
		t.Fatalf("payload = %s (%d bytes) from %s, want /big.mp4 with %d", result.URL, result.Bytes, result.Source, want)
	}
	got := hits()
	if got["/avatar.jpg"] != 0 || got["/thumb.jpg"] != 0 {
		t.Fatalf("an image was asked for although the page has videos: %v", got)
	}
	if got["/small.mp4"] != 1 || got["/big.mp4"] != 2 {
		t.Fatalf("requests = %v, want the small video once and the big one twice", got)
	}
	pageLen := int64(len(page(server.URL)))
	if result.TotalBytes != pageLen+want {
		t.Fatalf("total = %d, want page %d + payload %d: a refused object must not be read", result.TotalBytes, pageLen, want)
	}
}

// A page that offers nothing large enough makes the source unusable; it is never a slow success.
func TestTelegramSourceWithOnlySmallMediaIsUnusable(t *testing.T) {
	page := func(base string) string {
		return `<img src="` + base + `/avatar.jpg"><img src="` + base + `/thumb.jpg">`
	}
	server, hits := telegramTestServer(t, page, map[string]int64{"/avatar.jpg": 6216, "/thumb.jpg": 22353, "/file": 400_000})

	opts := throughputOptions(server.URL, 400_000)
	opts.MinObjectBytes = 100_000
	opts.Sources = []DownloadSource{{ID: "telegram", URL: server.URL + "/channel", Telegram: true}}
	result, err := MeasureDownload(context.Background(), opts)
	if !errors.Is(err, ErrObjectTooSmall) {
		t.Fatalf("err = %v (result %+v), want ErrObjectTooSmall", err, result)
	}
	if result.Bytes != 0 || result.Source != "" {
		t.Fatalf("a small image became a sample: %+v", result)
	}
	if got := hits(); got["/avatar.jpg"] > 1 || got["/thumb.jpg"] > 1 {
		t.Fatalf("a small object was repeated: %v", got)
	}

	// With another source behind it the run goes on, and the figure belongs to that source.
	opts.Sources = append(opts.Sources, DownloadSource{ID: "generic", URL: server.URL + "/file"})
	result, err = MeasureDownload(context.Background(), opts)
	if err != nil || result.Source != "generic" || result.Bytes != 400_000 {
		t.Fatalf("result = %+v, err %v, want the generic source", result, err)
	}
	if first := result.Attempts[0]; first.Source != "telegram" {
		t.Fatalf("attempts = %+v", result.Attempts)
	}
}

// The floor holds for any source and for a body of unannounced length.
func TestSmallObjectIsRefusedNotRepeated(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.(http.Flusher).Flush() // chunked: no Content-Length
		throughputWriteBytes(w, 6216)
	}))
	defer server.Close()

	opts := throughputOptions(server.URL, 1_000_000)
	opts.MinObjectBytes = 0 // the default
	_, err := MeasureDownload(context.Background(), opts)
	if !errors.Is(err, ErrObjectTooSmall) {
		t.Fatalf("err = %v, want ErrObjectTooSmall", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

// A figure is a tunnel's speed only when its window is long enough to judge by.
func TestSampleTooShortToJudge(t *testing.T) {
	const warmup = 2 * time.Second
	tests := []struct {
		name          string
		bytes, steady int64
		elapsed       time.Duration
		tooShort      bool
		ramp          bool
	}{
		{name: "budget tail inside the warm-up", bytes: 5 << 20, elapsed: 400 * time.Millisecond, tooShort: true, ramp: true},
		{name: "half a second of steady flow", bytes: 12 << 20, steady: 3 << 20, elapsed: 2500 * time.Millisecond, tooShort: true},
		{name: "a second and two megabytes", bytes: 8 << 20, steady: 2 << 20, elapsed: 3 * time.Second},
		{name: "a second but a trickle", bytes: 300_000, steady: 100_000, elapsed: 3 * time.Second, tooShort: true},
		{name: "a slow link over a long window", bytes: 1_500_000, steady: 1_300_000, elapsed: 20 * time.Second},
		{name: "a whole 25 MB on a fast link", bytes: 25 << 20, elapsed: 1500 * time.Millisecond, ramp: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := sourceMeasurement{bytes: tt.bytes, steadyBytes: tt.steady}
			got := m.resultForElapsed(DownloadSource{ID: "x"}, warmup, tt.elapsed)
			if got.TooShort != tt.tooShort || got.RampIncluded != tt.ramp {
				t.Fatalf("too short %v, ramp %v; want %v, %v (%+v)", got.TooShort, got.RampIncluded, tt.tooShort, tt.ramp, got)
			}
		})
	}
}

// A source timer that fired while the response arrived must not be re-armed into a
// transfer that then ends as a "time limit" sample.
func TestArmTransferAfterTheSourceTimerFired(t *testing.T) {
	var expired atomic.Bool
	fired := make(chan struct{})
	timer := time.AfterFunc(time.Millisecond, func() {
		expired.Store(true)
		close(fired) // the cancel has not reached the context yet
	})
	defer timer.Stop()
	<-fired
	run := downloadRun{parent: context.Background(), ctx: context.Background(), timer: timer, expired: &expired,
		opts: DownloadOptions{MaxDuration: time.Minute}}
	if err := run.armTransfer(); !errors.Is(err, errSourceTimeout) {
		t.Fatalf("armTransfer = %v, want errSourceTimeout", err)
	}

	live := time.AfterFunc(time.Minute, func() {})
	defer live.Stop()
	var no atomic.Bool
	run.timer, run.expired = live, &no
	if err := run.armTransfer(); err != nil {
		t.Fatalf("a live timer was refused: %v", err)
	}
}
