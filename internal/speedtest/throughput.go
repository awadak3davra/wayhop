package speedtest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultDownloadBytes   int64 = 100_000_000
	DefaultDownloadTimeout       = 20 * time.Second
	DefaultWarmup                = 2 * time.Second
	DefaultSourceTimeout         = 8 * time.Second
	DownloadBufferSize           = 64 << 10
	MaxCloudflareBytes     int64 = 99_999_999
	maxTelegramPageBytes   int64 = 2 << 20
	maxTelegramURLBytes          = 16 << 10
	maxDownloadErrorLength       = 160
	// maxSourceRequests bounds how often one source is asked again for a small object.
	maxSourceRequests = 256
	// DefaultMinObjectBytes is the smallest object a source may serve. A smaller one (an avatar, a
	// thumbnail) repeated on one connection measures round trips, not throughput.
	DefaultMinObjectBytes int64 = 1 << 20
	// A sample can be judged when its steady window (after the warm-up) lasted minSteadyWindow and
	// carried minSteadyBytes, or lasted longSteadyWindow on a slow link, or when the whole transfer
	// carried wholeTransferBytes (the ramp-up is then a minor part of it). Anything less is TooShort.
	minSteadyWindow          = time.Second
	minSteadyBytes     int64 = 2 << 20
	longSteadyWindow         = 5 * time.Second
	wholeTransferBytes int64 = 16 << 20
	// maxTelegramCandidates bounds how many media URLs of a channel page are kept and asked.
	maxTelegramCandidates = 4
	maxTelegramFallbacks  = 2
	// downloadUserAgent: Cloudflare and Telegram answer a browser-like client; the tool this was
	// measured with on the router sent the same.
	downloadUserAgent = "Mozilla/5.0"
)

// DownloadSource identifies a download endpoint. Telegram sources are public
// channel pages; the payload is a video file (cdn*.telesco.pe) of at least
// MinObjectBytes found on the page, never its avatar or a thumbnail.
type DownloadSource struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Telegram bool   `json:"telegram,omitempty"`
}

// DefaultDownloadSources returns the standard download endpoints in rotation
// order. The returned slice is independent for each caller.
func DefaultDownloadSources() []DownloadSource {
	return []DownloadSource{
		{ID: "cloudflare", URL: "https://speed.cloudflare.com/__down"},
		{ID: "ovh", URL: "https://proof.ovh.net/files/100Mb.dat"},
		{ID: "hetzner", URL: "https://fsn1-speed.hetzner.com/100MB.bin"},
		// A Google-hosted file: an exit that forwards only Google destinations answers this one.
		{ID: "google", URL: "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"},
	}
}

// DownloadOptions controls a download measurement. Zero values select the
// defaults above.
type DownloadOptions struct {
	MaxBytes int64
	// MaxTotalBytes, when positive, caps ALL source/page bodies together, including rejected attempts.
	// The server sets it to the remaining monthly budget; zero leaves only MaxBytes in force.
	MaxTotalBytes int64
	// MaxDuration bounds the accepted source's transfer, counted from its first response.
	MaxDuration time.Duration
	Warmup      time.Duration
	// SourceTimeout bounds each source's wait for a first response (connect, TLS, headers and, for a
	// Telegram source, the channel page). Zero is DefaultSourceTimeout.
	SourceTimeout time.Duration
	// MinObjectBytes is the smallest object a source may serve when it is smaller than the volume
	// asked for. Zero is DefaultMinObjectBytes.
	MinObjectBytes int64
	// Progress, when set, is called from the measuring goroutine about once a second with the bytes
	// read from the current source and its average rate so far.
	Progress    func(bytes int64, mbps float64)
	Sources     []DownloadSource
	DialContext func(context.Context, string, string) (net.Conn, error)
	Network     string
}

// SourceAttempt records one HTTP request made by a measurement.
type SourceAttempt struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Bytes  int64  `json:"bytes"`
	TTFBMs int64  `json:"ttfb_ms"`
	Error  string `json:"error"`
}

// DownloadResult describes the accepted source. TotalBytes also includes
// bodies read from rejected sources and Telegram channel pages.
type DownloadResult struct {
	Source     string  `json:"source"`
	URL        string  `json:"url"`
	Bytes      int64   `json:"bytes"`
	TotalBytes int64   `json:"total_bytes"`
	ElapsedMs  int64   `json:"elapsed_ms"`
	TTFBMs     int64   `json:"ttfb_ms"`
	SteadyMbps float64 `json:"steady_mbps"`
	// SteadyMs and SteadyBytes are the window SteadyMbps was rated over: after the warm-up, or the
	// whole transfer (RampIncluded) when it ended inside the warm-up.
	SteadyMs     int64 `json:"steady_ms,omitempty"`
	SteadyBytes  int64 `json:"steady_bytes,omitempty"`
	RampIncluded bool  `json:"ramp_included,omitempty"`
	// TooShort marks a sample too small to judge a tunnel by (see minSteadyWindow). The figure is
	// reported, but it must not stand as the tunnel's speed nor enter an election.
	TooShort       bool            `json:"too_short,omitempty"`
	ZeroSecondsPct float64         `json:"zero_seconds_pct"`
	MaxPauseMs     int64           `json:"max_pause_ms"`
	Interrupted    bool            `json:"interrupted"`
	Attempts       []SourceAttempt `json:"attempts"`
}

var (
	errDownloadTotalBudget = errors.New("download total byte budget reached")
	// errTransferDeadline ends an accepted source at MaxDuration: a bounded sample, not a failure.
	errTransferDeadline = errors.New("download time limit reached")
	errSourceTimeout    = errors.New("source did not answer in time")
	// ErrObjectTooSmall: the source's object is below MinObjectBytes, so the source cannot be used.
	ErrObjectTooSmall = errors.New("source object is too small to measure throughput with")
)

// MeasureDownload streams a payload into one fixed buffer and discards it; nothing is kept but
// counters. Sources are tried in order. One is accepted when it supplied MaxBytes, or was still
// supplying bytes when MaxDuration (counted from its first response) or the total byte budget ended,
// or broke off after the warm-up was over (Interrupted). A source that refuses, stalls before its
// first response for SourceTimeout, or breaks off earlier is passed over for the next one.
func MeasureDownload(ctx context.Context, opts DownloadOptions) (DownloadResult, error) {
	var result DownloadResult
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultDownloadBytes
	}
	if opts.MaxDuration == 0 {
		opts.MaxDuration = DefaultDownloadTimeout
	}
	if opts.Warmup == 0 {
		opts.Warmup = DefaultWarmup
	}
	if opts.SourceTimeout == 0 {
		opts.SourceTimeout = DefaultSourceTimeout
	}
	if opts.MinObjectBytes <= 0 {
		opts.MinObjectBytes = DefaultMinObjectBytes
	}
	if opts.Network == "" {
		opts.Network = "tcp4"
	}
	if len(opts.Sources) == 0 {
		opts.Sources = DefaultDownloadSources()
	}
	if opts.MaxBytes < 0 {
		return result, errors.New("download max bytes must not be negative")
	}
	if opts.MaxTotalBytes < 0 {
		return result, errors.New("download total byte budget must not be negative")
	}
	if opts.MaxDuration < 0 || opts.SourceTimeout < 0 {
		return result, errors.New("download durations must not be negative")
	}
	if opts.Warmup < 0 {
		return result, errors.New("download warmup must not be negative")
	}
	if opts.Network != "tcp4" && opts.Network != "tcp6" {
		return result, errors.New("download network must be tcp4 or tcp6")
	}

	baseDial := opts.DialContext
	if baseDial == nil {
		dialer := &net.Dialer{Timeout: opts.SourceTimeout}
		baseDial = dialer.DialContext
	}
	network := opts.Network
	transport := &http.Transport{
		DialContext: func(ctx context.Context, transportNetwork, addr string) (net.Conn, error) {
			if transportNetwork == "tcp" {
				transportNetwork = network
			}
			return baseDial(ctx, transportNetwork, addr)
		},
		// The environment's proxy would carry the download off the bound interface.
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        2,
		TLSHandshakeTimeout: opts.SourceTimeout,
		// A non-nil empty map disables the transport's automatic HTTP/2 setup.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	run := downloadRun{
		parent: ctx,
		client: client,
		opts:   opts,
		buffer: make([]byte, DownloadBufferSize),
	}

	var lastErr error
	interrupted := false
	for _, source := range opts.Sources {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		if opts.MaxTotalBytes > 0 && run.totalBytes >= opts.MaxTotalBytes {
			lastErr = errDownloadTotalBudget
			break
		}
		measurement, err := run.downloadSource(source)
		if ctx.Err() != nil {
			lastErr = ctx.Err() // the caller gave up: a cut-short figure is not a measurement
			break
		}
		bounded := errors.Is(err, errTransferDeadline) || errors.Is(err, errDownloadTotalBudget)
		brokeLate := err != nil && !bounded && !measurement.start.IsZero() &&
			time.Since(measurement.start) >= opts.Warmup+time.Second
		if err == nil || (measurement.bytes > 0 && (bounded || brokeLate)) {
			if bounded && len(run.attempts) > 0 {
				// Reaching the time or byte bound with a partial body is the sample's planned end.
				run.attempts[len(run.attempts)-1].Error = ""
			}
			result = measurement.result(source, opts.Warmup)
			result.Interrupted = brokeLate
			result.TotalBytes = run.totalBytes
			result.Attempts = run.attempts
			return result, nil
		}
		if measurement.bytes > 0 || errors.Is(err, io.ErrUnexpectedEOF) {
			interrupted = true
		}
		lastErr = err
	}

	result.TotalBytes = run.totalBytes
	result.Attempts = run.attempts
	result.Interrupted = interrupted
	if lastErr == nil {
		lastErr = errors.New("no download source available")
	}
	return result, fmt.Errorf("download failed: %w", lastErr)
}

type downloadRun struct {
	parent     context.Context
	client     *http.Client
	opts       DownloadOptions
	buffer     []byte
	attempts   []SourceAttempt
	totalBytes int64

	// Per source: ctx ends at the source's own bound, which the timer moves from SourceTimeout
	// (no response yet) to MaxDuration (transfer) at the first accepted response.
	ctx          context.Context
	timer        *time.Timer
	expired      *atomic.Bool
	lastProgress time.Time
}

// ctxErr names why the source's context ended: the caller's own error, or which of the source's
// two bounds ran out.
func (r *downloadRun) ctxErr(transferring bool) error {
	if err := r.parent.Err(); err != nil {
		return err
	}
	if r.ctx.Err() == nil {
		return nil
	}
	if r.expired.Load() && transferring {
		return errTransferDeadline
	}
	return errSourceTimeout
}

type sourceMeasurement struct {
	url            string
	bytes          int64
	start          time.Time
	ttfb           time.Duration
	steadyBytes    int64
	lastData       time.Time
	maxPause       time.Duration
	bucket         int64
	bucketHasBytes bool
	nonzeroBuckets int64
}

func (m *sourceMeasurement) startTransfer(at time.Time, ttfb time.Duration) {
	if !m.start.IsZero() {
		return
	}
	m.start = at
	m.ttfb = ttfb
}

func (m *sourceMeasurement) add(n int, at time.Time, warmup time.Duration) {
	if n <= 0 {
		return
	}
	m.bytes += int64(n)
	if !m.lastData.IsZero() {
		if pause := at.Sub(m.lastData); pause > m.maxPause {
			m.maxPause = pause
		}
	}
	m.lastData = at
	if at.Sub(m.start) >= warmup {
		m.steadyBytes += int64(n)
	}

	bucket := int64(at.Sub(m.start) / time.Second)
	if bucket < 0 {
		bucket = 0
	}
	for m.bucket < bucket {
		if m.bucketHasBytes {
			m.nonzeroBuckets++
		}
		m.bucket++
		m.bucketHasBytes = false
	}
	m.bucketHasBytes = true
}

func (m *sourceMeasurement) result(source DownloadSource, warmup time.Duration) DownloadResult {
	return m.resultForElapsed(source, warmup, time.Since(m.start))
}

func (m *sourceMeasurement) resultForElapsed(source DownloadSource, warmup, elapsed time.Duration) DownloadResult {
	steadyBytes := m.steadyBytes
	steadyDuration := elapsed - warmup
	ramp := elapsed <= warmup
	if ramp {
		steadyBytes = m.bytes
		steadyDuration = elapsed
	}
	judged := m.bytes >= wholeTransferBytes ||
		(!ramp && steadyDuration >= minSteadyWindow && (steadyBytes >= minSteadyBytes || steadyDuration >= longSteadyWindow))
	return DownloadResult{
		SteadyMs:       steadyDuration.Milliseconds(),
		SteadyBytes:    steadyBytes,
		RampIncluded:   ramp,
		TooShort:       !judged,
		Source:         source.ID,
		URL:            m.url,
		Bytes:          m.bytes,
		ElapsedMs:      elapsed.Milliseconds(),
		TTFBMs:         m.ttfb.Milliseconds(),
		SteadyMbps:     downloadMbps(steadyBytes, steadyDuration),
		ZeroSecondsPct: m.zeroSecondsPct(elapsed),
		MaxPauseMs:     m.maxPause.Milliseconds(),
	}
}

func (m *sourceMeasurement) zeroSecondsPct(elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	// Include the final partial bucket, but do not invent a new bucket when
	// elapsed lands exactly on a second boundary.
	buckets := int64((elapsed-1)/time.Second) + 1
	nonzero := m.nonzeroBuckets
	if m.bucketHasBytes && m.bucket < buckets {
		nonzero++
	}
	if nonzero > buckets {
		nonzero = buckets
	}
	return float64(buckets-nonzero) * 100 / float64(buckets)
}

func downloadMbps(bytes int64, duration time.Duration) float64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return float64(bytes) * 8 / duration.Seconds() / 1e6
}

// downloadSource reads one source until MaxBytes. A source whose object is smaller (Cloudflare caps a
// request below 100 MB, a Telegram video is a few MB) is asked again on the same connection until the
// volume or the time bound is reached; an object below MinObjectBytes is refused instead. A Telegram
// page offers several media files: the first one large enough is the payload.
func (r *downloadRun) downloadSource(source DownloadSource) (sourceMeasurement, error) {
	ctx, cancel := context.WithCancel(r.parent)
	defer cancel()
	var expired atomic.Bool
	timer := time.AfterFunc(r.opts.SourceTimeout, func() {
		expired.Store(true)
		cancel()
	})
	defer timer.Stop()
	r.ctx, r.timer, r.expired = ctx, timer, &expired

	candidates := []string{source.URL}
	cloudflare := isCloudflareSource(source)
	if source.Telegram {
		media, err := r.telegramMediaURLs(source)
		if err != nil {
			return sourceMeasurement{}, err
		}
		candidates, cloudflare = media, false
	}
	var measurement sourceMeasurement
	var err error
	for _, rawURL := range candidates {
		measurement = sourceMeasurement{url: rawURL}
		err = r.transfer(source, rawURL, cloudflare, &measurement)
		// Only an object refused by its announced size, before any of it was read, leaves the
		// source's wait for an answer untouched: the next candidate may still be asked.
		if !errors.Is(err, ErrObjectTooSmall) || measurement.bytes > 0 {
			break
		}
	}
	return measurement, err
}

func (r *downloadRun) transfer(source DownloadSource, rawURL string, cloudflare bool, measurement *sourceMeasurement) error {
	for requests := 0; measurement.bytes < r.opts.MaxBytes && requests < maxSourceRequests; requests++ {
		requestBytes := r.opts.MaxBytes - measurement.bytes
		requestURL := rawURL
		if cloudflare {
			if requestBytes > MaxCloudflareBytes {
				requestBytes = MaxCloudflareBytes
			}
			var err error
			requestURL, err = cloudflareURL(rawURL, requestBytes)
			if err != nil {
				r.addErrorAttempt(source, rawURL, err)
				return err
			}
		}
		read, err := r.downloadBody(source, requestURL, requestBytes, measurement)
		if err != nil {
			return err
		}
		if read == 0 {
			err := errors.New("source returned an empty body")
			r.attempts[len(r.attempts)-1].Error = err.Error()
			return err
		}
		// A body of unannounced length that ended this early is as useless as an announced one.
		if requests == 0 && read < requestBytes && read < r.opts.MinObjectBytes {
			r.attempts[len(r.attempts)-1].Error = ErrObjectTooSmall.Error()
			return ErrObjectTooSmall
		}
	}
	return nil
}

// armTransfer moves the source's bound from the wait for an answer to the transfer's time. A timer
// that already fired has ended the source, even when its cancel has not reached the context yet:
// re-arming it would end the transfer just accepted as a "time limit" sample after milliseconds.
func (r *downloadRun) armTransfer() error {
	if !r.timer.Reset(r.opts.MaxDuration) || r.expired.Load() {
		if err := r.parent.Err(); err != nil {
			return err
		}
		return errSourceTimeout
	}
	return nil
}

func (r *downloadRun) readSize(want int64) (int, error) {
	if want <= 0 {
		return 0, errDownloadTotalBudget
	}
	n := want
	if n > int64(len(r.buffer)) {
		n = int64(len(r.buffer))
	}
	if r.opts.MaxTotalBytes > 0 {
		left := r.opts.MaxTotalBytes - r.totalBytes
		if left <= 0 {
			return 0, errDownloadTotalBudget
		}
		if left < n {
			n = left
		}
	}
	return int(n), nil
}

// downloadBody reads up to want bytes of one response into the fixed buffer. A body that ends
// cleanly before want is not an error: the caller asks again.
func (r *downloadRun) downloadBody(source DownloadSource, rawURL string, want int64, measurement *sourceMeasurement) (int64, error) {
	response, attempt, err := r.get(source, rawURL, !measurement.start.IsZero())
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
		r.attempts[attempt].Error = boundedDownloadError(err)
		return 0, err
	}
	fail := func(read int64, err error) (int64, error) {
		r.attempts[attempt].Error = boundedDownloadError(err)
		return read, err
	}
	if measurement.start.IsZero() {
		if n := response.ContentLength; n >= 0 && n < want && n < r.opts.MinObjectBytes {
			return fail(0, fmt.Errorf("%w (%d bytes)", ErrObjectTooSmall, n))
		}
		// The source answered: from here its bound is the transfer's, not the wait for an answer.
		if err := r.armTransfer(); err != nil {
			return fail(0, err)
		}
		measurement.startTransfer(time.Now(), time.Duration(r.attempts[attempt].TTFBMs)*time.Millisecond)
	}

	var read int64
	for read < want {
		if err := r.ctxErr(true); err != nil {
			return fail(read, err)
		}
		readSize, sizeErr := r.readSize(want - read)
		if sizeErr != nil {
			return fail(read, sizeErr)
		}
		n, readErr := response.Body.Read(r.buffer[:readSize])
		if n > 0 {
			now := time.Now()
			read += int64(n)
			r.totalBytes += int64(n)
			r.attempts[attempt].Bytes += int64(n)
			measurement.add(n, now, r.opts.Warmup)
			if r.opts.Progress != nil && now.Sub(r.lastProgress) >= time.Second {
				r.lastProgress = now
				r.opts.Progress(measurement.bytes, downloadMbps(measurement.bytes, now.Sub(measurement.start)))
			}
		}
		if readErr != nil {
			if err := r.ctxErr(true); err != nil {
				return fail(read, err)
			}
			if errors.Is(readErr, io.EOF) {
				return read, nil
			}
			return fail(read, readErr)
		}
	}
	return read, nil
}

// get sends one request. A source asked again for more of the same object (transferring) keeps its
// one attempt record, so the record list stays as short as the source list.
func (r *downloadRun) get(source DownloadSource, rawURL string, transferring bool) (*http.Response, int, error) {
	if !transferring || len(r.attempts) == 0 {
		r.attempts = append(r.attempts, SourceAttempt{Source: source.ID, URL: rawURL})
	}
	index := len(r.attempts) - 1

	if _, err := validateDownloadURL(rawURL); err != nil {
		r.attempts[index].Error = boundedDownloadError(err)
		return nil, index, err
	}
	request, err := http.NewRequestWithContext(r.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		r.attempts[index].Error = boundedDownloadError(err)
		return nil, index, err
	}
	request.Header.Set("User-Agent", downloadUserAgent)
	start := time.Now()
	response, err := r.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if ctxErr := r.ctxErr(transferring); ctxErr != nil {
			err = ctxErr
		}
		r.attempts[index].Error = boundedDownloadError(err)
		return nil, index, err
	}
	r.attempts[index].Status = response.StatusCode
	if !transferring {
		r.attempts[index].TTFBMs = time.Since(start).Milliseconds()
	}
	return response, index, nil
}

func (r *downloadRun) addErrorAttempt(source DownloadSource, rawURL string, err error) {
	r.attempts = append(r.attempts, SourceAttempt{
		Source: source.ID,
		URL:    rawURL,
		Error:  boundedDownloadError(err),
	})
}

func isCloudflareSource(source DownloadSource) bool {
	if strings.EqualFold(source.ID, "cloudflare") {
		return true
	}
	parsed, err := url.Parse(source.URL)
	return err == nil && strings.EqualFold(parsed.Hostname(), "speed.cloudflare.com")
}

func cloudflareURL(raw string, bytes int64) (string, error) {
	parsed, err := validateDownloadURL(raw)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("bytes", strconv.FormatInt(bytes, 10))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validateDownloadURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("empty download URL")
	}
	if strings.Contains(raw, "#") {
		return nil, errors.New("download URL must not contain a fragment")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid download URL: %s", boundedDownloadError(err))
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("download URL scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, errors.New("download URL must have a host")
	}
	if parsed.User != nil {
		return nil, errors.New("download URL must not contain userinfo")
	}
	return parsed, nil
}

func boundedDownloadError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > maxDownloadErrorLength {
		message = message[:maxDownloadErrorLength]
	}
	return message
}

// telegramMediaURLs reads the channel page and returns the media files worth asking, videos first.
// The page is scanned as a stream and read to its end (or the page cap): its first CDN URLs are the
// channel's avatar and thumbnails of a few KB.
func (r *downloadRun) telegramMediaURLs(source DownloadSource) ([]string, error) {
	response, attempt, err := r.get(source, source.URL, false)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	fail := func(err error) ([]string, error) {
		r.attempts[attempt].Error = boundedDownloadError(err)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("unexpected HTTP status %d", response.StatusCode))
	}

	extractor := telegramURLExtractor{candidate: make([]byte, 0, 256)}
	var pageBytes int64
	for pageBytes < maxTelegramPageBytes && len(extractor.videos) < maxTelegramCandidates {
		if err := r.ctxErr(false); err != nil {
			return fail(err)
		}
		readSize, sizeErr := r.readSize(maxTelegramPageBytes - pageBytes)
		if sizeErr != nil {
			return fail(sizeErr)
		}
		n, readErr := response.Body.Read(r.buffer[:readSize])
		if n > 0 {
			pageBytes += int64(n)
			r.totalBytes += int64(n)
			r.attempts[attempt].Bytes += int64(n)
			extractor.scan(r.buffer[:n])
		}
		if readErr != nil {
			if err := r.ctxErr(false); err != nil {
				return fail(err)
			}
			if !errors.Is(readErr, io.EOF) {
				return fail(readErr)
			}
			extractor.finish()
			break
		}
	}
	media := extractor.media()
	if len(media) == 0 {
		return fail(fmt.Errorf("%w: no CDN media file on the Telegram page (first 2 MiB)", ErrObjectTooSmall))
	}
	return media, nil
}

// telegramMediaAllowed restricts a Telegram source's payload to the Telegram CDN over HTTPS, whatever
// the page says. A variable only so a test can serve the media itself.
var telegramMediaAllowed = func(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	return u.Scheme == "https" && strings.HasPrefix(host, "cdn") && strings.HasSuffix(host, ".telesco.pe")
}

// telegramURLExtractor recognizes URL candidates incrementally, so a channel
// page is never assembled in memory. Only a few bounded media URLs are retained:
// the first videos, and the last other files in case the page has no video.
type telegramURLExtractor struct {
	candidate  []byte
	prefix     int
	discarding bool
	videos     []string
	others     []string
}

// media is what to ask, in order: videos, else the last other CDN files seen.
func (e *telegramURLExtractor) media() []string {
	if len(e.videos) > 0 {
		return e.videos
	}
	return e.others
}

func (e *telegramURLExtractor) scan(p []byte) {
	const scheme = "http" // https too: the candidate runs to the next delimiter, and telegramMediaAllowed judges it
	for _, c := range p {
		if e.discarding {
			if telegramURLDelimiter(c) {
				e.discarding = false
			}
			continue
		}
		if len(e.candidate) == 0 {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c == scheme[e.prefix] {
				e.prefix++
				if e.prefix == len(scheme) {
					e.candidate = append(e.candidate, scheme...)
					e.prefix = 0
				}
			} else {
				e.prefix = 0
				if c == 'h' {
					e.prefix = 1
				}
			}
			continue
		}
		if telegramURLDelimiter(c) {
			e.finish()
			continue
		}
		e.candidate = append(e.candidate, c)
		if len(e.candidate) > maxTelegramURLBytes {
			e.candidate = e.candidate[:0]
			e.discarding = true
		}
	}
}

// finish closes the candidate being read and files it when it is a CDN media URL.
func (e *telegramURLExtractor) finish() {
	if len(e.candidate) == 0 {
		e.prefix = 0
		return
	}
	candidate := string(e.candidate)
	e.candidate = e.candidate[:0]
	candidate = strings.ReplaceAll(candidate, "\\/", "/")
	candidate = html.UnescapeString(candidate)
	parsed, err := validateDownloadURL(candidate)
	if err != nil {
		return
	}
	if !telegramMediaAllowed(parsed) {
		return
	}
	mediaURL := parsed.String()
	for _, seen := range e.videos {
		if seen == mediaURL {
			return
		}
	}
	if strings.HasSuffix(strings.ToLower(parsed.Path), ".mp4") {
		if len(e.videos) < maxTelegramCandidates {
			e.videos = append(e.videos, mediaURL)
		}
		return
	}
	if len(e.others) == maxTelegramFallbacks {
		e.others = append(e.others[:0], e.others[1:]...)
	}
	e.others = append(e.others, mediaURL)
}

func telegramURLDelimiter(c byte) bool {
	switch c {
	case '\'', '"', '<', '>', ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}
