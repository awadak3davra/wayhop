package server

import (
	"compress/gzip"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// staticHandler serves the embedded UI with revalidate-on-version caching. The
// ETag is a hash of the bundled assets, so a new build changes it and the browser
// fetches fresh JS/CSS (no hard-reload needed), while an unchanged build returns a
// tiny 304 instead of re-sending ~97KB on every page load.
func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.ui))
	// Compress each embedded asset ONCE instead of on every request: re-gzipping the ~474 KB UI
	// bundle per page load measured at ~1.15 s on a router CPU, which was the biggest single
	// contributor to first paint. See staticGzipCache.
	gzCache := newStaticGzipCache(s.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The SPA catch-all is intentionally broad, but static bytes are only meaningful for
		// retrieval methods. Serving index.html to TRACE (or to a mistyped mutating request)
		// turns an unsupported method into a misleading 200 and leaves TRACE enabled at the
		// panel boundary. Reject everything except GET/HEAD before ETag or asset handling.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A browser asks for /favicon.ico whatever the document declares, so answering 404 to a
		// request the panel provokes itself left a permanent error on every cold load — which the UI
		// gates then had to carry an exception for. Rewritten rather than shipped twice, so both
		// paths share one asset, one ETag and one pre-gzipped entry.
		if r.URL.Path == "/favicon.ico" {
			r = r.Clone(r.Context())
			r.URL.Path = "/favicon.svg"
		}
		etag := s.uiETag()
		w.Header().Set("Cache-Control", "no-cache") // always revalidate
		w.Header().Set("ETag", etag)
		if gzCache.variesByEncoding(r) {
			w.Header().Set("Vary", "Accept-Encoding")
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		// Serve the cached gzip body directly. This writes Content-Encoding itself, and because the
		// response is already encoded, gzipResponseWriter must NOT compress it again (it skips any
		// response that already declares an encoding — see decide()).
		if gzCache.serve(w, r) {
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// uiETag is a content hash of the embedded UI assets, computed once. Weak ETag
// (W/) because gzip changes the on-the-wire bytes per representation.
func (s *Server) uiETag() string {
	s.etagOnce.Do(func() { s.etag = computeUIETag(s.ui) })
	return s.etag
}

// computeUIETag hashes EVERY embedded UI asset (walked + sorted for determinism, each file's NAME and
// CONTENT folded in so add/remove/rename/edit all change the hash). A hardcoded file list was used
// before and kept omitting new assets — first i18n.js, then iptv-i18n.js — so their edits
// returned a 304 and browsers kept a stale UI. Walking the tree eliminates that recurring omission.
func computeUIETag(ui fs.FS) string {
	h := fnv.New64a()
	var names []string
	_ = fs.WalkDir(ui, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, p)
		}
		return nil
	})
	sort.Strings(names)
	for _, name := range names {
		if b, err := fs.ReadFile(ui, name); err == nil {
			_, _ = h.Write([]byte(name + "\x00"))
			_, _ = h.Write(b)
		}
	}
	return fmt.Sprintf(`W/"wr-%x"`, h.Sum64())
}

// logRequests logs only mutating requests and errors — never the high-frequency
// GET polls (traffic/health), which would otherwise flood the router's logread.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		if mutating || sw.status >= 400 {
			log.Printf("%s %s %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

// statusWriter records the response status while passing everything through.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

// Flush keeps SSE / streaming working through the wrapper (the traffic-stream
// handler asserts http.Flusher directly).
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController (used by httputil.ReverseProxy for the
// Clash proxy) reach the underlying ResponseWriter's Flusher/Hijacker through
// this access-log wrapper, instead of silently losing them.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ---- gzip ----

var gzipPool = sync.Pool{New: func() any {
	gz, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return gz
}}

// gzipMiddleware compresses compressible responses for clients that accept gzip.
// It skips the streaming endpoints (the SSE traffic stream and the Clash reverse
// proxy) and non-text content (the QR PNG), deciding from the response Content-Type.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") ||
			r.URL.Path == "/api/traffic/stream" ||
			r.URL.Path == "/api/netdiag/stream" ||
			strings.HasPrefix(r.URL.Path, "/api/clash/") {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzipPool.Get().(*gzip.Writer)
		gw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
		defer func() {
			if gw.use == useGzip {
				_ = gw.gz.Close()
			}
			gzipPool.Put(gz)
		}()
		next.ServeHTTP(gw, r)
	})
}

const (
	useUnknown = iota
	useGzip
	usePlain
)

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	use         int
	wroteHeader bool
}

// decide picks gzip vs passthrough from the Content-Type the handler set, and
// (when gzipping) re-targets the pooled writer at the real ResponseWriter.
func (w *gzipResponseWriter) decide() {
	if w.use != useUnknown {
		return
	}
	// Already encoded by the handler (the pre-compressed static cache): compressing again would
	// produce a double-gzipped body the browser cannot read.
	if w.Header().Get("Content-Encoding") != "" {
		w.use = usePlain
		return
	}
	if gzipCompressible(w.Header().Get("Content-Type")) {
		w.use = useGzip
		w.gz.Reset(w.ResponseWriter)
		w.Header().Del("Content-Length") // length changes after compression
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
	} else {
		w.use = usePlain
	}
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.decide()
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.use == useGzip {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipResponseWriter) Flush() {
	if w.use == useGzip {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func gzipCompressible(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "css") ||
		strings.Contains(ct, "svg") ||
		strings.Contains(ct, "xml")
}

// ---- same-origin (CSRF) guard ----

// sameOriginGuard rejects state-changing requests (POST/PUT/PATCH/DELETE) that
// arrive with a *cross-origin* Origin (or, as a fallback, Referer) header.
//
// The panel binds to :8088 on all interfaces, has no authentication, and decodes
// JSON bodies without requiring a non-simple Content-Type — so without this guard
// a malicious web page open in any LAN browser could silently POST to
// http://<router>:8088/api/service/restart, /api/apply, /api/apply/rollback,
// /api/updater/self/install, /api/server/provision, … (a cross-origin fetch in
// no-cors mode, or a plain <form> auto-submit, is a CORS "simple request" that
// sends with no preflight). That is classic CSRF against a router admin panel.
//
// A browser ALWAYS attaches an Origin to a cross-origin fetch/XHR and to form
// POSTs, so checking it closes the browser-borne vector while leaving the
// same-origin SPA untouched (its Origin equals our Host). Non-browser clients
// (curl, scripts, the service's own calls) send no Origin/Referer and are allowed
// — they are not the confused-deputy threat this defends against. Malformed or
// mismatched values fail closed (403).
//
// Caveat: this compares the Origin host to the request Host as the server sees it.
// If the panel is ever fronted by a reverse proxy that rewrites Host while the
// browser keeps the public Origin, legitimate requests would be rejected; such a
// deployment must forward the original Host (or terminate same-origin upstream).
// It does NOT stop DNS-rebinding (Origin==Host post-rebind) — that needs Host
// allow-listing, tracked separately so we don't risk locking out valid hostnames.
func sameOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r) // safe (non-mutating) methods need no guard
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !originMatchesHost(origin, r.Host) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
				return
			}
		} else if ref := r.Header.Get("Referer"); ref != "" {
			// Older browsers may omit Origin on form POSTs but still send Referer.
			if !originMatchesHost(ref, r.Host) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originMatchesHost reports whether the authority (host:port) of an Origin or
// Referer URL equals the request's Host. Fails closed on anything unparseable.
func originMatchesHost(originOrReferer, host string) bool {
	u, err := url.Parse(originOrReferer)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == host
}

// ---- request body size cap ----

// maxRequestBody bounds how much of any single request body the server will
// buffer. The panel is LAN-reachable and unauthenticated, and every JSON handler
// decodes r.Body without its own limit, so without this cap one oversized POST
// from any LAN host (the same-origin guard still lets header-less curl/script
// clients through) could buffer hundreds of MB and OOM the ~256 MB router — and
// the kernel OOM-killer could take sing-box, i.e. the family's routing, down with
// it. 16 MiB is far above any legitimate body (configs/IDs are KB; the largest is
// a pasted subscription, and the fetched-subscription reader already caps content
// at 8 MiB) while trivially defeating the exhaustion attack.
const maxRequestBody = 16 << 20

// slowBodyReadTimeout bounds how long the server will spend READING a request body, as opposed to
// how many bytes it will accept. MaxBytesReader caps the size; it does nothing about the RATE the
// bytes arrive, so an unauthenticated LAN client can hold a POST/PUT open indefinitely by trickling
// one byte at a time, pinning a goroutine and a file descriptor per connection until a ~256 MB
// router runs out — a slowloris the byte cap is blind to. The window is deliberately generous: any
// legitimate body is small (configs/IDs are KB, a pasted subscription a few KB more, and the 16 MiB
// ceiling is far above anything real), so even a 16 MiB import over a slow link finishes with room
// to spare, while an attacker who wants to hold connections for hours is cut off. A package var, not
// a const, only so a test can shorten it — production never rewrites it.
var slowBodyReadTimeout = 2 * time.Minute

// limitBody wraps r.Body in a MaxBytesReader so a read past maxRequestBody fails
// instead of growing unbounded, and bounds the TIME spent reading it (slowBodyReadTimeout) so a
// slow-trickle body cannot pin the connection forever. The JSON handlers already surface a body-read
// error as a 400, so legitimate traffic is unaffected and the cap is invisible
// until something abusive hits it. GET, HEAD, and OPTIONS are skipped: those
// methods never carry a meaningful body, and Dashboard polls (GET /api/health,
// GET /api/traffic, …) are the highest-frequency requests on a router, so
// avoiding the per-request allocation + wrapper there is a worthwhile saving.
// Skipping them also means a long-lived streaming GET (the SSE endpoints, which set their own
// per-frame WRITE deadline) never has a body-READ deadline imposed on it.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
				// Best-effort: SetReadDeadline returns an error on a ResponseWriter whose connection
				// does not support deadlines (e.g. httptest.ResponseRecorder), where there is no socket
				// to slowloris anyway — ignore it and leave the byte cap as the only bound there.
				_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(slowBodyReadTimeout))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Host allow-list (DNS-rebinding guard) ----

// hostAllowGuard rejects (403) any request whose Host this router does not answer to. It is the
// DNS-rebinding defense the same-origin guard cannot provide: after a rebind Origin==Host both equal
// the attacker's hostname, so that guard passes and only pinning Host helps. It applies to ALL
// methods and every route, static UI included — a rebind can GET secrets, not just POST.
//
// An empty allowed_hosts is SECURE BY DEFAULT, not permissive: the request must still carry a Host
// this machine actually has (an interface IP, loopback, or the OS hostname). Operator entries are
// ADDITIVE to that base rather than replacing it, so a narrow or mistaken allowed_hosts can never
// lock the panel out — the LAN IP keeps working, and the list can be fixed from the live UI.
//
// The decision is taken per request through accessors, so a saved allow-list or compatibility flag
// takes effect without a restart.
func hostAllowGuard(d *hostDecider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.allow(r.Host) {
			// The Host is echoed back to nobody: the body is fixed text, so a rejected attacker
			// hostname is never reflected into a response. The rejection is live security state,
			// not reusable content; prevent a shared/proxy cache from retaining it.
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// normalizeHost reduces a Host/authority to a bare host for comparison: strips any :port, IPv6
// brackets, surrounding space and the FQDN trailing dot, and lower-cases it. The trailing dot
// matters: "router.lan." and "router.lan" are the same name to a resolver, so treating them as
// different would let one form bypass an allow-list entry written in the other.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	// A bare "::" or an all-dots value must not normalize to something matchable.
	for strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	return h
}

// ---- security response headers ----

// securityHeaders sets defensive headers on every reply. The panel is an
// unauthenticated LAN admin UI with one-click state-changing controls (Apply /
// Apply&Save in the header, Rollback / Restart elsewhere), so the chief residual
// browser risk AFTER the same-origin/CSRF guard is clickjacking: a malicious page
// can frame the panel and trick the user into clicking those controls — and since
// such a click is genuinely same-origin, the CSRF guard does NOT stop it.
// X-Frame-Options + CSP frame-ancestors make the browser refuse to render the
// panel in any frame, closing that gap. nosniff blocks MIME-confusion, and
// Referrer-Policy keeps panel URLs (incl. /api/sub/<token>) out of the Referer
// header sent to external sites.
//
// The CSP also pins script-src to 'self' — the panel is unauthenticated, so an
// injected/reflected script would be game-over; this neutralises that class even
// if a sink exists. It works because the bundled UI loads only same-origin
// scripts (i18n.js, nav.js, app.js) and has no inline <script> or on*= handlers
// (the former nav-toggle handler moved to nav.js for exactly this). We do NOT set
// style-src/img-src/connect-src/default-src: the UI uses inline style attributes
// (a style-src would need 'unsafe-inline', and style injection can't execute JS),
// so leaving them unset keeps styles/images/fetches unrestricted — meaning this
// policy can only ever affect scripts, never silently break the rest of the UI.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}
