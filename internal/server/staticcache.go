package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// staticGzipCache serves the embedded UI assets PRE-COMPRESSED, compressing each file at most once
// for the life of the process.
//
// Why this exists: gzipMiddleware compresses every response on every request. That is fine for small
// JSON, but the UI bundle decodes to ~474 KB, and on a router CPU gzipping it per page load measured
// at ~1.15 s for app.js alone — the single largest contributor to first paint, dwarfing the actual
// transfer. The assets come from an embedded FS and cannot change while the process runs, so the
// compressed bytes are perfectly cacheable: the first request pays once, every later one (and every
// other client) is served straight from memory.
//
// Memory cost is bounded and small — the whole compressed UI is ~200 KB, versus the seconds of CPU
// it replaces on exactly the device that can least afford it.
type staticGzipCache struct {
	ui fs.FS
	mu sync.RWMutex
	m  map[string][]byte // clean path -> gzipped body
}

func newStaticGzipCache(ui fs.FS) *staticGzipCache {
	return &staticGzipCache{ui: ui, m: map[string][]byte{}}
}

// gzipMinBytes: below this, compression saves less than the bookkeeping costs, and tiny files are not
// where the router's CPU goes. They fall through to the normal path.
const gzipMinBytes = 1024

// get returns the gzipped body for name, compressing on first use. ok=false means "serve normally"
// (missing, too small, or not a compressible type) — never an error the caller must handle.
func (c *staticGzipCache) get(name string) (body []byte, ok bool) {
	c.mu.RLock()
	b, hit := c.m[name]
	c.mu.RUnlock()
	if hit {
		return b, b != nil
	}

	raw, err := fs.ReadFile(c.ui, name)
	if err != nil || len(raw) < gzipMinBytes || !gzipCompressible(contentTypeFor(name)) {
		c.mu.Lock()
		c.m[name] = nil // remember the negative answer so we do not re-stat on every request
		c.mu.Unlock()
		return nil, false
	}

	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression) // one-time cost, so use the best ratio
	_, _ = zw.Write(raw)
	_ = zw.Close()
	out := buf.Bytes()
	// If compression did not actually help, do not serve it encoded.
	if len(out) >= len(raw) {
		out = nil
	}

	c.mu.Lock()
	c.m[name] = out
	c.mu.Unlock()
	return out, out != nil
}

// contentTypeFor guesses a content type from the extension, matching what http.FileServer would set.
func contentTypeFor(name string) string {
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func staticAssetName(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", false
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	return name, true
}

// bodyFor returns the cached gzip representation selected by the request. Keeping selection in one
// helper lets a conditional response advertise the same Vary metadata as the corresponding 200,
// without duplicating path/encoding rules that could drift apart.
func (c *staticGzipCache) bodyFor(r *http.Request) (body []byte, name string, ok bool) {
	name, ok = staticAssetName(r)
	if !ok || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return nil, "", false
	}
	body, ok = c.get(name)
	return body, name, ok
}

// variesByEncoding reports whether this asset can have both plain and gzip representations. Every
// 200 and 304 for such an asset must carry Vary, including a request that selected the plain body;
// if only gzip responses advertise it, a cache can store an earlier plain response as generic.
//
// This deliberately follows the outer gzip middleware's CONTENT-TYPE decision, not membership in
// the pre-compressed cache. Assets below gzipMinBytes bypass that cache but are still compressed by
// gzipMiddleware, so tying Vary to c.get made their 200 vary while their early 304 did not.
func (c *staticGzipCache) variesByEncoding(r *http.Request) bool {
	name, methodOK := staticAssetName(r)
	if !methodOK || !gzipCompressible(contentTypeFor(name)) {
		return false
	}
	info, err := fs.Stat(c.ui, name)
	return err == nil && !info.IsDir()
}

// serve writes the cached gzip body for the request, reporting whether it handled it. It only acts
// for GET/HEAD requests from clients that accept gzip; anything else falls through to the caller's
// normal file serving.
func (c *staticGzipCache) serve(w http.ResponseWriter, r *http.Request) bool {
	body, name, ok := c.bodyFor(r)
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("Content-Type", contentTypeFor(name))
	h.Set("Content-Encoding", "gzip")
	h.Set("Vary", "Accept-Encoding")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, bytes.NewReader(body))
	}
	return true
}
