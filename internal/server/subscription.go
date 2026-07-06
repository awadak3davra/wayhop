package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"wayhop/internal/exporter"
	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// handleEndpointExport returns one endpoint's share link or .conf so the UI can
// show a QR / copy / download it.
func (s *Server) handleEndpointExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, e := range s.store.Profile().Endpoints {
		if e.ID == id {
			res, ok := exporter.Export(e)
			if !ok {
				writeErr(w, http.StatusUnprocessableEntity, "this protocol has no shareable link or .conf")
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "endpoint not found")
}

// handleQR renders arbitrary text as a QR PNG. POST (not GET) so the payload —
// which may be a secret config — never lands in a URL or the access log.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
		Size int    `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Text == "" {
		writeErr(w, http.StatusBadRequest, "text is required")
		return
	}
	size := b.Size
	if size < 128 || size > 1024 {
		size = 320
	}
	png, err := qrcode.Encode(b.Text, qrcode.Medium, size)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not encode QR: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// subscriptionTitle extracts a human display name from a fetched subscription's
// response headers, "" when none is offered. The clash / subconverter convention
// is a "Profile-Title" header whose value is base64 of the title (case variants
// like "profile-title" are folded by http.Header's canonicalization); some
// providers instead expose only a Content-Disposition filename. We honor both so
// an imported subscription gets the provider's own name instead of a generic one.
// Decoding (base64-or-raw + sanitization) is delegated to importer.DecodeProfileTitle.
func subscriptionTitle(h http.Header) string {
	if h == nil {
		return ""
	}
	if t := importer.DecodeProfileTitle(h.Get("Profile-Title")); t != "" {
		return t
	}
	// Fall back to a Content-Disposition filename, e.g.
	//   attachment; filename="My Servers.txt"  ->  "My Servers"
	if cd := h.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			name := params["filename"]
			if name == "" {
				name = params["filename*"] // RFC 5987 extended form (already decoded by mime)
			}
			// Drop a trailing extension (.txt/.yaml/…) — it's noise in a display name.
			if dot := strings.LastIndexByte(name, '.'); dot > 0 {
				name = name[:dot]
			}
			// A filename is plain text, never base64 — DecodeProfileTitle still
			// sanitizes it and won't base64-mangle a name that isn't valid base64.
			if t := importer.DecodeProfileTitle(name); t != "" {
				return t
			}
		}
	}
	return ""
}

// handleSubInfo returns the subscription token + path (creating the token once),
// plus the imported subscription URL and its auto-refresh interval (hours; 0 =
// off) so the UI can show + manage periodic refresh.
func (s *Server) handleSubInfo(w http.ResponseWriter, r *http.Request) {
	tok := s.subToken()
	c := s.config()
	last, added, errStr := s.subStatus.snapshot()
	var lastUnix int64
	if !last.IsZero() {
		lastUnix = last.Unix()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":             tok,
		"path":              "/api/sub/" + tok,
		"url":               c.Subscription.URL,
		"refresh_hours":     c.Subscription.RefreshHours,
		"last_refresh_unix": lastUnix, // 0 = never refreshed
		"last_added":        added,
		"last_error":        errStr, // "" = last attempt OK
	})
}

// handleSubServe serves the client subscription: base64 of newline-joined share
// links for every enabled, exportable endpoint (the universal v2ray sub format
// understood by v2rayN/NG, Nekobox, Shadowrocket, v2box, …). Phones/apps poll
// this, so a failover swap or key rotation propagates without re-sharing a QR.
func (s *Server) handleSubServe(w http.ResponseWriter, r *http.Request) {
	// Constant-time compare: this token is the only gate on the user's full set of
	// share links (UUIDs/passwords), so don't leak it through a byte-by-byte `!=`
	// timing side-channel. The "" guard stops an unset token from ever matching.
	tok := s.subToken()
	if tok == "" || subtle.ConstantTimeCompare([]byte(r.PathValue("token")), []byte(tok)) != 1 {
		writeErr(w, http.StatusForbidden, "invalid subscription token")
		return
	}
	// Collect the enabled endpoints once; both output formats consume them.
	var enabled []model.Endpoint
	for _, e := range s.store.Profile().Endpoints {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}

	// Serve a friendly, on-brand HTML install page when a *human* opens the
	// subscription URL in a browser (for sharing / onboarding). wantsHTML is
	// deliberately conservative so a VPN client never matches — a false positive
	// would hand a client HTML instead of its config and break the import. This
	// sits BEFORE wantsClash so a ?flag=clash browser still gets clash YAML (an
	// explicit client-format flag forces wantsHTML to false), and every existing
	// client path stays byte-identical.
	if wantsHTML(r) {
		s.serveSubLandingPage(w, r, enabled)
		return
	}

	// Serve clash-meta YAML when the client is a clash/mihomo client — by an
	// explicit ?flag=clash / ?format=clash query, or a clash-family User-Agent.
	// Otherwise fall through to the default base64 v2ray share-link body, which
	// stays byte-identical to before.
	if wantsClash(r) {
		// Carry the failover groups so a clash client keeps the panel's auto-failover
		// (each group -> a clash url-test/fallback/select proxy-group), not a flat list.
		yaml, _ := exporter.ClashConfigWithGroups(enabled, s.store.Profile().Groups)
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Profile-Update-Interval", "12") // hours; hint for clients
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(yaml))
		return
	}

	var links []string
	for _, e := range enabled {
		if link, ok := exporter.ShareLink(e); ok {
			links = append(links, link)
		}
	}
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "12") // hours; hint for clients
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// wantsClash reports whether the subscription request should be served as a
// clash-meta YAML config rather than the default base64 share-link body. It
// triggers on an explicit ?flag=clash / ?format=clash query, or a User-Agent
// (case-insensitive) that names a clash-family client (clash / mihomo / meta).
func wantsClash(r *http.Request) bool {
	q := r.URL.Query()
	if strings.EqualFold(q.Get("flag"), "clash") || strings.EqualFold(q.Get("format"), "clash") {
		return true
	}
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "meta")
}

// wantsHTML reports whether the subscription request should be answered with the
// human-friendly HTML install page instead of a machine config. It is intentionally
// CONSERVATIVE: a VPN client must never match, since serving HTML in place of a
// config would silently break an import.
//
//   - An explicit client-format flag (?flag= / ?format=) means the caller asked for
//     a specific config — never HTML.
//   - An explicit ?web=1 / ?web=true means a deliberate "view in browser" — HTML.
//   - Otherwise only treat it as a browser when BOTH the Accept header offers
//     text/html AND the User-Agent looks like a browser ("mozilla"). VPN clients
//     (v2rayN/NG, sing-box, clash/mihomo, …) send Accept: */* (or none) and a
//     non-browser UA, so they never match.
func wantsHTML(r *http.Request) bool {
	q := r.URL.Query()
	// An explicit client-format request wins: the caller wants a config, not a page.
	if q.Get("flag") != "" || q.Get("format") != "" {
		return false
	}
	// A deliberate "open in browser" override.
	if v := strings.ToLower(q.Get("web")); v == "1" || v == "true" {
		return true
	}
	// Heuristic last resort: a real browser advertises text/html AND a Mozilla UA.
	accept := strings.ToLower(r.Header.Get("Accept"))
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(accept, "text/html") && strings.Contains(ua, "mozilla")
}

// serveSubLandingPage renders a self-contained, on-brand HTML install page for the
// subscription. It deliberately exposes ONLY the (already token-gated) subscription
// URL plus import helpers — never the per-endpoint share links / UUIDs / passwords.
func (s *Server) serveSubLandingPage(w http.ResponseWriter, r *http.Request, enabled []model.Endpoint) {
	// Reconstruct the absolute subscription URL (without query) for the QR + helpers.
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	subURL := scheme + "://" + r.Host + r.URL.Path

	// QR is best-effort: if encoding fails, omit the <img> rather than fail the page.
	var qrTag string
	if png, err := qrcode.Encode(subURL, qrcode.Medium, 320); err == nil {
		data := base64.StdEncoding.EncodeToString(png)
		qrTag = `<img class="qr" width="240" height="240" alt="Subscription QR code" src="data:image/png;base64,` + data + `">`
	}

	// Escape every dynamic value before embedding. The copy button's handler is the STATIC
	// /subcopy.js (web/dist) which reads the URL from the visible <code id="u"> — no inline
	// <script>, so the page works under the panel's CSP (script-src 'self') and no JS-literal
	// escaping of the URL is needed at all.
	subURLHTML := html.EscapeString(subURL) // for visible text / attribute
	subURLQuery := url.QueryEscape(subURL)  // for the deep-link import helpers
	clashHref := html.EscapeString("clash://install-config?url=" + subURLQuery)
	singboxHref := html.EscapeString("sing-box://import-remote-profile?url=" + subURLQuery + "&name=WayHop")

	count := len(enabled)
	connLabel := strconv.Itoa(count) + " connection"
	if count != 1 {
		connLabel += "s"
	}

	page := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>WayHop subscription</title>
<style>
:root{--bg:#0e1116;--card:#161b22;--border:#262d36;--fg:#e6edf3;--muted:#9aa7b4;--accent:#3fb950;--accent-d:#2ea043;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:28px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{margin:0 0 4px;font-size:22px}
.sub{margin:0 0 18px;color:var(--muted);font-size:14px}
.count{display:inline-block;margin-bottom:18px;padding:3px 10px;border:1px solid var(--border);border-radius:999px;
  color:var(--accent);font-size:12px}
.qr{display:block;margin:0 auto 18px;border-radius:10px;background:#fff;padding:10px}
.urlrow{display:flex;gap:8px;align-items:stretch;margin:0 0 16px}
code#u{flex:1;min-width:0;overflow:auto;white-space:nowrap;background:#0b0e13;border:1px solid var(--border);
  border-radius:8px;padding:9px 11px;font-size:12px;color:var(--fg);text-align:left}
button,.btn{cursor:pointer;border:1px solid var(--border);border-radius:8px;padding:9px 13px;font-size:13px;
  font-weight:600;text-decoration:none;display:inline-block}
#copy{background:var(--accent);border-color:var(--accent);color:#06120a}
#copy:hover{background:var(--accent-d)}
.imports{display:flex;gap:8px;margin:0 0 16px}
.imports .btn{flex:1;background:#0b0e13;color:var(--fg)}
.imports .btn:hover{border-color:var(--accent)}
.works{margin:0;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="card">
  <h1>WayHop subscription</h1>
  <p class="sub">Import this into your VPN client</p>
  <div class="count">` + html.EscapeString(connLabel) + `</div>
  ` + qrTag + `
  <div class="urlrow">
    <code id="u">` + subURLHTML + `</code>
    <button id="copy" type="button">Copy</button>
  </div>
  <div class="imports">
    <a class="btn" href="` + clashHref + `">Import to Clash</a>
    <a class="btn" href="` + singboxHref + `">Import to sing-box</a>
  </div>
  <p class="works">Works with: sing-box, v2rayN/NG, Clash Meta / Mihomo, Hiddify, Streisand</p>
</div>
<script src="/subcopy.js" defer></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

// newSubToken returns a fresh random subscription token (96 bits / 24 hex chars).
func newSubToken() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// subToken returns the subscription token, generating + persisting one on first use.
func (s *Server) subToken() string {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfg.Subscription.Token == "" {
		tok, err := newSubToken()
		if err != nil {
			return "" // never happens on a healthy host
		}
		s.cfg.Subscription.Token = tok
		if err := s.cfg.Save(); err != nil {
			// Non-fatal: the token is live in memory for this session. Log it (siblings do) so a
			// read-only overlay / ENOSPC that would silently regenerate the token every restart is
			// visible instead of a mystery "my subscription URL keeps changing".
			log.Printf("subscription: could not persist the first-use token: %v", err)
		}
	}
	return s.cfg.Subscription.Token
}

// handleSubRotate generates a FRESH subscription token, invalidating the current
// /api/sub/{token} URL. Use it if that URL leaked — the token is the only gate on every
// endpoint's share-link secrets (UUIDs/passwords). Clients must be re-pointed at the new
// URL afterward (their old URL will 403). Same-origin-guarded (it is a panel action).
func (s *Server) handleSubRotate(w http.ResponseWriter, r *http.Request) {
	tok, err := newSubToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a token")
		return
	}
	s.cfgMu.Lock()
	s.cfg.Subscription.Token = tok
	err = s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "path": "/api/sub/" + tok})
}
