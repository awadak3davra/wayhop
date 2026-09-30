package server

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"wayhop/internal/exporter"
	"wayhop/internal/importer"
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
			// The export is the endpoint's full share link / .conf — UUID, password,
			// reality keys, WireGuard private key. Keep it out of any browser/proxy cache,
			// matching the backup/config/job-snapshot exports.
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, res)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "endpoint not found")
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

const hiddenSubscriptionSource = "configured source (details hidden)"

var subscriptionURLPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+`)

// redactSubscriptionSource returns a display-only provider identity. Subscription
// URLs routinely put the account credential in userinfo, a query parameter, or a
// bearer-like path segment, so the safe allow-list is deliberately small: scheme,
// hostname, and an explicit port. Everything after the authority is represented by
// an ellipsis instead of trying to guess which path or query names are sensitive.
//
// The stored URL remains untouched and is still used by refreshSubscriptionOnce.
func redactSubscriptionSource(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return hiddenSubscriptionSource
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return hiddenSubscriptionSource
	}
	host := u.Hostname()
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") { // bracket an IPv6 literal
		host = "[" + host + "]"
	}
	return scheme + "://" + host + "/…"
}

// redactSubscriptionError keeps useful error context while removing every URL.
// Besides the provider's HTTP URL, parser errors can mention a credential-bearing
// vless:// / trojan:// line returned by that provider. No public status response or
// log message needs those credentials to explain that a refresh failed.
func redactSubscriptionError(raw string) string {
	return subscriptionURLPattern.ReplaceAllStringFunc(raw, func(found string) string {
		// Error formatting commonly puts punctuation immediately after a URL. Keep it
		// outside the replacement so the surrounding sentence remains readable.
		core := strings.TrimRight(found, ".,;:)]}")
		suffix := found[len(core):]
		u, err := url.Parse(core)
		if err == nil {
			scheme := strings.ToLower(u.Scheme)
			if scheme == "http" || scheme == "https" {
				return redactSubscriptionSource(core) + suffix
			}
			if scheme != "" {
				return scheme + "://…" + suffix
			}
		}
		return "[source hidden]" + suffix
	})
}

// handleSubInfo returns only the imported subscription's public refresh state.
// The raw URL is intentionally absent: Source is a display-only scheme+host value,
// while refresh operations continue to read the full URL from the private config.
func (s *Server) handleSubInfo(w http.ResponseWriter, _ *http.Request) {
	c := s.config()
	last, added, errStr := s.subStatus.snapshot()
	var lastUnix int64
	if !last.IsZero() {
		lastUnix = last.Unix()
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":        c.Subscription.URL != "",
		"source":            redactSubscriptionSource(c.Subscription.URL),
		"refresh_hours":     c.Subscription.RefreshHours,
		"last_refresh_unix": lastUnix, // 0 = never refreshed
		"last_added":        added,
		"last_error":        redactSubscriptionError(errStr), // "" = last attempt OK
	})
}
