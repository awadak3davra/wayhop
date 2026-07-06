// Package iptv is the pure, cgo-free core of the IPTV plugin: parse → filter → dedup → sort →
// render → health-probe an M3U playlist. It has NO device/network dependence beyond an injected
// http.Client (the prober), so every stage is fixture-unit-testable and cross-compiles to
// mipsle/aarch64. The plugin module (internal/feature/iptv) wires these stages to fetch/serve/refresh.
package iptv

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// Channel is one entry parsed from an M3U playlist. Parse fills the identity/stream fields; the
// health fields (Live/LastGood/…) are populated later by Probe.
type Channel struct {
	TvgID     string   `json:"tvg_id,omitempty"`
	Name      string   `json:"name"`
	Logo      string   `json:"logo,omitempty"`
	Group     string   `json:"group,omitempty"`
	URL       string   `json:"url"`
	UserAgent string   `json:"user_agent,omitempty"` // lifted from #EXTVLCOPT/#EXTHTTP for the prober
	Referrer  string   `json:"referrer,omitempty"`
	Headers   []string `json:"headers,omitempty"` // raw #EXTVLCOPT/#EXTHTTP/#KODIPROP lines, preserved verbatim

	// Extra holds every EXTINF attribute NOT modeled as a dedicated field (tvg-chno channel numbers,
	// catchup/catchup-source/catchup-days for provider catch-up, tvg-shift EPG offset, tvg-name, …), in
	// source order, preserved verbatim through parse→render so a player keeps the provider metadata it
	// relies on. tvg-id/tvg-logo/group-title are excluded (re-emitted from their own fields).
	Extra [][2]string `json:"extra,omitempty"`

	// Health (filled by Probe, not Parse).
	Live       bool   `json:"live"`
	Status     string `json:"status,omitempty"` // "alive" | "geo" (region-locked) | "dead"
	LastGood   int64  `json:"last_good,omitempty"`
	LastFail   int64  `json:"last_fail,omitempty"`
	ConsecFail int    `json:"-"`
	ConsecOK   int    `json:"-"`
}

// Playlist is a parsed M3U: its channels plus the header url-tvg (EPG guide) attribute, preserved so
// the emitted playlist can pass the guide through to the player.
type Playlist struct {
	URLTvg   string    `json:"url_tvg,omitempty"`
	Channels []Channel `json:"channels"`
}

// maxLine bounds a single M3U line (long EXTINF attr lists / URLs) so a malicious/huge line can't
// blow up memory on a small router. The body itself is separately capped by the fetch io.LimitReader.
const maxLine = 1 << 20 // 1 MiB

// bom is the UTF-8 byte-order mark (U+FEFF) some playlists prefix; it is written as an escape
// because a literal BOM byte mid-file is a Go compile error ("illegal byte order mark").
var bom = string(rune(0xFEFF))

// Parse reads an M3U/M3U8 playlist leniently: it streams line-by-line (never ReadAll), skips
// unknown/malformed lines, drops an #EXTINF with no following URL, strips a leading UTF-8 BOM, and
// preserves per-channel option lines (#EXTVLCOPT/#EXTHTTP/#KODIPROP) verbatim while lifting
// http-user-agent / http-referrer into UserAgent/Referrer for the health prober.
func Parse(r io.Reader) (*Playlist, error) {
	pl := &Playlist{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	var cur *Channel // the channel being assembled between its #EXTINF and its URL line
	for sc.Scan() {
		line := strings.TrimPrefix(strings.TrimSpace(sc.Text()), bom)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "#EXTM3U"):
			// url-tvg is the common EPG header; x-tvg-url is a widespread alias (several iptv-org
			// category/region playlists use it), so accept either.
			if v := extAttr(line, "url-tvg"); v != "" {
				pl.URLTvg = v
			} else if v := extAttr(line, "x-tvg-url"); v != "" {
				pl.URLTvg = v
			}
		case strings.HasPrefix(line, "#EXTINF"):
			cur = parseExtinf(line)
		case strings.HasPrefix(line, "#EXTVLCOPT"), strings.HasPrefix(line, "#EXTHTTP"), strings.HasPrefix(line, "#KODIPROP"):
			if cur != nil {
				cur.Headers = append(cur.Headers, line)
				applyOpt(cur, line)
			}
		case strings.HasPrefix(line, "#"):
			// other comments / directives — ignore
		default:
			// a URL line completes the current channel.
			if cur != nil {
				cur.URL = line
				if cur.Name == "" {
					cur.Name = line
				}
				pl.Channels = append(pl.Channels, *cur)
				cur = nil
			}
		}
	}
	return pl, sc.Err()
}

// parseExtinf parses `#EXTINF:<duration> <k="v" …>,<display name>` into a Channel. The name/attr
// split is the FIRST comma that is NOT inside a quoted attribute value (channel names may contain
// commas after that).
func parseExtinf(line string) *Channel {
	ch := &Channel{}
	rest := strings.TrimPrefix(line, "#EXTINF:")
	inQ, comma := false, -1
	for i, r := range rest {
		if r == '"' {
			inQ = !inQ
		} else if r == ',' && !inQ {
			comma = i
			break
		}
	}
	attrs := rest
	if comma >= 0 {
		attrs = rest[:comma]
		ch.Name = strings.TrimSpace(rest[comma+1:])
	}
	ch.TvgID = extAttr(attrs, "tvg-id")
	ch.Logo = extAttr(attrs, "tvg-logo")
	ch.Group = extAttr(attrs, "group-title")
	if ch.Name == "" {
		ch.Name = extAttr(attrs, "tvg-name")
	}
	// Preserve every other attribute verbatim (channel numbers, catch-up, EPG shift, …). The known
	// fields above are extracted with extAttr (unchanged behavior); extraAttrs only collects the rest.
	ch.Extra = extraAttrs(attrs)
	return ch
}

// extraAttrs tokenizes the key="value" pairs of an EXTINF attribute prefix in source order and returns
// those NOT modeled as dedicated fields (tvg-id/tvg-logo/group-title, which Render re-emits from their
// own fields). Keys are restricted to a safe attribute charset and unquoted/malformed fragments are
// skipped — the scanner always advances, so it terminates and never panics on adversarial input.
func extraAttrs(s string) [][2]string {
	var out [][2]string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') { // separators
			i++
		}
		ks := i
		for i < len(s) && isAttrKeyByte(s[i]) {
			i++
		}
		key := s[ks:i]
		if key == "" || i >= len(s) || s[i] != '=' {
			if i < len(s) {
				i++ // not a key= start — advance one byte to guarantee progress
			}
			continue
		}
		i++ // '='
		if i >= len(s) || s[i] != '"' {
			continue // unquoted value — skip
		}
		i++ // opening quote
		vs := i
		for i < len(s) && s[i] != '"' {
			i++
		}
		val := s[vs:i]
		if i < len(s) {
			i++ // closing quote
		}
		// Case-SENSITIVE exclusion, matching extAttr's case-sensitive extraction: a lowercase modeled
		// key is re-emitted from its field (skip here to avoid duplication), but a mixed-case one
		// (TVG-ID, Group-Title) — which extAttr does NOT capture — falls through and is preserved
		// verbatim in Extra rather than being lost by both paths.
		switch key {
		case "tvg-id", "tvg-logo", "group-title":
		default:
			out = append(out, [2]string{key, val})
		}
	}
	return out
}

// isAttrKeyByte reports whether b is valid in an EXTINF attribute name (letters, digits, '-', '_').
func isAttrKeyByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

// extAttr extracts the value of a `key="value"` attribute from an EXTINF/EXTM3U line ("" if absent).
// The match must be at a key BOUNDARY: `group-title="` is NOT matched inside a longer key such as
// `x-group-title="`, so a provider extension attribute can't fabricate a phantom modeled attribute.
func extAttr(s, key string) string {
	k := key + `="`
	for from := 0; ; {
		i := strings.Index(s[from:], k)
		if i < 0 {
			return ""
		}
		i += from
		if i == 0 || !isAttrKeyByte(s[i-1]) { // boundary: not a suffix of a longer attribute name
			i += len(k)
			j := strings.IndexByte(s[i:], '"')
			if j < 0 {
				return ""
			}
			return s[i : i+j]
		}
		from = i + 1 // suffix match — keep scanning for a properly-anchored occurrence
	}
}

// applyOpt lifts a per-channel HTTP header option into UserAgent/Referrer (the line is also kept
// verbatim in Headers). Handles #EXTVLCOPT:http-user-agent=… / http-referrer=… and the #EXTHTTP JSON
// form; #KODIPROP is preserved only (its inputstream props are player-specific).
func applyOpt(ch *Channel, line string) {
	switch {
	case strings.HasPrefix(line, "#EXTVLCOPT:"):
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "#EXTVLCOPT:"), "=")
		if !ok {
			return
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "http-user-agent":
			ch.UserAgent = strings.TrimSpace(v)
		case "http-referrer", "http-referer":
			ch.Referrer = strings.TrimSpace(v)
		}
	case strings.HasPrefix(line, "#EXTHTTP:"):
		var m map[string]string
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "#EXTHTTP:")), &m) != nil {
			return
		}
		for k, v := range m {
			switch strings.ToLower(k) {
			case "user-agent":
				ch.UserAgent = v
			case "referer", "referrer":
				ch.Referrer = v
			}
		}
	}
}
