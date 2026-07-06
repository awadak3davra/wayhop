package importer

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"wayhop/internal/model"
)

// ParseSubscription parses a subscription blob into endpoints, returning a
// per-failure error list. It accepts either a base64-encoded body (the common
// "v2ray subscription" format) or plain text, with one share link per line.
func ParseSubscription(text string) ([]model.Endpoint, []string) {
	// A leading UTF-8 BOM (U+FEFF) is not whitespace, so TrimSpace leaves it on the
	// first line — which would make the first line "<BOM>proxies:" miss the clash key
	// scan and the share-link/base64 detection, silently dropping the whole config.
	// Strip it once.
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.TrimSpace(text)

	// Clash / Clash-Meta YAML is the dominant config format in this ecosystem and
	// is structurally distinct from a share-link / base64 subscription (it has a
	// top-level `proxies:` key). Detect + parse it before the line-by-line/base64
	// path so a pasted clash config yields connections. looksLikeClash is strict
	// (rejects share links and base64 blobs), so this never shadows the existing
	// paths for a non-clash input.
	if looksLikeClash(text) {
		return ParseClash(text)
	}

	// A pasted sing-box config.json is the INVERSE of the generator — a JSON object
	// with an outbounds/endpoints array. Detect + parse it before the line-by-line/
	// base64 path so it yields connections. looksLikeSingbox is strict (valid JSON
	// object with outbounds OR endpoints), so it never shadows a share link, a base64
	// blob (json.Valid rejects those), or a clash YAML doc.
	if looksLikeSingbox(text) {
		return ParseSingbox(text)
	}

	// A base64 subscription has no scheme markers until decoded.
	if !strings.Contains(text, "://") && !strings.Contains(text, "[Interface]") {
		if dec := decodeB64(text); dec != "" {
			text = dec
		}
	}

	eps := []model.Endpoint{}
	errs := []string{}
	// genID is protocol+server+port, so two transport/TLS variants of the same
	// host (a common subscription shape) produce the same ID and would silently
	// overwrite each other on bulk import. Keep batch IDs distinct by suffixing
	// collisions; single endpoints keep their natural slug.
	seen := map[string]bool{}
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := Parse(line)
		if err != nil {
			errs = append(errs, line[:min(len(line), 40)]+": "+err.Error())
			continue
		}
		e.ID = uniqueID(e.ID, seen)
		eps = append(eps, *e)
	}
	return eps, errs
}

// maxTitleLen caps a decoded subscription title so a hostile/garbage server can't
// push an absurdly long display name into the UI / group name.
const maxTitleLen = 80

// DecodeProfileTitle turns the value of a subscription's "Profile-Title" response
// header into a human display name. The clash / subconverter convention is that
// the value is base64 of the title (so non-ASCII names survive an HTTP header),
// but some providers send the title verbatim — so we accept either.
//
// Strategy: try a base64 decode; accept the decoded form ONLY if it is clean,
// printable UTF-8 text (this is the discriminator — a raw title like "Main" is
// itself valid base64 yet decodes to binary garbage, so we must reject that and
// fall back to the raw value). Otherwise use the raw value. The result is then
// sanitized (control chars stripped, whitespace collapsed, length-capped). An
// empty / un-usable header yields "" so the caller keeps its own naming.
func DecodeProfileTitle(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	title := raw
	if dec := decodeTitleB64(raw); dec != "" {
		title = dec
	}
	return sanitizeTitle(title)
}

// decodeTitleB64 returns the base64-decoded form of s only when it both decodes
// cleanly to printable UTF-8 text AND that text is "obviously decoded content"
// (it carries a space or a non-ASCII rune). Otherwise it returns "" so the caller
// keeps the raw value.
//
// The second condition is the key guard against false positives: a short raw
// title like "Main" or "NL" is itself valid base64 and decodes to short
// base64-alphabet ASCII ("1\xa8\xa7", "4") — without this check those raw names
// would be silently mangled. A genuinely base64-encoded title almost always
// decodes to text with whitespace or non-ASCII characters (multi-word names,
// flags, CJK), which a raw base64-string can't itself contain.
func decodeTitleB64(s string) string {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(s)
		if err != nil || len(b) == 0 {
			continue
		}
		dec := string(b)
		if isPrintableText(dec) && looksDecoded(dec) {
			return dec
		}
	}
	return ""
}

// isPrintableText reports whether s is valid UTF-8 made only of graphic runes and
// blanks (spaces/tabs) — i.e. plausibly a human-readable title, not binary data.
func isPrintableText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\t' || r == ' ' {
			continue
		}
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

// looksDecoded reports whether s carries a signal that it is decoded title text
// rather than a string that merely happens to be valid base64: a whitespace rune
// or any non-ASCII rune. (A raw base64 token is, by construction, ASCII with no
// spaces.) This distinguishes "Main Servers"/"🇳🇱 NL" (accept the decode) from a
// short raw title like "NL" whose base64 interpretation is spurious.
func looksDecoded(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// sanitizeTitle strips control characters, collapses runs of whitespace to a
// single space, and caps the length so a subscription title is safe to use as a
// display name / group name.
func sanitizeTitle(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	out := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(out) > maxTitleLen {
		// Trim on a rune boundary, not a byte boundary, to avoid splitting UTF-8.
		n := 0
		for i := range out {
			if n == maxTitleLen {
				out = out[:i]
				break
			}
			n++
		}
		out = strings.TrimSpace(out)
	}
	return out
}

// uniqueID returns id if unused, else id-2 / id-3 / … so each parsed endpoint in
// a batch keeps a distinct ID. Records the chosen id in seen.
func uniqueID(id string, seen map[string]bool) string {
	if id != "" && !seen[id] {
		seen[id] = true
		return id
	}
	for n := 2; ; n++ {
		cand := id + "-" + strconv.Itoa(n)
		if !seen[cand] {
			seen[cand] = true
			return cand
		}
	}
}
