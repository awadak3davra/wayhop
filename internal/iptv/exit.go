package iptv

import "strings"

// InferExitCountry guesses the exit country of a proxy endpoint from free-text signals (typically its
// display name and its server hostname), so a WayHop exit can be matched to an IPTV playlist's country
// — many national streams only play from an in-country IP. It is a best-effort OFFLINE heuristic (no
// geo-IP database, no network), deliberately CONSERVATIVE to avoid false positives; R2/R3
// (device-gated) refine it against the live exit-IP geolocation. Signals, most-reliable first, across
// texts in order:
//
//  1. a flag emoji (🇷🇺 → ru);
//  2. a whole-word UPPERCASE ISO-3166 alpha-2 code in the catalog (RU, NL, US) — uppercase-only so
//     lowercase English words that happen to be ISO codes ("in", "is", "no", "me") never match;
//  3. a catalog country NAME as a whole-word phrase, case-insensitive ("Russia", "United States").
//
// Returns ("", false) when nothing matches. The first hit wins.
func InferExitCountry(texts ...string) (string, bool) {
	for _, s := range texts {
		if code, ok := flagCode(s); ok {
			return code, true
		}
	}
	for _, s := range texts {
		if code, ok := isoCodeToken(s); ok {
			return code, true
		}
	}
	for _, s := range texts {
		if code, ok := countryNameMatch(s); ok {
			return code, true
		}
	}
	return "", false
}

// flagCode returns the country code of the first regional-indicator flag pair in s whose code is in
// the catalog.
func flagCode(s string) (string, bool) {
	rs := []rune(s)
	for i := 0; i+1 < len(rs); i++ {
		a, b := rs[i], rs[i+1]
		if a >= 0x1F1E6 && a <= 0x1F1FF && b >= 0x1F1E6 && b <= 0x1F1FF {
			code := string(rune('a'+(a-0x1F1E6))) + string(rune('a'+(b-0x1F1E6)))
			if KnownCountry(code) {
				return code, true
			}
		}
	}
	return "", false
}

// isoCodeToken returns the first whole-word 2-letter UPPERCASE token in s that is a catalog code.
func isoCodeToken(s string) (string, bool) {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return !isASCIILetter(r) }) {
		if len(tok) == 2 && tok[0] >= 'A' && tok[0] <= 'Z' && tok[1] >= 'A' && tok[1] <= 'Z' {
			if code := strings.ToLower(tok); KnownCountry(code) {
				return code, true
			}
		}
	}
	return "", false
}

// countryNameMatch returns the code of the first catalog country whose name appears in s as a
// whole-word phrase (case-insensitive). Longest names are tried first so "United States" wins over a
// hypothetical shorter substring.
func countryNameMatch(s string) (string, bool) {
	low := strings.ToLower(s)
	best, bestLen := "", -1
	for code, name := range countryNames {
		n := strings.ToLower(name)
		if len(n) > bestLen && wholePhrase(low, n) {
			best, bestLen = code, len(n)
		}
	}
	if bestLen >= 0 {
		return best, true
	}
	return "", false
}

// wholePhrase reports whether needle occurs in haystack bounded by non-letters (both lowercase).
func wholePhrase(haystack, needle string) bool {
	from := 0
	for {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isASCIILetter(rune(haystack[i-1]))
		end := i + len(needle)
		afterOK := end == len(haystack) || !isASCIILetter(rune(haystack[end]))
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
