package iptv

import (
	"regexp"
	"strings"
)

// adultRe matches UNAMBIGUOUS adult/NSFW terms as WHOLE WORDS (\b anchors) so it never
// false-positives. It deliberately EXCLUDES ambiguous words that appear in legitimate channel names
// — "adult" (Adult Swim / Adult Contemporary), "naked"/"nude" (Naked Science), "hardcore" (Hardcore
// History), bare "sex" (Middlesex / Sussex / Essex) — because the iptv-org sources are already
// NSFW-free (this is defense-in-depth on a family router) and a false positive that silently drops a
// real channel is worse than missing a rare stray. Case-insensitive.
var adultRe = regexp.MustCompile(`(?i)(\b(?:xxx|porn|pornhub|xhamster|redtube|brazzers|hentai|nsfw|erotica?|onlyfans|camgirl|playboy|sexy)\b|\b18\+)`)

// FilterOptions tunes Filter.
type FilterOptions struct {
	AdultAllow bool            // when false (the default), channels matching adultRe (name/group) are dropped
	Blocklist  map[string]bool // tvg-ids OR exact stream URLs to always drop (DMCA/takedown propagation)
}

// FilterCounts breaks down what Filter dropped, for the UI status line.
type FilterCounts struct {
	Adult   int // dropped by the adult filter (only when AdultAllow is false)
	Blocked int // dropped by the blocklist
	Junk    int // dropped as unplayable/placeholder (no URL, or a blank / "Undefined" name)
}

// Filter drops, in precedence order: blocklisted channels (by tvg-id or URL), junk (no URL, or a
// blank / "Undefined" name), and — unless AdultAllow — adult channels. Pure; the input slice is not
// mutated; returns the kept channels + the drop breakdown.
func Filter(chs []Channel, opts FilterOptions) ([]Channel, FilterCounts) {
	out := make([]Channel, 0, len(chs))
	var c FilterCounts
	for _, ch := range chs {
		switch {
		case blocked(opts.Blocklist, ch):
			c.Blocked++
		case ch.URL == "" || isJunkName(ch.Name):
			c.Junk++
		case !opts.AdultAllow && adultRe.MatchString(ch.Name+" "+ch.Group):
			c.Adult++
		default:
			out = append(out, ch)
		}
	}
	return out, c
}

func blocked(bl map[string]bool, ch Channel) bool {
	if len(bl) == 0 {
		return false
	}
	return (ch.TvgID != "" && bl[ch.TvgID]) || bl[ch.URL]
}

// isJunkName reports an unplayable placeholder name: blank or the common "Undefined" filler.
func isJunkName(name string) bool {
	n := strings.TrimSpace(name)
	return n == "" || strings.EqualFold(n, "undefined")
}
