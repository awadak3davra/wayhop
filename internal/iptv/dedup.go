package iptv

import "strings"

// Dedup removes duplicate channels, keeping the FIRST occurrence, and returns the deduped slice +
// the number dropped. A later channel is a duplicate if it shares an EXACT stream URL with an
// earlier one, OR the same channel identity — its tvg-id, or (when tvg-id is empty) its
// case/whitespace-normalized name within the same group. The input slice is not mutated.
func Dedup(chs []Channel) ([]Channel, int) {
	seenURL := make(map[string]struct{}, len(chs))
	seenID := make(map[string]struct{}, len(chs))
	out := make([]Channel, 0, len(chs))
	dropped := 0
	for _, c := range chs {
		id := c.TvgID
		if id == "" {
			id = "name:" + normName(c.Name) + "\x00" + strings.ToLower(strings.TrimSpace(c.Group))
		} else {
			id = "id:" + id
		}
		_, dupURL := seenURL[c.URL]
		_, dupID := seenID[id]
		if (c.URL != "" && dupURL) || dupID {
			dropped++
			continue
		}
		if c.URL != "" {
			seenURL[c.URL] = struct{}{}
		}
		seenID[id] = struct{}{}
		out = append(out, c)
	}
	return out, dropped
}

// normName lowercases + collapses runs of whitespace, for name-based comparison.
func normName(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }
