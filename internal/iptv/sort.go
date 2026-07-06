package iptv

import (
	"sort"
	"strings"
)

// Sort orders channels A-Z: by group-title first (case-insensitive), then by name within a group.
// Stable, so channels with an equal key keep their prior (dedup/source) order. Mutates chs in place.
func Sort(chs []Channel) { SortWithPins(chs, nil) }

// SortWithPins orders channels like Sort but floats PINNED categories to the top, in the pin order the
// user gave (so a pinned group actually leads in the served M3U — flat-list players show them first).
// Non-pinned categories follow, A-Z. pins are category names, matched case-insensitively; empty pins
// behaves exactly like Sort. Mutates chs in place.
func SortWithPins(chs []Channel, pins []string) {
	rank := make(map[string]int, len(pins))
	for i, p := range pins {
		if lc := strings.ToLower(strings.TrimSpace(p)); lc != "" {
			if _, dup := rank[lc]; !dup { // first occurrence wins the rank
				rank[lc] = i
			}
		}
	}
	const unpinned = 1 << 30 // sorts after every pinned category
	pinRank := func(ch Channel) int {
		if r, ok := rank[strings.ToLower(categoryOf(ch))]; ok {
			return r
		}
		return unpinned
	}
	sort.SliceStable(chs, func(i, j int) bool {
		ri, rj := pinRank(chs[i]), pinRank(chs[j])
		if ri != rj {
			return ri < rj
		}
		gi, gj := strings.ToLower(chs[i].Group), strings.ToLower(chs[j].Group)
		if gi != gj {
			return gi < gj
		}
		return strings.ToLower(chs[i].Name) < strings.ToLower(chs[j].Name)
	})
}
