package iptv

import (
	"sort"
	"strings"
)

// Uncategorized is the display bucket for channels with an empty group-title.
const Uncategorized = "Uncategorized"

// Category is a group-title bucket with its channel count, for the curation UI.
type Category struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// categoryOf returns a channel's display category (its group-title, or "Uncategorized" when empty).
func categoryOf(ch Channel) string {
	if g := strings.TrimSpace(ch.Group); g != "" {
		return g
	}
	return Uncategorized
}

// CategoryOf is the exported view of a channel's display category (group-title, or "Uncategorized"),
// so the module can bucket channels for the per-category drill-down consistently with Categorize.
func CategoryOf(ch Channel) string { return categoryOf(ch) }

// Categorize buckets channels by group-title and returns the categories sorted by count (desc) then
// name — the order the curation UI shows them (biggest buckets first). Empty group-titles fold into
// "Uncategorized".
func Categorize(chs []Channel) []Category {
	counts := map[string]int{}
	for _, ch := range chs {
		counts[categoryOf(ch)]++
	}
	out := make([]Category, 0, len(counts))
	for name, n := range counts {
		out = append(out, Category{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// NormCategories lowercases + trims a list of category names into a set for FilterCategories (nil for
// an empty input).
func NormCategories(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		if s := strings.TrimSpace(strings.ToLower(n)); s != "" {
			m[s] = true
		}
	}
	return m
}

// FilterCategories drops channels whose category is in exclude (compared case-insensitively; build
// exclude via NormCategories). An EMPTY exclude set keeps everything — the deliberate auto-update-safe
// default, so a category that newly appears upstream is included until the user explicitly cuts it
// (an exclude-list, never an include-list). Pure; returns the kept channels + the dropped count.
func FilterCategories(chs []Channel, exclude map[string]bool) ([]Channel, int) {
	return FilterCategoriesKeep(chs, exclude, nil)
}

// FilterCategoriesKeep is FilterCategories with a per-channel RESCUE: a channel whose category is
// excluded is still kept when its tvg-id is in keepTvg (an exact-match set). This lets a user cut a
// whole category yet re-admit a few specific channels from it. keepTvg empty behaves exactly like
// FilterCategories. Pure; returns the kept channels + the count actually dropped (rescued channels
// are NOT counted as dropped).
func FilterCategoriesKeep(chs []Channel, exclude, keepTvg map[string]bool) ([]Channel, int) {
	if len(exclude) == 0 {
		return chs, 0
	}
	out := make([]Channel, 0, len(chs))
	dropped := 0
	for _, ch := range chs {
		if exclude[strings.ToLower(categoryOf(ch))] && !(ch.TvgID != "" && keepTvg[ch.TvgID]) {
			dropped++
			continue
		}
		out = append(out, ch)
	}
	return out, dropped
}
