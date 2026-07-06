package iptv

import (
	"reflect"
	"testing"
)

func TestCategorize(t *testing.T) {
	chs := []Channel{
		{Name: "a", Group: "News", URL: "u"},
		{Name: "b", Group: "News", URL: "u"},
		{Name: "c", Group: "Sports", URL: "u"},
		{Name: "d", Group: "", URL: "u"}, // → Uncategorized
		{Name: "e", Group: "Kids", URL: "u"},
	}
	got := Categorize(chs)
	want := []Category{{"News", 2}, {"Kids", 1}, {"Sports", 1}, {"Uncategorized", 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Categorize = %+v, want %+v (count desc, then name asc)", got, want)
	}
}

func TestFilterCategories(t *testing.T) {
	chs := []Channel{
		{Name: "n1", Group: "News", URL: "u"},
		{Name: "s1", Group: "Sports", URL: "u"},
		{Name: "r1", Group: "Religious", URL: "u"},
		{Name: "u1", Group: "", URL: "u"},
	}
	// Case-insensitive exclusion of "religious" + "uncategorized".
	kept, dropped := FilterCategories(chs, NormCategories([]string{"Religious", "uncategorized"}))
	if dropped != 2 || len(kept) != 2 {
		t.Fatalf("kept=%d dropped=%d, want 2/2", len(kept), dropped)
	}
	for _, ch := range kept {
		if ch.Group == "Religious" || ch.Group == "" {
			t.Fatalf("excluded category survived: %+v", ch)
		}
	}
}

func TestFilterCategoriesKeepRescue(t *testing.T) {
	chs := []Channel{
		{Name: "CNN", TvgID: "cnn.us", Group: "News", URL: "u1"},
		{Name: "Fox", TvgID: "fox.us", Group: "News", URL: "u2"},
		{Name: "ESPN", TvgID: "espn.us", Group: "Sports", URL: "u3"},
	}
	// Cut "News" but rescue CNN by tvg-id.
	kept, dropped := FilterCategoriesKeep(chs, NormCategories([]string{"News"}), map[string]bool{"cnn.us": true})
	if dropped != 1 { // only Fox dropped; CNN rescued
		t.Fatalf("dropped = %d, want 1 (Fox), CNN rescued", dropped)
	}
	names := map[string]bool{}
	for _, ch := range kept {
		names[ch.Name] = true
	}
	if !names["CNN"] || names["Fox"] || !names["ESPN"] {
		t.Fatalf("kept wrong set: %v (want CNN + ESPN, not Fox)", names)
	}
}

func TestFilterCategoriesEmptyKeepsAll(t *testing.T) {
	chs := []Channel{{Name: "a", Group: "News", URL: "u"}, {Name: "b", Group: "New", URL: "u"}}
	kept, dropped := FilterCategories(chs, nil)
	if dropped != 0 || len(kept) != 2 {
		t.Fatal("empty exclude set must keep everything (auto-update safe)")
	}
}
