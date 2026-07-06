package iptv

import "testing"

func TestSortWithPins(t *testing.T) {
	chs := []Channel{
		{Name: "ESPN", Group: "Sports", URL: "u"},
		{Name: "Alpha", Group: "Arts", URL: "u"},
		{Name: "CNN", Group: "News", URL: "u"},
		{Name: "Fox", Group: "News", URL: "u"},
	}
	// Pin Sports first, then News; the rest (Arts) follows A-Z.
	SortWithPins(chs, []string{"Sports", "news"}) // case-insensitive
	got := make([]string, len(chs))
	for i, c := range chs {
		got[i] = c.Group + "/" + c.Name
	}
	want := []string{"Sports/ESPN", "News/CNN", "News/Fox", "Arts/Alpha"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SortWithPins order = %v, want %v", got, want)
		}
	}
}

func TestSortWithPinsEmptyEqualsSort(t *testing.T) {
	a := []Channel{{Name: "B", Group: "Z", URL: "u"}, {Name: "A", Group: "A", URL: "u"}}
	b := []Channel{{Name: "B", Group: "Z", URL: "u"}, {Name: "A", Group: "A", URL: "u"}}
	Sort(a)
	SortWithPins(b, nil)
	if a[0].Group != b[0].Group || a[1].Group != b[1].Group {
		t.Fatal("SortWithPins(nil) must behave exactly like Sort")
	}
	if a[0].Group != "A" {
		t.Fatalf("plain sort wrong: %v", a)
	}
}
