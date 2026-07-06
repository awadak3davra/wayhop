package iptv

import "testing"

func TestDedup(t *testing.T) {
	in := []Channel{
		chn("CNN", "News", "cnn.us", "http://s/cnn1"),
		chn("CNN (backup)", "News", "cnn.us", "http://s/cnn2"), // same tvg-id → dup, keep first
		chn("BBC", "News", "", "http://s/bbc"),
		chn("BBC ONE", "News", "", "http://s/bbc"),   // same exact URL → dup
		chn("bbc  ", "news", "", "http://s/bbc-alt"), // same normalized name+group, no tvg-id → dup
		chn("Sky", "Sports", "", "http://s/sky"),
		chn("Sky", "Movies", "", "http://s/sky2"), // same name, DIFFERENT group → kept
	}
	got, dropped := Dedup(in)
	want := []string{"CNN", "BBC", "Sky", "Sky"}
	if names(got)[0] != "CNN" || len(got) != 4 || dropped != 3 {
		t.Fatalf("Dedup kept %v (dropped %d), want %v (dropped 3)", names(got), dropped, want)
	}
	// The kept CNN is the FIRST occurrence's URL.
	if got[0].URL != "http://s/cnn1" {
		t.Errorf("dedup kept the wrong CNN stream: %q", got[0].URL)
	}
}

func TestDedupEmptyAndNoDups(t *testing.T) {
	if got, d := Dedup(nil); len(got) != 0 || d != 0 {
		t.Fatalf("nil input: %v %d", got, d)
	}
	uniq := []Channel{chn("A", "G", "a", "http://a"), chn("B", "G", "b", "http://b")}
	if got, d := Dedup(uniq); len(got) != 2 || d != 0 {
		t.Fatalf("no dups altered: %v %d", names(got), d)
	}
}
