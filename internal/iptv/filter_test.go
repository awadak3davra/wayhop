package iptv

import "testing"

func chn(name, group, id, url string) Channel {
	return Channel{Name: name, Group: group, TvgID: id, URL: url}
}

// TestFilterAdultFalsePositiveGuard is the load-bearing test: legitimate channels whose names
// contain adult SUBSTRINGS or ambiguous words must survive the default (adult-off) filter.
func TestFilterAdultFalsePositiveGuard(t *testing.T) {
	safe := []Channel{
		chn("Middlesex Community TV", "Local", "", "http://s/1"),
		chn("Sussex News", "News", "", "http://s/2"),
		chn("Essex Radio", "Music", "", "http://s/3"),
		chn("Hot Ones", "Food", "", "http://s/4"),
		chn("Naked Science", "Documentary", "", "http://s/5"),
		chn("Hardcore History", "Podcasts", "", "http://s/6"),
		chn("Adult Swim", "Cartoons", "", "http://s/7"),
		chn("Adult Contemporary FM", "Music", "", "http://s/8"),
		chn("Analog Classics", "Retro", "", "http://s/9"),
	}
	got, c := Filter(safe, FilterOptions{}) // AdultAllow=false (default)
	if len(got) != len(safe) || c.Adult != 0 {
		t.Fatalf("adult false positive: kept %d/%d, adult-dropped %d; want all kept", len(got), len(safe), c.Adult)
	}
}

func TestFilterAdultDropsAndAllows(t *testing.T) {
	adult := []Channel{
		chn("XXX Movies", "", "", "http://s/a"),
		chn("18+ Films", "", "", "http://s/b"),
		chn("Sexy Hits", "", "", "http://s/c"),
		chn("Playboy TV", "", "", "http://s/d"),
		chn("Brazzers TV", "", "", "http://s/e"),
		chn("Some Channel", "XXX", "", "http://s/f"), // adult via GROUP
	}
	got, c := Filter(adult, FilterOptions{}) // off → all dropped
	if len(got) != 0 || c.Adult != len(adult) {
		t.Fatalf("adult-off kept %d (adult=%d); want all %d dropped", len(got), c.Adult, len(adult))
	}
	got2, c2 := Filter(adult, FilterOptions{AdultAllow: true}) // opt-in → all kept
	if len(got2) != len(adult) || c2.Adult != 0 {
		t.Fatalf("adult-allow kept %d/%d (adult=%d)", len(got2), len(adult), c2.Adult)
	}
}

func TestFilterBlocklistAndJunk(t *testing.T) {
	chs := []Channel{
		chn("Good", "N", "good.id", "http://s/good"),
		chn("Blocked by id", "N", "bad.id", "http://s/x"),
		chn("Blocked by url", "N", "", "http://s/blockedurl"),
		chn("", "N", "", "http://s/blank"),      // junk: blank name
		chn("Undefined", "N", "", "http://s/u"), // junk: placeholder name
		chn("No URL", "N", "n.id", ""),          // junk: unplayable
	}
	got, c := Filter(chs, FilterOptions{Blocklist: map[string]bool{"bad.id": true, "http://s/blockedurl": true}})
	if len(got) != 1 || got[0].Name != "Good" {
		t.Fatalf("kept %v, want only [Good]", names(got))
	}
	if c.Blocked != 2 || c.Junk != 3 {
		t.Fatalf("counts blocked=%d junk=%d, want 2/3", c.Blocked, c.Junk)
	}
}

func names(chs []Channel) []string {
	out := make([]string, len(chs))
	for i, c := range chs {
		out[i] = c.Name
	}
	return out
}
