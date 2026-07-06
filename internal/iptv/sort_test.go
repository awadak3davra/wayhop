package iptv

import "testing"

func TestSort(t *testing.T) {
	chs := []Channel{
		chn("Zeta", "News", "", "u1"),
		chn("alpha", "Sports", "", "u2"),
		chn("Beta", "News", "", "u3"),
		chn("gamma", "sports", "", "u4"), // case-insensitive group match with "Sports"
		chn("Delta", "", "", "u5"),       // no group → sorts first ("" < any)
	}
	Sort(chs)
	// Expected: "" group first (Delta), then News (Beta, Zeta), then Sports (alpha, gamma).
	want := []string{"Delta", "Beta", "Zeta", "alpha", "gamma"}
	if got := names(chs); !equal(got, want) {
		t.Fatalf("Sort = %v, want %v", got, want)
	}
}

// TestSortStable: equal (group,name) keys keep input order.
func TestSortStable(t *testing.T) {
	chs := []Channel{
		chn("Dup", "G", "first", "u1"),
		chn("Dup", "G", "second", "u2"),
	}
	Sort(chs)
	if chs[0].TvgID != "first" || chs[1].TvgID != "second" {
		t.Fatalf("Sort not stable: %s then %s", chs[0].TvgID, chs[1].TvgID)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
