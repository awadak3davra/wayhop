package store

import (
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// TestSetRoutingListCaches: a batch cache write updates exactly the matching lists in ONE atomic
// write (recording CIDRRefreshed), skips entries whose id is gone OR whose CIDRSource changed
// mid-fetch (never resurrect an old feed's CIDRs into a re-sourced list), spends NO write when
// nothing matches, and persists across reopen.
func TestSetRoutingListCaches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := s.UpsertRoutingList(model.RoutingList{ID: id, Name: id, CIDRSource: "asn:1", Outbound: "direct", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.SetRoutingListCaches(nil); err != nil || n != 0 {
		t.Errorf("nil map must be a no-op: n=%d err=%v", n, err)
	}
	n, err := s.SetRoutingListCaches(map[string]CacheUpdate{
		"a":       {Source: "asn:1", CIDRs: []string{"1.1.1.0/24"}},
		"b":       {Source: "asn:1", CIDRs: []string{"2.2.2.0/24", "3.3.3.0/24"}},
		"c":       {Source: "asn:OTHER", CIDRs: []string{"6.6.6.0/24"}}, // source changed mid-fetch — must skip
		"missing": {Source: "asn:1", CIDRs: []string{"9.9.9.0/24"}},     // no such list — ignored
	})
	if err != nil || n != 2 {
		t.Fatalf("matched = %d err=%v, want 2 (a+b; c source-mismatch, missing gone)", n, err)
	}
	check := func(st *Store) {
		p := st.Profile()
		if rl := p.RoutingListByID("a"); rl == nil || len(rl.CIDRCache) != 1 || rl.CIDRCache[0] != "1.1.1.0/24" || rl.CIDRRefreshed == 0 {
			t.Errorf("a cache/timestamp wrong: %+v", rl)
		}
		if rl := p.RoutingListByID("b"); rl == nil || len(rl.CIDRCache) != 2 {
			t.Errorf("b cache wrong: %+v", rl)
		}
		if rl := p.RoutingListByID("c"); rl == nil || len(rl.CIDRCache) != 0 || rl.CIDRRefreshed != 0 {
			t.Errorf("c (source mismatch) must be untouched: %+v", rl)
		}
	}
	check(s)
	s2, err := Open(path) // one atomic write → survives reopen
	if err != nil {
		t.Fatal(err)
	}
	check(s2)

	// All-mismatch batch: zero matches -> no flash write at all (mtime-invariant is hard to assert
	// portably; assert the contract: n==0, nil err, content unchanged).
	if n, err := s.SetRoutingListCaches(map[string]CacheUpdate{"a": {Source: "asn:CHANGED", CIDRs: []string{"7.7.7.0/24"}}}); err != nil || n != 0 {
		t.Errorf("all-mismatch batch: n=%d err=%v, want 0,nil", n, err)
	}
	pAfter := s.Profile()
	if rl := pAfter.RoutingListByID("a"); len(rl.CIDRCache) != 1 || rl.CIDRCache[0] != "1.1.1.0/24" {
		t.Errorf("a must be unchanged after the all-mismatch batch: %+v", rl)
	}
}
