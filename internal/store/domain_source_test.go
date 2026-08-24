package store

import (
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// A whole-struct edit that omits domain_source does NOT read as "the user cleared the feed": the
// store treats a changed DomainSource as a reason to drop DomainCache and DomainRefreshed too, so
// an edit that merely renamed a list used to delete the feed URL AND every domain it had fetched.
// The list stayed in the panel and quietly stopped matching anything, with nothing left to refill
// it. This pins the store contract the panel now depends on: an edit that CARRIES the same source
// keeps the cache, and one that genuinely CHANGES it still drops the stale cache.
func TestUpsertRoutingList_DomainFeedSurvivesAnUnrelatedEdit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	const feed = "https://example.test/domains.txt"
	base := model.RoutingList{ID: "ads", Name: "Ads", Outbound: model.OutboundBlock, Enabled: true, DomainSource: feed}
	if err := s.UpsertRoutingList(base); err != nil {
		t.Fatal(err)
	}
	// The refresh loop fills the system-managed cache.
	withCache := base
	withCache.DomainCache = []string{"ads.example", "tracker.example"}
	withCache.DomainRefreshed = 1700000000
	if err := s.UpsertRoutingList(withCache); err != nil {
		t.Fatal(err)
	}

	// An ordinary edit: rename only, carrying the source through the way the panel now does, and
	// omitting the system-managed cache the way it always has.
	renamed := model.RoutingList{ID: "ads", Name: "Ad blocking", Outbound: model.OutboundBlock, Enabled: true, DomainSource: feed}
	if err := s.UpsertRoutingList(renamed); err != nil {
		t.Fatal(err)
	}
	got := findList(t, s, "ads")
	if got.DomainSource != feed {
		t.Fatalf("the domain feed was lost on a rename: %q", got.DomainSource)
	}
	if len(got.DomainCache) != 2 || got.DomainRefreshed == 0 {
		t.Fatalf("the fetched domains were dropped on a rename: cache=%v refreshed=%d", got.DomainCache, got.DomainRefreshed)
	}

	// And the other half of the contract: genuinely changing the source must still drop the stale
	// cache, or the list would keep serving domains the new feed never listed.
	moved := renamed
	moved.DomainSource = "https://example.test/other.txt"
	if err := s.UpsertRoutingList(moved); err != nil {
		t.Fatal(err)
	}
	got = findList(t, s, "ads")
	if len(got.DomainCache) != 0 || got.DomainRefreshed != 0 {
		t.Fatalf("a changed feed kept its stale cache: cache=%v refreshed=%d", got.DomainCache, got.DomainRefreshed)
	}
}

func findList(t *testing.T, s *Store, id string) model.RoutingList {
	t.Helper()
	for _, rl := range s.Profile().RoutingLists {
		if rl.ID == id {
			return rl
		}
	}
	t.Fatalf("routing list %q disappeared", id)
	return model.RoutingList{}
}
