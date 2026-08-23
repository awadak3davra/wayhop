package server

import (
	"encoding/json"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func liteTestProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{{ID: "wg1", Name: "Yerevan", Protocol: "wireguard", Enabled: true}},
		RoutingLists: []model.RoutingList{
			{
				ID: "ru-bypass", Name: "RU bypass", Enabled: true,
				CIDRSource: "https://example.invalid/ru.txt",
				CIDRCache:  []string{"1.2.3.0/24", "5.6.7.0/24", "9.10.11.0/24"},
			},
			{
				ID: "ads", Name: "Ads", Enabled: true,
				DomainSource: "https://example.invalid/ads.txt",
				DomainCache:  []string{"ads.example", "track.example"},
			},
			{ID: "manual", Name: "Manual", Enabled: true},
		},
	}
}

// The panel reloads the profile on every render and after every mutation; the feed caches are the
// only large thing in it and nothing in the UI reads their contents. Lite must drop them and keep
// the two facts the UI does read: how many entries were fetched, and whether anything was.
func TestLiteProfileDropsCachesKeepsCounts(t *testing.T) {
	b, err := json.Marshal(liteProfileOf(liteTestProfile(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	for _, gone := range []string{"1.2.3.0/24", "ads.example", `"cidr_cache"`, `"domain_cache"`} {
		if strings.Contains(body, gone) {
			t.Fatalf("lite profile still carries %s: %s", gone, body)
		}
	}

	var got struct {
		Endpoints []struct {
			ID string `json:"id"`
		} `json:"endpoints"`
		Lists []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			CIDRSource string `json:"cidr_source"`
			CIDRCount  int    `json:"cidr_cache_count"`
			DomCount   int    `json:"domain_cache_count"`
		} `json:"routing_lists"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Lists) != 3 {
		t.Fatalf("lite profile has %d lists, want 3", len(got.Lists))
	}
	if got.Lists[0].CIDRCount != 3 || got.Lists[1].DomCount != 2 {
		t.Fatalf("counts lost: %+v", got.Lists)
	}
	// A list with a source and a zero count is the "not fetched yet" the Routing page shows, and it
	// must stay distinguishable from a hand-written list with no source at all.
	if got.Lists[0].CIDRSource == "" {
		t.Fatalf("the feed source must survive: %+v", got.Lists[0])
	}
	if got.Lists[2].CIDRCount != 0 || got.Lists[2].CIDRSource != "" {
		t.Fatalf("a manual list must report no source and no cache: %+v", got.Lists[2])
	}
	// Everything else the page renders has to come through untouched.
	if len(got.Endpoints) != 1 || got.Endpoints[0].ID != "wg1" || got.Lists[0].Name != "RU bypass" {
		t.Fatalf("lite profile lost non-cache fields: %s", body)
	}
}

// The full form is the BACKUP format POST /api/profile restores. If it ever started dropping caches,
// a restored router would come back with every feed-backed list empty — which is a hard Apply
// blocker, not a slow start.
func TestFullProfileKeepsCaches(t *testing.T) {
	b, err := json.Marshal(liteTestProfile())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	if !strings.Contains(body, "1.2.3.0/24") || !strings.Contains(body, "ads.example") {
		t.Fatalf("the full profile must carry the caches: %s", body)
	}
	if strings.Contains(body, "cidr_cache_count") {
		t.Fatalf("the full profile must not carry the lite-only counts: %s", body)
	}
}

// The point of the whole change is size, so the size is asserted rather than assumed. The shape is
// a live router: one feed-backed list holding thousands of CIDRs, which made /api/profile
// 275 KB on a payload the panel re-fetches on every render.
func TestLiteProfileIsSubstantiallySmaller(t *testing.T) {
	big := make([]string, 15866) // the measured count on a live router
	for i := range big {
		big[i] = "10.0.0.0/24"
	}
	p := model.Profile{RoutingLists: []model.RoutingList{
		{ID: "ru", Name: "RU", Enabled: true, CIDRSource: "https://example.invalid/ru.txt", CIDRCache: big},
	}}
	full, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal full: %v", err)
	}
	lite, err := json.Marshal(liteProfileOf(p, nil))
	if err != nil {
		t.Fatalf("marshal lite: %v", err)
	}
	if len(lite)*20 > len(full) {
		t.Fatalf("lite is %d B against full %d B — the caches are still dominating", len(lite), len(full))
	}
	// And a profile with no caches must not get BIGGER: two always-present zero counts across the 66
	// lists of the stress profile cost more than they save, which is why the counts are omitempty.
	empty := model.Profile{RoutingLists: make([]model.RoutingList, 66)}
	fullEmpty, _ := json.Marshal(empty)
	liteEmpty, _ := json.Marshal(liteProfileOf(empty, nil))
	if len(liteEmpty) > len(fullEmpty) {
		t.Fatalf("lite grew a cacheless profile: %d B against %d B", len(liteEmpty), len(fullEmpty))
	}
}

// A profile whose lists are absent must not turn into `"routing_lists": null` — the UI calls .map on
// it, and Go marshals a nil slice as null.
func TestLiteProfileWithNoListsIsAnArray(t *testing.T) {
	b, err := json.Marshal(liteProfileOf(model.Profile{}, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"routing_lists":[]`) {
		t.Fatalf("want an empty array, got: %s", b)
	}
}
