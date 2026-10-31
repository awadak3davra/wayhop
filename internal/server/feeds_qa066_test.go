package server

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// A domain feed is coreless only where dnsmasq turns its names into set members. Offered as
// coreless on OpenWrt, it saved a list that then blocked every Apply on a router without sing-box.
func TestDomainPresetsNeedTheCoreOffKeenetic(t *testing.T) {
	for _, pl := range []platform.Platform{platform.OpenWrt, platform.Keenetic} {
		n := 0
		for _, p := range routingPresetsFor(pl) {
			if p.DomainSource == "" {
				continue
			}
			n++
			if want := pl != platform.Keenetic; p.RequiresCore != want {
				t.Errorf("%s: preset %s requires_core = %v, want %v", pl, p.ID, p.RequiresCore, want)
			}
		}
		if n == 0 {
			t.Fatal("test setup: the catalog has no domain-feed preset")
		}
	}
}

// QA-122: off KeeneticOS a domain preset carries the "needs sing-box" badge, so its description must
// not say "no proxy core needed"; on KeeneticOS, where that is true, the text is left as written.
func TestDomainPresetTextMatchesTheCoreBadge(t *testing.T) {
	keen := map[string]string{}
	for _, p := range routingPresetsFor(platform.Keenetic) {
		keen[p.ID] = p.Description
	}
	rewritten := 0
	for _, p := range routingPresetsFor(platform.OpenWrt) {
		if p.RequiresCore && strings.Contains(p.Description, "no proxy core needed") {
			t.Errorf("%s needs the core here but says: %q", p.ID, p.Description)
		}
		if p.Description != keen[p.ID] {
			rewritten++
		}
	}
	if rewritten == 0 {
		t.Fatal("test setup: no description promised a coreless domain feed")
	}
	for _, p := range model.RoutingPresets() {
		if keen[p.ID] != p.Description {
			t.Errorf("%s: KeeneticOS text changed: %q", p.ID, keen[p.ID])
		}
	}
}

// The KeeneticOS compatibility core skips the IP feed of a list the ipset plane already carries, and
// keeps everything else: a list with no zone of its own, a scoped zone, and every name.
func TestCompatCoreSkipsKernelCarriedFeeds(t *testing.T) {
	lists := []model.RoutingList{
		{ID: "carried", CIDRCache: []string{"198.51.100.0/24"}, DomainCache: []string{"example.net"}},
		{ID: "core-only", CIDRCache: []string{"203.0.113.0/24"}},
		{ID: "scoped", CIDRCache: []string{"192.0.2.0/24"}},
	}
	plan := &pbr.Plan{Zones: []pbr.Zone{
		{Name: pbr.ListZoneName("carried")},
		{Name: pbr.ListZoneName("scoped"), SrcScoped: true},
	}}
	got := withoutKernelCarriedFeeds(lists, plan)
	if got[0].CIDRCache != nil || !slices.Equal(got[0].DomainCache, []string{"example.net"}) {
		t.Errorf("carried list = %+v, want its IP feed dropped and its names kept", got[0])
	}
	if len(got[1].CIDRCache) != 1 || len(got[2].CIDRCache) != 1 {
		t.Errorf("lists the plane does not carry for everyone lost their feed: %+v", got[1:])
	}
	if lists[0].CIDRCache == nil {
		t.Error("the caller's profile was modified")
	}
}

// A list fed only by a domain feed routes names exactly as a typed one does, and so needs the
// router to answer clients' DNS just as much.
func TestDomainFeedCountsAsDomainRouted(t *testing.T) {
	p := model.Profile{RoutingLists: []model.RoutingList{
		{ID: "svc-ai", Name: "Google AI", Enabled: true, DomainSource: "https://example.net/ai.lst", DomainCache: []string{"example.net"}},
	}}
	if got := domainRoutedLists(p); !slices.Equal(got, []string{"Google AI"}) {
		t.Errorf("domainRoutedLists = %v, want the feed-only list", got)
	}
}

// A refilter-sized feed sent to a proxy now lands in the core inline (QA-066), where it costs memory,
// check time and flash. The review says so; the same feed at a kernel egress in hybrid costs the core
// nothing and draws no warning.
func TestReviewWarnsWhenTheCoreHoldsALargeFeed(t *testing.T) {
	feed := make([]string, 0, coreInlineWarnEntries+1)
	for i := 0; len(feed) <= coreInlineWarnEntries; i++ {
		feed = append(feed, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	profile := func(outbound string) *model.Profile {
		return &model.Profile{
			Endpoints: []model.Endpoint{
				{ID: "px", Name: "px", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
					Server: "198.51.100.9", Port: 443, Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
				{ID: "k", Name: "k", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "awg1"}},
			},
			RoutingLists: []model.RoutingList{{ID: "big", Name: "Big", Enabled: true, Outbound: outbound,
				CIDRSource: "https://example.net/big.lst", CIDRCache: feed}},
		}
	}
	if got := coreInlineSizeFindings(profile("px"), "tun"); len(got) != 1 || got[0].Blocks != platform.BlocksNothing {
		t.Fatalf("feed to a proxy: findings = %+v, want one advisory", got)
	}
	if got := coreInlineSizeFindings(profile("k"), "hybrid"); len(got) != 0 {
		t.Errorf("feed at a kernel egress in hybrid: findings = %+v, want none", got)
	}
}
