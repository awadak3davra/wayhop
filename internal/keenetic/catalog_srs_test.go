package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestApplyCatalogSRS_AndInlineSkip: big/common lists are rewritten to a catalog .srs (Format
// binary), small/unmapped lists keep their .lst Source; InlineDomainSources then inlines only
// the unmapped ones and leaves the .srs remote.
func TestApplyCatalogSRS_AndInlineSkip(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "rkn_full", Source: "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst", Outbound: "g", Enabled: true},
		{ID: "youtube", Source: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.lst", Outbound: "g", Enabled: true},
		{ID: "geoblock", Source: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst", Outbound: "g", Enabled: true}, // unmapped → inline
	}}
	applyCatalogSRS(p)

	by := map[string]*model.RoutingList{}
	for i := range p.RoutingLists {
		by[p.RoutingLists[i].ID] = &p.RoutingLists[i]
	}
	if !strings.HasSuffix(by["rkn_full"].Source, ".srs") || by["rkn_full"].Format != "binary" {
		t.Errorf("rkn_full must map to a .srs binary rule_set, got %+v", by["rkn_full"])
	}
	if !strings.HasSuffix(by["youtube"].Source, "youtube.srs") || by["youtube"].Format != "binary" {
		t.Errorf("youtube must map to youtube.srs, got %+v", by["youtube"])
	}
	if by["geoblock"].Format == "binary" {
		t.Error("geoblock is unmapped — must keep its .lst Source for inlining")
	}

	// InlineDomainSources leaves the .srs binary lists remote, inlines only the unmapped .lst.
	fetched := map[string]bool{}
	_ = InlineDomainSources(p, func(url string) ([]string, error) {
		fetched[url] = true
		return []string{"a.example", "b.example"}, nil
	})
	if fetched[by["rkn_full"].Source] || fetched[by["youtube"].Source] {
		t.Error("a .srs binary rule_set must NOT be fetched/inlined")
	}
	if by["geoblock"].Source != "" || len(by["geoblock"].Manual) != 2 {
		t.Errorf("geoblock (.lst) must be inlined to Manual, got %+v", by["geoblock"])
	}
}
