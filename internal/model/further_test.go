package model

import "testing"

// further_ep builds a structurally valid endpoint with the given id/enabled flag.
func further_ep(id string, enabled bool) Endpoint {
	return Endpoint{
		ID:       id,
		Name:     "ep-" + id,
		Engine:   EngineSingBox,
		Protocol: ProtoVLESS,
		Server:   "1.1.1.1",
		Port:     443,
		Enabled:  enabled,
	}
}

// TestRoutingListDownloadViaGroup: a routing list whose download_via points at a
// GROUP id must validate OK. Groups are always "enabled" in Validate's resolution
// map, so a download_detour aimed at a group resolves to a real outbound tag.
func TestRoutingListDownloadViaGroup(t *testing.T) {
	p := &Profile{
		Endpoints: []Endpoint{further_ep("e1", true)},
		Groups:    []Group{{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1"}}},
		RoutingLists: []RoutingList{{
			ID: "l1", Name: "L1",
			Source:      "https://example.com/x.srs",
			Outbound:    OutboundDirect,
			DownloadVia: "g1", // fetch the rule-set THROUGH the group
			Enabled:     true,
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("download_via pointing at a group should validate, got: %v", err)
	}

	// Sanity: aiming download_via at a non-existent id must still fail, so the
	// pass above is meaningful (it's not that download_via is simply ignored).
	p.RoutingLists[0].DownloadVia = "ghost"
	if err := p.Validate(); err == nil {
		t.Fatal("download_via pointing at an unknown id should fail Validate")
	}
}

// TestRoutingListManualOnlyBlock: a manual-only routing list (no Source) whose
// outbound is the builtin "block" is valid — Manual entries satisfy the
// content requirement and "block" is a builtin outbound that always resolves.
func TestRoutingListManualOnlyBlock(t *testing.T) {
	p := &Profile{
		RoutingLists: []RoutingList{{
			ID: "l1", Name: "blocklist",
			Manual:   []string{"ads.example.com", "10.0.0.0/8"},
			Outbound: OutboundBlock,
			Enabled:  true,
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("manual-only list to block should validate, got: %v", err)
	}

	// Removing the manual entries leaves neither source nor manual -> invalid.
	p.RoutingLists[0].Manual = nil
	if err := p.Validate(); err == nil {
		t.Fatal("a list with no source and no manual entries should fail Validate")
	}
}

// TestRoutingListIDCollidesWithEndpointOrGroup: a routing list id that duplicates
// an existing endpoint or group id must fail — ids share one namespace.
func TestRoutingListIDCollidesWithEndpointOrGroup(t *testing.T) {
	cases := []struct {
		name string
		mk   func() *Profile
	}{
		{
			name: "collides-with-endpoint",
			mk: func() *Profile {
				return &Profile{
					Endpoints: []Endpoint{further_ep("e1", true)},
					RoutingLists: []RoutingList{{
						ID: "e1", Name: "dup", // same id as the endpoint
						Manual: []string{"x.com"}, Outbound: OutboundDirect, Enabled: true,
					}},
				}
			},
		},
		{
			name: "collides-with-group",
			mk: func() *Profile {
				return &Profile{
					Endpoints: []Endpoint{further_ep("e1", true)},
					Groups:    []Group{{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1"}}},
					RoutingLists: []RoutingList{{
						ID: "g1", Name: "dup", // same id as the group
						Manual: []string{"x.com"}, Outbound: OutboundDirect, Enabled: true,
					}},
				}
			},
		},
		{
			name: "collides-with-another-routing-list",
			mk: func() *Profile {
				return &Profile{
					RoutingLists: []RoutingList{
						{ID: "l1", Name: "a", Manual: []string{"x.com"}, Outbound: OutboundDirect, Enabled: true},
						{ID: "l1", Name: "b", Manual: []string{"y.com"}, Outbound: OutboundDirect, Enabled: true},
					},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mk().Validate(); err == nil {
				t.Fatalf("%s: expected duplicate-id rejection, got nil", tc.name)
			}
		})
	}
}

// TestRoutingListNeitherSourceNorManual: a routing list with neither a source URL
// nor manual entries has no content and must fail Validate.
func TestRoutingListNeitherSourceNorManual(t *testing.T) {
	p := &Profile{
		RoutingLists: []RoutingList{{
			ID: "l1", Name: "empty",
			Outbound: OutboundDirect, Enabled: true,
		}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a routing list with neither source nor manual should fail Validate")
	}

	// Adding a source alone fixes it.
	p.RoutingLists[0].Source = "https://example.com/x.srs"
	if err := p.Validate(); err != nil {
		t.Fatalf("a source-only list should validate, got: %v", err)
	}
}

// TestRoutingListOutboundEndpointEnabledVsDisabled: a routing list outbound that
// points at an enabled endpoint validates; flipping that endpoint to disabled must
// make Validate reject it (the generator wouldn't emit the disabled outbound tag).
func TestRoutingListOutboundEndpointEnabledVsDisabled(t *testing.T) {
	mk := func(enabled bool) *Profile {
		return &Profile{
			Endpoints: []Endpoint{further_ep("e1", enabled)},
			RoutingLists: []RoutingList{{
				ID: "l1", Name: "L1",
				Source:   "https://example.com/x.srs",
				Outbound: "e1", // route matched traffic out through the endpoint
				Enabled:  true,
			}},
		}
	}
	if err := mk(true).Validate(); err != nil {
		t.Fatalf("outbound to an enabled endpoint should validate, got: %v", err)
	}
	if err := mk(false).Validate(); err == nil {
		t.Fatal("outbound to a disabled endpoint should fail Validate")
	}
}

// TestRoutingListByID confirms RoutingListByID returns a pointer into the profile
// for a hit (mutations stick) and nil for a miss.
func TestRoutingListByID(t *testing.T) {
	p := &Profile{
		RoutingLists: []RoutingList{
			{ID: "l1", Name: "first", Manual: []string{"a.com"}, Outbound: OutboundDirect, Enabled: true},
			{ID: "l2", Name: "second", Manual: []string{"b.com"}, Outbound: OutboundBlock, Enabled: true},
		},
	}

	got := p.RoutingListByID("l2")
	if got == nil {
		t.Fatal("RoutingListByID(l2) returned nil")
	}
	if got.ID != "l2" || got.Name != "second" {
		t.Fatalf("RoutingListByID(l2) returned wrong element: %+v", got)
	}
	// The returned pointer must alias the stored element, not a copy.
	got.Name = "renamed"
	if p.RoutingLists[1].Name != "renamed" {
		t.Fatal("RoutingListByID should return a pointer into the profile, not a copy")
	}

	if miss := p.RoutingListByID("ghost"); miss != nil {
		t.Fatalf("RoutingListByID(ghost) should be nil, got %+v", miss)
	}
}
