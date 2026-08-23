package model

import "testing"

// TestValidate_CIDRSource: a routing list may use a cidr_source as its content (no Manual
// needed), but the scheme must be https://, http://, or asn:N[,N…]; anything else is
// rejected, as is a list with no content at all.
func TestValidate_CIDRSource(t *testing.T) {
	mk := func(rl RoutingList) Profile { return Profile{RoutingLists: []RoutingList{rl}} }

	valid := []string{"https://x/feed.txt", "http://x/f", "asn:13238", "asn:AS13238,47541", "asn:13238, 47541 "}
	for _, src := range valid {
		p := mk(RoutingList{ID: "l", Name: "L", CIDRSource: src, Outbound: "direct", Enabled: true})
		if err := p.Validate(); err != nil {
			t.Errorf("CIDRSource %q should be valid: %v", src, err)
		}
	}

	invalid := []string{"ftp://x", "asn:", "asn:notanumber", "asn:13238,bad", "justtext"}
	for _, src := range invalid {
		p := mk(RoutingList{ID: "l", Name: "L", CIDRSource: src, Outbound: "direct", Enabled: true})
		if err := p.Validate(); err == nil {
			t.Errorf("CIDRSource %q should be rejected", src)
		}
	}

	// A list with a CIDRCache but no Manual/Source/CIDRSource is still valid content.
	cacheOnly := mk(RoutingList{ID: "l", Name: "L", CIDRCache: []string{"1.2.3.0/24"}, Outbound: "direct", Enabled: true})
	if err := cacheOnly.Validate(); err != nil {
		t.Errorf("a list with only a CIDRCache should be valid: %v", err)
	}
	// A list with no content at all is rejected.
	empty := mk(RoutingList{ID: "l", Name: "L", Outbound: "direct", Enabled: true})
	if err := empty.Validate(); err == nil {
		t.Error("a list with no source/manual/cidr should be rejected")
	}
}
