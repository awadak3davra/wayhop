package model

import "testing"

// TestValidRefreshHours: the CRUD-boundary bound — with a cidr_source, refresh_hours must be 0
// (default 24h) or in [6,720]; without one, any non-negative value is fine (it is only sing-box's
// rule_set update_interval there).
func TestValidRefreshHours(t *testing.T) {
	cidr := func(h int) RoutingList {
		return RoutingList{ID: "l", Name: "L", CIDRSource: "asn:13238", RefreshHours: h, Outbound: "direct", Enabled: true}
	}
	for _, h := range []int{0, 6, 12, 24, 168, 720} {
		if !ValidRefreshHours(cidr(h)) {
			t.Errorf("refresh_hours=%d with cidr_source should be valid", h)
		}
	}
	for _, h := range []int{1, 5, 721, 10000} {
		if ValidRefreshHours(cidr(h)) {
			t.Errorf("refresh_hours=%d with cidr_source should be rejected", h)
		}
	}
	src := RoutingList{ID: "l", Name: "L", Source: "https://example.com/x.srs", RefreshHours: 4, Outbound: "direct", Enabled: true}
	if !ValidRefreshHours(src) {
		t.Error("refresh_hours=4 with only a Source (no cidr_source) should be allowed")
	}
	if ValidRefreshHours(RoutingList{RefreshHours: -1}) {
		t.Error("negative refresh_hours is never valid")
	}
}

// TestValidate_ToleratesLegacyRefreshHours: Validate gates Apply/generate, so it must NOT hard-fail
// a profile whose refresh_hours predates the bounds (e.g. 3 with a cidr_source was legal before
// 0.4.1) — the ticker clamps it instead. Bricking Apply over legacy data is the failure mode this
// test pins down.
func TestValidate_ToleratesLegacyRefreshHours(t *testing.T) {
	p := Profile{RoutingLists: []RoutingList{{
		ID: "l", Name: "L", CIDRSource: "asn:13238", RefreshHours: 3, Outbound: "direct", Enabled: true,
	}}}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate must tolerate legacy out-of-range refresh_hours (Apply must not brick): %v", err)
	}
}
