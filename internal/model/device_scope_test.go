package model

import "testing"

// TestValidate_DeviceGroups covers the per-device scoping model (P1): device groups (MAC/IP members)
// and a RoutingList's scope_mode/scope_groups, plus that adding neither keeps existing profiles valid.
func TestValidate_DeviceGroups(t *testing.T) {
	kids := DeviceGroup{ID: "kids", Name: "Kids", Members: []DeviceMember{
		{MAC: "aa:bb:cc:dd:ee:ff"},
		{IP: "192.168.1.50"},
		{MAC: "11:22:33:44:55:66", IP: "192.168.1.0/24"},
	}}

	// Happy path: a group + a list scoped "only" to it.
	ok := Profile{
		DeviceGroups: []DeviceGroup{kids},
		RoutingLists: []RoutingList{{ID: "yt", Name: "YT", Manual: []string{"youtube.com"}, Outbound: "direct", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids"}}},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid device-group + scoped list should pass: %v", err)
	}

	// "except" mode with a group is valid.
	exc := Profile{DeviceGroups: []DeviceGroup{kids}, RoutingLists: []RoutingList{{ID: "yt", Name: "YT", Manual: []string{"x.com"}, Outbound: "block", Enabled: true, ScopeMode: "except", ScopeGroups: []string{"kids"}}}}
	if err := exc.Validate(); err != nil {
		t.Fatalf("except-mode scoped list should pass: %v", err)
	}

	// Backward compat: no device groups + no scope = still valid, unchanged.
	compat := Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: []string{"a.com"}, Outbound: "direct", Enabled: true}}}
	if err := compat.Validate(); err != nil {
		t.Fatalf("a no-scope list must stay valid: %v", err)
	}

	bad := []struct {
		name string
		p    Profile
	}{
		{"empty-group-id", Profile{DeviceGroups: []DeviceGroup{{Name: "x", Members: []DeviceMember{{IP: "1.2.3.4"}}}}}},
		{"member-blank", Profile{DeviceGroups: []DeviceGroup{{ID: "g", Members: []DeviceMember{{}}}}}},
		{"member-whitespace", Profile{DeviceGroups: []DeviceGroup{{ID: "g", Members: []DeviceMember{{MAC: "  ", IP: " "}}}}}},
		{"bad-mac", Profile{DeviceGroups: []DeviceGroup{{ID: "g", Members: []DeviceMember{{MAC: "zz:zz"}}}}}},
		{"bad-ip", Profile{DeviceGroups: []DeviceGroup{{ID: "g", Members: []DeviceMember{{IP: "not-an-ip"}}}}}},
		{"scope-unknown-group", Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: []string{"a"}, Outbound: "direct", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"ghost"}}}}},
		{"scope-bad-mode", Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: []string{"a"}, Outbound: "direct", Enabled: true, ScopeMode: "sometimes"}}}},
		{"only-no-groups", Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: []string{"a"}, Outbound: "direct", Enabled: true, ScopeMode: "only"}}}},
		{"except-no-groups", Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: []string{"a"}, Outbound: "direct", Enabled: true, ScopeMode: "except"}}}},
		{"dup-id-group-vs-list", Profile{DeviceGroups: []DeviceGroup{{ID: "dup", Members: []DeviceMember{{IP: "1.2.3.4"}}}}, RoutingLists: []RoutingList{{ID: "dup", Name: "L", Manual: []string{"a"}, Outbound: "direct", Enabled: true}}}},
	}
	for _, tc := range bad {
		if err := tc.p.Validate(); err == nil {
			t.Errorf("%s: expected a validation error, got nil", tc.name)
		}
	}
}
