package store

import (
	"path/filepath"
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// TestDeviceGroupCRUD_AndScopePrune: Upsert/Delete device groups (copy-on-write), and deleting a group
// prunes its id from every RoutingList.ScopeGroups — a list left with no groups falls back to
// all-clients — so the profile stays Validate-clean (symmetric with DeleteGroup's nested-member prune).
func TestDeviceGroupCRUD_AndScopePrune(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "192.168.1.50"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "adults", Name: "Adults", Members: []model.DeviceMember{{IP: "192.168.1.60"}}}); err != nil {
		t.Fatal(err)
	}
	// yt: scoped to ONLY kids (a per-device block). vpn: scoped to kids + adults.
	if err := s.UpsertRoutingList(model.RoutingList{ID: "yt", Name: "YT", Manual: []string{"youtube.com"}, Outbound: model.OutboundBlock, Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoutingList(model.RoutingList{ID: "vpn", Name: "VPN", Manual: []string{"x.com"}, Outbound: model.OutboundDirect, Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids", "adults"}}); err != nil {
		t.Fatal(err)
	}

	p := s.Profile()
	if len(p.DeviceGroups) != 2 {
		t.Fatalf("want 2 device groups, got %d", len(p.DeviceGroups))
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("profile should validate: %v", err)
	}

	// Upsert replaces an existing group wholesale.
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids2", Members: []model.DeviceMember{{MAC: "11:22:33:44:55:66"}}}); err != nil {
		t.Fatal(err)
	}
	p = s.Profile()
	var kids *model.DeviceGroup
	for i := range p.DeviceGroups {
		if p.DeviceGroups[i].ID == "kids" {
			kids = &p.DeviceGroups[i]
		}
	}
	if kids == nil || kids.Name != "Kids2" || len(kids.Members) != 1 {
		t.Fatalf("upsert should replace the group wholesale: %+v", kids)
	}

	// Delete kids → yt (only-kids) resets to all-clients; vpn (kids+adults) prunes to [adults].
	if err := s.DeleteDeviceGroup("kids"); err != nil {
		t.Fatalf("DeleteDeviceGroup: %v", err)
	}
	p = s.Profile()
	if len(p.DeviceGroups) != 1 || p.DeviceGroups[0].ID != "adults" {
		t.Fatalf("kids should be gone, adults kept: %+v", p.DeviceGroups)
	}
	byID := map[string]model.RoutingList{}
	for _, rl := range p.RoutingLists {
		byID[rl.ID] = rl
	}
	if yt := byID["yt"]; yt.ScopeMode != "" || len(yt.ScopeGroups) != 0 {
		t.Fatalf("yt scope should reset to all after its only group deleted: mode=%q groups=%v", yt.ScopeMode, yt.ScopeGroups)
	}
	if vpn := byID["vpn"]; vpn.ScopeMode != "only" || !reflect.DeepEqual(vpn.ScopeGroups, []string{"adults"}) {
		t.Fatalf("vpn scope should prune to [adults]: mode=%q groups=%v", vpn.ScopeMode, vpn.ScopeGroups)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("profile must be Validate-clean after delete+prune: %v", err)
	}

	// Deleting an unknown group errors; empty id on upsert errors.
	if err := s.DeleteDeviceGroup("ghost"); err == nil {
		t.Error("deleting an unknown device group should error")
	}
	if err := s.UpsertDeviceGroup(model.DeviceGroup{Name: "no-id"}); err == nil {
		t.Error("upserting a group with empty id should error")
	}
}
