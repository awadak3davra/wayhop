package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCompileListDeviceScope: an "only"-scoped routing list compiles to SEPARATE MAC and IP source-
// scoped zones (so a group's members OR — matches by MAC OR IP); an unscoped list stays a single
// unscoped zone (backward-compat); and an "only" scope resolving to no device produces no zone.
func TestCompileListDeviceScope(t *testing.T) {
	base := func(lists []model.RoutingList, groups []model.DeviceGroup) *model.Profile {
		return &model.Profile{
			Endpoints:    []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
			DeviceGroups: groups,
			RoutingLists: lists,
		}
	}
	kids := model.DeviceGroup{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "192.168.1.50/32"}}}

	// Scoped "only" → two zones (MAC + IP), both SrcScoped, both carrying the dest.
	p := base([]model.RoutingList{{ID: "yt", Name: "YT", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids"}}}, []model.DeviceGroup{kids})
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	byName := map[string]Zone{}
	for _, z := range plan.Zones {
		byName[z.Name] = z
	}
	dm, ok := byName["list_yt_dm"]
	if !ok {
		t.Fatalf("expected a MAC-scoped zone list_yt_dm; zones=%+v", plan.Zones)
	}
	if !dm.SrcScoped || len(dm.SrcMAC) != 1 || dm.SrcMAC[0] != "aa:bb:cc:dd:ee:ff" || len(dm.SrcV4) != 0 {
		t.Errorf("MAC zone wrong: %+v", dm)
	}
	if len(dm.V4) != 1 || !strings.Contains(dm.V4[0], "8.8.8.0") {
		t.Errorf("MAC zone must carry the dest CIDR: %v", dm.V4)
	}
	di, ok := byName["list_yt_di"]
	if !ok {
		t.Fatalf("expected an IP-scoped zone list_yt_di; zones=%+v", plan.Zones)
	}
	if !di.SrcScoped || len(di.SrcV4) != 1 || !strings.Contains(di.SrcV4[0], "192.168.1.50") || len(di.SrcMAC) != 0 {
		t.Errorf("IP zone wrong: %+v", di)
	}
	if _, ok := byName["list_yt"]; ok {
		t.Error("a scoped list must not also emit the unscoped zone")
	}

	// Backward-compat: no scope → a single unscoped zone.
	p2 := base([]model.RoutingList{{ID: "yt", Name: "YT", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true}}, nil)
	plan2, _, _ := Compile(p2, Options{})
	if len(plan2.Zones) != 1 || plan2.Zones[0].Name != "list_yt" || plan2.Zones[0].SrcScoped {
		t.Fatalf("unscoped list must be a single unscoped zone, got %+v", plan2.Zones)
	}

	// "only" scope resolving to an empty group → route for nobody (no list zone).
	empty := model.DeviceGroup{ID: "empty", Name: "Empty"}
	p3 := base([]model.RoutingList{{ID: "yt", Name: "YT", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"empty"}}}, []model.DeviceGroup{empty})
	plan3, _, _ := Compile(p3, Options{})
	for _, z := range plan3.Zones {
		if strings.HasPrefix(z.Name, "list_yt") {
			t.Errorf("empty-scope list must produce no zone, got %+v", z)
		}
	}
}

// TestCompileListExceptScope: an "except"-scoped list compiles to ONE negated source zone (marks every
// device EXCEPT the group), and the rendered nft uses `!=` for both the MAC and IP source predicates.
func TestCompileListExceptScope(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
		DeviceGroups: []model.DeviceGroup{{ID: "guests", Name: "Guests", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "192.168.1.99/32"}}}},
		RoutingLists: []model.RoutingList{{ID: "vpn", Name: "VPN", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "except", ScopeGroups: []string{"guests"}}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var z *Zone
	for i := range plan.Zones {
		if plan.Zones[i].Name == "list_vpn" {
			z = &plan.Zones[i]
		}
	}
	if z == nil {
		t.Fatalf("expected one negated zone list_vpn; zones=%+v", plan.Zones)
	}
	if !z.SrcScoped || !z.SrcNegate {
		t.Errorf("except zone must be SrcScoped + SrcNegate, got %+v", z)
	}
	if len(z.SrcMAC) != 1 || z.SrcMAC[0] != "aa:bb:cc:dd:ee:ff" || len(z.SrcV4) != 1 || !strings.Contains(z.SrcV4[0], "192.168.1.99") {
		t.Errorf("except zone must carry the group's MAC + IP as source predicates, got %+v", z)
	}
	nft := plan.RenderNft()
	if !strings.Contains(nft, "ether saddr != ") {
		t.Errorf("rendered nft must negate the MAC match:\n%s", nft)
	}
	if !strings.Contains(nft, "ip saddr != @list_vpn_s4") {
		t.Errorf("rendered nft must negate the IP saddr match:\n%s", nft)
	}
}

// TestExceptCrossFamilyStillRoutes: an "except" group whose only IP member is IPv6 (plus a MAC),
// applied to a v4-dest list, must STILL route v4 for everyone-except-the-MAC. The v6 member can't be
// excluded on the v4 plane, so the v4 dest line is emitted carved only by the MAC — never dropped
// (dropping it would silently route nobody on v4, the opposite of "everyone except this group").
func TestExceptCrossFamilyStillRoutes(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
		DeviceGroups: []model.DeviceGroup{{ID: "g", Name: "G", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "fd00::1/128"}}}},
		RoutingLists: []model.RoutingList{{ID: "vpn", Name: "VPN", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "except", ScopeGroups: []string{"g"}}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	// The v4 dest line must exist and carry the MAC negation (route all v4 except the MAC).
	if !strings.Contains(nft, "ether saddr != ") || !strings.Contains(nft, "ip daddr @list_vpn_4") {
		t.Errorf("v6-only-scoped except must still route v4 minus the MAC (v4 line dropped):\n%s", nft)
	}
	// It must NOT reference a v4 source set — the group has no v4 member, so no _s4 set exists.
	if strings.Contains(nft, "@list_vpn_s4") {
		t.Errorf("v4 line must not reference a non-existent v4 src set:\n%s", nft)
	}
}

// TestCompileExceptEmptyGroupRoutesAll: "except" an empty group = "everyone except nobody" = everyone,
// so it must compile to a single UNSCOPED zone (route all), not a negated/empty zone that routes nobody.
func TestCompileExceptEmptyGroupRoutesAll(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
		DeviceGroups: []model.DeviceGroup{{ID: "empty", Name: "Empty"}},
		RoutingLists: []model.RoutingList{{ID: "vpn", Name: "VPN", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "except", ScopeGroups: []string{"empty"}}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var z *Zone
	for i := range plan.Zones {
		if plan.Zones[i].Name == "list_vpn" {
			z = &plan.Zones[i]
		}
	}
	if z == nil {
		t.Fatalf("except-empty must still route (one unscoped zone); zones=%+v", plan.Zones)
	}
	if z.SrcScoped || z.SrcNegate {
		t.Errorf("except-empty must be an UNSCOPED route-all zone, got SrcScoped=%v SrcNegate=%v", z.SrcScoped, z.SrcNegate)
	}
}
