package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// userspaceProfile is a native AmneziaWG endpoint ("native") next to one WayHop's userspace engine
// runs ("u"), with the routing objects each case adds.
func userspaceProfile() model.Profile {
	native := awgEndpoint()
	native.ID, native.Enabled, native.Protocol = "native", true, model.ProtoAmneziaWG
	u := awgEndpoint()
	u.ID, u.Enabled, u.Protocol, u.Server = "u", true, model.ProtoAmneziaWG, "198.51.100.44"
	return model.Profile{Endpoints: []model.Endpoint{native, u}}
}

var userspaceDevices = map[string]string{"u": "wr_test0001"}

// The endpoint gets no NDM interface block, the device as its route-target name, and its peer's
// anti-loop route - and nothing in the plan asks NDM to name the device.
func TestCompileUserspaceEndpoint(t *testing.T) {
	profile := userspaceProfile()
	plan, err := Compile(&profile, CompileOptions{Userspace: userspaceDevices})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Interfaces) != 1 || plan.IfaceFor["u"] != "wr_test0001" || plan.CompatibilityRouting || plan.Singbox != nil {
		t.Fatalf("plan: %d blocks, IfaceFor %v, compatibility %v, singbox %v",
			len(plan.Interfaces), plan.IfaceFor, plan.CompatibilityRouting, plan.Singbox != nil)
	}
	routes := strings.Join(plan.Routes, "\n")
	if !strings.Contains(routes, "ip route 198.51.100.44 255.255.255.255 ISP") || strings.Contains(routes, "wr_test0001") {
		t.Errorf("routes: %v", plan.Routes)
	}
	proxy := model.Endpoint{ID: "p", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoAmneziaWG}
	profile.Endpoints = append(profile.Endpoints, proxy)
	if _, err := Compile(&profile, CompileOptions{Userspace: map[string]string{"p": "wr_test0002"}}); err == nil {
		t.Error("a non-AmneziaWG endpoint was handed to the userspace engine")
	}
}

// NDM routes by NDM interface, so anything that would need it to reach the device - a default route,
// a group, a list with no kernel plane to carry it - moves the policy to the compatibility core. A
// list the ipset plane carries needs no NDM route and stays native.
func TestUserspaceRoutingNeedsADevicePlane(t *testing.T) {
	defaultRule := []model.Rule{{ID: "all", Default: true, Outbound: "u"}}
	list := []model.RoutingList{{ID: "l", Enabled: true, Outbound: "u", Manual: []string{"203.0.113.0/24"}}}
	group := []model.Group{{ID: "g", Members: []string{"native", "u"}}}
	groupList := []model.RoutingList{{ID: "gl", Enabled: true, Outbound: "g", Manual: []string{"203.0.113.0/24"}}}
	for _, c := range []struct {
		name          string
		rules         []model.Rule
		lists         []model.RoutingList
		groups        []model.Group
		listsViaIpset bool
		compatibility bool
	}{
		{"default route through the device", defaultRule, nil, nil, true, true},
		{"list, no kernel plane", nil, list, nil, false, true},
		{"list, ipset plane", nil, list, nil, true, false},
		{"group with a userspace member", nil, groupList, group, true, true},
	} {
		profile := userspaceProfile()
		profile.Rules, profile.RoutingLists, profile.Groups = c.rules, c.lists, c.groups
		opt := CompileOptions{Userspace: userspaceDevices, ListsViaIpset: c.listsViaIpset,
			GlobalPriorityNow: map[string]int{"ISP": 1000}}
		plan, err := Compile(&profile, opt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if plan.CompatibilityRouting != c.compatibility {
			t.Errorf("%s: compatibility routing = %v, want %v", c.name, plan.CompatibilityRouting, c.compatibility)
		}
		// The review asks the same question with the same planes.
		if got := PlanRequiresCore(&profile, opt.planes()); got != (plan.Singbox != nil) {
			t.Errorf("%s: PlanRequiresCore = %v, Compile produced a core = %v", c.name, got, plan.Singbox != nil)
		}
		for _, r := range plan.Routes {
			if strings.Contains(r, "wr_test0001") {
				t.Errorf("%s: NDM was asked to route to the device: %q", c.name, r)
			}
		}
		for iface := range plan.GlobalPriority {
			if iface == "wr_test0001" {
				t.Errorf("%s: NDM was asked to raise the device on the ladder", c.name)
			}
		}
	}
}

// A userspace endpoint nothing routes into pulls in no core: the engine plugin runs it, not sing-box.
func TestCoreReasonsLeaveUserspaceEndpointsToThePlugin(t *testing.T) {
	profile := userspaceProfile()
	planes := RoutePlanes{Userspace: userspaceDevices}
	if reasons := CoreReasons(&profile, planes); len(reasons) != 0 {
		t.Errorf("core reasons for a plugin-run endpoint: %v", reasons)
	}
	// Without the userspace set the same endpoint is a native one, and native needs no core either;
	// what the set changes is only what may route into it.
	profile.Rules = []model.Rule{{ID: "all", Default: true, Outbound: "u"}}
	if PlanRequiresCore(&profile, RoutePlanes{}) {
		t.Error("a default route to a native endpoint pulled in the core")
	}
	if !PlanRequiresCore(&profile, planes) {
		t.Error("a default route to a userspace endpoint did not pull in the core")
	}
}
