package pbr

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// devicesProfile has one endpoint of every kind the plane meets on KeeneticOS: an AmneziaWG tunnel NDM
// creates ("ndm"), one WayHop's own engine runs ("engine"), an adopted router tunnel ("adopted") and a
// proxy ("proxy"), plus a group whose first kernel member is the NDM one.
func devicesProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ndm", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "198.51.100.7", Port: 51820,
				Enabled: true, Params: map[string]any{"local_address": []string{"10.66.0.2/32", "fd00:66::2/128"}}},
			{ID: "engine", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "198.51.100.8", Port: 51820,
				Enabled: true},
			{ID: "adopted", Engine: model.EngineExternal, Protocol: model.ProtoWireGuard, Enabled: true,
				Params: map[string]any{"interface": "nwg3", "endpoint_ip": "198.51.100.9"}},
			{ID: "proxy", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "198.51.100.10", Port: 443,
				Enabled: true},
		},
		Groups: []model.Group{{ID: "grp", Members: []string{"proxy", "ndm", "engine"}}},
		RoutingLists: []model.RoutingList{
			{ID: "l-ndm", Manual: []string{"203.0.113.0/24", "2001:db8::/32"}, Outbound: "ndm", Enabled: true},
			{ID: "l-engine", Manual: []string{"192.0.2.0/24"}, Outbound: "engine", Enabled: true},
			{ID: "l-adopted", Manual: []string{"198.18.0.0/24"}, Outbound: "adopted", Enabled: true},
			{ID: "l-grp", Manual: []string{"198.18.1.0/24"}, Outbound: "grp", Enabled: true},
			{ID: "l-proxy", Manual: []string{"198.18.2.0/24"}, Outbound: "proxy", Enabled: true},
		},
	}
}

func egressesByTag(plan *Plan) map[string]Egress {
	out := map[string]Egress{}
	for _, e := range plan.Egresses {
		out[e.Tag] = e
	}
	return out
}

// Devices renames the device an endpoint's table is seeded with, the masquerade set and a group's
// member device - and nothing else: marks, tables, zones (IPv6 kept, so the endpoint stays an
// AmneziaWG one in every other respect), bypass and warnings are those of the plan without it. A
// proxy endpoint it names stays a proxy endpoint.
func TestCompileDevicesRenamesOnlyTheDevice(t *testing.T) {
	derived, derivedWarns, err := Compile(devicesProfile(), Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	devices := map[string]string{"ndm": "nwg10", "proxy": "nwg11"}
	renamed, renamedWarns, err := Compile(devicesProfile(), Options{CollectDomainZones: true, Devices: devices})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"ndm": "nwg10", "grp": "nwg10", "engine": util.AWGIface("engine"), "adopted": "nwg3",
	}
	got := egressesByTag(renamed)
	for tag, device := range want {
		if got[tag].Kind != EgressInterface || got[tag].Iface != device {
			t.Errorf("egress %q = %+v, want device %s", tag, got[tag], device)
		}
	}
	if _, routed := got["proxy"]; routed {
		t.Errorf("a proxy endpoint became kernel-routed through its Devices entry: %+v", got["proxy"])
	}
	if e := egressesByTag(derived)["ndm"]; e.Iface != util.AWGIface("ndm") {
		t.Fatalf("without Devices the device is %q, want the derived %s", e.Iface, util.AWGIface("ndm"))
	}

	if len(derived.Egresses) != len(renamed.Egresses) {
		t.Fatalf("egress count %d vs %d", len(derived.Egresses), len(renamed.Egresses))
	}
	for i := range derived.Egresses {
		a, b := derived.Egresses[i], renamed.Egresses[i]
		if a.Tag != b.Tag || a.Kind != b.Kind || a.Mark != b.Mark || a.Table != b.Table || a.FailClosed != b.FailClosed {
			t.Errorf("egress %d moved: %+v vs %+v", i, a, b)
		}
	}
	if !reflect.DeepEqual(derived.Zones, renamed.Zones) || !reflect.DeepEqual(derived.BypassV4, renamed.BypassV4) ||
		!reflect.DeepEqual(derived.BypassV6, renamed.BypassV6) || !reflect.DeepEqual(derivedWarns, renamedWarns) {
		t.Errorf("Devices changed more than devices:\nzones %+v\nvs    %+v\nwarns %v vs %v",
			derived.Zones, renamed.Zones, derivedWarns, renamedWarns)
	}
	for _, z := range renamed.Zones {
		if z.EgressTag == "ndm" && !reflect.DeepEqual(z.V6, []string{"2001:db8::/32"}) {
			t.Errorf("the renamed AmneziaWG egress lost its IPv6 destinations: %+v", z)
		}
	}

	if !contains(renamed.MasqIfaces, "nwg10") || contains(renamed.MasqIfaces, util.AWGIface("ndm")) ||
		contains(renamed.MasqIfaces, "nwg11") {
		t.Errorf("MasqIfaces = %v", renamed.MasqIfaces)
	}
	script := renamed.RenderIPScript(Options{})
	if !strings.Contains(script, "ip route add default dev nwg10 table ") || strings.Contains(script, util.AWGIface("ndm")) {
		t.Errorf("seed routes:\n%s", script)
	}
}

// An empty map, or one naming nothing the plane routes, leaves the plan byte for byte as it was.
func TestCompileDevicesNamingNothingRoutedIsInert(t *testing.T) {
	encode := func(opt Options) string {
		t.Helper()
		plan, warns, err := Compile(devicesProfile(), opt)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(struct {
			Plan  *Plan
			Warns []Warning
			IP    string
		}{plan, warns, plan.RenderIPScript(Options{})})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	base := encode(Options{})
	for name, devices := range map[string]map[string]string{
		"empty":           {},
		"unknown":         {"gone": "nwg4"},
		"proxy only":      {"proxy": "nwg5"},
		"derived already": {"engine": util.AWGIface("engine")},
	} {
		if got := encode(Options{Devices: devices}); got != base {
			t.Errorf("%s: the plan changed:\n%s\nvs\n%s", name, got, base)
		}
	}
}

// The device is rendered unquoted into the Keenetic plane's shell and into nft, so a name that is not
// an interface name is refused - never dropped, which would fall back to the derived device.
func TestCompileRefusesADeviceThatIsNotAnInterfaceName(t *testing.T) {
	for _, bad := range []string{"", "nwg10; reboot", "nwg10 table 1", "a234567890123456", "-nwg10"} {
		if _, _, err := Compile(devicesProfile(), Options{Devices: map[string]string{"ndm": bad}}); err == nil {
			t.Errorf("device %q was accepted", bad)
		}
	}
}

// KernelDevice renames; it never makes an endpoint the plane does not route into a kernel one.
func TestKernelDevice(t *testing.T) {
	p := devicesProfile()
	devices := map[string]string{"ndm": "nwg10", "proxy": "nwg11"}
	for id, want := range map[string]string{
		"ndm": "nwg10", "engine": util.AWGIface("engine"), "adopted": "nwg3", "proxy": "",
	} {
		if got := KernelDevice(p.EndpointByID(id), devices); got != want {
			t.Errorf("KernelDevice(%s) = %q, want %q", id, got, want)
		}
		if got, derived := KernelDevice(p.EndpointByID(id), nil), KernelIface(p.EndpointByID(id)); got != derived {
			t.Errorf("KernelDevice(%s, nil) = %q, want KernelIface's %q", id, got, derived)
		}
	}
}
