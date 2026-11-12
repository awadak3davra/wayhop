package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// OpenWrt's generic path (sing-box + engine plugins) takes a profile the native planner refuses, but
// never from interfaces a native Apply created: that path reconciles nothing native, and an engine
// plugin would run a link under the same name netifd runs. Nor does a native plan take a connection
// from an engine plugin the generic path ran, for the same reason the other way round. These tests
// drive materialize the way an Apply does, with the previous record's materialization as the baseline.

func fallbackApply(d DesiredSnapshot, h HostSnapshotV1, c executionNativeCaptureV1,
	previous *executionMaterializationV1) (executionMaterializationV1, []string, error) {
	return materialize(materializeInput{desired: d, host: ExecutionHostFactsV1{Host: h}, native: &c, previous: previous})
}

func fellBackToGeneric(m executionMaterializationV1, warnings []string, err error) bool {
	return err == nil && m.Native == nil &&
		strings.Contains(strings.Join(warnings, "\n"), "router-native tunnels are not used")
}

// withEndpointParams copies d with the endpoint at index i holding params on top of its own; the
// endpoints and the params map are copied, so the fixture d came from is left as it was.
func withEndpointParams(d DesiredSnapshot, i int, params map[string]any) DesiredSnapshot {
	d.Profile.Endpoints = append([]model.Endpoint(nil), d.Profile.Endpoints...)
	merged := make(map[string]any, len(d.Profile.Endpoints[i].Params)+len(params))
	for k, v := range d.Profile.Endpoints[i].Params {
		merged[k] = v
	}
	for k, v := range params {
		merged[k] = v
	}
	d.Profile.Endpoints[i].Params = merged
	return d
}

func withCapabilityState(set platform.CapabilitySet, id string, state platform.CapState) platform.CapabilitySet {
	items := make(map[string]platform.Capability, len(set.Items))
	for k, v := range set.Items {
		items[k] = v
	}
	capability := items[id]
	capability.ID, capability.State = id, state
	items[id] = capability
	set.Items = items
	return set
}

var warpClientID = map[string]any{"reserved": []any{1.0, 2.0, 3.0}}

// Every native refusal that would hand a profile to the generic path after a native Apply is refused
// instead, naming the planner's reason and the interface the earlier Apply created; the same change
// on a router where WayHop holds no native interface still falls back.
func TestMaterializeOpenWrtKeepsTheGenericPathOffItsOwnNativeInterfaces(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	native, _, err := fallbackApply(desired, host, capture, nil)
	if err != nil || native.Native == nil {
		t.Fatalf("the fixture must materialize native-first: native=%v err=%v", native.Native != nil, err)
	}
	iface := netvpn.InterfaceName(desired.Profile.Endpoints[0])
	if owned := nativeOwnershipFrom(nativeBaselineFromMaterialization(&native)); owned["ep-native"] != iface {
		t.Fatalf("the native Apply owns %v, want ep-native on %s", owned, iface)
	}
	// Nothing refused while the planner takes the profile: the baseline alone is no reason.
	if again, _, err := fallbackApply(desired, host, capture, &native); err != nil || again.Native == nil {
		t.Fatalf("a native Apply over a native baseline: native=%v err=%v", again.Native != nil, err)
	}

	createID := platform.NativeOperationCapabilityID(string(model.ProtoAmneziaWG), platform.NativeCreate)
	for _, tc := range []struct {
		name    string
		trigger string // what the planner's own refusal says
		change  func(*DesiredSnapshot, *HostSnapshotV1, *executionNativeCaptureV1)
	}{
		{"a WARP client id the UCI writer has no option for", "WARP client id",
			func(d *DesiredSnapshot, _ *HostSnapshotV1, _ *executionNativeCaptureV1) {
				*d = withEndpointParams(*d, 0, warpClientID)
			}},
		{"the reviewed firewall zone cleared", "firewall zone",
			func(d *DesiredSnapshot, _ *HostSnapshotV1, c *executionNativeCaptureV1) {
				d.Config.NativeFirewallZone, c.FirewallZone = "", "" // the capture copies the setting
			}},
		{"the native create capability flapped", createID,
			func(_ *DesiredSnapshot, h *HostSnapshotV1, _ *executionNativeCaptureV1) {
				h.CapabilitySet = withCapabilityState(h.CapabilitySet, createID, platform.CapUnknown)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, h, c := desired, host, capture
			tc.change(&d, &h, &c)
			if m, warnings, err := fallbackApply(d, h, c, nil); !fellBackToGeneric(m, warnings, err) {
				t.Fatalf("with no native baseline: native=%v warnings=%q err=%v, want the generic path",
					m.Native != nil, warnings, err)
			}
			_, _, err := fallbackApply(d, h, c, &native)
			stage, detail, remedy := materializeFailure(err)
			if err == nil || stage != "native" {
				t.Fatalf("after a native Apply: stage %q, err %v; want a native refusal", stage, err)
			}
			for _, want := range []string{tc.trigger, `"native" (ep-native) on ` + iface} {
				if !strings.Contains(detail, want) {
					t.Errorf("detail %q does not name %q", detail, want)
				}
			}
			if !strings.Contains(remedy, "switch off the connections") || !strings.Contains(remedy, "apply again") {
				t.Errorf("remedy %q does not give the way round", remedy)
			}
		})
	}
}

// A connection deleted since the native Apply still has its interface on the router, and only the
// native reconcile removes it: the refusal names it although the profile no longer does.
func TestMaterializeOpenWrtNamesTheInterfaceOfADeletedConnection(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	native, _, err := fallbackApply(desired, host, capture, nil)
	if err != nil || native.Native == nil {
		t.Fatalf("native=%v err=%v", native.Native != nil, err)
	}
	iface := netvpn.InterfaceName(desired.Profile.Endpoints[0])
	replaced := withEndpointParams(desired, 0, warpClientID)
	replaced.Profile.Endpoints[0].ID, replaced.Profile.Endpoints[0].Name = "ep-warp", "warp"
	_, _, err = fallbackApply(replaced, host, capture, &native)
	if stage, detail, _ := materializeFailure(err); err == nil || stage != "native" ||
		!strings.Contains(detail, "ep-native (no longer configured) on "+iface) {
		t.Errorf("err %v, stage %q, detail %q; want the deleted connection's interface named", err, stage, detail)
	}
}

// withSecondConnection adds a second AmneziaWG connection the native writer can carry, and returns
// both connections' "label on interface" entries joined in interface order, the way a refusal lists
// them.
func withSecondConnection(d DesiredSnapshot) (DesiredSnapshot, string) {
	second := withEndpointParams(d, 0, map[string]any{"local_address": []string{"10.77.0.3/32"}}).Profile.Endpoints[0]
	second.ID, second.Name, second.Port = "ep-second", "second", 51821
	d.Profile.Endpoints = append(append([]model.Endpoint(nil), d.Profile.Endpoints...), second)
	first, last := d.Profile.Endpoints[0], d.Profile.Endpoints[1]
	if netvpn.InterfaceName(last) < netvpn.InterfaceName(first) {
		first, last = last, first
	}
	return d, endpointLabel(first) + " on " + netvpn.InterfaceName(first) + ", " +
		endpointLabel(last) + " on " + netvpn.InterfaceName(last)
}

// Every interface the baseline holds is named, in interface order, whichever connection the planner
// refused.
func TestMaterializeOpenWrtNamesEveryHeldInterface(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	desired, want := withSecondConnection(desired)
	native, _, err := fallbackApply(desired, host, capture, nil)
	if err != nil || native.Native == nil || len(nativeOwnershipFrom(nativeBaselineFromMaterialization(&native))) != 2 {
		t.Fatalf("the two-connection fixture must create two native interfaces: native=%v err=%v", native.Native != nil, err)
	}
	_, _, err = fallbackApply(withEndpointParams(desired, 1, warpClientID), host, capture, &native)
	if _, detail, _ := materializeFailure(err); err == nil || !strings.HasSuffix(detail, "created: "+want) {
		t.Errorf("err %v, detail %q; want it to end with %q", err, detail, want)
	}
}

// The way round the refusal gives: with the connection switched off, a native Apply compiles and its
// reconcile removes the interface; switched back on, the generic path takes it from nothing native.
func TestMaterializeOpenWrtFallsBackOnceTheNativeInterfacesAreRemoved(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	native, _, err := fallbackApply(desired, host, capture, nil)
	if err != nil || native.Native == nil {
		t.Fatalf("native=%v err=%v", native.Native != nil, err)
	}
	iface := netvpn.InterfaceName(desired.Profile.Endpoints[0])
	// The router as that Apply left it: the interface configured and a member of the reviewed zone.
	applied := capture
	applied.NetworkUCI += "network." + iface + "=interface\nnetwork." + iface + ".proto='amneziawg'\n"
	applied.FirewallUCI += "firewall.@zone[0].network='" + iface + "'\n"

	off := desired
	off.Profile.Endpoints = append([]model.Endpoint(nil), desired.Profile.Endpoints...)
	off.Profile.Endpoints[0].Enabled = false
	removed, _, err := fallbackApply(off, host, applied, &native)
	if err != nil || removed.Native == nil {
		t.Fatalf("switching the connection off: native=%v err=%v", removed.Native != nil, err)
	}
	if r := removed.Native.Delta.Reconcile.OpenWrtRemovals; len(r) != 1 || r[0].Iface != iface {
		t.Fatalf("removals %+v, want %s", r, iface)
	}

	m, warnings, err := fallbackApply(withEndpointParams(desired, 0, warpClientID), host, capture, &removed)
	if !fellBackToGeneric(m, warnings, err) {
		t.Errorf("back on after the removal: native=%v warnings=%q err=%v, want the generic path", m.Native != nil, warnings, err)
	}
}

// An engine-plugin baseline holds no interface netifd runs - the device is the plugin's on either
// path and nothing was written to /etc/config/network for it - so the generic path may still take
// over from it.
func TestMaterializeOpenWrtFallsBackOverAnEnginePluginBaseline(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	gen3 := withEndpointParams(desired, 0, map[string]any{"header_protection_key": "k", "disable_cookies": true})
	engine, _, err := fallbackApply(gen3, host, capture, nil)
	if err != nil || engine.Native == nil || len(engine.Plugins) != 1 {
		t.Fatalf("the AmneziaWG 3 fixture must run on the engine next to the native plan: native=%v plugins=%d err=%v",
			engine.Native != nil, len(engine.Plugins), err)
	}
	if owned := nativeOwnershipFrom(nativeBaselineFromMaterialization(&engine)); len(owned) != 0 {
		t.Fatalf("the engine baseline owns native interfaces %v", owned)
	}
	cleared, c := gen3, capture
	cleared.Config.NativeFirewallZone, c.FirewallZone = "", ""
	if m, warnings, err := fallbackApply(cleared, host, c, &engine); !fellBackToGeneric(m, warnings, err) {
		t.Errorf("native=%v warnings=%q err=%v, want the generic path", m.Native != nil, warnings, err)
	}
}

// genericEngineBaseline is d applied while the router's own AmneziaWG could not create interfaces: the
// generic path ran every AmneziaWG connection on WayHop's engine plugin.
func genericEngineBaseline(t *testing.T, d DesiredSnapshot, host HostSnapshotV1,
	c executionNativeCaptureV1) executionMaterializationV1 {
	t.Helper()
	createID := platform.NativeOperationCapabilityID(string(model.ProtoAmneziaWG), platform.NativeCreate)
	missing := host
	missing.CapabilitySet = withCapabilityState(host.CapabilitySet, createID, platform.CapUnknown)
	generic, warnings, err := fallbackApply(d, missing, c, nil)
	if !fellBackToGeneric(generic, warnings, err) || len(generic.pluginSpecs()) == 0 {
		t.Fatalf("the generic baseline: native=%v plugins=%d warnings=%q err=%v",
			generic.Native != nil, len(generic.pluginSpecs()), warnings, err)
	}
	return generic
}

// Once the router's own AmneziaWG can create the interface, the native plan would take the connection
// the engine plugin ran, on the same device name: refused by name, as the planner refuses the move
// from a native baseline.
func TestMaterializeOpenWrtRefusesMovingAnEnginePluginToNative(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	generic := genericEngineBaseline(t, desired, host, capture)
	iface := netvpn.InterfaceName(desired.Profile.Endpoints[0])
	if spec := generic.pluginSpecs()[0]; spec.Endpoint.Engine != model.EngineAmneziaWG || util.AWGIface(spec.Endpoint.ID) != iface {
		t.Fatalf("the engine ran %+v, want the connection on %s", spec, iface)
	}
	_, _, err := fallbackApply(desired, host, capture, &generic)
	stage, detail, remedy := materializeFailure(err)
	if err == nil || stage != "native" {
		t.Fatalf("stage %q, err %v; want a native refusal", stage, err)
	}
	for _, want := range []string{"WayHop's AmneziaWG engine", `"native" (ep-native) on ` + iface} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not name %q", detail, want)
		}
	}
	if !strings.Contains(remedy, "Switch these connections off") || !strings.Contains(remedy, "apply again") {
		t.Errorf("remedy %q does not give the way round", remedy)
	}
}

// The move is judged on a plan that compiled. When another connection fails the native plan anyway,
// the Apply goes to the generic path again and the plugin keeps running: nothing moves, nothing is
// refused - whichever connection comes first.
func TestMaterializeOpenWrtKeepsAnEnginePluginWhenTheNativePlanFailsAnyway(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	warp := withEndpointParams(desired, 0, map[string]any{
		"reserved": warpClientID["reserved"], "local_address": []string{"10.77.0.4/32"},
	}).Profile.Endpoints[0]
	warp.ID, warp.Name, warp.Port = "ep-warp", "warp", 51821
	desired.Profile.Endpoints = append(append([]model.Endpoint(nil), desired.Profile.Endpoints...), warp)
	generic, warnings, err := fallbackApply(desired, host, capture, nil)
	if !fellBackToGeneric(generic, warnings, err) || len(generic.pluginSpecs()) != 2 {
		t.Fatalf("the generic baseline: native=%v plugins=%d err=%v", generic.Native != nil, len(generic.pluginSpecs()), err)
	}
	if m, warnings, err := fallbackApply(desired, host, capture, &generic); !fellBackToGeneric(m, warnings, err) {
		t.Errorf("native=%v warnings=%q err=%v, want the generic path again", m.Native != nil, warnings, err)
	}
}

// A connection the native plan hands to the userspace lane stays on the engine: no native interface
// takes its device, so it is not a move.
func TestMaterializeOpenWrtEnginePluginToTheUserspaceLaneIsNoMove(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	gen3 := withEndpointParams(desired, 0, map[string]any{"header_protection_key": "k", "disable_cookies": true})
	generic := genericEngineBaseline(t, gen3, host, capture)
	m, _, err := fallbackApply(gen3, host, capture, &generic)
	if err != nil || m.Native == nil || len(m.Plugins) != 1 {
		t.Errorf("native=%v plugins=%d err=%v, want native-first with the plugin", m.Native != nil, len(m.Plugins), err)
	}
}

// The way round the refusal gives: switched off, the connection leaves the engine (the plugin is not
// in the next plan, so the executor retires it); switched back on, the native plan creates it.
func TestMaterializeOpenWrtTakesAnEnginePluginNativeInTwoApplies(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	generic := genericEngineBaseline(t, desired, host, capture)
	off := desired
	off.Profile.Endpoints = append([]model.Endpoint(nil), desired.Profile.Endpoints...)
	off.Profile.Endpoints[0].Enabled = false
	retired, _, err := fallbackApply(off, host, capture, &generic)
	if err != nil || retired.Native == nil || len(retired.pluginSpecs()) != 0 {
		t.Fatalf("switched off: native=%v plugins=%d err=%v", retired.Native != nil, len(retired.pluginSpecs()), err)
	}
	on, _, err := fallbackApply(desired, host, capture, &retired)
	if err != nil || on.Native == nil || len(nativeOwnershipFrom(nativeBaselineFromMaterialization(&on))) != 1 {
		t.Errorf("switched on: native=%v err=%v, want the native interface", on.Native != nil, err)
	}
}

// Every connection that would move is named, in interface order.
func TestMaterializeOpenWrtNamesEveryMovingConnection(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	desired, want := withSecondConnection(desired)
	generic := genericEngineBaseline(t, desired, host, capture)
	_, _, err := fallbackApply(desired, host, capture, &generic)
	if _, detail, _ := materializeFailure(err); err == nil || !strings.Contains(detail, "device names: "+want+";") {
		t.Errorf("err %v, detail %q; want it to list %q", err, detail, want)
	}
}
