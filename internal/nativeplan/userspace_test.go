package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// keeneticWithoutAWG is KeeneticOS whose firmware has no AmneziaWG writer WayHop can use: the
// WireGuard component is not installed.
func keeneticWithoutAWG() platform.CapabilitySet {
	return platform.Evaluate(platform.Capabilities{
		Platform: string(platform.Keenetic), Native: map[string]bool{},
		Installable: map[string]string{"amneziawg": "WireGuard component"},
	}, platform.RuntimeFacts{})
}

// Which endpoints KeeneticOS hands to WayHop's engine, and why - the set the planner decides by and
// the review explains by.
func TestKeeneticUserspace(t *testing.T) {
	gen3 := awg31Managed()
	gen3.ID = "gen3"
	plain := managedAWG()
	plain.ID = "plain"
	facts := keeneticFacts(plain) // NDM can create and remove AmneziaWG interfaces

	set := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{gen3, plain}}, facts.Capabilities)
	if len(set) != 1 {
		t.Fatalf("userspace set = %+v, want only the 3.x endpoint", set)
	}
	u := set["gen3"]
	if u.Device != util.AWGIface("gen3") || u.Code != platform.ReasonPlatformUnsupported ||
		!strings.Contains(u.Reason, "header_protection_key, random_trailers") {
		t.Errorf("3.x endpoint = %+v", u)
	}

	// No AmneziaWG in the firmware: every WayHop-owned AmneziaWG endpoint runs on the engine, with the
	// firmware's own reason and remedy.
	set = KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{plain}}, keeneticWithoutAWG())
	u, ok := set["plain"]
	if !ok || u.Code != platform.ReasonMissingFirmwareComp || u.Remedy == "" ||
		!strings.Contains(u.Reason, "KeeneticOS cannot run it natively") {
		t.Errorf("endpoint without native AmneziaWG = %+v (in set: %v)", u, ok)
	}

	// Never: a disabled endpoint, an adopted tunnel, one WayHop does not own, or a sing-box WireGuard
	// endpoint - there is no userspace engine for that one here.
	disabled := gen3
	disabled.Enabled = false
	adopted := gen3
	adopted.Owner = model.OwnerExternal
	foreign := gen3
	foreign.Owner = model.Owner("future-owner")
	singbox := gen3
	singbox.Engine, singbox.Protocol = model.EngineSingBox, model.ProtoWireGuard
	for name, e := range map[string]model.Endpoint{
		"disabled": disabled, "adopted": adopted, "not owned": foreign, "sing-box WireGuard": singbox,
	} {
		if got := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{e}}, keeneticWithoutAWG()); len(got) != 0 {
			t.Errorf("%s endpoint was handed to the userspace engine: %+v", name, got)
		}
	}
}

// A profile with a native endpoint and an AmneziaWG 3 one: NDM gets the first, WayHop's engine the
// second - no interface block, no native authority, the device as its interface, and the peer's
// anti-loop route still planned.
func TestCompileKeeneticRunsAWG3OnTheUserspaceEngine(t *testing.T) {
	plain := managedAWG()
	plain.ID, plain.Server = "plain", "198.51.100.11"
	gen3 := awg31Managed()
	gen3.ID, gen3.Server = "gen3", "198.51.100.33"
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{plain, gen3}}, keeneticFacts(plain))
	if err != nil {
		t.Fatal(err)
	}
	decisions := map[string]EndpointDecision{}
	for _, d := range plan.Decisions {
		decisions[d.EndpointID] = d
	}
	if d := decisions["plain"]; d.Path != PathNativeCreate || !strings.HasPrefix(d.Interface, "Wireguard") {
		t.Errorf("native endpoint = %+v", d)
	}
	want := EndpointDecision{EndpointID: "gen3", Protocol: model.ProtoAmneziaWG, Path: PathEnginePlugin, Interface: util.AWGIface("gen3")}
	if d := decisions["gen3"]; d != want {
		t.Errorf("userspace endpoint = %+v, want %+v", d, want)
	}
	if len(plan.Keenetic.Interfaces) != 1 || plan.Keenetic.IfaceFor["gen3"] != util.AWGIface("gen3") {
		t.Errorf("NDM blocks %d, IfaceFor %v", len(plan.Keenetic.Interfaces), plan.Keenetic.IfaceFor)
	}
	if !strings.Contains(strings.Join(plan.Keenetic.Routes, "\n"), "ip route 198.51.100.33 255.255.255.255 ISP") {
		t.Errorf("the userspace peer has no anti-loop route: %v", plan.Keenetic.Routes)
	}
}

// An endpoint that was native and now needs AmneziaWG 3 moves to the engine: its old NDM interface is
// torn down by the reconcile - and only with the remove authority still proven, so a capability probe
// that merely failed can never move a working tunnel.
func TestReconcileKeeneticNativeToUserspace(t *testing.T) {
	endpoint := managedAWG()
	facts := keeneticFacts(endpoint)
	previous, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	oldIface := previous.Decisions[0].Interface
	upgraded := awg31Managed()
	target, err := Compile(&model.Profile{Endpoints: []model.Endpoint{upgraded}}, facts)
	if err != nil || target.Decisions[0].Path != PathEnginePlugin {
		t.Fatalf("target = %+v, err %v", target, err)
	}
	rec, err := Reconcile(previous, target, facts.Capabilities, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rec.KeeneticTeardown, "\n"), "no interface "+oldIface) {
		t.Errorf("teardown %v does not remove the old %s", rec.KeeneticTeardown, oldIface)
	}
	lost := keeneticFacts(endpoint)
	delete(lost.Capabilities.Items, platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeRemove))
	if _, err := Reconcile(previous, target, lost.Capabilities, "", ""); err == nil {
		t.Error("the move went ahead without the authority to remove the old interface")
	}
}

// A capability probe that failed is not an answer: an endpoint NDM could carry stays on the native
// path, which refuses for want of the capability, rather than moving to the engine on a measurement
// that did not happen. An AmneziaWG 3 endpoint moves regardless - its settings, not the probe, say NDM
// cannot carry it.
func TestKeeneticUserspaceIgnoresAFailedProbe(t *testing.T) {
	poisoned := platform.Evaluate(platform.Capabilities{
		Platform: string(platform.Keenetic), Native: map[string]bool{"amneziawg": true},
		Installable: map[string]string{},
	}, platform.RuntimeFacts{
		NativeOperations: map[string]bool{
			platform.NativeOperationCapabilityID("amneziawg", platform.NativeCreate): true,
			platform.NativeOperationCapabilityID("amneziawg", platform.NativeRemove): true,
		},
		ProbeError: "ndm did not answer",
	})
	plain := managedAWG()
	if got := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{plain}}, poisoned); len(got) != 0 {
		t.Fatalf("a failed probe moved a native endpoint to the engine: %+v", got)
	}
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{plain}}, HostFacts{
		Platform: platform.Keenetic, Capabilities: poisoned, OccupiedInterfaces: map[string]bool{},
	}); err == nil || !strings.Contains(err.Error(), "native.operation.amneziawg.create") {
		t.Errorf("compile under a failed probe = %v, want the capability refusal", err)
	}
	if got := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{awg31Managed()}}, poisoned); len(got) != 1 {
		t.Errorf("the AmneziaWG 3 endpoint did not move: %+v", got)
	}
}
