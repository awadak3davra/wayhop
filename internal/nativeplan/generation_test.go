package nativeplan

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

func keeneticFacts(endpoint model.Endpoint) HostFacts {
	protocol := string(endpoint.Protocol)
	return HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeCreate),
			platform.NativeOperationCapabilityID(protocol, platform.NativeRemove),
		),
		OccupiedInterfaces: map[string]bool{},
	}
}

func awg31Managed() model.Endpoint {
	endpoint := managedAWG()
	endpoint.Params["header_protection_key"] = "k"
	endpoint.Params["random_trailers"] = true
	endpoint.Params["s3"] = 20
	return endpoint
}

// OpenWrt, whose own AmneziaWG would take the endpoint but cannot carry its 3.x settings, hands it
// to WayHop's userspace engine: an engine-plugin decision on the plugin's device, and a binding that
// puts that device into the reviewed firewall zone - nothing written to /etc/config/network for it.
func TestCompileOpenWrtRunsAWG3OnTheUserspaceEngine(t *testing.T) {
	endpoint := awg31Managed()
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, openWrtFacts(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	device := util.AWGIface(endpoint.ID)
	want := EndpointDecision{EndpointID: endpoint.ID, Protocol: model.ProtoAmneziaWG, Path: PathEnginePlugin, Interface: device}
	if len(plan.Decisions) != 1 || plan.Decisions[0] != want {
		t.Fatalf("decisions = %+v, want %+v", plan.Decisions, want)
	}
	if len(plan.OpenWrt) != 0 || len(plan.OpenWrtBindings) != 1 {
		t.Fatalf("UCI plans %d, bindings %+v", len(plan.OpenWrt), plan.OpenWrtBindings)
	}
	b := plan.OpenWrtBindings[0]
	if b.Device != device || b.Zone != "vpn" || b.ZoneRef != "@zone[0]" || len(b.Commands) != 1 {
		t.Errorf("binding = %+v", b)
	}
	noZone := openWrtFacts(endpoint)
	noZone.FirewallZone = ""
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, noZone); err == nil ||
		!strings.Contains(err.Error(), "reviewed OpenWrt firewall zone") {
		t.Errorf("no reviewed zone: %v", err)
	}
}

// A move between the router's own AmneziaWG and the engine, either way, is refused within one Apply:
// both run the endpoint on one device name.
func TestCompileOpenWrtRefusesAMoveWithinOneApply(t *testing.T) {
	endpoint := awg31Managed()
	device := util.AWGIface(endpoint.ID)

	wasNative := openWrtFacts(endpoint)
	wasNative.OwnedInterfaces = map[string]string{endpoint.ID: device}
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, wasNative)
	var move *MoveError
	if !errors.As(err, &move) || move.ToNative || move.Device != device {
		t.Errorf("native to userspace: %v", err)
	}

	stillThere := openWrtFacts(endpoint)
	stillThere.NetworkUCI = "network." + device + "=interface\nnetwork." + device + ".proto='amneziawg'\n"
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, stillThere); !errors.As(err, &move) {
		t.Errorf("an interface of that name on the router: %v", err)
	}

	back := managedAWG() // generation 1 again: the native writer would take it
	wasPlugin := openWrtFacts(back)
	wasPlugin.PluginDevices = map[string]string{back.ID: device}
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{back}}, wasPlugin); !errors.As(err, &move) || !move.ToNative {
		t.Errorf("userspace to native: %v", err)
	}
	if !strings.Contains(move.Error(), "switch the connection off and apply") {
		t.Errorf("the refusal does not say how round it: %v", move)
	}
}

// Generation 2 is what both writers carry, so such an endpoint stays native; so does a 3.1 switch that
// is off, which asks nothing of the router.
func TestCompileKeepsGeneration2Native(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Params["s3"] = 20
	endpoint.Params["h1"] = "100-200"
	endpoint.Params["i1"] = "<r 8>"
	endpoint.Params["random_trailers"] = false
	for _, facts := range []HostFacts{keeneticFacts(endpoint), openWrtFacts(endpoint)} {
		plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
		if err != nil {
			t.Fatalf("%s: %v", facts.Platform, err)
		}
		if plan.Decisions[0].Path != PathNativeCreate {
			t.Errorf("%s: decision = %#v, want native create", facts.Platform, plan.Decisions[0])
		}
	}
}

// Without a usable native AmneziaWG the capability refusal comes first on OpenWrt, and the endpoint
// is not in the lane: that refusal is what keeps the generic path - where the plugin runs AmneziaWG 3
// on amneziawg-go - available to the whole profile.
func TestCompileWithoutNativeAWGReportsTheCapabilityNotTheGeneration(t *testing.T) {
	endpoint := awg31Managed()
	facts := openWrtFacts(endpoint)
	facts.Capabilities = platform.CapabilitySet{}
	if lane := OpenWrtUserspace(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts.Capabilities); len(lane) != 0 {
		t.Errorf("the lane took an endpoint the router could not run natively anyway: %+v", lane)
	}
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	var move *MoveError
	if err == nil || errors.As(err, &move) || !strings.Contains(err.Error(), "native.operation.amneziawg.create") {
		t.Errorf("error = %v, want the missing create capability", err)
	}
}

// BeyondNative asks each platform's own writer, and only about AmneziaWG endpoints.
func TestBeyondNativeFollowsTheWriters(t *testing.T) {
	if NativeAWGGeneration(platform.Keenetic) != keenetic.AWGGeneration ||
		NativeAWGGeneration(platform.OpenWrt) != netvpn.AWGGeneration ||
		NativeAWGGeneration(platform.Platform("linux")) != awg.GenNone {
		t.Fatal("NativeAWGGeneration does not report the platforms' writers")
	}
	wireguard := awg31Managed()
	wireguard.Protocol = model.ProtoWireGuard
	if got := BeyondNative(wireguard, platform.Keenetic); got != nil {
		t.Errorf("a WireGuard endpoint has no AmneziaWG settings to lose, got %v", got)
	}
	if got := BeyondNative(awg31Managed(), platform.OpenWrt); !reflect.DeepEqual(got,
		[]string{"header_protection_key", "random_trailers"}) {
		t.Errorf("BeyondNative = %v", got)
	}
}

// The reconcile unbinds a device the baseline bound and the target no longer has, where a zone still
// lists it - and leaves a kept binding, an already-unlisted device and anything it never bound alone.
func TestReconcileOpenWrtUnbindsRetiredDevices(t *testing.T) {
	endpoint := awg31Managed()
	facts := openWrtFacts(endpoint)
	previous, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil || len(previous.OpenWrtBindings) != 1 {
		t.Fatalf("baseline: %+v, %v", previous, err)
	}
	device := previous.OpenWrtBindings[0].Device
	listed := facts.FirewallUCI + "firewall.@zone[0].device='" + device + "' 'wr_mine'\n"
	target, err := Compile(&model.Profile{}, facts)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Reconcile(previous, target, facts.Capabilities, facts.NetworkUCI, listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.OpenWrtUnbindings) != 1 || rec.OpenWrtUnbindings[0].Device != device ||
		!reflect.DeepEqual(rec.OpenWrtUnbindings[0].Commands, []string{"uci del_list firewall.@zone[0].device='" + device + "'"}) {
		t.Errorf("unbindings = %+v", rec.OpenWrtUnbindings)
	}
	if rec, _ := Reconcile(previous, previous, facts.Capabilities, facts.NetworkUCI, listed); len(rec.OpenWrtUnbindings) != 0 {
		t.Errorf("a kept binding was unbound: %+v", rec.OpenWrtUnbindings)
	}
	if rec, _ := Reconcile(previous, target, facts.Capabilities, facts.NetworkUCI, facts.FirewallUCI); len(rec.OpenWrtUnbindings) != 0 {
		t.Errorf("a device no zone lists got an unbinding: %+v", rec.OpenWrtUnbindings)
	}
}
