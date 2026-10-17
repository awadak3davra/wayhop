package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// chosenAWG is a generation-2 AmneziaWG connection the router's own AmneziaWG could carry, set to run
// on amneziawg-go all the same.
func chosenAWG() model.Endpoint {
	e := managedAWG()
	e.AWGUserspace = true
	return e
}

// A connection set to run on amneziawg-go joins the userspace lane on both platforms although the
// native writer could carry its settings, with the operator's choice as the reason and the way back
// as the remedy. Automatic keeps the same connection native.
func TestUserspaceLaneTakesAChosenConnection(t *testing.T) {
	for _, c := range []struct {
		name  string
		p     platform.Platform
		facts HostFacts
		whose string
	}{
		{"KeeneticOS", platform.Keenetic, keeneticFacts(managedAWG()), "KeeneticOS's own AmneziaWG"},
		{"OpenWrt", platform.OpenWrt, openWrtFacts(managedAWG()), "OpenWrt's own AmneziaWG"},
	} {
		lane := Userspace(&model.Profile{Endpoints: []model.Endpoint{chosenAWG()}}, c.p, c.facts.Capabilities)
		u, ok := lane[managedAWG().ID]
		if !ok || u.Code != platform.ReasonOperatorChoice || u.Device != util.AWGIface(managedAWG().ID) ||
			!strings.Contains(u.Reason, "set to run on amneziawg-go") || !strings.Contains(u.Reason, c.whose) ||
			!strings.Contains(u.Remedy, "Automatic") {
			t.Errorf("%s: chosen connection = %+v (in lane: %v)", c.name, u, ok)
		}
		if lane := Userspace(&model.Profile{Endpoints: []model.Endpoint{managedAWG()}}, c.p, c.facts.Capabilities); len(lane) != 0 {
			t.Errorf("%s: an automatic generation-2 connection left the native path: %+v", c.name, lane)
		}
	}
}

// On OpenWrt the lane is for routers whose own AmneziaWG would otherwise take the connection. Without
// one the capability refusal hands the profile to the generic path, where the plugin honours the
// choice itself - the lane must not claim it.
func TestOpenWrtLaneLeavesAChosenConnectionToTheGenericPath(t *testing.T) {
	if lane := OpenWrtUserspace(&model.Profile{Endpoints: []model.Endpoint{chosenAWG()}}, platform.CapabilitySet{}); len(lane) != 0 {
		t.Errorf("the lane took a chosen connection the router could not run natively anyway: %+v", lane)
	}
}

// The planner acts on the lane: the chosen connection is the engine plugin's, on its own device, and
// on OpenWrt that device is bound into the reviewed firewall zone like any lane endpoint.
func TestCompileRunsAChosenConnectionOnTheEngine(t *testing.T) {
	endpoint := chosenAWG()
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, openWrtFacts(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != PathEnginePlugin ||
		plan.Decisions[0].Interface != util.AWGIface(endpoint.ID) {
		t.Errorf("decisions = %#v, want the engine plugin on %s", plan.Decisions, util.AWGIface(endpoint.ID))
	}
}

// NativeAWGAvailable is the Components page's question - can the router create and remove an
// AmneziaWG interface of its own at all - asked without an endpoint.
func TestNativeAWGAvailable(t *testing.T) {
	if !NativeAWGAvailable(openWrtFacts(managedAWG()).Capabilities) {
		t.Error("OpenWrt with native AmneziaWG operations was reported without them")
	}
	if NativeAWGAvailable(platform.CapabilitySet{}) {
		t.Error("a router with no native operations was reported with them")
	}
}
