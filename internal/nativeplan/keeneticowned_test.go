package nativeplan

import (
	"reflect"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// QA-108. Only an interface the authenticated previous plan CREATED is offered back to the next
// compile as the endpoint's own block: an adopted tunnel, a WayHop engine device and a block no
// decision names are never WayHop's to keep, and nothing comes from an OpenWrt or missing baseline.
func TestKeeneticOwnedBlocksComeOnlyFromCreatedInterfaces(t *testing.T) {
	created := []string{"interface Wireguard10", "description a", "up"}
	stray := []string{"interface Wireguard12", "description nobody", "up"}
	// Blocks that decisions on other paths do name: the path, not a matching name, decides.
	adopted := []string{"interface Wireguard3", "description theirs", "up"}
	external := []string{"interface Wireguard4", "description outside", "up"}
	plugin := []string{"interface awg0", "description engine", "up"}
	previous := &Plan{
		Platform: platform.Keenetic,
		Decisions: []EndpointDecision{
			{EndpointID: "a", Protocol: model.ProtoWireGuard, Path: PathNativeCreate, Interface: "Wireguard10"},
			{EndpointID: "ext", Protocol: model.ProtoWireGuard, Path: PathNativeAdopt, Interface: "nwg0"},
			{EndpointID: "adopted", Protocol: model.ProtoWireGuard, Path: PathNativeAdopt, Interface: "Wireguard3"},
			{EndpointID: "outside", Protocol: model.ProtoWireGuard, Path: PathExternal, Interface: "Wireguard4"},
			{EndpointID: "gen3", Protocol: model.ProtoAmneziaWG, Path: PathEnginePlugin, Interface: "awg0"},
		},
		Keenetic: &keenetic.Plan{Interfaces: [][]string{created, stray, adopted, external, plugin}},
	}
	got := KeeneticOwnedBlocks(previous)
	if want := map[string][]string{"a": created}; !reflect.DeepEqual(got, want) {
		t.Fatalf("owned blocks = %v, want %v", got, want)
	}
	got["a"][1] = "description changed"
	if previous.Keenetic.Interfaces[0][1] != "description a" {
		t.Error("the owned block aliases the baseline plan")
	}
	for name, baseline := range map[string]*Plan{
		"none":    nil,
		"openwrt": {Platform: platform.OpenWrt, Decisions: previous.Decisions},
		"no plan": {Platform: platform.Keenetic, Decisions: previous.Decisions},
	} {
		if got := KeeneticOwnedBlocks(baseline); len(got) != 0 {
			t.Errorf("%s baseline: owned blocks = %v, want none", name, got)
		}
	}
}
