package platform

import (
	"reflect"
	"testing"
)

func TestDemoCapabilities(t *testing.T) {
	got := DemoCapabilities()

	if got.Platform != string(OpenWrt) {
		t.Fatalf("Platform = %q, want %q", got.Platform, OpenWrt)
	}
	wantNative := map[string]bool{"amneziawg": true, "wireguard": true}
	if !reflect.DeepEqual(got.Native, wantNative) {
		t.Errorf("Native = %#v, want %#v", got.Native, wantNative)
	}
	if !reflect.DeepEqual(got.NetifdProtos, wantNative) {
		t.Errorf("NetifdProtos = %#v, want %#v", got.NetifdProtos, wantNative)
	}
	if got.Installable == nil || len(got.Installable) != 0 {
		t.Errorf("Installable = %#v, want an owned empty map", got.Installable)
	}
	if !reflect.DeepEqual(got.SingboxRequired, singboxRequired) {
		t.Errorf("SingboxRequired = %#v, want package floor %#v", got.SingboxRequired, singboxRequired)
	}
	if !got.SingboxPresent {
		t.Error("SingboxPresent = false, want true")
	}
	if got.Accel != (Accel{Kind: "nft-flowtable", HW: true}) {
		t.Errorf("Accel = %#v, want nft-flowtable with hardware support", got.Accel)
	}
}

func TestDemoCapabilitiesReturnsOwnedCollections(t *testing.T) {
	first := DemoCapabilities()
	second := DemoCapabilities()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("successive fixtures differ: first=%#v second=%#v", first, second)
	}
	if len(singboxRequired) == 0 {
		t.Fatal("package singboxRequired floor is unexpectedly empty")
	}
	packageFirstProtocol := singboxRequired[0]

	first.Native["wireguard"] = false
	first.NetifdProtos["amneziawg"] = false
	first.Installable["test"] = "test-package"
	first.SingboxRequired[0] = "mutated"

	if !second.Native["wireguard"] {
		t.Error("mutating one result changed another result's Native map")
	}
	if !second.NetifdProtos["amneziawg"] {
		t.Error("mutating one result changed another result's NetifdProtos map")
	}
	if _, ok := second.Installable["test"]; ok {
		t.Error("mutating one result changed another result's Installable map")
	}
	if second.SingboxRequired[0] != packageFirstProtocol {
		t.Error("mutating one result changed another result's SingboxRequired slice")
	}
	if singboxRequired[0] != packageFirstProtocol {
		t.Error("mutating a result changed the package singboxRequired data")
	}
}
