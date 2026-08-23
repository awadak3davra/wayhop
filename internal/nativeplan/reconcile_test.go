package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func TestReconcileOpenWrtRemovesOnlyFormerWayHopOwnedInterfaces(t *testing.T) {
	previous := &Plan{
		Platform: platform.OpenWrt,
		Decisions: []EndpointDecision{
			{EndpointID: "owned", Protocol: model.ProtoAmneziaWG, Path: PathNativeManage,
				Interface: "wr_dead", RollbackCap: "native.operation.amneziawg.remove"},
			{EndpointID: "system", Protocol: model.ProtoAmneziaWG, Path: PathNativeAdopt,
				Interface: "nwg5"},
		},
	}
	target := &Plan{Platform: platform.OpenWrt}
	network := strings.Join([]string{
		"network.wr_dead=interface",
		"network.wr_dead.proto='amneziawg'",
		"network.peer_dead=amneziawg_wr_dead",
		"network.peer_dead.public_key='public'",
		"network.nwg5=interface",
		"network.nwg5.proto='amneziawg'",
	}, "\n") + "\n"
	firewall := "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\nfirewall.@zone[0].network='wr_dead nwg5'\n"
	result, err := Reconcile(previous, target,
		usableCapabilities("native.operation.amneziawg.remove"), network, firewall)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OpenWrtRemovals) != 1 || result.OpenWrtRemovals[0].Iface != "wr_dead" {
		t.Fatalf("removals = %#v", result.OpenWrtRemovals)
	}
	commands := strings.Join(result.OpenWrtRemovals[0].Commands, "\n")
	if strings.Contains(commands, "nwg5") {
		t.Fatalf("external interface entered destructive removal plan:\n%s", commands)
	}
}

func TestReconcileOpenWrtRefusesDanglingZoneForAlreadyMissingInterface(t *testing.T) {
	previous := &Plan{Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
		EndpointID: "owned", Path: PathNativeCreate, Interface: "wr_dead",
		RollbackCap: "native.operation.amneziawg.remove",
	}}}
	target := &Plan{Platform: platform.OpenWrt}
	_, err := Reconcile(previous, target, usableCapabilities("native.operation.amneziawg.remove"), "network.lan=interface\n",
		"firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\nfirewall.@zone[0].network='wr_dead'\n")
	if err == nil || !strings.Contains(err.Error(), "remains in firewall zone") {
		t.Fatalf("error = %v, want inconsistent dangling-zone refusal", err)
	}
}

func TestReconcileOpenWrtRequiresAuthenticatedRemoveAuthority(t *testing.T) {
	previous := &Plan{Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
		EndpointID: "owned", Path: PathNativeCreate, Interface: "wr_dead",
	}}}
	_, err := Reconcile(previous, &Plan{Platform: platform.OpenWrt}, platform.CapabilitySet{},
		"network.wr_dead=interface\nnetwork.wr_dead.proto='amneziawg'\n", "")
	if err == nil || !strings.Contains(err.Error(), "remove authority") {
		t.Fatalf("error = %v, want remove-authority refusal", err)
	}
}

func TestReconcileRefusesLiveNameAsOwnershipEvidence(t *testing.T) {
	target := &Plan{Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
		EndpointID: "owned", Path: PathNativeManage, Interface: "wr_collision",
	}}}
	for name, previous := range map[string]*Plan{
		"no baseline": nil,
		"adopted baseline": {Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
			EndpointID: "owned", Path: PathNativeAdopt, Interface: "wr_collision",
		}}},
		"different endpoint": {Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
			EndpointID: "other", Path: PathNativeCreate, Interface: "wr_collision",
		}}},
		"different interface": {Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
			EndpointID: "owned", Path: PathNativeCreate, Interface: "wr_other",
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Reconcile(previous, target, platform.CapabilitySet{},
				"network.wr_collision=interface\n", ""); err == nil ||
				!strings.Contains(err.Error(), "matching authenticated ownership") {
				t.Fatalf("error = %v, want ownership refusal", err)
			}
		})
	}
}

func TestReconcileAllowsManagedTargetOwnedByAuthenticatedBaseline(t *testing.T) {
	previous := &Plan{Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
		EndpointID: "owned", Path: PathNativeCreate, Interface: "wr_owned",
	}}}
	target := &Plan{Platform: platform.OpenWrt, Decisions: []EndpointDecision{{
		EndpointID: "owned", Path: PathNativeManage, Interface: "wr_owned",
	}}}
	result, err := Reconcile(previous, target, platform.CapabilitySet{},
		"network.wr_owned=interface\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Target != target || len(result.OpenWrtRemovals) != 0 {
		t.Fatalf("reconciliation = %#v", result)
	}
}

func TestReconcileKeeneticTeardownExcludesAdoptedInterfaces(t *testing.T) {
	previous := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{
		Interfaces: [][]string{{"interface Wireguard10", "up"}},
		Routes:     []string{"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto"},
		IfaceFor:   map[string]string{"owned": "Wireguard10", "external": "Wireguard5"},
	}, Decisions: []EndpointDecision{{EndpointID: "owned", Path: PathNativeManage,
		Interface: "Wireguard10", RollbackCap: "native.operation.amneziawg.remove"}}}
	target := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{IfaceFor: map[string]string{}}}
	result, err := Reconcile(previous, target,
		usableCapabilities("native.operation.amneziawg.remove"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(result.KeeneticTeardown, "\n")
	if !strings.Contains(joined, "no interface Wireguard10") || strings.Contains(joined, "Wireguard5") {
		t.Fatalf("unsafe Keenetic teardown:\n%s", joined)
	}
}

func TestReconcileKeeneticDoesNotRemovePreparedTargetIdentity(t *testing.T) {
	previous := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{
		Interfaces: [][]string{{"interface Wireguard10", "description old", "up"}},
		Routes: []string{
			"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto",
			"ip route 198.51.100.0 255.255.255.0 Wireguard10 auto",
		},
	}, Decisions: []EndpointDecision{{EndpointID: "owned", Path: PathNativeManage,
		Interface: "Wireguard10", RollbackCap: "native.operation.amneziawg.remove"}}}
	target := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{
		Interfaces: [][]string{{"interface Wireguard10", "description new", "up"}},
		Routes:     []string{"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto"},
	}}
	result, err := Reconcile(previous, target,
		usableCapabilities("native.operation.amneziawg.remove"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(result.KeeneticTeardown, "\n")
	if strings.Contains(joined, "no interface Wireguard10") ||
		strings.Contains(joined, "203.0.113.0") || !strings.Contains(joined, "198.51.100.0") {
		t.Fatalf("target resources were removed or obsolete route was retained:\n%s", joined)
	}
}
