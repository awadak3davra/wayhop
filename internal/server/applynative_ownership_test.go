package server

import (
	"context"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

func qa146Committed() *executionMaterializationV1 {
	m := applyboot_kernelMaterialization()
	m.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
		SchemaVersion: executionNativeDeltaSchemaV1,
		Reconcile: nativeplan.Reconciliation{
			Platform: platform.Keenetic,
			Target: &nativeplan.Plan{
				Platform: platform.Keenetic,
				Decisions: []nativeplan.EndpointDecision{{
					EndpointID: "old", Path: nativeplan.PathNativeCreate, Interface: "Wireguard10",
				}},
				Keenetic: &keenetic.Plan{
					Interfaces: [][]string{{
						"interface Wireguard10",
						"wireguard private-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
						"up",
					}},
					Routes:            []string{"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto"},
					IfaceFor:          map[string]string{"old": "Wireguard10"},
					GlobalPriority:    map[string]int{"Wireguard10": 100},
					GlobalPriorityWas: map[string]int{"Wireguard10": 0},
				},
			},
		},
	}}
	return &m
}

func qa146Capture(publicKey string) *executionNativeCaptureV1 {
	return &executionNativeCaptureV1{
		ndmPresent: map[string]bool{
			"interface Wireguard10":                          true,
			"ip route 203.0.113.0 255.255.255.0 Wireguard10": true,
		},
		ndmPublicKeys: map[string]string{"interface Wireguard10": publicKey},
	}
}

func TestOwnershipBaselineRejectsCommittedSlotReuse(t *testing.T) {
	live := applyboot_kernelMaterialization()
	committed := qa146Committed()
	block := committed.Native.Delta.Reconcile.Target.Keenetic.Interfaces[0]
	expected, present := exactKeeneticBlockPublicKey(block)
	if !present || expected == "" {
		t.Fatal("the test block must have a derivable public key")
	}

	t.Run("different live key keeps the replacement out of the union", func(t *testing.T) {
		got := ownershipBaseline(&live, committed, qa146Capture("different-public-key"))
		if got != &live {
			t.Fatalf("a slot with a different key was claimed by the old committed plan: %+v", got)
		}
	})
	t.Run("matching live key keeps the committed objects", func(t *testing.T) {
		got := ownershipBaseline(&live, committed, qa146Capture(expected))
		if got == &live {
			t.Fatal("the matching committed plan was not added to the union")
		}
		target := got.Native.Delta.Reconcile.Target
		if len(target.Decisions) != 1 || len(target.Keenetic.Interfaces) != 1 ||
			len(target.Keenetic.Routes) != 1 || target.Keenetic.GlobalPriority["Wireguard10"] != 100 {
			t.Fatalf("committed objects missing from the union: %+v", target)
		}
	})
	t.Run("missing key capture keeps the name-based fallback", func(t *testing.T) {
		capture := qa146Capture("")
		capture.ndmPublicKeys = nil
		got := ownershipBaseline(&live, committed, capture)
		if got == &live {
			t.Fatal("an unavailable key listing must not change the old fallback")
		}
	})
}

func TestCaptureExecutionNativeReadsInterfacePublicKeys(t *testing.T) {
	const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	ndm := newFakeNDM()
	ndm.order = []string{"Wireguard0"}
	ndm.ifaces["Wireguard0"] = &fakeNDMIface{lines: []string{"wireguard private-key " + privateKey}}
	s := &Server{keeneticConfigReader: ndm.readConfig, keeneticInterfacesReader: ndm.readInterfaces}
	desired, host := keeneticForeignTuple(t, map[string]any{"interface": "awg1", "source": "runtime"})
	capture, err := s.captureExecutionNative(context.Background(), desired, host)
	if err != nil {
		t.Fatal(err)
	}
	expected, present := exactKeeneticBlockPublicKey([]string{"wireguard private-key " + privateKey})
	if !present || capture.ndmPublicKeys["interface Wireguard0"] != expected {
		t.Fatalf("captured public keys = %#v, want %q", capture.ndmPublicKeys, expected)
	}
}

func TestOwnershipBaselineIncludesCommittedOpenWrtKernelTeardown(t *testing.T) {
	live := applyboot_kernelMaterialization()
	committed := applyboot_kernelMaterialization()
	committed.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
		SchemaVersion: executionNativeDeltaSchemaV1,
		Reconcile: nativeplan.Reconciliation{
			Platform: platform.OpenWrt, Target: &nativeplan.Plan{Platform: platform.OpenWrt},
		},
	}}
	const existingRule = "ip rule del fwmark 0x10000 table 100"
	const staleRule = "ip rule del fwmark 0x20000 table 101"
	live.Kernel.Teardown = []string{existingRule}
	committed.Kernel.Teardown = []string{existingRule, staleRule}

	got := ownershipBaseline(&live, &committed, &executionNativeCaptureV1{})
	if got == &live {
		t.Fatal("committed OpenWrt kernel teardown was not added to the ownership union")
	}
	if len(got.Kernel.Teardown) != 2 || got.Kernel.Teardown[1] != staleRule {
		t.Fatalf("union kernel teardown = %v, want the committed stale rule included once", got.Kernel.Teardown)
	}
	target := executionKernelArtifactV1{}
	bindKernelRetire(&target, got)
	if len(target.Retire) != 2 || target.Retire[0] != existingRule || target.Retire[1] != staleRule {
		t.Fatalf("next Apply retire list = %v, want both rules in order", target.Retire)
	}
}
