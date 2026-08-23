package platform

import (
	"strings"
	"testing"
)

func nativeOperation(t *testing.T, set CapabilitySet, protocol string, op NativeOperation) Capability {
	t.Helper()
	return set.Get(NativeOperationCapabilityID(protocol, op))
}

func TestNativeOperationsOpenWrtSeparateCarryFromWriterAuthority(t *testing.T) {
	caps := Capabilities{
		Platform:     string(OpenWrt),
		Native:       map[string]bool{"amneziawg": true, "wireguard": true},
		NetifdProtos: map[string]bool{"amneziawg": true},
	}
	set := Evaluate(caps, RuntimeFacts{})
	for _, proto := range []string{"amneziawg", "wireguard"} {
		for _, op := range nativeOperations {
			if got := nativeOperation(t, set, proto, op); !got.State.Usable() {
				t.Errorf("%s %s = %+v, want supported", proto, op, got)
			}
		}
	}
	if got := nativeOperation(t, set, "wireguard", NativeCreate); !strings.Contains(got.Evidence, "compatibility") {
		t.Fatalf("WireGuard fallback evidence is not explicit: %+v", got)
	}
}

func TestNativeOperationsOpenWrtUnknownHandlerProbeFailsWritesClosed(t *testing.T) {
	set := Evaluate(Capabilities{
		Platform:     string(OpenWrt),
		Native:       map[string]bool{"amneziawg": true},
		NetifdProtos: nil,
	}, RuntimeFacts{})
	if got := nativeOperation(t, set, "amneziawg", NativeCarry); !got.State.Usable() {
		t.Fatalf("proven kernel carriage was lost: %+v", got)
	}
	for _, op := range []NativeOperation{NativeCreate, NativeManage, NativeUpdate, NativeRemove} {
		got := nativeOperation(t, set, "amneziawg", op)
		if got.State != CapUnknown || got.RuntimeState != VerdictUnknown || got.Reason != ReasonProbeFailed {
			t.Errorf("unknown netifd probe %s = %+v, want fail-closed unknown", op, got)
		}
	}
}

func TestNativeOperationsOpenWrtMissingHandlerDoesNotInheritCarry(t *testing.T) {
	set := Evaluate(Capabilities{
		Platform:     string(OpenWrt),
		Native:       map[string]bool{"amneziawg": true},
		NetifdProtos: map[string]bool{},
	}, RuntimeFacts{})
	for _, op := range []NativeOperation{NativeCreate, NativeManage, NativeUpdate, NativeRemove} {
		got := nativeOperation(t, set, "amneziawg", op)
		if got.State.Usable() || got.Reason != ReasonMissingService {
			t.Errorf("native carry leaked into %s authority: %+v", op, got)
		}
	}
}

func TestNativeOperationsKeeneticRemainUnwiredExceptCarry(t *testing.T) {
	set := Evaluate(Capabilities{
		Platform: string(Keenetic),
		Native:   map[string]bool{"amneziawg": true, "wireguard": true},
	}, RuntimeFacts{})
	for _, proto := range []string{"amneziawg", "wireguard"} {
		if got := nativeOperation(t, set, proto, NativeCarry); !got.State.Usable() {
			t.Errorf("%s carry = %+v, want supported", proto, got)
		}
		for _, op := range []NativeOperation{NativeAdopt, NativeCreate, NativeManage, NativeUpdate, NativeRemove} {
			got := nativeOperation(t, set, proto, op)
			if got.State.Usable() || got.WayHopSupport != VerdictNo || got.Reason != ReasonBackendNotWired {
				t.Errorf("Keenetic %s %s = %+v, want backend-not-wired", proto, op, got)
			}
		}
	}
}

func TestNativeOperationsKeeneticExposeOnlyExplicitRuntimeAuthorities(t *testing.T) {
	create := NativeOperationCapabilityID("amneziawg", NativeCreate)
	remove := NativeOperationCapabilityID("amneziawg", NativeRemove)
	set := Evaluate(Capabilities{
		Platform: string(Keenetic),
		Native:   map[string]bool{"amneziawg": true, "wireguard": true},
	}, RuntimeFacts{NativeOperations: map[string]bool{create: true, remove: true}})
	for _, operation := range nativeOperations {
		got := nativeOperation(t, set, "amneziawg", operation)
		want := operation == NativeCarry || operation == NativeCreate || operation == NativeRemove
		if got.State.Usable() != want {
			t.Errorf("Keenetic amneziawg %s = %+v, usable want %v", operation, got, want)
		}
	}
	// Authority is protocol-specific: proving AmneziaWG removal must not grant WireGuard removal.
	if got := nativeOperation(t, set, "wireguard", NativeRemove); got.State.Usable() {
		t.Fatalf("AmneziaWG runtime authority leaked into WireGuard: %+v", got)
	}
}

func TestNativeOperationsUnknownPlatformFailClosed(t *testing.T) {
	set := Evaluate(Capabilities{Platform: string(Unknown)}, RuntimeFacts{})
	for _, op := range nativeOperations {
		if got := nativeOperation(t, set, "wireguard", op); got.State != CapUnknown {
			t.Errorf("unknown platform %s = %+v", op, got)
		}
	}
}

func TestOlcRTCIsUnavailableUntilStrictExecutorExists(t *testing.T) {
	set := Evaluate(Capabilities{Platform: string(OpenWrt)}, RuntimeFacts{})
	got := set.Get(CapEngineOlcRTC)
	if got.State.Usable() || got.WayHopSupport != VerdictNo || got.Reason != ReasonBackendNotWired {
		t.Fatalf("olcRTC capability = %+v, want explicit build-level unavailability", got)
	}
}
