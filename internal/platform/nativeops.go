package platform

import "strings"

// NativeOperation names a distinct authority over a router-native connection. These operations
// deliberately do not collapse into one "native" boolean: firmware may carry an existing tunnel
// while WayHop is still unable to create, manage, or remove it safely.
type NativeOperation string

const (
	NativeCarry  NativeOperation = "carry"
	NativeAdopt  NativeOperation = "adopt"
	NativeCreate NativeOperation = "create"
	NativeManage NativeOperation = "manage"
	NativeUpdate NativeOperation = "update"
	NativeRemove NativeOperation = "remove"

	CapNativeOperationPrefix = "native.operation."
)

var nativeOperations = []NativeOperation{
	NativeCarry, NativeAdopt, NativeCreate, NativeManage, NativeUpdate, NativeRemove,
}

// NativeOperationCapabilityID is the stable capability key consumed by API clients and the strict
// Apply review. Unknown protocols or operations still produce a key whose missing CapabilitySet
// entry fails closed through CapabilitySet.Get.
func NativeOperationCapabilityID(protocol string, operation NativeOperation) string {
	return CapNativeOperationPrefix + strings.ToLower(strings.TrimSpace(protocol)) + "." + string(operation)
}

// addNativeOperationCapabilities publishes the truthful operation matrix for the two native
// WireGuard-family protocols. Carry describes the host datapath. Adopt/create/manage/remove also
// require an implementation wired into this build and runtime evidence for the exact platform path.
func addNativeOperationCapabilities(add func(Capability), caps Capabilities, rt RuntimeFacts) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		addNativeProtocolOperations(add, caps, rt, protocol)
	}
}

func addNativeProtocolOperations(add func(Capability), caps Capabilities, rt RuntimeFacts, protocol string) {
	yes, no, unknown := VerdictYes, VerdictNo, VerdictUnknown
	native := caps.Native[protocol]
	installable, hasInstall := caps.Installable[protocol]
	platformKnown := caps.Platform == string(OpenWrt) || caps.Platform == string(Keenetic)

	carryID := NativeOperationCapabilityID(protocol, NativeCarry)
	switch {
	case !platformKnown:
		add(newCap(carryID, unknown, unknown, unknown, ReasonProbeFailed,
			"the router platform is unknown, so native carriage cannot be confirmed", "", "", BlocksFeature))
	case native:
		add(newCap(carryID, yes, yes, yes, ReasonNone, "",
			"the kernel or firmware reports a native "+protocol+" path", "", BlocksNothing))
	case hasInstall:
		add(newCap(carryID, yes, yes, no, ReasonMissingKernelModule,
			"the router cannot carry "+protocol+" natively until its platform component is installed",
			"missing: "+installable, installRemedy(caps.PackageManager, installable), BlocksFeature))
	default:
		add(newCap(carryID, no, yes, no, ReasonPlatformUnsupported,
			"this router reports no native "+protocol+" datapath", "", "", BlocksFeature))
	}

	for _, operation := range nativeOperations[1:] {
		id := NativeOperationCapabilityID(protocol, operation)
		switch caps.Platform {
		case string(OpenWrt):
			addOpenWrtNativeOperation(add, caps, protocol, operation, id, native)
		case string(Keenetic):
			if !native {
				if hasInstall {
					add(newCap(id, yes, no, no, ReasonMissingFirmwareComp,
						"KeeneticOS cannot perform this native operation until its WireGuard component is installed",
						"missing: "+installable, "Install the WireGuard firmware component in KeeneticOS.", BlocksFeature))
				} else {
					add(newCap(id, no, no, no, ReasonPlatformUnsupported,
						"KeeneticOS reports no native "+protocol+" path", "", "", BlocksFeature))
				}
				continue
			}
			if rt.NativeOperations[id] {
				add(newCap(id, yes, yes, yes, ReasonNone, "",
					"the strict Keenetic NDM executor implements this exact "+string(operation)+" operation",
					"", BlocksNothing))
				continue
			}
			add(newCap(id, yes, no, unknown, ReasonBackendNotWired,
				"KeeneticOS can carry this connection, but WayHop's NDM/RCI "+string(operation)+
					" path is not connected to strict Apply yet",
				"internal/keenetic exists but the production transaction executor does not select it",
				"Keep the interface firmware-owned until the Keenetic native executor is wired and verified.",
				BlocksFeature))
		default:
			add(newCap(id, unknown, unknown, unknown, ReasonProbeFailed,
				"the router platform is unknown, so native operation support cannot be confirmed",
				"", "", BlocksFeature))
		}
	}
}

func addOpenWrtNativeOperation(
	add func(Capability),
	caps Capabilities,
	protocol string,
	operation NativeOperation,
	id string,
	native bool,
) {
	yes, no, unknown := VerdictYes, VerdictNo, VerdictUnknown
	if operation == NativeAdopt {
		if native {
			add(newCap(id, yes, yes, yes, ReasonNone, "",
				"WayHop can bind routing to a discovered OS-owned native interface without taking ownership",
				"", BlocksNothing))
			return
		}
		add(newCap(id, no, yes, no, ReasonInterfaceMissing,
			"no native "+protocol+" path is available to adopt", "", "", BlocksFeature))
		return
	}

	if caps.NetifdProtos == nil {
		add(newCap(id, yes, yes, unknown, ReasonProbeFailed,
			"the OpenWrt netifd handler probe failed, so WayHop cannot prove this native write is executable",
			"netifd protocol handlers were not observed", "Retry the capability probe.", BlocksFeature))
		return
	}
	handler := caps.NetifdProtos[protocol]
	evidence := "/lib/netifd/proto/" + protocol + ".sh"
	if protocol == "wireguard" && !handler && caps.NetifdProtos["amneziawg"] {
		// The AmneziaWG netifd handler is a WireGuard superset when no obfuscation is configured.
		handler = true
		evidence = "/lib/netifd/proto/amneziawg.sh (plain WireGuard compatibility)"
	}
	if handler {
		add(newCap(id, yes, yes, yes, ReasonNone, "", evidence,
			"", BlocksNothing))
		return
	}
	add(newCap(id, yes, yes, no, ReasonMissingService,
		"the kernel may carry "+protocol+", but OpenWrt has no netifd handler WayHop can use to "+
			string(operation)+" it safely",
		evidence+" absent", "Install the matching netifd protocol handler.", BlocksFeature))
}
