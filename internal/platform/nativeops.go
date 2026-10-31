package platform

import (
	"strings"

	"wayhop/internal/awg"
)

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

	// CapNativeAWGGen2 is the router's own AmneziaWG taking the AmneziaWG 2 settings (S3/S4, H ranges,
	// I1-I5). It is published only where a KeeneticOS release proves NDM does not (4.2 to 5.0, see
	// KeeneticReleaseAWG): unsupported, ReasonPlatformUnsupported. Absent, the native writer's own
	// generation stands, as it did before the release was read.
	CapNativeAWGGen2 = "native.amneziawg.gen2"
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
	addKeeneticAWGGeneration(add, caps)
}

// keeneticAWGTooOld reports a KeeneticOS release that has no `wireguard asc` (before 4.2, QA-127),
// with the words the operation capabilities give for it. ok is false on any other platform or
// protocol, on a newer release and on one that cannot be read.
func keeneticAWGTooOld(caps Capabilities, protocol string) (detail, evidence, remedy string, ok bool) {
	if caps.Platform != string(Keenetic) || protocol != "amneziawg" {
		return "", "", "", false
	}
	if generation, known := KeeneticReleaseAWG(caps.FirmwareRelease); !known || generation != awg.GenNone {
		return "", "", "", false
	}
	return "this KeeneticOS release has WireGuard but no AmneziaWG: `wireguard asc` arrived in KeeneticOS " +
			keeneticASCSince.String(),
		"release: " + caps.FirmwareRelease,
		"Update KeeneticOS to " + keeneticASCSince.String() + " or newer to run AmneziaWG on the router's own WireGuard.",
		true
}

// addKeeneticAWGGeneration publishes CapNativeAWGGen2 where the KeeneticOS release proves NDM takes
// only the AmneziaWG 1 settings on `wireguard asc` (4.2 to 5.0).
func addKeeneticAWGGeneration(add func(Capability), caps Capabilities) {
	if caps.Platform != string(Keenetic) || !caps.Native["amneziawg"] {
		return
	}
	if generation, known := KeeneticReleaseAWG(caps.FirmwareRelease); !known || generation != awg.Gen1 {
		return
	}
	add(newCap(CapNativeAWGGen2, VerdictNo, VerdictYes, VerdictNo, ReasonPlatformUnsupported,
		"this KeeneticOS release takes the AmneziaWG 1 settings on `wireguard asc`, and S3/S4, H ranges and I1-I5 arrived only in KeeneticOS "+
			keeneticASC2Since.String()+", as community reports about its test releases have it",
		"release: "+caps.FirmwareRelease,
		"Update KeeneticOS to "+keeneticASC2Since.String()+" or newer to run AmneziaWG 2 connections on the router's own WireGuard.",
		BlocksFeature))
}

func addNativeProtocolOperations(add func(Capability), caps Capabilities, rt RuntimeFacts, protocol string) {
	yes, no, unknown := VerdictYes, VerdictNo, VerdictUnknown
	native := caps.Native[protocol]
	installable, hasInstall := caps.Installable[protocol]
	platformKnown := caps.Platform == string(OpenWrt) || caps.Platform == string(Keenetic)
	// The release outranks the component (QA-127): Native is decided by decideKeenetic already, and
	// this holds the evaluator to it for a Capabilities value assembled anywhere else.
	tooOldDetail, tooOldEvidence, tooOldRemedy, tooOld := keeneticAWGTooOld(caps, protocol)
	if tooOld {
		native, hasInstall = false, false
	}

	carryID := NativeOperationCapabilityID(protocol, NativeCarry)
	switch {
	case !platformKnown:
		add(newCap(carryID, unknown, unknown, unknown, ReasonProbeFailed,
			"the router platform is unknown, so native carriage cannot be confirmed", "", "", BlocksFeature))
	case tooOld:
		add(newCap(carryID, no, yes, no, ReasonPlatformUnsupported, tooOldDetail, tooOldEvidence, tooOldRemedy,
			BlocksFeature))
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
			opNative, opInstall, opInstallable := native, hasInstall, installable
			if tooOld && operation == NativeAdopt {
				// Adoption routes through a link that already exists - an NDM interface, or a tunnel run
				// outside KeeneticOS, which is how AmneziaWG runs on such a release - and writes no
				// `wireguard asc`. The release does not limit it; the WireGuard component does, as before.
				opInstallable, opInstall = caps.Installable["wireguard"]
				opNative = caps.Native["wireguard"]
			}
			if !opNative {
				if tooOld && operation != NativeAdopt {
					add(newCap(id, no, no, no, ReasonPlatformUnsupported, tooOldDetail, tooOldEvidence, tooOldRemedy,
						BlocksFeature))
				} else if opInstall {
					add(newCap(id, yes, no, no, ReasonMissingFirmwareComp,
						"KeeneticOS cannot perform this native operation until its WireGuard component is installed",
						"missing: "+opInstallable, "Install the WireGuard firmware component in KeeneticOS.", BlocksFeature))
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
