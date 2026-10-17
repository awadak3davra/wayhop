package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// This file is the single capability contract the UI and the apply path both read.
//
// It exists because a warning is not protection. platform.Preflight reports what a router will
// silently discard, but it deliberately refuses nothing, and handleApply never consults it — so a
// direct API request can still apply a configuration the router cannot execute. Gating in the UI
// alone protects nobody: the API is the real boundary.
//
// The central design rule is that three genuinely different questions must never be collapsed into
// one boolean, because they fail independently and demand different remedies:
//
//	HostSupport   — could this OS, firmware, kernel and hardware do it at all?
//	WayHopSupport — is that execution path implemented AND wired into THIS build's apply path?
//	RuntimeState  — are the binaries, modules, services, interfaces and permissions ready now?
//
// Keenetic kernel policy routing is the case that forces the distinction: the strict Apply path can
// create supported native tunnels, but it does not yet write KeeneticOS policy rules. Host support
// alone therefore cannot make Fast or Hybrid routing usable.
// A single "supported" boolean would report that as usable and be wrong in the most damaging way.

// Verdict is one of the three independent answers about a capability.
type Verdict string

const (
	// VerdictYes: this dimension is satisfied.
	VerdictYes Verdict = "yes"
	// VerdictNo: this dimension is definitively not satisfied.
	VerdictNo Verdict = "no"
	// VerdictUnknown: the probe could not establish it. Never treat as yes — an unverifiable
	// capability must disable the risky action rather than assume it works.
	VerdictUnknown Verdict = "unknown"
)

// CapState is the combined verdict the UI renders and the apply gate enforces.
type CapState string

const (
	CapSupported             CapState = "supported"
	CapAvailableAfterInstall CapState = "available_after_install"
	CapBlockedByDependency   CapState = "blocked_by_dependency"
	CapUnsupportedPlatform   CapState = "unsupported_platform"
	CapUnsupportedFirmware   CapState = "unsupported_firmware"
	CapUnknown               CapState = "unknown"
)

// Usable reports whether a capability may be activated. Only an outright "supported" qualifies:
// every other state, including unknown, fails closed.
func (s CapState) Usable() bool { return s == CapSupported }

// ReasonCode is a stable machine-readable cause. The UI may localise around it; logs and support
// bundles can be grepped for it; and it survives copy changes that would break message matching.
type ReasonCode string

const (
	ReasonNone                  ReasonCode = ""
	ReasonPlatformUnsupported   ReasonCode = "PLATFORM_UNSUPPORTED"
	ReasonBackendNotWired       ReasonCode = "BACKEND_NOT_WIRED"
	ReasonMissingBinary         ReasonCode = "MISSING_BINARY"
	ReasonBinaryTooOld          ReasonCode = "BINARY_TOO_OLD"
	ReasonBinaryNotRunnable     ReasonCode = "BINARY_NOT_RUNNABLE"
	ReasonMissingKernelModule   ReasonCode = "MISSING_KERNEL_MODULE"
	ReasonMissingFirmwareComp   ReasonCode = "MISSING_FIRMWARE_COMPONENT"
	ReasonMissingService        ReasonCode = "MISSING_SERVICE"
	ReasonPermissionDenied      ReasonCode = "PERMISSION_DENIED"
	ReasonProbeFailed           ReasonCode = "PROBE_FAILED"
	ReasonModeConflict          ReasonCode = "MODE_CONFLICT"
	ReasonInterfaceMissing      ReasonCode = "INTERFACE_MISSING"
	ReasonPortConflict          ReasonCode = "PORT_CONFLICT"
	ReasonSavedValueIncompat    ReasonCode = "SAVED_VALUE_INCOMPATIBLE"
	ReasonFeatureWouldBeDropped ReasonCode = "FEATURE_WOULD_BE_DROPPED"
	// ReasonOperatorChoice: the router could do it natively, and the operator chose otherwise.
	ReasonOperatorChoice ReasonCode = "OPERATOR_CHOICE"
)

// Blocks says how far a missing capability reaches. An optimisation that cannot load must not stop
// an Apply; a routing mode that would carry no traffic must.
const (
	BlocksNothing      = "nothing"
	BlocksOptimisation = "optimisation"
	// BlocksFeature: this object cannot work, but the Apply itself stays honest. A configured vless
	// endpoint with no sing-box installed is the canonical case - the config is written, the core
	// fails to start, and the apply path already reports applied_ok=false rather than claiming
	// success. Refusing the whole Apply there would block unrelated changes and contradict the
	// spec's own rule that a disabled or unusable object must not create unrelated blockers.
	BlocksFeature = "feature"
	// BlocksApply is reserved for the case that actually justifies refusal: applying would produce a
	// FALSE SUCCESS - the router reports the configuration as active while carrying no traffic, or
	// while a control implies a datapath change that will never happen.
	BlocksApply = "apply"
	BlocksEdit  = "edit"
)

// Stable capability IDs. UI, generator, parser and tests all key off these rather than keeping
// their own lists, which is how such lists drift apart.
const (
	CapRoutingModeMixed  = "routing.mode.mixed"
	CapRoutingModeTun    = "routing.mode.tun"
	CapRoutingModeHybrid = "routing.mode.hybrid"
	CapRoutingModeFast   = "routing.mode.fast"

	CapMatcherDomain      = "routing.matcher.domain"
	CapMatcherIPCIDR      = "routing.matcher.ip_cidr"
	CapMatcherSourceIP    = "routing.matcher.source_ip"
	CapMatcherSourceMAC   = "routing.matcher.source_mac"
	CapMatcherSourceIface = "routing.matcher.source_iface"
	CapMatcherSourcePort  = "routing.matcher.source_port"

	CapRemoteRuleset = "routing.remote_ruleset"
	CapDeviceScope   = "routing.device_scope"

	CapPBRKernel      = "pbr.kernel"
	CapKillSwitch     = "firewall.kill_switch"
	CapOffloadSW      = "offload.software"
	CapOffloadHW      = "offload.hardware"
	CapDNSProxyPlane  = "dns.proxy_plane"
	CapDNSFakeIP      = "dns.fakeip"
	CapDNSNativeRead  = "dns.native.read"
	CapDNSNativeWrite = "dns.native.write"
	CapDNSDoH         = "dns.doh"
	CapDNSDoT         = "dns.dot"
	CapDNSDoQ         = "dns.doq"
	CapDNSDoH3        = "dns.doh3"

	CapEngineSingbox   = "engine.singbox"
	CapEngineAmneziaWG = "engine.amneziawg"
	CapEngineOlcRTC    = "engine.olcrtc"

	CapIPv6Routing = "ipv6.routing"

	// CapProtocolPrefix + <proto> forms a protocol capability id.
	CapProtocolPrefix = "protocol."
)

// Capability is one gated feature with its three independent verdicts and the combined state.
type Capability struct {
	ID    string   `json:"id"`
	State CapState `json:"state"`

	HostSupport   Verdict `json:"host_support"`
	WayHopSupport Verdict `json:"wayhop_support"`
	RuntimeState  Verdict `json:"runtime_state"`

	Reason   ReasonCode `json:"reason_code,omitempty"`
	Detail   string     `json:"detail,omitempty"`   // plain language, for a person
	Evidence string     `json:"evidence,omitempty"` // what was actually observed
	Remedy   string     `json:"remedy,omitempty"`
	Blocks   string     `json:"blocks"`
}

// CapabilitySet is the whole contract plus the revision the apply gate compares against.
type CapabilitySet struct {
	Rev        string                `json:"capability_rev"`
	ProbedAt   time.Time             `json:"probed_at"`
	ProbeError string                `json:"probe_error,omitempty"`
	Platform   string                `json:"platform"`
	Items      map[string]Capability `json:"items"`
}

// Get returns a capability, or an unknown-state placeholder. A caller asking about an id this build
// does not evaluate must get "unknown" (which fails closed), never a zero value that reads as
// supported.
func (s CapabilitySet) Get(id string) Capability {
	if c, ok := s.Items[id]; ok {
		return c
	}
	return Capability{
		ID: id, State: CapUnknown,
		HostSupport: VerdictUnknown, WayHopSupport: VerdictUnknown, RuntimeState: VerdictUnknown,
		Reason: ReasonProbeFailed,
		Detail: "this build does not evaluate that capability, so its support cannot be confirmed",
		Blocks: BlocksFeature,
	}
}

// Usable is the single question the apply gate asks.
func (s CapabilitySet) Usable(id string) bool { return s.Get(id).State.Usable() }

// combine folds the three verdicts into the state the UI shows and the gate enforces.
//
// Order matters and encodes the product rule: a permanent platform limit outranks a missing
// dependency, which outranks an unverifiable probe. Unknown is deliberately LAST so a genuine
// "never on this platform" is reported as such rather than as a probe problem the user might try
// to fix.
func combine(host, wayhop, runtime Verdict, reason ReasonCode) CapState {
	switch {
	case host == VerdictNo:
		return CapUnsupportedPlatform
	case wayhop == VerdictNo:
		// The host could, but this build cannot. Not the user's to fix by installing anything.
		return CapUnsupportedPlatform
	case runtime == VerdictNo:
		if reason == ReasonMissingBinary || reason == ReasonMissingKernelModule ||
			reason == ReasonMissingFirmwareComp || reason == ReasonBinaryTooOld {
			return CapAvailableAfterInstall
		}
		return CapBlockedByDependency
	case host == VerdictUnknown || wayhop == VerdictUnknown || runtime == VerdictUnknown:
		return CapUnknown
	default:
		return CapSupported
	}
}

// cap builds one entry, deriving State from the verdicts so the two can never disagree.
func newCap(id string, host, wayhop, runtime Verdict, reason ReasonCode, detail, evidence, remedy, blocks string) Capability {
	return Capability{
		ID: id, State: combine(host, wayhop, runtime, reason),
		HostSupport: host, WayHopSupport: wayhop, RuntimeState: runtime,
		Reason: reason, Detail: detail, Evidence: evidence, Remedy: remedy, Blocks: blocks,
	}
}

// RuntimeFacts are the observations Capabilities does not already carry. Passed in rather than
// probed here so the evaluation stays a pure function and every branch is unit-testable.
type RuntimeFacts struct {
	// KernelPBRWired means the policy-rule plane used by Fast/Hybrid can actually load. It is
	// independent of native tunnel lifecycle support: Keenetic can create an owned tunnel while this
	// stays false because its policy-rule writer is not implemented yet.
	KernelPBRWired      bool
	KernelPBRProbeError string // only this plane is unknown; do not poison unrelated capabilities
	// SingboxRunnable means the CONFIGURED binary path exists, is executable, and reported a
	// version. A binary merely present on PATH is not proof the configured core can run.
	SingboxRunnable bool
	SingboxVersion  string
	// NativeDNSRead / NativeDNSWrite are separate on purpose: discovery being implemented says
	// nothing about write-back being safe, and conflating them would expose a control that edits
	// the router's DNS with no rollback.
	NativeDNSRead  bool
	NativeDNSWrite bool
	// NativeOperations names exact operation-capability IDs whose strict production executor is
	// wired for this process. Host carriage alone never sets these; absent entries fail closed.
	NativeOperations map[string]bool
	IPv6Routable     bool
	// ProbeError, when set, marks the whole set as untrustworthy.
	ProbeError string
	ProbedAt   time.Time
}

// Evaluate builds the capability set from the platform probe plus runtime facts. Pure.
func Evaluate(caps Capabilities, rt RuntimeFacts) CapabilitySet {
	yes, no := VerdictYes, VerdictNo
	items := map[string]Capability{}
	add := func(c Capability) { items[c.ID] = c }

	openwrt := caps.Platform == "openwrt"
	keenetic := caps.Platform == "keenetic"
	knownPlatform := openwrt || keenetic

	// ---- kernel policy routing: the fact most other routing capabilities hang off ----------
	switch {
	case !knownPlatform:
		add(newCap(CapPBRKernel, VerdictUnknown, VerdictUnknown, VerdictUnknown, ReasonProbeFailed,
			"the platform could not be identified, so kernel policy routing cannot be confirmed",
			"platform="+caps.Platform, "", BlocksApply))
	case rt.KernelPBRProbeError != "":
		add(newCap(CapPBRKernel, VerdictUnknown, yes, VerdictUnknown, ReasonProbeFailed,
			"the kernel policy-routing plane could not be verified on this router",
			"nft check did not complete successfully", "Retry the capability check, or use \"tun\" routing.", BlocksApply))
	case keenetic && !rt.KernelPBRWired:
		// The native tunnel lifecycle is wired independently. Fast/hybrid additionally need a
		// policy-rule plane, which on KeeneticOS is ipset + iptables rather than nftables; without
		// those binaries there is nothing to install the rules with.
		add(newCap(CapPBRKernel, yes, no, VerdictUnknown, ReasonMissingBinary,
			"the KeeneticOS policy-rule plane needs ipset and iptables, which are not installed",
			"platform=keenetic; native tunnel lifecycle available; ipset/iptables missing",
			"Install them (`opkg install ipset iptables`), or use \"tun\" or \"mixed\" routing.", BlocksApply))
	case keenetic:
		add(newCap(CapPBRKernel, yes, yes, yes, ReasonNone, "",
			"platform=keenetic; ipset and iptables present, policy-rule plane wired", "", BlocksNothing))
	case rt.KernelPBRWired:
		add(newCap(CapPBRKernel, yes, yes, yes, ReasonNone, "", "nft present and the plane loads", "", BlocksNothing))
	default:
		// On OpenWrt this is the fw3-era case: 19.07/21.02 ship iptables and no nft. It is worth
		// naming the exact command, because the remedy is genuinely sufficient and was measured to
		// be — `opkg install nftables` succeeds from both those (EOL) feeds, and the nft it brings,
		// 0.9.2 on 19.07 and 0.9.6 on 21.02, loads WayHop's rendered `table inet wayhop_pbr`
		// unchanged with all of its chains and sets. So there is no second datapath to build for
		// these releases; there is a package to install.
		remedy := "Install nftables support, or use \"tun\" routing."
		if openwrt {
			if cmd := installCmd(caps.PackageManager, "nftables"); cmd != "" {
				remedy = "Install nftables support (`" + cmd + "`), or use \"tun\" routing."
			}
		}
		add(newCap(CapPBRKernel, yes, yes, no, ReasonMissingBinary,
			"the kernel policy-routing plane cannot load on this host",
			"nft missing or the plane failed to install",
			remedy, BlocksApply))
	}
	pbr := items[CapPBRKernel].State.Usable()

	// ---- the proxy core -----------------------------------------------------------------------
	// Routing-mode choices consume this same item below. TUN always needs the core; Hybrid needs
	// both the core and the kernel policy plane. Keeping this dependency at the capability source
	// prevents the panel from offering a mode that a later review must inevitably refuse.
	switch {
	case rt.SingboxRunnable:
		add(newCap(CapEngineSingbox, yes, yes, yes, ReasonNone, "", "sing-box "+rt.SingboxVersion, "", BlocksNothing))
	case caps.SingboxPresent:
		// Present but not provably runnable: found on PATH is not proof the CONFIGURED core runs.
		add(newCap(CapEngineSingbox, yes, yes, VerdictUnknown, ReasonBinaryNotRunnable,
			"a sing-box binary was found but could not be run to report its version",
			"version invocation failed", "Check the configured sing-box path and permissions.", BlocksFeature))
	default:
		add(newCap(CapEngineSingbox, yes, yes, no, ReasonMissingBinary,
			"the sing-box core is not installed", "no sing-box binary",
			"Install sing-box to use proxy protocols.", BlocksFeature))
	}
	core := items[CapEngineSingbox]

	// ---- routing modes -----------------------------------------------------------------------
	// tun and mixed never need the policy-rule plane; hybrid and fast do, and they fail DIFFERENTLY.
	// On Keenetic, Mixed is the 0.5.5 native-control mode: the exact NDM plan owns supported
	// router-native interfaces/routes and adds sing-box only when a selected protocol needs it. TUN is
	// deliberately still offered, but named as the compatibility path rather than presented as native.
	if keenetic {
		add(newCap(CapRoutingModeMixed, yes, yes, yes, ReasonNone,
			"Keenetic native mode: supported router-native tunnels and routes stay under KeeneticOS control; sing-box is added only for connection protocols the router cannot carry",
			// No release number in the sentence a user reads: it described the mode, not the build, and
			// went stale the moment the next version shipped. The history stays in the comment above.
			"platform=keenetic; exact NDM native lifecycle available", "", BlocksNothing))
	} else {
		add(newCap(CapRoutingModeMixed, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	}
	if core.State.Usable() {
		detail, evidence, remedy := "", "", ""
		if keenetic {
			detail = "Keenetic sing-box compatibility mode: general gateway traffic uses the optional userspace TUN"
			evidence = "platform=keenetic; sing-box runnable; policy-rule writer unavailable"
			remedy = "Choose Mixed when gateway capture is not required."
		}
		add(newCap(CapRoutingModeTun, yes, yes, yes, ReasonNone, detail, evidence, remedy, BlocksNothing))
	} else {
		add(newCap(CapRoutingModeTun, core.HostSupport, core.WayHopSupport, core.RuntimeState, core.Reason,
			"TUN routing requires the sing-box compatibility add-on, which is not usable on this router",
			core.Evidence, "Install or repair sing-box, or choose Mixed.", BlocksApply))
	}

	if pbr {
		add(newCap(CapRoutingModeFast, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	} else {
		p := items[CapPBRKernel]
		// fast has NO TUN. Without the kernel plane nothing steers traffic at all.
		add(newCap(CapRoutingModeFast, p.HostSupport, p.WayHopSupport, p.RuntimeState, p.Reason,
			"\"fast\" steers traffic ONLY through the kernel plane and has no capture-all TUN, so "+
				"without that plane no traffic would be routed through WayHop at all",
			p.Evidence, "Use \"tun\" (or \"mixed\") on this router.", BlocksApply))
	}
	if !pbr {
		p := items[CapPBRKernel]
		// hybrid keeps its capture-all TUN, so traffic is still carried: carve-outs are lost.
		add(newCap(CapRoutingModeHybrid, p.HostSupport, p.WayHopSupport, p.RuntimeState, p.Reason,
			"\"hybrid\" cannot install its IP/CIDR carve-outs without the kernel plane; general "+
				"traffic still transits the TUN, so it behaves like \"tun\" here",
			p.Evidence, "Use \"tun\" to make that explicit.", BlocksApply))
	} else if !core.State.Usable() {
		add(newCap(CapRoutingModeHybrid, core.HostSupport, core.WayHopSupport, core.RuntimeState, core.Reason,
			"Hybrid routing requires its capture-all sing-box TUN, but the compatibility add-on is not usable",
			core.Evidence, "Install or repair sing-box, or choose Fast if this profile is fully kernel-native.", BlocksApply))
	} else {
		add(newCap(CapRoutingModeHybrid, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	}

	// Kernel-only matchers depend on the plane; sing-box has no equivalent for MAC or ingress iface.
	kernelMatcher := func(id, what string) {
		if pbr {
			add(newCap(id, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
			return
		}
		p := items[CapPBRKernel]
		add(newCap(id, p.HostSupport, p.WayHopSupport, p.RuntimeState, p.Reason,
			what+" is matched in the kernel only, and this router has no kernel plane",
			p.Evidence, "Match on domain or IP/CIDR instead.", BlocksApply))
	}
	kernelMatcher(CapMatcherSourceMAC, "source MAC")
	kernelMatcher(CapMatcherSourceIface, "ingress interface")
	kernelMatcher(CapDeviceScope, "per-device scope")

	// These work on either plane.
	add(newCap(CapMatcherIPCIDR, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	add(newCap(CapMatcherSourceIP, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	add(newCap(CapMatcherSourcePort, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	add(newCap(CapKillSwitch, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))

	// ---- everything else that needs the proxy core --------------------------------------------
	// Domain matching and fake-IP need the proxy plane to sniff; so does every proxy protocol.
	needCore := func(id, what, remedy string) {
		if core.State.Usable() {
			add(newCap(id, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
			return
		}
		add(newCap(id, yes, yes, core.RuntimeState, core.Reason,
			what+" requires the sing-box core, which is not usable on this router",
			core.Evidence, remedy, BlocksFeature))
	}
	needCore(CapMatcherDomain, "domain matching", "Install sing-box, or match on IP/CIDR.")
	needCore(CapDNSProxyPlane, "the DNS proxy plane", "Install sing-box.")
	needCore(CapDNSFakeIP, "fake-IP", "Install sing-box.")
	needCore(CapRemoteRuleset, "remote rule-sets", "Install sing-box.")
	for _, enc := range []string{CapDNSDoH, CapDNSDoT, CapDNSDoQ, CapDNSDoH3} {
		needCore(enc, "encrypted DNS", "Install sing-box.")
	}

	// Proxy protocols: one capability each, all gated on the same runnable core.
	for _, proto := range caps.SingboxRequired {
		id := CapProtocolPrefix + proto
		if core.State.Usable() {
			add(newCap(id, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
			continue
		}
		add(newCap(id, yes, yes, core.RuntimeState, core.Reason,
			proto+" has no kernel or firmware path and needs the sing-box core, which is not usable here",
			core.Evidence, "Install sing-box, or use a natively supported protocol.", BlocksFeature))
	}
	// Natively carried protocols need no core.
	for proto, ok := range caps.Native {
		if !ok {
			continue
		}
		id := CapProtocolPrefix + proto
		if _, taken := items[id]; taken {
			continue
		}
		add(newCap(id, yes, yes, yes, ReasonNone, "", "carried natively by the kernel/firmware", "", BlocksNothing))
	}
	// Installable-but-absent protocols are the classic "after install" case.
	for proto, pkg := range caps.Installable {
		id := CapProtocolPrefix + proto
		if c, taken := items[id]; taken && c.State.Usable() {
			continue
		}
		add(newCap(id, yes, yes, no, ReasonMissingKernelModule,
			proto+" is not available on this router yet",
			"package not installed: "+pkg,
			installRemedy(caps.PackageManager, pkg), BlocksFeature))
	}

	// ---- offload: capability is not the same question as "WayHop can drive it" ---------------
	switch caps.Accel.Kind {
	case "nft-flowtable":
		add(newCap(CapOffloadSW, yes, yes, yes, ReasonNone, "", "nftables flowtable", "", BlocksNothing))
		if caps.Accel.HW {
			add(newCap(CapOffloadHW, yes, yes, yes, ReasonNone, "", "hardware flowtable path", "", BlocksNothing))
		} else {
			add(newCap(CapOffloadHW, no, yes, no, ReasonMissingKernelModule,
				"this kernel reports no hardware offload path, so hardware offload would run as software",
				"flowtable present, hw flag absent", "Use software offload.", BlocksOptimisation))
		}
	case "ppe":
		// Firmware PPE is not WayHop's nftables flow offload. Offering sw/hw here would imply a
		// control WayHop does not have.
		for _, id := range []string{CapOffloadSW, CapOffloadHW} {
			add(newCap(id, yes, no, VerdictUnknown, ReasonBackendNotWired,
				"acceleration on this router is the firmware's own hardware NAT (PPE); WayHop does "+
					"not drive it, so its offload setting would have no effect",
				"accel=ppe", "Manage acceleration in the router firmware.", BlocksOptimisation))
		}
	default:
		for _, id := range []string{CapOffloadSW, CapOffloadHW} {
			add(newCap(id, no, yes, no, ReasonMissingKernelModule,
				"no forwarding accelerator was detected on this router",
				"accel=none", "Leave offload off.", BlocksOptimisation))
		}
	}

	// ---- native DNS: read and write are separate capabilities --------------------------------
	addBool := func(id string, ok bool, detail, remedy, blocks string) {
		if ok {
			add(newCap(id, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
			return
		}
		add(newCap(id, yes, no, VerdictUnknown, ReasonBackendNotWired, detail, "", remedy, blocks))
	}
	addBool(CapDNSNativeRead, rt.NativeDNSRead,
		"reading the router's own DNS configuration is not implemented for this platform", "", BlocksNothing)
	addBool(CapDNSNativeWrite, rt.NativeDNSWrite,
		"writing back to the router's own DNS configuration is not implemented for this platform, "+
			"so no control may offer it", "", BlocksApply)

	// ---- router-native connection authority -------------------------------------------------
	// Keep carry/adopt/create/manage/remove separate. A loaded kernel module or an existing NDM
	// interface proves carriage only; it does not authorize WayHop to create or destroy anything.
	addNativeOperationCapabilities(add, caps, rt)

	// ---- engines -----------------------------------------------------------------------------
	if caps.Native["amneziawg"] {
		add(newCap(CapEngineAmneziaWG, yes, yes, yes, ReasonNone, "", "amneziawg native", "", BlocksNothing))
	} else if pkg, ok := caps.Installable["amneziawg"]; ok {
		add(newCap(CapEngineAmneziaWG, yes, yes, no, ReasonMissingKernelModule,
			"AmneziaWG is not available on this router yet", "package not installed: "+pkg,
			installRemedy(caps.PackageManager, pkg), BlocksFeature))
	} else {
		add(newCap(CapEngineAmneziaWG, no, yes, no, ReasonPlatformUnsupported,
			"AmneziaWG is not available on this platform", "", "", BlocksFeature))
	}
	add(newCap(CapEngineOlcRTC, VerdictUnknown, no, VerdictUnknown, ReasonBackendNotWired,
		"this WayHop build does not have a content-addressed olcRTC executor, so it cannot safely start or roll back that engine",
		"strict execution classifies olcRTC as unavailable", "Keep this connection disabled.", BlocksFeature))

	// ---- IPv6 ---------------------------------------------------------------------------------
	if rt.IPv6Routable {
		add(newCap(CapIPv6Routing, yes, yes, yes, ReasonNone, "", "", "", BlocksNothing))
	} else {
		add(newCap(CapIPv6Routing, yes, yes, no, ReasonInterfaceMissing,
			"no routable IPv6 path was observed on this router",
			"no usable global IPv6 route", "", BlocksOptimisation))
	}

	// A failed probe poisons the whole set: every entry that was not definitively resolved becomes
	// unknown, so nothing is activated on the strength of a measurement that did not happen.
	if rt.ProbeError != "" {
		for id, c := range items {
			if c.State == CapSupported {
				c.State = CapUnknown
				c.RuntimeState = VerdictUnknown
				c.Reason = ReasonProbeFailed
				c.Detail = "the capability probe failed, so support cannot be confirmed"
				items[id] = c
			}
		}
	}

	set := CapabilitySet{
		ProbedAt: rt.ProbedAt, ProbeError: rt.ProbeError,
		Platform: caps.Platform, Items: items,
	}
	set.Rev = set.computeRev()
	return set
}

// installRemedy phrases the fix using the package manager the host actually has. Hard-coding opkg
// is wrong on an apk OpenWrt, and a wrong command is worse than none.
func installRemedy(mgr, pkg string) string {
	switch mgr {
	case "apk":
		return "Install it: apk add " + pkg
	case "opkg":
		return "Install it: opkg update && opkg install " + pkg
	default:
		return "Install the package providing " + pkg + " for this platform."
	}
}

// computeRev hashes the decision-bearing fields only. Timestamps are deliberately excluded: a
// re-probe that observes an identical router must produce an identical revision, or every poll
// would invalidate a review the user is still reading.
func (s CapabilitySet) computeRev() string {
	ids := make([]string, 0, len(s.Items))
	for id := range s.Items {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	h := sha256.New()
	h.Write([]byte(s.Platform))
	h.Write([]byte{0})
	for _, id := range ids {
		c := s.Items[id]
		h.Write([]byte(strings.Join([]string{
			id, string(c.State), string(c.HostSupport), string(c.WayHopSupport),
			string(c.RuntimeState), string(c.Reason), c.Blocks,
		}, "\x1f")))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
