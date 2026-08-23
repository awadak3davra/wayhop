package platform

import (
	"fmt"
	"strings"
)

// Preflight answers "will this configuration actually do what it says on THIS box?" before Apply
// runs, instead of after.
//
// The apply path is full of deliberate, correct degradations: pbrCompileOptions drops an offload
// mode the accelerator cannot honour, pbrAvail turns the whole kernel plane off on Keenetic, and
// Plan.Apply swallows a flowtable that will not load so a routing plane already up is not torn
// down. Each of those is right in isolation and silent by design — which means a user can save
// `offload: hw` on a Keenetic, apply successfully, and be told nothing at all while the setting is
// discarded. That silence is the bug this closes: the same facts the apply path already uses to
// degrade are surfaced up front, so a setting that cannot take effect is visible BEFORE it is
// committed rather than inferred later from a throughput graph that never moved.
//
// It is a pure function over captured facts — no host I/O — so every branch is unit-testable and
// the API, the review panel, and the apply path cannot disagree about what this router supports.
//
// Severity is a promise about consequences, not a style of wording:
//
//	blocked  — traffic will NOT be handled as configured. Something the user asked for is simply
//	           absent, and the difference is observable as broken or unprotected traffic.
//	degraded — the configuration works, but a specific capability silently downgrades or drops.
//
// Nothing here refuses an Apply. Reporting is the point: the user may knowingly keep a setting for
// a router they are about to migrate to, and a hard block would be wrong.
type Unsupported struct {
	Setting  string `json:"setting"`          // "routing_mode" | "offload" | "offload_devices" | "protocol:<name>"
	Value    string `json:"value"`            // the configured value being judged
	Severity string `json:"severity"`         // "blocked" | "degraded"
	Reason   string `json:"reason"`           // what will actually happen, in the user's terms
	Remedy   string `json:"remedy,omitempty"` // the concrete way out, when one exists
}

// Severity constants — compared by value in the UI, so they must stay stable.
const (
	SeverityBlocked  = "blocked"
	SeverityDegraded = "degraded"
	// SeverityPrivacy is a configuration that WORKS and discloses something while doing it. It is
	// separate from the two above because both of those are statements about this router — "the
	// hardware cannot", "the capability degrades" — and a lookup that names the destination before
	// the tunnel carries it is neither. Filing it as `blocked` put it under a heading that blamed the
	// router for a coherence problem in the configuration.
	//
	// Severity does not decide the gate by itself. A plaintext lookup outside the tunnel carries
	// Blocks=apply; an encrypted resolver/traffic exit mismatch may be acknowledged as an explicit
	// privacy-policy trade-off.
	SeverityPrivacy = "privacy"
)

// PreflightInput is the configuration under judgement plus the two host facts the apply path
// consults that are NOT derivable from Capabilities alone.
type PreflightInput struct {
	// RoutingMode must be the EFFECTIVE mode (after the empty-string/Gateway derivation), not the
	// raw config field — otherwise "" is judged as its own mode and the real one goes unchecked.
	RoutingMode string
	Offload     string
	// OffloadDevices empty is not automatically a fault: the apply path probes for the WAN/LAN
	// devices when the list is empty on a non-demo host. Only a probe that would find nothing is.
	OffloadDevices []string
	// PBRAvailable mirrors Server.pbrAvailable(): the kernel policy-routing plane can actually load
	// (nft present, not Keenetic). This is the single fact that decides whether carve-outs exist.
	PBRAvailable bool
	// HasDomainRules is true when any routing rule matches on domains rather than IP/CIDR. Domain
	// matching needs the TUN to sniff, so it is inert in a mode that has no TUN.
	HasDomainRules bool
	// Protocols are the endpoint protocols in use, lowercased (e.g. "vless", "wireguard").
	Protocols []string
	// Observed is the measured datapath state. Capabilities say what this box CAN do; only the
	// observation shows a fast path that a live policy-routing plane has already defeated, which is
	// the case the operator most needs to see before they apply another offload setting.
	Observed OffloadState
}

// Preflight returns every configured setting that will not take full effect on this host. An empty
// result means the configuration is fully supported as written.
func Preflight(in PreflightInput, caps Capabilities) []Unsupported {
	var out []Unsupported

	out = append(out, preflightRoutingMode(in)...)
	out = append(out, preflightOffload(in, caps)...)
	out = append(out, preflightProtocols(in, caps)...)
	out = append(out, preflightLegacyProtocols(in)...)
	return out
}

// preflightLegacyProtocols warns about protocols that WORK but do not protect anything. This is not
// a capability gap — the router carries PPTP perfectly well — which is exactly why it needs saying
// out loud: nothing else in the product would ever tell the user, and a tunnel that appears healthy
// while providing no confidentiality is worse than one that visibly fails.
func preflightLegacyProtocols(in PreflightInput) []Unsupported {
	var out []Unsupported
	seen := map[string]bool{}
	for _, p := range in.Protocols {
		warn, legacy := LegacyProtocolWarning[p]
		if !legacy || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, Unsupported{
			Setting: "protocol:" + p, Value: p, Severity: SeverityDegraded,
			Reason: warn,
			Remedy: "Use WireGuard, AmneziaWG, or a proxy protocol instead.",
		})
	}
	return out
}

// preflightRoutingMode judges the mode against the availability of the kernel PBR plane.
//
// The severities differ sharply between modes and that difference is the whole value of the check.
// "hybrid" keeps its capture-all TUN when PBR is missing, so traffic is still carried — only the
// IP/CIDR carve-outs vanish. "fast" deliberately has NO TUN: the kernel plane is the only thing
// steering traffic, so losing it means nothing is routed through WayHop at all while the UI still
// shows a saved, applied configuration. That is the most expensive silent failure in the product,
// and it is exactly the shape a Keenetic hits today.
func preflightRoutingMode(in PreflightInput) []Unsupported {
	var out []Unsupported

	if !in.PBRAvailable {
		switch in.RoutingMode {
		case "fast":
			out = append(out, Unsupported{
				Setting: "routing_mode", Value: "fast", Severity: SeverityBlocked,
				Reason: "\"fast\" steers traffic ONLY through the kernel policy-routing plane, and this " +
					"router cannot load it (no nftables). With no capture-all TUN either, no traffic " +
					"would be routed through WayHop — carve-outs included.",
				Remedy: "Use \"tun\" (or \"hybrid\") on this router, which carries traffic through the " +
					"sing-box TUN and does not depend on nftables.",
			})
		case "hybrid":
			out = append(out, Unsupported{
				Setting: "routing_mode", Value: "hybrid", Severity: SeverityDegraded,
				Reason: "This router cannot load the kernel policy-routing plane (no nftables), so the " +
					"IP/CIDR carve-outs will not be installed. General traffic still transits the TUN, " +
					"so \"hybrid\" behaves like \"tun\" here.",
				Remedy: "Use \"tun\" to make that explicit, or move carve-outs to domain rules, which the " +
					"TUN can still match.",
			})
		}
	}

	// Independent of PBR: "fast" has no TUN to sniff domains with, so domain rules silently never
	// match LAN traffic. Worth saying only when the config actually contains domain rules.
	if in.RoutingMode == "fast" && in.HasDomainRules && in.PBRAvailable {
		out = append(out, Unsupported{
			Setting: "routing_mode", Value: "fast", Severity: SeverityDegraded,
			Reason: "\"fast\" has no capture-all TUN, so domain-based rules cannot match LAN traffic. " +
				"Only IP/CIDR carve-outs take effect in this mode.",
			Remedy: "Use \"hybrid\" if the domain rules matter, or express them as IP/CIDR carve-outs.",
		})
	}
	return out
}

// preflightOffload mirrors pbrCompileOptions' gating decisions so the user sees them in advance.
func preflightOffload(in PreflightInput, caps Capabilities) []Unsupported {
	// "auto" is self-correcting: it already picked the safest supported option, so it is never a
	// fault. It still needs explaining when it lands on Off — the user asked for acceleration and is
	// getting none, and an unexplained downgrade is indistinguishable from a silent failure.
	if in.Offload == "auto" {
		effective, reason := ResolveOffload("auto", caps)
		if effective != "off" || in.RoutingMode != "fast" {
			return nil
		}
		return []Unsupported{{
			Setting: "offload", Value: "auto", Severity: SeverityDegraded,
			Reason: "Automatic offload selected Off: " + reason + ".",
			Remedy: "No action needed — this is the safest supported option for this router.",
		}}
	}
	if in.Offload != "sw" && in.Offload != "hw" {
		return nil
	}
	var out []Unsupported

	// Offload is compiled for "fast" mode only; in any other mode the value is inert. Reported
	// first because it makes every other offload finding moot.
	if in.RoutingMode != "fast" {
		return []Unsupported{{
			Setting: "offload", Value: in.Offload, Severity: SeverityDegraded,
			Reason: fmt.Sprintf("Flow offload applies to \"fast\" routing mode only; this router is set "+
				"to %q, so the setting has no effect.", in.RoutingMode),
			Remedy: "Switch to \"fast\" mode to use flow offload, or set offload to \"off\".",
		}}
	}

	switch caps.Accel.Kind {
	case "nft-flowtable":
		// The right accelerator. The only remaining gap is asking for hardware on a box whose
		// flowtable has no hardware path — the flowtable still loads, just in software.
		if in.Offload == "hw" && !caps.Accel.HW {
			out = append(out, Unsupported{
				Setting: "offload", Value: "hw", Severity: SeverityDegraded,
				Reason: "This kernel supports a software flowtable but reports no hardware offload path, " +
					"so \"hw\" will run as software offload.",
				Remedy: "Set offload to \"sw\" to match what this router can do.",
			})
		}
		// The capability is present and the datapath is still offloading nothing, with WayHop's own
		// mark-based plane installed — the documented interaction, and the one a capability probe
		// cannot see. Gated on the live plane so this cannot fire as "you have not applied yet".
		if in.Observed.MarkedPlane && in.Observed.Effective == "off" {
			out = append(out, Unsupported{
				Setting: "offload", Value: in.Offload, Severity: SeverityDegraded,
				Reason: "WayHop's mark-based policy-routing plane is installed and this router is currently " +
					"offloading nothing: " + strings.Join(in.Observed.Reasons, "; ") + ".",
				Remedy: in.Observed.Recommendation,
			})
		}
	case "ppe":
		out = append(out, Unsupported{
			Setting: "offload", Value: in.Offload, Severity: SeverityBlocked,
			Reason: "Offload on this router is the firmware's own hardware NAT (PPE), which WayHop does " +
				"not drive. The nftables flow-offload this setting controls does not exist here, so it " +
				"will be dropped at apply.",
			Remedy: "Leave offload \"off\"; manage acceleration in the router firmware instead.",
		})
	default:
		out = append(out, Unsupported{
			Setting: "offload", Value: in.Offload, Severity: SeverityBlocked,
			Reason: "No forwarding accelerator was detected on this router, so the flow-offload setting " +
				"will be dropped at apply.",
			Remedy: "Set offload to \"off\".",
		})
	}

	// A flowtable with no devices attaches to nothing. Only meaningful once the accelerator itself
	// is usable — otherwise the offload finding above already explains the outcome.
	if caps.Accel.Kind == "nft-flowtable" && len(in.OffloadDevices) == 0 {
		out = append(out, Unsupported{
			Setting: "offload_devices", Value: "(empty)", Severity: SeverityDegraded,
			Reason: "No offload devices are configured. WayHop will probe for the WAN uplink and LAN " +
				"bridge at apply; if the probe finds nothing, offload is skipped silently.",
			Remedy: "Set the offload devices explicitly (typically the WAN interface and br-lan).",
		})
	}
	return out
}

// preflightProtocols reports endpoint protocols that cannot run as configured. A proxy protocol
// with no kernel path anywhere needs the sing-box core; if the core is absent, those endpoints do
// not merely degrade — they never carry traffic.
func preflightProtocols(in PreflightInput, caps Capabilities) []Unsupported {
	if caps.SingboxPresent || len(in.Protocols) == 0 {
		return nil
	}
	needs := map[string]bool{}
	for _, p := range caps.SingboxRequired {
		needs[p] = true
	}

	var out []Unsupported
	seen := map[string]bool{}
	for _, p := range in.Protocols {
		if !needs[p] || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, Unsupported{
			Setting: "protocol:" + p, Value: p, Severity: SeverityBlocked,
			Reason: fmt.Sprintf("%s has no kernel or firmware path and requires the sing-box core, which "+
				"is not installed on this router. Endpoints using it will not carry traffic.", p),
			Remedy: "Install sing-box, or use a protocol this router supports natively.",
		})
	}
	return out
}
