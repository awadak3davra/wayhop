package server

import (
	"context"
	"net/http"

	"wayhop/internal/dnsaudit"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// handleNativeCapabilities reports what the host can route natively (kernel/firmware
// paths present NOW), which protocols are installable and via which package, and which
// proxy protocols still require sing-box. Read-only host probe; captures no secrets.
// The verdict is computed server-side (platform.DetectCapabilities) so every client agrees.
func (s *Server) handleNativeCapabilities(w http.ResponseWriter, r *http.Request) {
	caps := platform.DetectCapabilities()
	// Report the SAME accelerator facts the apply path uses, rather than a second independent probe.
	// pbrCompileOptions reads the server's accelKind()/accelHW(), which carry the demo override;
	// DetectCapabilities() does not. noteAccel keeps this fresh observation for them and returns the
	// override - before both the serialised response and the preflight verdict - so every consumer
	// reads one source of truth.
	caps.Accel = s.noteAccel(caps.Accel)
	off := s.offloadObservation(r.Context())
	runtime := s.runtimeFacts(r.Context())
	runtime.NativeOperations = cloneHostBoolMap(s.nativeOperations)
	// The selector needs the same operation-level answer as Apply, not the old raw booleans. In
	// particular, a Keenetic can carry policy routes in firmware while this WayHop build cannot drive
	// that plane; only Evaluate preserves that host=yes/WayHop=no distinction. Recheck nft with the
	// non-mutating production probe so an installed-but-unusable binary does not make Fast selectable.
	if available, err := probeKernelPBRFresh(r.Context(), s, caps.Platform); err != nil {
		runtime.KernelPBRWired = false
		runtime.KernelPBRProbeError = "kernel policy-routing capability could not be verified"
	} else {
		runtime.KernelPBRWired = available
	}
	caps = withConfiguredCore(caps, runtime.SingboxRunnable)
	capabilitySet := platform.Evaluate(caps, runtime)
	// The connection form's Retry asks here. Its answer has to be the one the save checks, or Retry
	// shows "supported" and the save goes on refusing from the cache.
	if !s.config().Demo {
		s.keepCapabilities(capabilitySet)
	}
	// caps.Accel is a CAPABILITY ("this SoC has a PPE"). offload_state is what the datapath is
	// ACTUALLY doing right now, with the reason for any downgrade — a box can advertise hardware
	// offload while a per-packet policy-routing plane keeps every flow on the slow path. Reporting
	// only the capability would claim offload is on merely because it was configured/supported.
	// Embed Capabilities so every existing field keeps its exact JSON shape (no hand-listed field can
	// drift from the struct's tags); offload_state is purely additive.
	//
	// preflight goes further than either: capabilities say what the box CAN do and offload_state says
	// what it IS doing, but neither tells the user that the configuration they are about to apply
	// asks for something this box will silently discard. That verdict is computed here, server-side,
	// against the same facts the apply path uses.
	// engine_plugin is the save check's own answer for a new AmneziaWG connection the router's own
	// cannot create (QA-133): the connection form offers it on WayHop's engine and says why.
	writeJSON(w, http.StatusOK, struct {
		platform.Capabilities
		CapabilitySet platform.CapabilitySet       `json:"capability_set"`
		OffloadState  platform.OffloadState        `json:"offload_state"`
		OffloadProbe  offloadProbeV1               `json:"offload_probe"`
		Preflight     []platform.Unsupported       `json:"preflight"`
		EnginePlugin  map[string]enginePluginOffer `json:"engine_plugin,omitempty"`
		Demo          bool                         `json:"demo,omitempty"`
	}{caps, capabilitySet, off.State, off.Probe, s.preflight(caps, off.State), s.enginePluginOffers(capabilitySet), s.config().Demo})
}

type offloadProbeV1 struct {
	SchemaVersion        int      `json:"schema_version"`
	ConntrackSampleLimit int      `json:"conntrack_sample_limit"`
	Errors               []string `json:"errors"`
}

type offloadObservationV1 struct {
	State platform.OffloadState
	Probe offloadProbeV1
}

// offloadObservation is the one effective-offload probe used by Diagnostics, capabilities and the
// legacy read-only review surface. It is bounded and cancellable like strict Apply: at most 400
// conntrack rows, bounded command output, fixed safe errors. K6 hardware trials compare this exact
// contract before/after; a whole-file or best-effort fallback would make those ratios incomparable.
func (s *Server) offloadObservation(ctx context.Context) offloadObservationV1 {
	requested := s.config().Offload
	observe := observeEffectiveOffloadContext
	if s.offloadObserver != nil {
		observe = s.offloadObserver
	}
	state, probeErrors := observe(ctx, requested, pbrKernelTable)
	probeErrors = uniqueApplyHostErrors(probeErrors)
	state.Reasons = uniqueApplyHostErrors(append(state.Reasons, probeErrors...))
	if probeErrors == nil {
		probeErrors = []string{}
	}
	return offloadObservationV1{
		State: state,
		Probe: offloadProbeV1{
			SchemaVersion: 1, ConntrackSampleLimit: applyHostConntrackLines, Errors: probeErrors,
		},
	}
}

func dnsPathUnsupported(a dnsaudit.Asymmetry) platform.Unsupported {
	// A list sent to a KeeneticOS access policy: WayHop cannot see whether the policy leaves by a
	// tunnel or by the WAN, and a DNS server's detour cannot name a policy, so the usual remedy could
	// not be followed. Reported as advice with steps that can be taken, never as an Apply blocker - it
	// refused a list on a WAN policy for a leak that did not exist (QA-063).
	if _, policy := model.NDMPolicyName(a.TrafficVia); policy {
		return platform.Unsupported{
			Setting: "dns_path:" + a.RoutingListID, Value: a.TrafficVia, Severity: platform.SeverityDegraded,
			Reason: a.Detail + "; whether that exposes anything depends on where the Keenetic access policy " +
				"sends the traffic, which WayHop cannot see",
			Remedy: "If the policy leaves through a tunnel, use an encrypted DNS server (DoH or DoT), or send " +
				"the list to a WayHop tunnel or group so its lookups can follow it.",
		}
	}
	severity, settingPrefix := platform.SeverityDegraded, "dns_path:"
	if a.Exposed {
		severity = platform.SeverityPrivacy
		if a.Encrypted {
			settingPrefix = "dns_path:encrypted:"
		} else {
			settingPrefix = "dns_path:plaintext:"
		}
	}
	return platform.Unsupported{
		Setting: settingPrefix + a.RoutingListID, Value: a.TrafficVia, Severity: severity,
		Reason: a.Detail,
		Remedy: "Point this list's DNS rule at a server whose detour matches the list's outbound, " +
			"so the lookup and the traffic use the same exit.",
	}
}
