package platform

import (
	"strings"
	"testing"
)

// find returns the first finding for a setting, or nil.
func find(list []Unsupported, setting string) *Unsupported {
	for i := range list {
		if list[i].Setting == setting {
			return &list[i]
		}
	}
	return nil
}

func flowtableCaps(hw bool) Capabilities {
	return Capabilities{Platform: "openwrt", Accel: Accel{Kind: "nft-flowtable", HW: hw}, SingboxPresent: true}
}

func keeneticCaps() Capabilities {
	return Capabilities{Platform: "keenetic", Accel: Accel{Kind: "ppe", HW: true}, SingboxPresent: true}
}

// The headline case: "fast" on a router with no kernel plane routes NOTHING, because that mode has
// no TUN to fall back on. It must be blocked, not merely noted — this is the failure that looks
// like a successful apply while traffic silently bypasses WayHop entirely.
func TestPreflight_FastWithoutPBRIsBlocked(t *testing.T) {
	got := Preflight(PreflightInput{RoutingMode: "fast", PBRAvailable: false}, keeneticCaps())

	f := find(got, "routing_mode")
	if f == nil {
		t.Fatal("fast mode without a kernel plane must be reported")
	}
	if f.Severity != SeverityBlocked {
		t.Errorf("severity = %q, want %q: no TUN and no PBR means no traffic is routed at all",
			f.Severity, SeverityBlocked)
	}
	if f.Remedy == "" {
		t.Error("a blocked mode must tell the user what to switch to")
	}
}

// "hybrid" without PBR still carries traffic through the TUN, so it degrades rather than blocks.
// Getting this distinction wrong in either direction misinforms the user about whether their
// traffic is protected.
func TestPreflight_HybridWithoutPBRIsDegradedNotBlocked(t *testing.T) {
	got := Preflight(PreflightInput{RoutingMode: "hybrid", PBRAvailable: false}, keeneticCaps())

	f := find(got, "routing_mode")
	if f == nil {
		t.Fatal("hybrid without a kernel plane must be reported: carve-outs will not exist")
	}
	if f.Severity != SeverityDegraded {
		t.Errorf("severity = %q, want %q: the TUN still carries traffic in hybrid",
			f.Severity, SeverityDegraded)
	}
}

// A fully supported configuration must produce nothing at all. A preflight that cries wolf on a
// healthy box trains users to ignore it.
func TestPreflight_SupportedConfigIsSilent(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "hw", OffloadDevices: []string{"wan", "br-lan"},
		PBRAvailable: true, Protocols: []string{"vless"},
	}, flowtableCaps(true))

	if len(got) != 0 {
		t.Errorf("a fully supported config must report nothing, got %+v", got)
	}
}

// "tun" mode never depends on the kernel plane, so a missing plane is not its problem.
func TestPreflight_TunModeUnaffectedByMissingPBR(t *testing.T) {
	got := Preflight(PreflightInput{RoutingMode: "tun", PBRAvailable: false}, keeneticCaps())
	if f := find(got, "routing_mode"); f != nil {
		t.Errorf("tun mode does not use the kernel plane; should not be flagged: %+v", f)
	}
}

// Offload on a PPE box (Keenetic) is the firmware's, not WayHop's — the setting is silently
// dropped at apply today, which is precisely what this must announce beforehand.
func TestPreflight_OffloadOnPPEIsBlocked(t *testing.T) {
	got := Preflight(PreflightInput{RoutingMode: "fast", Offload: "hw", PBRAvailable: true}, keeneticCaps())

	f := find(got, "offload")
	if f == nil {
		t.Fatal("nft flow-offload cannot work on a PPE box and must be reported")
	}
	if f.Severity != SeverityBlocked {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityBlocked)
	}
}

// Asking for hardware offload where only software exists still loads a flowtable, so it degrades.
func TestPreflight_HWOffloadWithoutHWPathDegrades(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "hw", OffloadDevices: []string{"wan"}, PBRAvailable: true,
	}, flowtableCaps(false))

	f := find(got, "offload")
	if f == nil {
		t.Fatal("hw offload on a software-only flowtable must be reported")
	}
	if f.Severity != SeverityDegraded {
		t.Errorf("severity = %q, want %q: the flowtable still loads in software", f.Severity, SeverityDegraded)
	}
	// "sw" on the same host is genuinely correct and must stay silent.
	if sw := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "sw", OffloadDevices: []string{"wan"}, PBRAvailable: true,
	}, flowtableCaps(false)); len(sw) != 0 {
		t.Errorf("sw offload on a software flowtable is supported; got %+v", sw)
	}
}

// Offload outside "fast" mode is inert. Report that once, and do not additionally complain about
// the accelerator — the mode is the reason, and stacking findings buries it.
func TestPreflight_OffloadOutsideFastModeReportsOnlyTheMode(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "tun", Offload: "hw", PBRAvailable: true,
	}, keeneticCaps())

	if len(got) != 1 {
		t.Fatalf("want exactly one finding explaining the mode, got %d: %+v", len(got), got)
	}
	if got[0].Setting != "offload" || got[0].Severity != SeverityDegraded {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

// offload "off"/"" is not a request for anything and must never be flagged.
func TestPreflight_OffloadOffIsSilent(t *testing.T) {
	for _, v := range []string{"", "off"} {
		got := Preflight(PreflightInput{RoutingMode: "fast", Offload: v, PBRAvailable: true}, keeneticCaps())
		if f := find(got, "offload"); f != nil {
			t.Errorf("offload %q must not be flagged: %+v", v, f)
		}
	}
}

// Empty offload devices are a soft warning: the apply path probes for them, but a failed probe
// skips offload silently.
func TestPreflight_EmptyOffloadDevicesWarns(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "sw", PBRAvailable: true,
	}, flowtableCaps(true))

	f := find(got, "offload_devices")
	if f == nil {
		t.Fatal("an empty device list should warn that offload may be skipped")
	}
	if f.Severity != SeverityDegraded {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityDegraded)
	}
}

// Domain rules in "fast" mode never match LAN traffic — a real, documented limitation that is
// invisible in the UI today.
func TestPreflight_DomainRulesInFastMode(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", PBRAvailable: true, HasDomainRules: true,
	}, flowtableCaps(true))

	if find(got, "routing_mode") == nil {
		t.Fatal("domain rules cannot match in fast mode and must be reported")
	}
	// Without domain rules there is nothing to warn about.
	if q := Preflight(PreflightInput{
		RoutingMode: "fast", PBRAvailable: true,
	}, flowtableCaps(true)); len(q) != 0 {
		t.Errorf("fast mode with no domain rules is fine; got %+v", q)
	}
}

// A proxy protocol with no kernel path cannot run without the core, and that is a blocked state:
// the endpoint exists in the UI but carries nothing.
func TestPreflight_ProxyProtocolNeedsCore(t *testing.T) {
	caps := Capabilities{
		Platform: "openwrt", Accel: Accel{Kind: "nft-flowtable"},
		SingboxRequired: []string{"vless", "vmess"}, SingboxPresent: false,
	}
	got := Preflight(PreflightInput{
		RoutingMode: "tun", PBRAvailable: true,
		Protocols: []string{"vless", "vless", "wireguard"}, // duplicate must collapse
	}, caps)

	f := find(got, "protocol:vless")
	if f == nil {
		t.Fatal("vless without the core must be reported")
	}
	if f.Severity != SeverityBlocked {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityBlocked)
	}
	if len(got) != 1 {
		t.Errorf("wireguard is native and vless must not be reported twice; got %+v", got)
	}
}

// With the core present, the same protocols are entirely fine.
func TestPreflight_ProxyProtocolFineWithCore(t *testing.T) {
	caps := Capabilities{
		Platform: "openwrt", Accel: Accel{Kind: "nft-flowtable"},
		SingboxRequired: []string{"vless"}, SingboxPresent: true,
	}
	got := Preflight(PreflightInput{RoutingMode: "tun", PBRAvailable: true, Protocols: []string{"vless"}}, caps)
	if len(got) != 0 {
		t.Errorf("the core is installed; nothing should be reported: %+v", got)
	}
}

// Every finding must be actionable and well-formed, whatever the branch — an empty reason or an
// unknown severity would render as a blank row in the review panel.
func TestPreflight_FindingsAreWellFormed(t *testing.T) {
	inputs := []PreflightInput{
		{RoutingMode: "fast", PBRAvailable: false},
		{RoutingMode: "hybrid", PBRAvailable: false},
		{RoutingMode: "fast", Offload: "hw", PBRAvailable: true},
		{RoutingMode: "fast", Offload: "sw", PBRAvailable: true, HasDomainRules: true},
		{RoutingMode: "tun", Offload: "sw", PBRAvailable: true, Protocols: []string{"trojan"}},
	}
	allCaps := []Capabilities{
		keeneticCaps(), flowtableCaps(true), flowtableCaps(false),
		{Platform: "unknown", SingboxRequired: []string{"trojan"}},
	}
	for _, in := range inputs {
		for _, caps := range allCaps {
			for _, f := range Preflight(in, caps) {
				if f.Setting == "" || f.Value == "" || f.Reason == "" {
					t.Errorf("incomplete finding %+v for input %+v", f, in)
				}
				if f.Severity != SeverityBlocked && f.Severity != SeverityDegraded {
					t.Errorf("unknown severity %q in %+v", f.Severity, f)
				}
			}
		}
	}
}

// "auto" is never a fault — it already picked the safest supported option — but an auto that lands
// on Off must still say why, or the user cannot tell it from a silent failure.
func TestPreflight_AutoExplainsItselfWhenItPicksOff(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "auto", OffloadDevices: []string{"wan"}, PBRAvailable: true,
	}, keeneticCaps())

	f := find(got, "offload")
	if f == nil {
		t.Fatal("auto resolving to Off on a PPE box must be explained")
	}
	if f.Severity != SeverityDegraded {
		t.Errorf("severity = %q, want %q: auto chose correctly, it is not a fault", f.Severity, SeverityDegraded)
	}
	if f.Reason == "" {
		t.Error("the explanation must state why offload is unavailable here")
	}
}

// Where auto CAN accelerate, it is silent — flagging a correct automatic choice would be noise.
func TestPreflight_AutoIsSilentWhenItCanAccelerate(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "fast", Offload: "auto", OffloadDevices: []string{"wan"}, PBRAvailable: true,
	}, flowtableCaps(true))
	if f := find(got, "offload"); f != nil {
		t.Errorf("auto picked hardware offload correctly; nothing to report: %+v", f)
	}
}

// The observed datapath is the one fact a capability probe cannot supply: the box reports a working
// hardware flowtable AND is offloading nothing, because WayHop's own mark-based plane is what
// defeated it. Reporting only the capability leaves the operator adjusting a setting that is not the
// cause.
func TestPreflightOffload_LivePlaneDefeatingTheFastPath(t *testing.T) {
	caps := Capabilities{Platform: "openwrt", Accel: Accel{Kind: "nft-flowtable", HW: true}}
	in := PreflightInput{
		RoutingMode: "fast", Offload: "hw", OffloadDevices: []string{"eth1", "br-lan"}, PBRAvailable: true,
		Observed: OffloadState{
			Effective: "off", MarkedPlane: true,
			Reasons:        []string{"a flowtable is installed but 0 of 200 sampled connections are offloaded"},
			Recommendation: "Enabling flow offload can raise routed throughput and lower CPU. WayHop's mark-based policy-routing plane is installed on this router right now",
		},
	}
	f := find(Preflight(in, caps), "offload")
	if f == nil {
		t.Fatal("a capable router that is demonstrably offloading nothing must be reported")
	}
	if !strings.Contains(f.Reason, "0 of 200") {
		t.Errorf("the finding must carry the measurement, got %q", f.Reason)
	}
	if !strings.Contains(f.Remedy, "policy-routing plane") {
		t.Errorf("the remedy must name the cause rather than suggest a blind flip, got %q", f.Remedy)
	}
}

// Without the marked plane installed, a not-yet-applied configuration must not be reported as a
// fault: "this router is not offloading yet" is what every first apply looks like.
func TestPreflightOffload_NoFindingBeforeThePlaneExists(t *testing.T) {
	caps := Capabilities{Platform: "openwrt", Accel: Accel{Kind: "nft-flowtable", HW: true}}
	in := PreflightInput{
		RoutingMode: "fast", Offload: "hw", OffloadDevices: []string{"eth1", "br-lan"}, PBRAvailable: true,
		Observed: OffloadState{Effective: "off", MarkedPlane: false, Reasons: []string{"no flowtable is installed"}},
	}
	if f := find(Preflight(in, caps), "offload"); f != nil {
		t.Errorf("a router without the marked plane must not raise an offload finding yet: %+v", f)
	}
}
