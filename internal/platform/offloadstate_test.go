package platform

import (
	"strings"
	"testing"
)

// conntrackNoOffload mirrors a real /proc/net/nf_conntrack sample from a live KeeneticOS router:
// entries are ASSURED/UNREPLIED but NONE carries an offload mark.
const conntrackNoOffload = `ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=203.0.113.5 sport=52344 dport=443 [ASSURED] mark=0 use=1
ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.11 dst=203.0.113.6 sport=52345 dport=443 [ASSURED] mark=0 use=1
ipv4     2 udp      17 29 src=192.0.2.12 dst=203.0.113.7 sport=5353 dport=53 [UNREPLIED] mark=0 use=1`

// conntrackSoftOffload carries the plain [OFFLOAD] tag: the flow left the slow path, but the tag
// alone does not say by which tier.
const conntrackSoftOffload = `ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=203.0.113.5 [ASSURED] [OFFLOAD] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.11 dst=203.0.113.6 [ASSURED] mark=0 use=1`

// conntrackHWOffload carries the tag that PROVES hardware.
const conntrackHWOffload = `ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=203.0.113.5 [ASSURED] [HW_OFFLOAD] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.11 dst=203.0.113.6 [ASSURED] mark=0 use=1`

const (
	uciOff = "config defaults\n\toption flow_offloading '0'\n\toption flow_offloading_hw '0'\n"
	uciSW  = "config defaults\n\toption flow_offloading '1'\n"
	uciHW  = "config defaults\n\toption flow_offloading '1'\n\toption flow_offloading_hw '1'\n"

	ftSW = "table inet fw4 {\n\tflowtable ft {\n\t\thook ingress priority filter\n\t}\n}\n"
	ftHW = "table inet fw4 {\n\tflowtable ft {\n\t\thook ingress priority filter\n\t\tflags offload\n\t}\n}\n"
	ftNo = "\n" // nft answered, and there is no flowtable in the ruleset
)

func reasons(st OffloadState) string { return strings.Join(st.Reasons, " | ") }

// The AX3000T contradiction, as one fixture. /etc/config/firewall said offload was off while the
// same router had 1 of 2 sampled connections offloaded. The old healthcheck read only the config and
// announced "flow offload is off … the hardware fast path is unused"; observed flows outrank intent,
// so the verdict has to follow the flows and the config becomes the thing that needs explaining.
func TestDetectOffload_UCIOffButFlowsAreOffloaded(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		Requested: "sw", FirewallUCI: uciOff, Flowtables: ftHW, FlowtablesKnown: true, Conntrack: conntrackSoftOffload,
	})
	if st.Effective != "hw" {
		t.Fatalf("Effective = %q, want hw: flows are offloaded and the flowtable carries `flags offload`", st.Effective)
	}
	if st.Configured != "off" {
		t.Errorf("Configured = %q, want off (that is what the config says)", st.Configured)
	}
	if !strings.Contains(reasons(st), "configured for off but the effective state is hw") {
		t.Errorf("the config/observation mismatch must be stated, got %q", reasons(st))
	}
	if strings.Contains(strings.ToLower(reasons(st)), "unused") {
		t.Errorf("a router with offloaded flows must never be described as unused: %q", reasons(st))
	}
}

// The plain [OFFLOAD] tag proves only that the flow left the slow path. Calling that "hw" is the
// scope-too-wide claim: with no `flags offload` anywhere, the honest tier is software.
func TestDetectOffload_PlainTagWithoutHardwareFlagIsSoftware(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		Requested: "sw", FirewallUCI: uciSW, Flowtables: ftSW, FlowtablesKnown: true, Conntrack: conntrackSoftOffload,
	})
	if st.Effective != "sw" {
		t.Fatalf("Effective = %q, want sw", st.Effective)
	}
	if st.FlowsOffl != 1 || st.FlowsHW != 0 || st.FlowsTotal != 2 {
		t.Errorf("flows = %d offloaded (%d hw) of %d, want 1 (0 hw) of 2", st.FlowsOffl, st.FlowsHW, st.FlowsTotal)
	}
	if !strings.Contains(reasons(st), "hardware-offloaded") {
		t.Errorf("the reason must say why this is not hw, got %q", reasons(st))
	}
}

// [HW_OFFLOAD] proves hardware on its own, whatever the flowtable flags say.
func TestDetectOffload_HardwareTagIsConclusive(t *testing.T) {
	st := DetectOffload(OffloadInputs{Requested: "sw", FirewallUCI: uciSW, Flowtables: ftSW, FlowtablesKnown: true, Conntrack: conntrackHWOffload})
	if st.Effective != "hw" {
		t.Fatalf("Effective = %q, want hw", st.Effective)
	}
	if !strings.Contains(reasons(st), "requested offload mode is sw but the effective state is hw") {
		t.Errorf("the requested/observed mismatch must be stated, got %q", reasons(st))
	}
}

// Configured for hardware and not one connection uses the flowtable: the honest answer is off, with
// the count that justifies it. An optimistic "hw" here is the claim-from-configuration defect.
func TestDetectOffload_UCIHardwareButZeroObservedFlows(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		Requested: "hw", FirewallUCI: uciHW, Flowtables: ftHW, FlowtablesKnown: true, Conntrack: conntrackNoOffload,
	})
	if st.Effective != "off" {
		t.Fatalf("Effective = %q, want off", st.Effective)
	}
	if st.Configured != "hw" {
		t.Errorf("Configured = %q, want hw", st.Configured)
	}
	if !strings.Contains(reasons(st), "0 of 3") {
		t.Errorf("the verdict must be quantified, got %q", reasons(st))
	}
}

// No flowtable in the ruleset settles it without needing a conntrack sample at all.
func TestDetectOffload_NoFlowtableIsConclusivelyOff(t *testing.T) {
	st := DetectOffload(OffloadInputs{Requested: "hw", FirewallUCI: uciOff, Flowtables: ftNo, FlowtablesKnown: true})
	if st.Effective != "off" {
		t.Fatalf("Effective = %q, want off", st.Effective)
	}
	if !strings.Contains(reasons(st), "no flowtable is installed") {
		t.Errorf("the reason must name the missing flowtable, got %q", reasons(st))
	}
}

// The headline Keenetic case: hardware PPE ENABLED, but the policy-routing shim forces
// nf_conntrack_fastnat=0, so nothing is offloaded. Reporting "hw" from the capability alone would be
// the false claim the spec forbids.
func TestDetectOffload_KeeneticDefeatedByFastNAT(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		Requested: "hw", PPEEnabled: "1\n", FastNAT: "0\n", Conntrack: conntrackNoOffload,
	})
	if st.Effective != "off" {
		t.Fatalf("Effective = %q, want off (PPE on but fast path disabled)", st.Effective)
	}
	if !st.PPEEnabled || st.FastNATOn || !st.KnobsKnown {
		t.Errorf("knobs wrong: ppe=%v fastnat=%v known=%v", st.PPEEnabled, st.FastNATOn, st.KnobsKnown)
	}
	j := reasons(st)
	if !strings.Contains(j, "nf_conntrack_fastnat") {
		t.Errorf("reason must name the disabled fast path, got %q", j)
	}
	if !strings.Contains(j, "0 of 3") {
		t.Errorf("reason should quantify offloaded flows, got %q", j)
	}
	if !strings.Contains(j, "requested offload mode is hw") {
		t.Errorf("mismatch between requested and effective must be reported, got %q", j)
	}
}

// PPE on, fast path on, nothing sampled as offloaded — still off, not an optimistic hw.
func TestDetectOffload_KnobsGoodButNothingOffloaded(t *testing.T) {
	st := DetectOffload(OffloadInputs{Requested: "hw", PPEEnabled: "1", FastNAT: "1", Conntrack: conntrackNoOffload})
	if st.Effective != "off" {
		t.Errorf("Effective = %q, want off (no flow actually offloaded)", st.Effective)
	}
}

// A readable but empty conntrack table proves that there are no active flows to classify. It does
// not prove that PPE is carrying traffic: knobs are configuration, not observed datapath evidence.
func TestDetectOffload_EmptyKnownSampleDoesNotClaimHardware(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		Requested: "hw", PPEEnabled: "1", FastNAT: "1", ConntrackKnown: true,
	})
	if st.Effective != "unknown" {
		t.Fatalf("Effective = %q, want unknown without an active flow", st.Effective)
	}
	if !st.FlowsKnown || st.FlowsTotal != 0 {
		t.Fatalf("flow evidence = known:%v total:%d, want readable empty sample", st.FlowsKnown, st.FlowsTotal)
	}
	if !strings.Contains(reasons(st), "no active connections") {
		t.Fatalf("reasons = %q, want the empty sample stated", reasons(st))
	}
}

func TestDetectOffload_PPEDisabled(t *testing.T) {
	st := DetectOffload(OffloadInputs{Requested: "off", PPEEnabled: "0", FastNAT: "1"})
	if st.Effective != "off" {
		t.Errorf("Effective = %q, want off", st.Effective)
	}
	for _, r := range st.Reasons {
		if strings.Contains(r, "requested offload mode") {
			t.Errorf("no mismatch expected when requested==effective, got %q", r)
		}
	}
}

// Nothing observable at all. The verdict must be unknown — never an optimistic on, never a false off
// — and it must say which signals were missing, or "unknown" is just a shrug.
func TestDetectOffload_NoEvidenceIsUnknown(t *testing.T) {
	st := DetectOffload(OffloadInputs{Requested: "hw", FirewallUCI: uciHW})
	if st.Effective != "unknown" {
		t.Fatalf("Effective = %q, want unknown", st.Effective)
	}
	if st.KnobsKnown || st.FlowsKnown || st.NftKnown {
		t.Errorf("nothing runtime was readable, but nft=%v knobs=%v flows=%v", st.NftKnown, st.KnobsKnown, st.FlowsKnown)
	}
	j := reasons(st)
	for _, want := range []string{"no flowtable list", "no fast-path knobs", "no conntrack sample"} {
		if !strings.Contains(j, want) {
			t.Errorf("the missing signal %q is not named: %q", want, j)
		}
	}
	// A mismatch against a state nobody measured is not a finding, and printing one sends an operator
	// chasing a fault that has not been shown to exist.
	if strings.Contains(j, "but the effective state is") {
		t.Errorf("an unmeasured state must not be reported as a mismatch: %q", j)
	}
	if st.Recommendation == "" || !strings.Contains(st.Recommendation, "no offload setting") {
		t.Errorf("an unknown verdict must not carry an actionable recommendation, got %q", st.Recommendation)
	}
}

// The recommendation may never advise a blind flow_offloading_hw flip, because WayHop steers tunnel
// carve-outs by firewall mark: a flowtable that does not exclude marked connections offloads a
// carve-out straight past the tunnel. When the marked plane is actually installed, it must say so.
func TestDetectOffload_RecommendationRespectsTheMarkedPlane(t *testing.T) {
	base := OffloadInputs{Requested: "hw", FirewallUCI: uciOff, Flowtables: ftNo, FlowtablesKnown: true}

	without := DetectOffload(base)
	if !strings.Contains(without.Recommendation, "EXCLUDE") {
		t.Errorf("the carve-out exclusion must always be stated, got %q", without.Recommendation)
	}

	base.MarkedPlane = true
	with := DetectOffload(base)
	if !with.MarkedPlane {
		t.Error("the marked plane was not recorded")
	}
	if !strings.Contains(with.Recommendation, "installed on this router right now") {
		t.Errorf("a live marked plane must be called out, got %q", with.Recommendation)
	}
	if !strings.Contains(with.Recommendation, "Do not enable flow_offloading_hw") {
		t.Errorf("with the plane live the advice must be explicit, got %q", with.Recommendation)
	}
}

// hw set without sw installs no flowtable at all — the device intent is off, and the reason has to
// explain the trap rather than report "hw".
func TestDetectOffload_HardwareWithoutSoftwareIsConfiguredOff(t *testing.T) {
	st := DetectOffload(OffloadInputs{
		FirewallUCI: "config defaults\n\toption flow_offloading_hw '1'\n", Flowtables: ftNo, FlowtablesKnown: true,
	})
	if st.Configured != "off" {
		t.Fatalf("Configured = %q, want off", st.Configured)
	}
	if !strings.Contains(reasons(st), "flow_offloading_hw is set but flow_offloading is not") {
		t.Errorf("the misconfiguration must be explained, got %q", reasons(st))
	}
}

func TestParseOffloadConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    string
		wantSW bool
		wantHW bool
	}{
		{"both off", uciOff, false, false},
		{"sw only", uciSW, true, false},
		{"both on", uciHW, true, true},
		{"unquoted truthy", "config defaults\n\toption flow_offloading 1\n\toption flow_offloading_hw true\n", true, true},
		{"hw without sw (misconfig)", "config defaults\n\toption flow_offloading_hw '1'\n", false, true},
		{"absent", "config defaults\n\toption input 'ACCEPT'\n", false, false},
		{"empty", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sw, hw := parseOffloadConfig(c.cfg)
			if sw != c.wantSW || hw != c.wantHW {
				t.Fatalf("parseOffloadConfig() = sw %v hw %v, want sw %v hw %v", sw, hw, c.wantSW, c.wantHW)
			}
		})
	}
}
