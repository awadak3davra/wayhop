package platform

import (
	"strings"
	"testing"
	"time"
)

func keeneticCapsFull() Capabilities {
	return Capabilities{
		Platform:        "keenetic",
		Native:          map[string]bool{"amneziawg": true, "wireguard": true, "pptp": true},
		Installable:     map[string]string{},
		SingboxRequired: []string{"vless", "vmess", "trojan"},
		SingboxPresent:  true,
		Accel:           Accel{Kind: "ppe", HW: true},
	}
}

func openwrtCapsFull(hw bool) Capabilities {
	return Capabilities{
		Platform:        "openwrt",
		Native:          map[string]bool{"wireguard": true},
		Installable:     map[string]string{"amneziawg": "kmod-amneziawg"},
		SingboxRequired: []string{"vless", "vmess"},
		SingboxPresent:  true,
		PackageManager:  "apk",
		Accel:           Accel{Kind: "nft-flowtable", HW: hw},
	}
}

func readyRuntime() RuntimeFacts {
	return RuntimeFacts{
		KernelPBRWired: true, SingboxRunnable: true, SingboxVersion: "1.12.0",
		NativeDNSRead: true, NativeDNSWrite: false, IPv6Routable: true,
		ProbedAt: time.Unix(1700000000, 0),
	}
}

// The case that forces the three-question split. Keenetic firmware can route, but the plane needs
// ipset and iptables and this router has neither, so WayHop cannot install the rules. Host yes,
// WayHop no. A single boolean would report it usable and be wrong in the most damaging direction.
//
// The reason used to be BACKEND_NOT_WIRED — WayHop had no Keenetic policy-rule executor at all.
// That executor exists now, so an unusable verdict has to name what is actually missing; saying the
// backend is unwired would send an operator looking for a WayHop release instead of a package.
func TestEvaluate_KeeneticKernelPBRIsHostYesWayHopNoWithoutTools(t *testing.T) {
	set := Evaluate(keeneticCapsFull(), RuntimeFacts{SingboxRunnable: true, ProbedAt: time.Unix(1, 0)})

	c := set.Get(CapPBRKernel)
	if c.HostSupport != VerdictYes {
		t.Errorf("HostSupport = %q, want yes: the firmware itself can route", c.HostSupport)
	}
	if c.WayHopSupport != VerdictNo {
		t.Errorf("WayHopSupport = %q, want no: ipset/iptables are absent", c.WayHopSupport)
	}
	if c.Reason != ReasonMissingBinary {
		t.Errorf("reason = %q, want %q", c.Reason, ReasonMissingBinary)
	}
	if c.State.Usable() {
		t.Fatal("kernel PBR must not be usable without the tools that install it")
	}
}

// The same router once its tools are present: the plane is genuinely available, and reporting
// otherwise is what kept every Keenetic Apply blocked while the executor was already able to run.
func TestEvaluate_KeeneticKernelPBRIsUsableOnceItsToolsArePresent(t *testing.T) {
	set := Evaluate(keeneticCapsFull(), RuntimeFacts{
		SingboxRunnable: true, KernelPBRWired: true, ProbedAt: time.Unix(1, 0),
	})

	c := set.Get(CapPBRKernel)
	if c.HostSupport != VerdictYes || c.WayHopSupport != VerdictYes || !c.State.Usable() {
		t.Fatalf("kernel PBR on a tooled Keenetic = %+v, want usable", c)
	}
}

// fast and hybrid fail differently and the difference is the whole point: hybrid still carries
// traffic on its TUN, fast carries nothing at all.
func TestEvaluate_FastAndHybridDifferWithoutKernelPlane(t *testing.T) {
	set := Evaluate(keeneticCapsFull(), RuntimeFacts{SingboxRunnable: true, ProbedAt: time.Unix(1, 0)})

	for _, id := range []string{CapRoutingModeFast, CapRoutingModeHybrid} {
		if set.Usable(id) {
			t.Errorf("%s must not be usable without a kernel plane", id)
		}
	}
	fast := set.Get(CapRoutingModeFast)
	if !contains(fast.Detail, "no traffic would be routed") {
		t.Errorf("fast must state that NOTHING is routed, got %q", fast.Detail)
	}
	hybrid := set.Get(CapRoutingModeHybrid)
	if !contains(hybrid.Detail, "behaves like \"tun\"") {
		t.Errorf("hybrid must state that traffic is still carried, got %q", hybrid.Detail)
	}
	// tun and mixed never needed the plane.
	for _, id := range []string{CapRoutingModeTun, CapRoutingModeMixed} {
		if !set.Usable(id) {
			t.Errorf("%s must remain usable on Keenetic", id)
		}
	}
	if tun := set.Get(CapRoutingModeTun); !contains(tun.Detail, "sing-box compatibility") {
		t.Errorf("Keenetic tun detail must identify the optional compatibility path, got %q", tun.Detail)
	}
	if mixed := set.Get(CapRoutingModeMixed); !contains(mixed.Detail, "native mode") {
		t.Errorf("Keenetic mixed detail must identify the native 0.5.5 path, got %q", mixed.Detail)
	}
}

func TestEvaluate_KernelPBRProbeFailureDoesNotPoisonSafeModes(t *testing.T) {
	set := Evaluate(openwrtCapsFull(true), RuntimeFacts{
		KernelPBRProbeError: "private probe failure",
		SingboxRunnable:     true,
		ProbedAt:            time.Unix(1, 0),
	})
	for _, id := range []string{CapRoutingModeTun, CapRoutingModeMixed} {
		if got := set.Get(id); !got.State.Usable() {
			t.Errorf("%s = %+v, want supported: it does not use the failed kernel plane", id, got)
		}
	}
	for _, id := range []string{CapPBRKernel, CapRoutingModeHybrid, CapRoutingModeFast} {
		if got := set.Get(id); got.State != CapUnknown || got.Reason != ReasonProbeFailed {
			t.Errorf("%s = %+v, want probe-failed unknown", id, got)
		}
	}
}

func TestEvaluate_KeeneticWithoutCompatibilityAddonIsMixedOnly(t *testing.T) {
	caps := keeneticCapsFull()
	caps.SingboxPresent = false
	set := Evaluate(caps, RuntimeFacts{ProbedAt: time.Unix(1, 0)})

	if !set.Usable(CapRoutingModeMixed) {
		t.Fatalf("native Mixed must stay usable without sing-box: %+v", set.Get(CapRoutingModeMixed))
	}
	for _, id := range []string{CapRoutingModeTun, CapRoutingModeHybrid, CapRoutingModeFast} {
		if set.Usable(id) {
			t.Errorf("%s must not be selectable on Keenetic without the compatibility add-on/policy plane", id)
		}
	}
	if tun := set.Get(CapRoutingModeTun); tun.Reason != ReasonMissingBinary || tun.Blocks != BlocksApply {
		t.Errorf("TUN = %+v, want missing-addon Apply blocker", tun)
	}
}

// Firmware PPE is not WayHop's nftables flow offload. Offering sw/hw would imply a control WayHop
// does not have — but it must only block the OPTIMISATION, never the whole Apply.
func TestEvaluate_PPEOffloadIsNotWayHopDrivable(t *testing.T) {
	set := Evaluate(keeneticCapsFull(), readyRuntime())

	for _, id := range []string{CapOffloadSW, CapOffloadHW} {
		c := set.Get(id)
		if c.State.Usable() {
			t.Errorf("%s must not be usable on a PPE box", id)
		}
		if c.WayHopSupport != VerdictNo || c.Reason != ReasonBackendNotWired {
			t.Errorf("%s: want wayhop=no/BACKEND_NOT_WIRED, got %q/%q", id, c.WayHopSupport, c.Reason)
		}
		if c.Blocks != BlocksOptimisation {
			t.Errorf("%s blocks %q; a missing accelerator must not block Apply", id, c.Blocks)
		}
	}
}

// A healthy OpenWrt should light up the routing modes and matchers.
func TestEvaluate_OpenWrtWithPlaneSupportsEverything(t *testing.T) {
	set := Evaluate(openwrtCapsFull(true), readyRuntime())

	for _, id := range []string{
		CapPBRKernel, CapRoutingModeFast, CapRoutingModeHybrid, CapRoutingModeTun,
		CapMatcherSourceMAC, CapMatcherSourceIface, CapDeviceScope,
		CapOffloadSW, CapOffloadHW, CapMatcherDomain,
	} {
		if !set.Usable(id) {
			t.Errorf("%s should be usable: %+v", id, set.Get(id))
		}
	}
}

// Hardware offload on a software-only flowtable is a host limit, not something to install.
func TestEvaluate_HardwareOffloadWithoutHWPath(t *testing.T) {
	set := Evaluate(openwrtCapsFull(false), readyRuntime())

	if !set.Usable(CapOffloadSW) {
		t.Error("software offload should still be usable")
	}
	hw := set.Get(CapOffloadHW)
	if hw.State != CapUnsupportedPlatform {
		t.Errorf("hw offload state = %q, want %q", hw.State, CapUnsupportedPlatform)
	}
	if hw.Blocks != BlocksOptimisation {
		t.Errorf("hw offload must block only the optimisation, got %q", hw.Blocks)
	}
}

// A binary found somewhere is not proof the CONFIGURED core runs. Present-but-not-runnable must
// land in unknown, which fails closed, rather than being taken as supported.
func TestEvaluate_SingboxPresentButNotRunnableIsUnknown(t *testing.T) {
	caps := openwrtCapsFull(true)
	rt := readyRuntime()
	rt.SingboxRunnable = false

	set := Evaluate(caps, rt)
	c := set.Get(CapEngineSingbox)
	if c.State.Usable() {
		t.Fatal("a core that could not be run must not be reported usable")
	}
	if c.Reason != ReasonBinaryNotRunnable {
		t.Errorf("reason = %q, want %q", c.Reason, ReasonBinaryNotRunnable)
	}
	// Everything that needs the core must fall with it.
	for _, id := range []string{CapProtocolPrefix + "vless", CapDNSProxyPlane, CapMatcherDomain, CapDNSFakeIP} {
		if set.Usable(id) {
			t.Errorf("%s must not be usable while the core is not runnable", id)
		}
	}
}

// Missing core entirely is an install problem, and the remedy must use the host's real package
// manager — opkg wording on an apk box is a wrong instruction.
func TestEvaluate_InstallRemedyUsesDetectedPackageManager(t *testing.T) {
	caps := openwrtCapsFull(true)
	rt := readyRuntime()
	set := Evaluate(caps, rt)

	c := set.Get(CapProtocolPrefix + "amneziawg")
	if c.State != CapAvailableAfterInstall {
		t.Fatalf("state = %q, want %q", c.State, CapAvailableAfterInstall)
	}
	if !contains(c.Remedy, "apk add") {
		t.Errorf("remedy must use apk on this host, got %q", c.Remedy)
	}
	// And opkg wording where opkg is what exists.
	caps.PackageManager = "opkg"
	if r := Evaluate(caps, rt).Get(CapProtocolPrefix + "amneziawg").Remedy; !contains(r, "opkg") {
		t.Errorf("remedy must use opkg on an opkg host, got %q", r)
	}
}

// Native DNS read and write are separate. Exposing write-back because discovery works would put a
// control on screen that edits the router's DNS with nothing behind it.
func TestEvaluate_NativeDNSReadAndWriteAreIndependent(t *testing.T) {
	rt := readyRuntime() // read=true, write=false
	set := Evaluate(openwrtCapsFull(true), rt)

	if !set.Usable(CapDNSNativeRead) {
		t.Error("native DNS read should be usable")
	}
	w := set.Get(CapDNSNativeWrite)
	if w.State.Usable() {
		t.Fatal("write-back must not be usable when only reading is implemented")
	}
	if w.Blocks != BlocksApply {
		t.Errorf("an unimplemented write-back must block apply, got %q", w.Blocks)
	}
}

// A failed probe must poison every otherwise-supported entry. Unknown never means supported.
func TestEvaluate_ProbeFailurePoisonsSupportedEntries(t *testing.T) {
	rt := readyRuntime()
	rt.ProbeError = "ndmc timed out"
	set := Evaluate(openwrtCapsFull(true), rt)

	for id, c := range set.Items {
		if c.State == CapSupported {
			t.Errorf("%s still reports supported after a probe failure", id)
		}
	}
	if !set.Usable(CapRoutingModeTun) == false {
		t.Error("sanity: nothing should be usable")
	}
	if set.ProbeError == "" {
		t.Error("the probe error must be carried on the set")
	}
}

// An id this build does not evaluate must fail closed, not read as a usable zero value.
func TestCapabilitySet_UnknownIDFailsClosed(t *testing.T) {
	set := Evaluate(openwrtCapsFull(true), readyRuntime())

	c := set.Get("routing.mode.teleport")
	if c.State != CapUnknown || c.State.Usable() {
		t.Fatalf("unknown id must be unknown and unusable, got %+v", c)
	}
	// It must never AUTHORISE anything - that is the fail-closed property. It must not, however,
	// refuse every unrelated Apply: a client asking about an id this build does not evaluate would
	// otherwise brick Apply entirely. Feature-level refusal is the correct scope.
	if c.Blocks == BlocksNothing {
		t.Errorf("an unevaluated capability must not be harmless, got %q", c.Blocks)
	}
	if c.Blocks == BlocksApply {
		t.Errorf("an unevaluated capability must not refuse unrelated applies, got %q", c.Blocks)
	}
}

// The revision must be stable for an identical router and must move when a verdict changes —
// otherwise the apply gate either invalidates every review or misses a real change.
func TestEvaluate_RevisionIsStableAndSensitive(t *testing.T) {
	a := Evaluate(openwrtCapsFull(true), readyRuntime())
	b := Evaluate(openwrtCapsFull(true), readyRuntime())
	if a.Rev != b.Rev {
		t.Fatalf("identical input produced different revisions: %s vs %s", a.Rev, b.Rev)
	}

	// A later probe of the same router must NOT churn the revision.
	rt := readyRuntime()
	rt.ProbedAt = rt.ProbedAt.Add(90 * time.Second)
	if c := Evaluate(openwrtCapsFull(true), rt); c.Rev != a.Rev {
		t.Errorf("a re-probe of an unchanged router changed the revision (%s -> %s)", a.Rev, c.Rev)
	}

	// A real capability change must move it.
	degraded := readyRuntime()
	degraded.KernelPBRWired = false
	if d := Evaluate(openwrtCapsFull(true), degraded); d.Rev == a.Rev {
		t.Error("losing the kernel plane did not change the revision")
	}
}

// Every entry must carry all three verdicts and a Blocks value; a half-filled record would let the
// gate read a zero value as a decision.
func TestEvaluate_EntriesAreWellFormed(t *testing.T) {
	for _, set := range []CapabilitySet{
		Evaluate(openwrtCapsFull(true), readyRuntime()),
		Evaluate(keeneticCapsFull(), readyRuntime()),
	} {
		for id, c := range set.Items {
			if c.ID != id {
				t.Errorf("%s: ID field is %q", id, c.ID)
			}
			for name, v := range map[string]Verdict{
				"host": c.HostSupport, "wayhop": c.WayHopSupport, "runtime": c.RuntimeState,
			} {
				if v != VerdictYes && v != VerdictNo && v != VerdictUnknown {
					t.Errorf("%s: %s verdict is %q", id, name, v)
				}
			}
			if c.Blocks == "" {
				t.Errorf("%s: Blocks is empty", id)
			}
			if !c.State.Usable() && c.Detail == "" && c.Reason == ReasonNone {
				t.Errorf("%s: unusable with neither reason nor detail", id)
			}
		}
	}
}

func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// An fw3-era OpenWrt (19.07/21.02: iptables, no nft) lands in the default branch. The remedy is
// worth being exact about, because it is genuinely sufficient: measured in containers, `opkg
// install nftables` succeeds from both EOL feeds and the nft it brings loads WayHop's rendered
// ruleset unchanged. An operator told only "install nftables support" has to go and find out how.
func TestEvaluate_Fw3EraOpenWrtIsToldTheExactInstallCommand(t *testing.T) {
	caps := openwrtCapsFull(false)
	caps.PackageManager = "opkg" // 19.07/21.02 predate apk
	rt := readyRuntime()
	rt.KernelPBRWired = false

	c := Evaluate(caps, rt).Get(CapPBRKernel)
	if c.State.Usable() {
		t.Fatal("kernel PBR must not be usable without nft")
	}
	if !strings.Contains(c.Remedy, "opkg install nftables") {
		t.Errorf("the remedy does not name the command that fixes it: %q", c.Remedy)
	}
}

// The same host with no detected package manager must fall back to the generic sentence rather
// than printing an empty command in backticks, which reads like a bug and tells nobody anything.
func TestEvaluate_UnknownPackageManagerGetsNoEmptyCommand(t *testing.T) {
	caps := openwrtCapsFull(false)
	caps.PackageManager = ""
	rt := readyRuntime()
	rt.KernelPBRWired = false

	c := Evaluate(caps, rt).Get(CapPBRKernel)
	if strings.Contains(c.Remedy, "``") || strings.Contains(c.Remedy, "()") {
		t.Errorf("an empty install command leaked into the remedy: %q", c.Remedy)
	}
	if !strings.Contains(c.Remedy, "Install nftables support") {
		t.Errorf("the generic remedy was lost: %q", c.Remedy)
	}
}

// A host whose platform could not be identified must never be reported as able to run the kernel
// plane. The branch that says so had no test: with it disabled an unknown host falls through to the
// "nft present and the plane loads" case and is declared fully capable, which is the one answer that
// cannot be justified — we do not know what it is.
func TestEvaluate_AnUnidentifiedPlatformIsNotCalledCapable(t *testing.T) {
	caps := openwrtCapsFull(false)
	caps.Platform = "unknown"

	c := Evaluate(caps, readyRuntime()).Get(CapPBRKernel)
	if c.State.Usable() {
		t.Fatal("a host of unknown platform was reported able to run kernel policy routing")
	}
	if c.Reason != ReasonProbeFailed {
		t.Errorf("reason = %q, want %q: the problem is that we could not tell, not that something is missing",
			c.Reason, ReasonProbeFailed)
	}
	if c.Blocks != BlocksApply {
		t.Errorf("blocks = %q, want %q", c.Blocks, BlocksApply)
	}
	// And the modes that need the plane must follow it down, or the refusal is decorative.
	set := Evaluate(caps, readyRuntime())
	for _, id := range []string{CapRoutingModeHybrid, CapRoutingModeFast} {
		if set.Usable(id) {
			t.Errorf("%s was offered on a host whose platform is unknown", id)
		}
	}
}
