package platform

import (
	"testing"

	"wayhop/internal/awg"
)

// QA-127. A KeeneticOS release, not the WireGuard component, decides whether NDM has `wireguard asc`
// (4.2) and whether it takes the AmneziaWG 2 settings (5.1). The release strings are invented: only
// their shape is the firmware's.
func keeneticVersionText(release string) string {
	return "      release: " + release + "\n      sandbox: stable\n   components: base, wireguard, opkg, ppe\n"
}

func keeneticWiredOps() RuntimeFacts {
	ops := map[string]bool{}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, op := range []NativeOperation{NativeAdopt, NativeCreate, NativeRemove} {
			ops[NativeOperationCapabilityID(protocol, op)] = true
		}
	}
	return RuntimeFacts{NativeOperations: ops}
}

// The hunt's repro: KeeneticOS 4.1 with the WireGuard component was reported as carrying AmneziaWG,
// so the endpoint stayed on NDM and the router refused `wireguard asc` at Apply.
func TestQA127Keenetic41HasNoNativeAmneziaWG(t *testing.T) {
	caps := decideKeenetic(hostInputs{ndmcVersion: keeneticVersionText("4.01.C.7.0-0")})
	if caps.FirmwareRelease != "4.01.C.7.0-0" {
		t.Fatalf("FirmwareRelease = %q, want the release line", caps.FirmwareRelease)
	}
	if caps.Native["amneziawg"] || !caps.Native["wireguard"] {
		t.Fatalf("Native = %+v, want WireGuard only", caps.Native)
	}
	if _, listed := caps.Installable["amneziawg"]; listed {
		t.Fatalf("the WireGuard component is offered for AmneziaWG on a release that has no `wireguard asc`: %+v", caps.Installable)
	}
	set := Evaluate(caps, keeneticWiredOps())
	for _, op := range []NativeOperation{NativeCarry, NativeCreate, NativeManage, NativeUpdate, NativeRemove} {
		c := set.Get(NativeOperationCapabilityID("amneziawg", op))
		// ReasonPlatformUnsupported is what moves the endpoint to WayHop's AmneziaWG engine
		// (nativeplan.keeneticUserspaceReason).
		if c.State.Usable() || c.Reason != ReasonPlatformUnsupported || c.Remedy == "" {
			t.Errorf("amneziawg %s = %s/%s remedy %q, want unsupported for the platform with a remedy", op, c.State, c.Reason, c.Remedy)
		}
	}
	// Adoption writes no `wireguard asc`: a tunnel run outside KeeneticOS stays adoptable.
	if !set.Usable(NativeOperationCapabilityID("amneziawg", NativeAdopt)) {
		t.Errorf("amneziawg adopt is not usable on a release with the WireGuard component: %+v",
			set.Get(NativeOperationCapabilityID("amneziawg", NativeAdopt)))
	}
	if !set.Usable(NativeOperationCapabilityID("wireguard", NativeCreate)) {
		t.Errorf("plain WireGuard create lost on KeeneticOS 4.1")
	}
	// The evaluator holds the line for a value assembled elsewhere, too.
	caps.Native["amneziawg"] = true
	if Evaluate(caps, keeneticWiredOps()).Usable(NativeOperationCapabilityID("amneziawg", NativeCreate)) {
		t.Errorf("Evaluate trusts Native[amneziawg] over a release with no `wireguard asc`")
	}
}

func TestQA127KeeneticReleaseGatesAWGGeneration(t *testing.T) {
	cases := []struct {
		release    string
		native     bool // Native[amneziawg]
		gen2Capped bool // CapNativeAWGGen2 published as unsupported
	}{
		{"3.09.C.4.0-0", false, false},
		{"4.01.C.7.0-0", false, false},
		{"4.1.7", false, false},
		{"4.02.C.3.0-0", true, true},
		{"4.3.5", true, true},
		{"5.00.C.6.0-0", true, true},
		{"5.03.C.0.0-0", true, false},
		{"6.0.1", true, false},
		// Unreadable or absent: the component's answer, as before the release was read.
		{"", true, false},
		{"preview", true, false},
	}
	for _, c := range cases {
		caps := decideKeenetic(hostInputs{ndmcVersion: keeneticVersionText(c.release)})
		if c.release == "" {
			caps = decideKeenetic(hostInputs{ndmcVersion: "components: base, wireguard\n"})
		}
		if caps.Native["amneziawg"] != c.native {
			t.Errorf("%q: Native[amneziawg] = %v, want %v", c.release, caps.Native["amneziawg"], c.native)
		}
		set := Evaluate(caps, keeneticWiredOps())
		if got := set.Usable(NativeOperationCapabilityID("amneziawg", NativeCreate)); got != c.native {
			t.Errorf("%q: amneziawg create usable = %v, want %v", c.release, got, c.native)
		}
		item, published := set.Items[CapNativeAWGGen2]
		if published != c.gen2Capped || (published && (item.Reason != ReasonPlatformUnsupported || item.State.Usable())) {
			t.Errorf("%q: %s = %+v (published %v), want published=%v unsupported", c.release, CapNativeAWGGen2, item, published, c.gen2Capped)
		}
	}
}

func TestQA127KeeneticReleaseAWG(t *testing.T) {
	cases := []struct {
		release string
		gen     awg.Generation
		known   bool
	}{
		{"4.01.C.7.0-0", awg.GenNone, true},
		{"4.02.A.2.0-0", awg.Gen1, true},
		{"5.0.8", awg.Gen1, true},
		{"5.01.A.3.0-0", awg.Gen2, true},
		{"5.2.1", awg.Gen2, true},
		{"", awg.GenNone, false},
		{"5", awg.GenNone, false},
		{"x.1.2", awg.GenNone, false},
	}
	for _, c := range cases {
		if gen, known := KeeneticReleaseAWG(c.release); gen != c.gen || known != c.known {
			t.Errorf("KeeneticReleaseAWG(%q) = %v, %v; want %v, %v", c.release, gen, known, c.gen, c.known)
		}
	}
}

// OpenWrt and the demo are untouched: no release, no generation item.
func TestQA127OpenWrtUnchanged(t *testing.T) {
	set := Evaluate(DemoCapabilities(), keeneticWiredOps())
	if _, published := set.Items[CapNativeAWGGen2]; published {
		t.Fatalf("%s published on OpenWrt", CapNativeAWGGen2)
	}
}
