package platform

import "testing"

// Auto must pick the best option the hardware genuinely supports, and must never pick upward.
func TestResolveOffload_Auto(t *testing.T) {
	cases := []struct {
		name       string
		caps       Capabilities
		wantMode   string
		wantReason bool // Auto must always explain itself
	}{
		{"flowtable with hardware path", Capabilities{Accel: Accel{Kind: "nft-flowtable", HW: true}}, "hw", true},
		{"flowtable, software only", Capabilities{Accel: Accel{Kind: "nft-flowtable"}}, "sw", true},
		{"firmware PPE (Keenetic)", Capabilities{Accel: Accel{Kind: "ppe", HW: true}}, "off", true},
		{"no accelerator", Capabilities{}, "off", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := ResolveOffload("auto", tc.caps)
			if got != tc.wantMode {
				t.Errorf("auto resolved to %q, want %q", got, tc.wantMode)
			}
			if tc.wantReason && reason == "" {
				t.Error("auto must explain what it chose and why; an unexplained downgrade is " +
					"indistinguishable from a silent failure")
			}
		})
	}
}

// A PPE box advertises hardware acceleration, but it is the FIRMWARE's and WayHop cannot drive it.
// Auto must not be fooled by Accel.HW being true.
func TestResolveOffload_AutoNotFooledByFirmwareHW(t *testing.T) {
	got, reason := ResolveOffload("auto", Capabilities{Accel: Accel{Kind: "ppe", HW: true}})
	if got != "off" {
		t.Fatalf("auto on a PPE box resolved to %q, want off: WayHop's nftables flow-offload does "+
			"not exist on that datapath", got)
	}
	if reason == "" {
		t.Error("the user must be told why offload is off on a box that advertises hardware NAT")
	}
}

// Explicit modes are passed through untouched — resolution does not second-guess an operator.
// Preflight is what reports a request this router cannot satisfy.
func TestResolveOffload_ExplicitModesArePassedThrough(t *testing.T) {
	caps := Capabilities{Accel: Accel{Kind: "ppe"}}
	for _, m := range []string{"sw", "hw"} {
		if got, _ := ResolveOffload(m, caps); got != m {
			t.Errorf("explicit %q resolved to %q; resolution must not override an explicit choice", m, got)
		}
	}
}

// Off and unset both mean off, with nothing to explain.
func TestResolveOffload_OffIsOff(t *testing.T) {
	for _, m := range []string{"", "off"} {
		got, reason := ResolveOffload(m, Capabilities{Accel: Accel{Kind: "nft-flowtable", HW: true}})
		if got != "off" {
			t.Errorf("%q resolved to %q, want off", m, got)
		}
		if reason != "" {
			t.Errorf("%q needs no explanation, got %q", m, reason)
		}
	}
}

// Anything unrecognised must fail closed rather than being treated as a request to accelerate.
func TestResolveOffload_UnknownFailsClosed(t *testing.T) {
	got, reason := ResolveOffload("turbo", Capabilities{Accel: Accel{Kind: "nft-flowtable", HW: true}})
	if got != "off" {
		t.Errorf("unknown mode resolved to %q, want off", got)
	}
	if reason == "" {
		t.Error("an unknown mode being ignored must be explained, not silent")
	}
}

// The resolver must be deterministic: preview, apply and reconcile all call it, and a resolver that
// disagreed with itself between them would reintroduce exactly the drift this design removes.
func TestResolveOffload_IsDeterministic(t *testing.T) {
	caps := Capabilities{Accel: Accel{Kind: "nft-flowtable", HW: true}}
	first, firstReason := ResolveOffload("auto", caps)
	for i := 0; i < 50; i++ {
		got, reason := ResolveOffload("auto", caps)
		if got != first || reason != firstReason {
			t.Fatalf("resolution changed between calls: %q/%q then %q/%q", first, firstReason, got, reason)
		}
	}
}
