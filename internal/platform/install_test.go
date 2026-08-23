package platform

import (
	"strings"
	"testing"
)

// The AX3000T as measured: apk, kernel 6.12.74, kmod feed pinned to that build, and an overlay with
// 6.1 MiB free of 60.6 — the number that makes the space check load-bearing rather than decorative.
func liveHost() InstallInput {
	return InstallInput{
		FreeBytes:   6_100_000,
		SpaceKnown:  true,
		NeedBytes:   300_000,
		KernelVer:   "6.12.74",
		KmodFeedVer: "6.12.74-1-60d938adcb727697d3015e4285d4c290",
	}
}

func capsWith(manager string, native map[string]bool, installable map[string]string) Capabilities {
	return Capabilities{
		Platform:       "openwrt",
		Native:         native,
		Installable:    installable,
		PackageManager: manager,
	}
}

func TestBuildInstallPlan_UsesTheDetectedManager(t *testing.T) {
	for _, tc := range []struct{ manager, wantRefresh, wantInstall string }{
		{"apk", "apk update", "apk add kmod-wireguard"},
		{"opkg", "opkg update", "opkg install kmod-wireguard"},
	} {
		caps := capsWith(tc.manager, map[string]bool{}, map[string]string{"wireguard": "kmod-wireguard"})
		p, err := BuildInstallPlan(caps, "wireguard", liveHost())
		if err != nil {
			t.Fatalf("%s: %v", tc.manager, err)
		}
		joined := strings.Join(p.Commands, " | ")
		if !strings.Contains(joined, tc.wantRefresh) || !strings.Contains(joined, tc.wantInstall) {
			t.Errorf("%s produced %q", tc.manager, joined)
		}
	}
}

// The index refresh must be IN the plan. Querying a stale index is how an earlier survey of this very
// router concluded that nothing was installable, when in fact 11179 packages were available.
func TestBuildInstallPlan_RefreshesTheIndexFirst(t *testing.T) {
	caps := capsWith("apk", map[string]bool{}, map[string]string{"wireguard": "kmod-wireguard"})
	p, _ := BuildInstallPlan(caps, "wireguard", liveHost())
	if len(p.Commands) < 2 || !strings.Contains(p.Commands[0], "update") {
		t.Fatalf("the index refresh is missing or not first: %v", p.Commands)
	}
}

// The refusal that protects the router. 6.1 MiB free and a package that wants more must not proceed:
// filling the overlay leaves a device that cannot save its own configuration.
func TestBuildInstallPlan_RefusesWhenTheOverlayWouldFill(t *testing.T) {
	caps := capsWith("apk", map[string]bool{}, map[string]string{"openvpn": "openvpn-openssl"})
	in := liveHost()
	in.NeedBytes = 5_000_000 // plus 2 MiB headroom is more than the 6.1 MiB free

	_, err := BuildInstallPlan(caps, "openvpn", in)
	if err == nil {
		t.Fatal("an install that would fill the overlay was accepted")
	}
	if !strings.Contains(err.Error(), "free") {
		t.Errorf("the error should say how much room there is: %v", err)
	}
}

// Unknown free space blocks by default — the opposite of updater.enoughSpaceFor, on purpose: that
// path can roll back a binary, this one cannot un-fill a partition.
func TestBuildInstallPlan_UnknownSpaceBlocksByDefault(t *testing.T) {
	caps := capsWith("apk", map[string]bool{}, map[string]string{"wireguard": "kmod-wireguard"})
	in := liveHost()
	in.SpaceKnown = false

	if _, err := BuildInstallPlan(caps, "wireguard", in); err == nil {
		t.Fatal("unknown free space was treated as permission to proceed")
	}
	in.Policy = AllowOnUnknownSpace
	p, err := BuildInstallPlan(caps, "wireguard", in)
	if err != nil {
		t.Fatalf("the explicit override was refused: %v", err)
	}
	if len(p.Warnings) == 0 {
		t.Error("proceeding on unknown space should say so out loud")
	}
}

// A kernel module built for another kernel downloads happily and then refuses to load. The feed is
// pinned to a build, so this is knowable before anything is fetched.
func TestBuildInstallPlan_RefusesAKmodForAnotherKernel(t *testing.T) {
	caps := capsWith("apk", map[string]bool{}, map[string]string{"amneziawg": "kmod-amneziawg"})
	in := liveHost()
	in.KmodFeedVer = "6.6.100-1-abcdef" // router still runs 6.12.74

	_, err := BuildInstallPlan(caps, "amneziawg", in)
	if err == nil {
		t.Fatal("a kmod built for a different kernel was accepted")
	}
	if !strings.Contains(err.Error(), "6.12.74") || !strings.Contains(err.Error(), "6.6.100") {
		t.Errorf("the error should name both kernels: %v", err)
	}

	// A non-kmod package is unaffected by the feed mismatch.
	caps2 := capsWith("apk", map[string]bool{}, map[string]string{"openvpn": "openvpn-openssl"})
	if _, err := BuildInstallPlan(caps2, "openvpn", in); err != nil {
		t.Errorf("a userspace package was blocked by a kmod feed mismatch: %v", err)
	}
}

// No manager detected is a refusal, never a guess. /etc/opkg exists on this apk-only router, so a
// directory or a release number must never stand in for the binary.
func TestBuildInstallPlan_RefusesWithoutADetectedManager(t *testing.T) {
	caps := capsWith("", map[string]bool{}, map[string]string{"wireguard": "kmod-wireguard"})
	_, err := BuildInstallPlan(caps, "wireguard", liveHost())
	if err == nil {
		t.Fatal("a plan was built with no package manager detected")
	}
	if !strings.Contains(err.Error(), "BINARIES") {
		t.Errorf("the error should say the detection is by binary, not by directory: %v", err)
	}
}

// Installing something already native changes nothing and should say so rather than run apk.
func TestBuildInstallPlan_RefusesWhenAlreadyNative(t *testing.T) {
	caps := capsWith("apk", map[string]bool{"amneziawg": true},
		map[string]string{"amneziawg": "kmod-amneziawg"})
	if _, err := BuildInstallPlan(caps, "amneziawg", liveHost()); err == nil {
		t.Fatal("a plan was built for a protocol that is already native")
	}
}

// A Keenetic firmware-component note is prose, not a package.
func TestBuildInstallPlan_RefusesAFirmwareComponentNote(t *testing.T) {
	caps := capsWith("opkg", map[string]bool{},
		map[string]string{"l2tp": "enable the component in the Keenetic app"})
	_, err := BuildInstallPlan(caps, "l2tp", liveHost())
	if err == nil {
		t.Fatal("a firmware-component note was treated as a package name")
	}
}

// The claim that matters after the install. `apk add` exiting 0 says the package manager is happy;
// only a fresh capability detection says the protocol became usable.
func TestInstallSucceeded_ReadsTheCapabilityNotTheExitCode(t *testing.T) {
	before := capsWith("apk", map[string]bool{"wireguard": false}, nil)
	if InstallSucceeded(before, "wireguard") {
		t.Error("reported success while the capability is still absent")
	}
	after := capsWith("apk", map[string]bool{"wireguard": true}, nil)
	if !InstallSucceeded(after, "wireguard") {
		t.Error("reported failure although the capability appeared")
	}
}
