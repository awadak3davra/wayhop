package platform

import (
	"fmt"
	"strings"
)

// install.go plans the installation of a package that would make a protocol native — the second tier
// of the native-first rule: use what the firmware already carries; install what the feeds can supply;
// fall back to sing-box only for protocols no kernel path exists for.
//
// It plans and refuses. Running the commands is the caller's job, deliberately, so the checks below
// cannot be skipped by a code path that just wants to get on with it.
//
// Every refusal here comes from something measured on a real router rather than imagined:
//
//   - The AX3000T's overlay is 60.6 MB and 89% full: 6.1 MB free. Package installs land there. A
//     failed install that fills it does not merely fail — it leaves a router that cannot write its
//     own config.
//   - Its kmod feed is pinned to the exact kernel build,
//     `.../kmods/6.12.74-1-60d938adcb727697d3015e4285d4c290/`. A kernel module compiled for another
//     build will not load, so a kmod whose feed does not match the running kernel is not installable
//     however successfully apk downloads it.
//   - `opkg` does not exist on OpenWrt 25.12 and `apk` does not exist before 24.10, while /etc/opkg
//     survives on apk systems — so the manager has to come from the detected binary, never from the
//     release number or a directory's presence.

// SpaceUnknownPolicy decides what an unreadable free-space figure means.
//
// updater.enoughSpaceFor treats unknown as permission to proceed, which is right for swapping a
// binary it can roll back. It is wrong here: a package install has no backup to restore, and the
// failure mode is a full overlay. Unknown therefore blocks, and the caller is told why rather than
// left with a mysterious refusal.
type SpaceUnknownPolicy int

const (
	// BlockOnUnknownSpace refuses when free space could not be read. The default, and the safe one.
	BlockOnUnknownSpace SpaceUnknownPolicy = iota
	// AllowOnUnknownSpace proceeds anyway. For callers that have their own guarantee.
	AllowOnUnknownSpace
)

// InstallPlan is a proposed package installation, ready to show and not yet run.
type InstallPlan struct {
	Proto    string   // the protocol this would make native
	Package  string   // the package to install
	Manager  string   // "apk" | "opkg"
	Commands []string // refresh the index, then install
	// Verify is what must become true afterwards. The install command exiting 0 says the package
	// manager was satisfied; it does not say the protocol became usable, and those are the two
	// different claims this field keeps apart.
	Verify string
	// Warnings do not stop the plan.
	Warnings []string
}

// InstallInput is what a plan needs to know about the host. Passed in rather than probed so this
// stays pure and so the caller cannot forget to gather one of them.
type InstallInput struct {
	FreeBytes   uint64 // free space where packages land (the overlay on OpenWrt)
	SpaceKnown  bool   // false when statfs failed
	NeedBytes   uint64 // expected install size; 0 when unknown
	KernelVer   string // `uname -r`
	KmodFeedVer string // the kernel version the kmod feed is built for; "" when there is no kmod feed
	Policy      SpaceUnknownPolicy
}

// headroomBytes is kept free on top of the install itself. An overlay filled to the last byte is a
// router that cannot save a config change, which is a worse outcome than not installing.
const headroomBytes = 2 << 20 // 2 MiB

// BuildInstallPlan returns the plan that would make proto native on this host, or an error saying
// why it cannot.
func BuildInstallPlan(caps Capabilities, proto string, in InstallInput) (InstallPlan, error) {
	if caps.Native[proto] {
		return InstallPlan{}, fmt.Errorf("install %s: already native on this router; installing would "+
			"change nothing", proto)
	}
	pkg := caps.Installable[proto]
	if pkg == "" {
		return InstallPlan{}, fmt.Errorf("install %s: no package is known to provide it on this "+
			"platform — it stays on sing-box", proto)
	}
	if strings.Contains(pkg, " ") {
		// Keenetic firmware components arrive here as prose, not package names.
		return InstallPlan{}, fmt.Errorf("install %s: %q is not a package this router installs, it is "+
			"a firmware component enabled in the device's own UI", proto, pkg)
	}
	if caps.PackageManager == "" {
		return InstallPlan{}, fmt.Errorf("install %s: no package manager was detected, so nothing here "+
			"can install %s (looked for apk and opkg as BINARIES — /etc/opkg exists on apk systems and "+
			"proves nothing)", proto, pkg)
	}
	cmd := installCmd(caps.PackageManager, pkg)
	if cmd == "" {
		return InstallPlan{}, fmt.Errorf("install %s: package manager %q is not one this can drive",
			proto, caps.PackageManager)
	}

	p := InstallPlan{
		Proto:   proto,
		Package: pkg,
		Manager: caps.PackageManager,
		Verify:  fmt.Sprintf("capabilities report %s as native", proto),
	}

	// A kernel module has to match the running kernel exactly. The feed is pinned to a build, so a
	// mismatch is knowable before anything is downloaded.
	if strings.HasPrefix(pkg, "kmod-") {
		if in.KmodFeedVer == "" {
			return p, fmt.Errorf("install %s: %s is a kernel module and this router has no kmod feed "+
				"configured, so there is nothing to install it from", proto, pkg)
		}
		if in.KernelVer != "" && !strings.HasPrefix(in.KmodFeedVer, in.KernelVer) {
			return p, fmt.Errorf("install %s: %s is built for kernel %s but this router runs %s — the "+
				"module would download and refuse to load", proto, pkg, in.KmodFeedVer, in.KernelVer)
		}
	}

	// Space. Refusing here is the whole reason this function exists rather than a string of commands.
	if !in.SpaceKnown {
		if in.Policy == BlockOnUnknownSpace {
			return p, fmt.Errorf("install %s: free space could not be read, and installing into an "+
				"overlay that turns out to be full leaves a router that cannot save its own config",
				proto)
		}
		p.Warnings = append(p.Warnings, "free space is unknown; proceeding because the caller asked to")
	} else {
		need := in.NeedBytes + headroomBytes
		if in.FreeBytes < need {
			return p, fmt.Errorf("install %s: %s needs about %s and %s of headroom, but only %s is "+
				"free — install something smaller or clear space first",
				proto, pkg, mib(in.NeedBytes), mib(headroomBytes), mib(in.FreeBytes))
		}
		if in.FreeBytes < need*2 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"only %s free after this install; the overlay is nearly full", mib(in.FreeBytes-need)))
		}
	}

	// The index refresh is part of the plan, not an assumption. A package "not found" against a stale
	// index reads as "not available on this platform", which is how an earlier survey of this router
	// concluded — wrongly — that nothing could be installed at all.
	p.Commands = []string{refreshCmd(caps.PackageManager), cmd}
	return p, nil
}

// refreshCmd updates the package index for the given manager.
func refreshCmd(manager string) string {
	switch manager {
	case "apk":
		return "apk update"
	case "opkg":
		return "opkg update"
	}
	return ""
}

// InstallSucceeded reports whether the protocol actually became native, given capabilities detected
// AFTER the install ran.
//
// This is the point of the exercise. `apk add` exiting 0 means the package manager is happy; it does
// not mean the kernel module loaded, the netifd protocol handler appeared, or the CLI is on PATH.
// Only a fresh detection can say that, and only that is worth reporting to the operator.
func InstallSucceeded(after Capabilities, proto string) bool {
	return after.Native[proto]
}

func mib(b uint64) string {
	if b == 0 {
		return "an unknown amount"
	}
	return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
}
