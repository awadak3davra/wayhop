package server

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/binstore"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/updater"
)

// awgcomponent.go answers, for the AmneziaWG 3 row on the Components page, the three questions the
// row exists for: what the router's own AmneziaWG can do, how each configured AmneziaWG connection is
// run - and therefore whether amneziawg-go is needed here at all - and what the component costs.
//
// Each answer is the one the rest of the daemon acts on, not a second opinion: the native lane comes
// from nativeplan.UserspaceFor with the Apply's kernel capture (what the planner hands to the
// engine), the engine's kernel/userspace choice from plugin.AWGDecision (what the plugin runs), and
// the footprint from the binstore record the updater wrote.

// awgComponentStatus is the AmneziaWG 3 block of the component's row.
type awgComponentStatus struct {
	// Kernel is the generation of the loaded AmneziaWG module: "none", "1", "2", "3.0", "3.1", or
	// "unknown" when the probe could not ask.
	Kernel string `json:"kernel"`
	// FirmwareOwned: the firmware runs its own tunnels on that module (KeeneticOS's NDM), so WayHop's
	// engine never uses it, whatever its generation.
	FirmwareOwned bool   `json:"firmware_owned,omitempty"`
	TUN           bool   `json:"tun"` // /dev/net/tun, which amneziawg-go needs
	ProbeError    string `json:"probe_error,omitempty"`
	// Connections are the enabled AmneziaWG connections this router would run, and how.
	Connections []awgConnectionRun `json:"connections"`
	// Needed: at least one of them runs on amneziawg-go, so the component is not optional here.
	Needed bool `json:"needed"`
	// Builtin is the newest generation the router carries without amneziawg-go: its own tunnels
	// (KeeneticOS's NDM, OpenWrt's UCI interfaces) or, where WayHop's engine may use it, the kernel
	// module - "none", "1", "2", "3.0", "3.1", or "unknown" when the probe could not tell.
	Builtin string `json:"builtin"`
	// Newest is the generation amneziawg-go runs, which a connection set to use it gets.
	Newest string `json:"newest"`
	// Optional: no connection needs amneziawg-go, and yet it would add something here - the router's
	// own AmneziaWG is older than Newest and /dev/net/tun is present. The row offers it and says why,
	// without presenting it as a gap: nothing is broken while every connection runs natively.
	Optional  bool          `json:"optional,omitempty"`
	Footprint *awgFootprint `json:"footprint,omitempty"`
	// FeedModes are the paths WayHop's own installer may take on this router (awgcomponent_install.go):
	// kmod and userspace on OpenWrt, userspace only on Entware - KeeneticOS among them, where no kmod
	// can be built safely for its kernels. Empty where the installer does not apply; the row then
	// offers only the release asset.
	FeedModes []string `json:"feed_modes,omitempty"`
	// Packages are the AmneziaWG packages opkg/apk has installed, with their versions: the source of
	// the kernel path, which the feed installer writes and removes.
	Packages []updater.AWGPackage `json:"packages,omitempty"`
	// Switching says which connections still run on amneziawg-go although this router now carries them
	// another way, and when they move: at their next start for the kernel module, through two Applies
	// for OpenWrt's own AmneziaWG. "" when none do. Running tunnels are never moved to make it true.
	Switching string `json:"switching,omitempty"`
	// NetifdRestart: netifd still runs an older AmneziaWG handler than the one installed, so 3.x options
	// do not reach it until the network service restarts (awgnetifd.go). The row offers that restart.
	NetifdRestart bool `json:"netifd_restart,omitempty"`
}

// awgConnectionRun is how one connection is run.
type awgConnectionRun struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Need string `json:"need"` // the AmneziaWG generation its settings need
	// Path: "native" (the router's own AmneziaWG), "kernel" (WayHop's engine on the kernel module),
	// "userspace" (WayHop's engine on amneziawg-go), or "unavailable".
	Path   string `json:"path"`
	Reason string `json:"reason"`
	// Switch is where a connection running on amneziawg-go now goes: "kernel" at its next start (the
	// plugin's decision for it is the kernel module), "native" through two Applies (OpenWrt's own
	// AmneziaWG carries it now). Empty when it stays where it runs.
	Switch string `json:"switch,omitempty"`
}

// awgFootprint is what the installed component costs.
type awgFootprint struct {
	Form       string `json:"form"`        // "binary" | "compressed" (the gzip kept on a small flash)
	FlashBytes int64  `json:"flash_bytes"` // the stored file
	// RAMBytes is the unpacked copy a compressed store runs from, in tmpfs - which is RAM.
	RAMBytes int64 `json:"ram_bytes,omitempty"`
	Running  int   `json:"running"`             // amneziawg-go processes running now
	RSSBytes int64 `json:"rss_bytes,omitempty"` // their resident memory, where /proc tells
}

// awgComponent builds the block for prof on this router.
func (s *Server) awgComponent(ctx context.Context, prof model.Profile) awgComponentStatus {
	demo := s.config().Demo
	p := s.detectedPlatform()
	probe := s.awgHostProbe()
	firmwareOwned := !demo && p == platform.Keenetic
	out := awgComponentStatus{Kernel: probe.Kernel.String(), FirmwareOwned: firmwareOwned, TUN: probe.TUN,
		ProbeError: probe.Err, Connections: []awgConnectionRun{}, Newest: awg.UserspaceGeneration.String()}
	if probe.Err != "" {
		out.Kernel = "unknown"
	}

	nativePlan := !demo && (p == platform.OpenWrt || p == platform.Keenetic)
	// What OpenWrt's UCI writer may write up to with this module and handler - the Apply's own capture
	// (awgkernel.go), so the row and the planner put each connection in the same lane.
	kernel := s.awgKernelCaptureFor(p, probe).Generation
	var capset platform.CapabilitySet
	lane := map[string]nativeplan.UserspaceEndpoint{}
	if nativePlan {
		capset = s.capabilitySet(ctx, false)
		lane = nativeplan.UserspaceFor(&prof, p, capset, kernel)
	}
	running := s.awgRunningOnUserspace()
	moves := map[string]string{}
	if nativePlan && p == platform.OpenWrt && len(running) > 0 {
		moves = s.openWrtUserspaceMoves(prof, capset, lane)
	}
	out.Builtin = awgBuiltin(probe, firmwareOwned, nativePlan && nativeplan.NativeAWGAvailable(capset), nativeplan.NativeAWGGenerationFor(p, kernel))
	for _, e := range prof.Endpoints {
		if !e.Enabled || e.Engine != model.EngineAmneziaWG || !e.OwnsResource() {
			continue
		}
		run := awgConnectionRun{ID: e.ID, Name: e.Name, Need: awg.Need(e.Params).String()}
		if run.Name == "" {
			run.Name = e.ID
		}
		u, inLane := lane[e.ID]
		switch {
		case nativePlan && !inLane && nativeAWGCreatable(e, capset):
			run.Path, run.Reason = "native", "the router's own AmneziaWG runs it"
			if running[e.ID] && moves[e.ID] != "" {
				run.Switch = "native"
			}
		case p == platform.Keenetic && nativePlan && !inLane:
			// Neither NDM nor the engine takes it: the planner refuses such an endpoint until the
			// capability probe answers (nativeplan.KeeneticUserspace ignores a failed probe on purpose).
			run.Path, run.Reason = "unavailable", "the router could not confirm its own AmneziaWG, so Apply refuses this connection until it can"
		default:
			d := plugin.AWGDecision(probe, firmwareOwned, e)
			run.Path, run.Reason = d.Path.String(), d.Reason
			if inLane {
				run.Reason = u.Reason + "; " + d.Reason
			}
			if awgSwitchesToKernel(probe, d, running[e.ID]) {
				run.Switch = "kernel"
			}
		}
		out.Needed = out.Needed || run.Path == "userspace"
		out.Connections = append(out.Connections, run)
	}
	out.Footprint = s.awgFootprint()
	out.Optional = !out.Needed && probe.TUN && out.Builtin != "unknown" && out.Builtin != out.Newest
	out.FeedModes = s.awgFeedModes()
	out.Switching = awgSwitchingNote(out.Connections)
	out.NetifdRestart = s.awgNetifdRestartPending()
	if s.updater != nil && !demo {
		out.Packages = s.updater.AWGPackages(ctx)
	}
	return out
}

// awgRunningOnUserspace is the set of AmneziaWG connections running on amneziawg-go now.
func (s *Server) awgRunningOnUserspace() map[string]bool {
	var ids []string
	switch {
	case s.awgUserspaceRunningOf != nil:
		ids = s.awgUserspaceRunningOf()
	case s.plugins != nil:
		ids = s.plugins.UserspaceAWGEndpoints()
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// awgSwitchesToKernel: a connection running on amneziawg-go whose next start takes the kernel module -
// one installed since it started. The plugin chose its path when it started and keeps it while it runs,
// so the switch waits for that next start rather than taking a working tunnel down. Only an answering
// probe counts: a failed one also reads as the kernel path ("as before"), which is no news.
func awgSwitchesToKernel(probe awg.Probe, next awg.Decision, runningOnUserspace bool) bool {
	return runningOnUserspace && probe.Err == "" && next.Path == awg.PathKernel
}

// awgSwitchingNote is awgComponentStatus.Switching for conns.
func awgSwitchingNote(conns []awgConnectionRun) string {
	var kernel, native []string
	for _, c := range conns {
		switch c.Switch {
		case "kernel":
			kernel = append(kernel, c.Name)
		case "native":
			native = append(native, c.Name)
		}
	}
	var parts []string
	if n := len(kernel); n == 1 {
		parts = append(parts, "1 connection ("+kernel[0]+") still runs on amneziawg-go; the kernel module carries it now, "+
			"and it switches over the next time it starts: after a WayHop restart or a reboot, or when an Apply changes it.")
	} else if n > 1 {
		parts = append(parts, fmt.Sprintf("%d connections (%s) still run on amneziawg-go; the kernel module carries them now, "+
			"and each switches over the next time it starts: after a WayHop restart or a reboot, or when an Apply changes it.",
			n, strings.Join(kernel, ", ")))
	}
	if n := len(native); n == 1 {
		parts = append(parts, "1 connection ("+native[0]+") runs on amneziawg-go and OpenWrt's own AmneziaWG carries it now: "+
			"moving it takes two Applies - switch it off and apply, then on and apply again.")
	} else if n > 1 {
		parts = append(parts, fmt.Sprintf("%d connections (%s) run on amneziawg-go and OpenWrt's own AmneziaWG carries them now: "+
			"moving each takes two Applies - switch it off and apply, then on and apply again.", n, strings.Join(native, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + " Running tunnels are not moved."
}

// awgHostProbe is what this router's AmneziaWG can do, measured fresh: the genl family of the loaded
// module is asked on every call, never cached, so a kernel module the feed installer has just loaded
// shows on the very next render.
func (s *Server) awgHostProbe() awg.Probe {
	if s.config().Demo {
		// The demo is an explicitly synthetic router: one with /dev/net/tun and no module, so every
		// AmneziaWG 3 connection shows the userspace path it would take on most routers.
		return awg.Probe{Kernel: awg.GenNone, TUN: true}
	}
	if s.awgProbeOf != nil {
		return s.awgProbeOf()
	}
	return awg.ProbeHost()
}

// awgBuiltin is awgComponentStatus.Builtin: the newer of the router's own tunnels (when it has usable
// native AmneziaWG, up to what its writer expresses) and the kernel module - unless the firmware owns
// the module, which WayHop's engine then never touches. An unanswered probe is "unknown" only when
// nothing else answers: a native writer's generation is known without it.
func awgBuiltin(probe awg.Probe, firmwareOwned, native bool, nativeGen awg.Generation) string {
	best := awg.GenNone
	if native {
		best = nativeGen
	}
	if !firmwareOwned {
		if probe.Err != "" {
			if best == awg.GenNone {
				return "unknown"
			}
		} else if probe.Kernel > best {
			best = probe.Kernel
		}
	}
	return best.String()
}

// awgCarriedByKernel is carried_by_kernel for the AmneziaWG component: the router carrying the
// protocol settles "nothing to install" only while no connection here runs on amneziawg-go AND its
// own AmneziaWG is already the newest generation. A generation-2 module next to an AmneziaWG 3
// connection is not a reason to hide the component, and neither is a generation-2 module alone: it
// cannot carry 3.x settings, and "the kernel carries AmneziaWG itself" would say it could.
func awgCarriedByKernel(native bool, st awgComponentStatus) bool {
	return native && !st.Needed && st.Builtin == st.Newest
}

// awgFootprint reads the installed component's cost, or nil when it is not installed.
func (s *Server) awgFootprint() *awgFootprint {
	bin := s.config().SingBox.Bin
	if bin == "" {
		return nil
	}
	dir := filepath.Dir(bin)
	f := &awgFootprint{Form: "binary"}
	if rec, ok := binstore.Read(dir, "amneziawg-go"); ok {
		f.FlashBytes = rec.Size
		if rec.Compressed {
			f.Form = "compressed"
			runDir := binstore.DefaultRunDir
			if s.updater != nil && s.updater.RunDir != "" {
				runDir = s.updater.RunDir
			}
			if fi, err := os.Stat(filepath.Join(runDir, "amneziawg-go")); err == nil {
				f.RAMBytes = fi.Size()
			}
		}
	} else if fi, err := os.Stat(filepath.Join(dir, "amneziawg-go")); err == nil && fi.Mode().IsRegular() {
		f.FlashBytes = fi.Size() // present but not recorded: installed some other way
	} else {
		return nil
	}
	if s.plugins != nil {
		for _, pid := range s.plugins.UserspaceAWGProcesses() {
			f.Running++
			f.RSSBytes += processRSS(pid)
		}
	}
	return f
}

// awgGoEngine is the updater's id (and binary name) for amneziawg-go.
const awgGoEngine = "amneziawg-go"

// awgDropStaleStore removes WayHop's own compressed amneziawg-go - the gzip on flash, its version record
// and the copy unpacked into RAM - once a package (opkg, apk, Entware) owns amneziawg-go; pkg is the
// package manager's answer about it. The copy is stale then: the plugin looks in the bin directory
// before PATH, so it would keep starting WayHop's older build instead of the package's, and it holds
// about 1.4 MB of flash for nothing. The package's binary is never touched (binstore.RemoveStaleCompressed),
// and a process running from the old copy keeps running until its next start - nothing is moved under
// a live tunnel. Only a definite answer counts: an ownership the package manager could not establish
// leaves everything where it is.
func (s *Server) awgDropStaleStore(pkg updater.PackageStatus) {
	if s.config().Demo || s.updater == nil || !pkg.Managed || !pkg.OwnershipKnown || s.updater.BinDir == "" {
		return
	}
	dir := s.updater.BinDir
	if pkg.Path != "" && filepath.Clean(pkg.Path) == filepath.Clean(binstore.Stored(dir, awgGoEngine, true)) {
		return // the "copy" is the package's own file: not WayHop's to remove
	}
	runDir := s.updater.RunDir
	if runDir == "" {
		runDir = binstore.DefaultRunDir
	}
	removed, err := binstore.RemoveStaleCompressed(dir, awgGoEngine, runDir)
	if len(removed) > 0 {
		log.Printf("updater: amneziawg-go belongs to the %s package now; removed WayHop's stale compressed copy: %s",
			pkg.Package, strings.Join(removed, ", "))
	}
	if err != nil {
		log.Printf("updater: removing WayHop's stale compressed amneziawg-go: %v", err)
	}
}

// awgDropStaleStoreNow asks the package manager about amneziawg-go and drops the stale store when a
// package owns it: after an install that may have handed it to one.
func (s *Server) awgDropStaleStoreNow(ctx context.Context) {
	if s.config().Demo || s.updater == nil {
		return
	}
	if e := updater.EngineByID(awgGoEngine); e != nil {
		s.awgDropStaleStore(s.updater.EnginePackageStatus(ctx, *e))
	}
}

// processRSS is a process's resident set in bytes from /proc/<pid>/status, 0 where it cannot be read.
func processRSS(pid int) int64 {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer file.Close()
	return parseVmRSS(bufio.NewScanner(file))
}

// parseVmRSS finds "VmRSS:  12345 kB" and returns it in bytes.
func parseVmRSS(sc *bufio.Scanner) int64 {
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}
