package server

import (
	"bufio"
	"context"
	"fmt"
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
)

// awgcomponent.go answers, for the AmneziaWG 3 row on the Components page, the three questions the
// row exists for: what the router's own AmneziaWG can do, how each configured AmneziaWG connection is
// run - and therefore whether amneziawg-go is needed here at all - and what the component costs.
//
// Each answer is the one the rest of the daemon acts on, not a second opinion: the native lane comes
// from nativeplan.Userspace (what the planner hands to the engine), the engine's kernel/userspace
// choice from plugin.AWGDecision (what the plugin runs), and the footprint from the binstore record
// the updater wrote.

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
	Needed    bool          `json:"needed"`
	Footprint *awgFootprint `json:"footprint,omitempty"`
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
	probe := awg.ProbeHost()
	if s.awgProbeOf != nil {
		probe = s.awgProbeOf()
	}
	if demo {
		// The demo is an explicitly synthetic router: one with /dev/net/tun and no module, so every
		// AmneziaWG 3 connection shows the userspace path it would take on most routers.
		probe = awg.Probe{Kernel: awg.GenNone, TUN: true}
	}
	firmwareOwned := !demo && p == platform.Keenetic
	out := awgComponentStatus{Kernel: probe.Kernel.String(), FirmwareOwned: firmwareOwned, TUN: probe.TUN,
		ProbeError: probe.Err, Connections: []awgConnectionRun{}}
	if probe.Err != "" {
		out.Kernel = "unknown"
	}

	nativePlan := !demo && (p == platform.OpenWrt || p == platform.Keenetic)
	var capset platform.CapabilitySet
	lane := map[string]nativeplan.UserspaceEndpoint{}
	if nativePlan {
		capset = s.capabilitySet(ctx, false)
		lane = nativeplan.Userspace(&prof, p, capset)
	}
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
		}
		out.Needed = out.Needed || run.Path == "userspace"
		out.Connections = append(out.Connections, run)
	}
	out.Footprint = s.awgFootprint()
	return out
}

// awgCarriedByKernel is carried_by_kernel for the AmneziaWG component: the kernel carrying the
// protocol settles "nothing to install" only while no connection here runs on amneziawg-go. A
// generation-2 module next to an AmneziaWG 3 connection is not a reason to hide the component.
func awgCarriedByKernel(native bool, st awgComponentStatus) bool { return native && !st.Needed }

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
