package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

// awgkernel.go captures nativeplan.HostFacts.AWGKernel: the AmneziaWG generation OpenWrt's own
// interfaces may be written up to, which is the loaded kernel module's generation held down to what the
// netifd handler passes on to `awg setconf` - min(awg.ProbeHost().Kernel,
// netvpn.HandlerAWGGeneration(/lib/netifd/proto/amneziawg.sh)), GenNone when there is no handler.
//
// The Apply review, the Components row, the per-endpoint UCI plan and the Apply itself all ask here, so
// they cannot disagree about where a connection runs: the planner refuses a move between lanes by the
// same value the review explains it with.
//
// The probe can fail without the module having changed: the generic-netlink round trip is bounded and
// can time out on a loaded router, and a socket can be refused. Reading such a failure as "no module"
// would push every AmneziaWG 3 connection OpenWrt runs natively into the userspace lane, which the
// planner refuses as a move (nativeplan.MoveError) - an Apply blocked by a hiccup, about a tunnel that
// is working. So a failed probe keeps the generation the last applied plan was compiled with, but only
// while the evidence says nothing changed underneath it:
//
//   - /sys/module/amneziawg still exists and identifies the same module build (its version, srcversion
//     and coresize, as recorded when the probe last answered): a module that was unloaded or replaced
//     may be any generation;
//   - /lib/netifd/proto/amneziawg.sh has the same SHA-256 as then: a changed handler may pass on fewer
//     options than the one the generation was judged against;
//   - the last capture itself was not GenNone and carried a module identity to compare with.
//
// Anything else is GenNone, the writer's generation-2 baseline - what the router ran before the module
// was asked at all. The value kept this way is persisted again with the same identities, so a probe that
// keeps failing keeps the plan only for as long as the module and the handler stay what they were.
//
// netifd reads protocol handlers only when it starts, so a handler file can be newer than the one netifd
// runs (an install without --restart-network). The capture describes the file, which is what the next
// netifd start runs; that netifd still has to restart is a separate fact, reported on its own
// (awgnetifd.go: the review's endpoint.amneziawg.netifd_restart and the Components row's button).

// The router files the capture reads.
const (
	awgHandlerPath = "/lib/netifd/proto/amneziawg.sh"
	awgModuleDir   = "/sys/module/amneziawg"
)

// awgKernelCaptureV1 is one capture of HostFacts.AWGKernel with the evidence a later capture compares
// against when its own probe fails. It is persisted inside the native capture and the applied native
// materialization (the apply-state record).
type awgKernelCaptureV1 struct {
	// Generation is HostFacts.AWGKernel.
	Generation awg.Generation `json:"generation"`
	// HandlerSHA256 is the netifd handler's digest, "" when the handler was absent or unreadable.
	HandlerSHA256 string `json:"handler_sha256,omitempty"`
	// Module identifies the loaded module build (awgModuleIdentity), "" when it was not loaded or did not
	// say.
	Module string `json:"module,omitempty"`
	// Kept: the probe failed, and Generation is the previous capture's, held by the rule above.
	Kept bool `json:"kept,omitempty"`
	// ProbeError is why the probe failed, for the log and the review; not part of the rule.
	ProbeError string `json:"probe_error,omitempty"`
}

// awgKernelReads are the router reads besides the probe; nil fields are the real files. Tests replace
// them, because no development host has either file.
type awgKernelReads struct {
	// handler returns the handler script, present=false when it does not exist or cannot be read.
	handler func() (script []byte, present bool)
	// module returns the module's identity and whether /sys/module/amneziawg exists.
	module func() (identity string, present bool)
}

func readAWGHandler() ([]byte, bool) {
	b, err := os.ReadFile(awgHandlerPath)
	if err != nil {
		return nil, false
	}
	return b, true
}

// readAWGModule identifies the loaded module by what sysfs says about the build: a module rebuilt or
// replaced (rmmod + insmod of another kmod) changes at least one of them.
func readAWGModule() (string, bool) {
	return awgModuleIdentity(awgModuleDir)
}

func awgModuleIdentity(dir string) (string, bool) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return "", false
	}
	var parts []string
	for _, name := range []string{"version", "srcversion", "coresize"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return "", true // present, but nothing to compare a later read with
			}
			continue
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, ";"), true
}

// resolveAWGKernel is the rule, pure. previous is the capture the last applied plan was compiled with,
// nil when there is none.
func resolveAWGKernel(probe awg.Probe, handler []byte, handlerPresent bool, module string, modulePresent bool,
	previous *awgKernelCaptureV1) awgKernelCaptureV1 {
	out := awgKernelCaptureV1{}
	if handlerPresent {
		sum := sha256.Sum256(handler)
		out.HandlerSHA256 = hex.EncodeToString(sum[:])
	}
	if modulePresent {
		out.Module = module
	}
	if probe.Err == "" {
		switch {
		case !handlerPresent:
			// No handler, no interface: netifd cannot bring an amneziawg section up at all.
			out.Generation = awg.GenNone
		default:
			out.Generation = probe.Kernel
			if h := netvpn.HandlerAWGGeneration(string(handler)); h < out.Generation {
				out.Generation = h
			}
		}
		return out
	}
	out.ProbeError = probe.Err
	if previous != nil && previous.Generation > awg.GenNone && previous.Module != "" &&
		modulePresent && handlerPresent && out.Module == previous.Module && out.HandlerSHA256 == previous.HandlerSHA256 {
		out.Generation, out.Kept = previous.Generation, true
		return out
	}
	out.Generation = awg.GenNone
	return out
}

// awgKernelCaptureFor captures HostFacts.AWGKernel for platform p, from probe. Only OpenWrt's UCI writer
// reads it; elsewhere (and in the demo, whose router is synthetic) it is the zero capture, which keeps a
// KeeneticOS capture encoding as it did before the module was asked.
func (s *Server) awgKernelCaptureFor(p platform.Platform, probe awg.Probe) awgKernelCaptureV1 {
	if p != platform.OpenWrt || s.config().Demo {
		return awgKernelCaptureV1{}
	}
	readHandler, readModule := readAWGHandler, readAWGModule
	if s.awgKernelReadsOf != nil {
		if s.awgKernelReadsOf.handler != nil {
			readHandler = s.awgKernelReadsOf.handler
		}
		if s.awgKernelReadsOf.module != nil {
			readModule = s.awgKernelReadsOf.module
		}
	}
	script, handlerPresent := readHandler()
	module, modulePresent := readModule()
	return resolveAWGKernel(probe, script, handlerPresent, module, modulePresent, s.lastAWGKernelCapture())
}

// awgKernelGeneration is HostFacts.AWGKernel for this router now, as the review and the Components row
// ask it - the same rule the Apply's capture applies.
func (s *Server) awgKernelGeneration() awg.Generation {
	p := s.detectedPlatform()
	if p != platform.OpenWrt || s.config().Demo {
		return awg.GenNone
	}
	return s.awgKernelCaptureFor(p, s.awgHostProbe()).Generation
}

// lastAWGKernelCapture is the capture the plan WayHop last applied was compiled with, nil when there
// is none (no Apply yet, a native-less one, or one from before the capture existed).
func (s *Server) lastAWGKernelCapture() *awgKernelCaptureV1 {
	base := s.appliedBaseline()
	if base == nil || base.Materialization.Native == nil {
		return nil
	}
	return cloneAWGKernelCapture(base.Materialization.Native.AWGKernel)
}

func cloneAWGKernelCapture(c *awgKernelCaptureV1) *awgKernelCaptureV1 {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

// generation is the capture's HostFacts.AWGKernel, GenNone for no capture.
func (c *awgKernelCaptureV1) generation() awg.Generation {
	if c == nil {
		return awg.GenNone
	}
	return c.Generation
}
