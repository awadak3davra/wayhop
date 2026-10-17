package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/platform"
	"wayhop/internal/updater"
	awgpkg "wayhop/packaging/awg"
)

// awgcomponent_install.go puts WayHop's own AmneziaWG installer (packaging/awg/install-awg.sh,
// embedded) behind the AmneziaWG row of the Components page: plan, install, remove.
//
// It answers under the pseudo-engine id "awg" on the routes the updater already has, the way /fit
// answers "self" for WayHop's own row:
//
//	GET    /api/updater/awg/fit       the installer's dry run: the path it would take here and why
//	POST   /api/updater/awg/install   {"mode":"kmod"|"userspace","restart_network":bool} - the path the
//	                                  plan showed; restart_network passes --restart-network
//	DELETE /api/updater/awg           --uninstall
//	POST   /api/updater/awg/restart-network   netifd re-reads the AmneziaWG handler (awgnetifd.go)
//
// The release-asset install of amneziawg-go (engine "amneziawg-go") stays as it was. It is the way
// round when the feed cannot be reached, and the source of the compressed store on a flash too small
// for the unpacked binary, which the feed's packages cannot be.

// awgFeedID is the pseudo-engine the feed install answers under.
const awgFeedID = "awg"

// awgEntwareOpkg marks Entware on a router that is neither OpenWrt nor KeeneticOS; a variable so tests
// can point it elsewhere.
var awgEntwareOpkg = "/opt/bin/opkg"

// awgKmodFlash is what the kernel path costs on flash, as measured for the AmneziaWG 3.1 plan
// (docs/AWG_FULL_INSTALL.md (development repository)): about 95 KB of module, 65 KB of awg and the
// small kmod dependencies.
const awgKmodFlash = "about 0.3 MB of flash"

// awgFeedModes are the paths the installer may take on this router. KeeneticOS is userspace only:
// its kernels have no SDK and MODVERSIONS off, so a kmod built elsewhere could crash the router.
func (s *Server) awgFeedModes() []string {
	if s.config().Demo {
		return []string{updater.AWGPathKmod, updater.AWGPathUserspace}
	}
	switch s.detectedPlatform() {
	case platform.OpenWrt:
		return []string{updater.AWGPathKmod, updater.AWGPathUserspace}
	case platform.Keenetic:
		return []string{updater.AWGPathUserspace}
	}
	if _, err := os.Stat(awgEntwareOpkg); err == nil {
		return []string{updater.AWGPathUserspace}
	}
	return nil
}

// awgInstaller is the embedded installer, run for real unless a test injected a runner or this is
// the demo, whose runner answers like a router and changes nothing.
func (s *Server) awgInstaller() updater.AWGInstaller {
	run := s.updater.AWGRunner()
	if run == nil && s.config().Demo {
		run = updater.DemoAWGRun
	}
	return updater.AWGInstaller{Script: awgpkg.InstallScript(), Dir: s.updater.RunDir, Run: run}
}

// awgFeedAnswer is what the row shows about one run of the installer.
type awgFeedAnswer struct {
	Run updater.AWGRun `json:"run"`
	// Summary is the one sentence the row leads with: what would be (or was) installed, for which
	// router, and why - or the refusal's reason.
	Summary string `json:"summary"`
	// Installable: a dry run naming a path the operator can approve as shown.
	Installable bool `json:"installable"`
	// Fallback: the plan did not produce an install, and the release asset of amneziawg-go is the way
	// round - /dev/net/tun is here, and its own pre-flights (flash, compressed store, memory) decide.
	Fallback bool   `json:"fallback,omitempty"`
	Demo     bool   `json:"demo,omitempty"`
	Kernel   string `json:"kernel,omitempty"` // after an install: the module generation the probe reads now
	// NetifdRestart: the run adds or changes netifd's AmneziaWG handler (a plan: would), and netifd has
	// not been restarted for it - it reads handlers only when it starts. A plan offers restart_network;
	// after an install the row offers the restart itself, or the next reboot does it.
	NetifdRestart bool `json:"netifd_restart,omitempty"`
	// NetworkRestarted: the installer restarted the network service itself (restart_network).
	NetworkRestarted bool `json:"network_restarted,omitempty"`
}

// withNetifd folds the installer's netifd account into the answer for a run it accepted - an install
// or an installable plan; a refusal or a failure changed nothing netifd reads.
func (a *awgFeedAnswer) withNetifd(r awgNetifdReport) {
	if !a.Installable && !(a.Run.OK() && a.Run.Op == "install") {
		return
	}
	a.NetworkRestarted = r.Restarted != nil && *r.Restarted
	a.NetifdRestart = r.RestartNeeded != nil && *r.RestartNeeded && !a.NetworkRestarted
	a.Summary += netifdNote(a.Run, r)
}

// awgWhere names the router a kmod is built for, as the plan sentence needs it.
func awgWhere(p platform.Platform, rel platform.OpenWrtRelease, demo bool) string {
	switch {
	case demo:
		return "OpenWrt 24.10.8 x86/64 (demo)"
	case p == platform.OpenWrt && rel.Release != "" && rel.Target != "":
		return "OpenWrt " + rel.Release + " " + rel.Target
	case p == platform.OpenWrt:
		return "this OpenWrt release"
	case p == platform.Keenetic:
		return "Entware on KeeneticOS"
	}
	return "Entware on this router"
}

// awgRunSummary is the sentence for a run. English, like every other reason on this row: it names
// packages, paths and versions, which are not words to translate.
func awgRunSummary(run updater.AWGRun, where string) string {
	gen := run.Generation
	if gen == "" {
		gen = awg.UserspaceGeneration.String()
	}
	pkgs := ""
	if len(run.Packages) > 0 {
		pkgs = " (" + strings.Join(run.Packages, ", ") + ")"
	}
	why := ""
	if run.Reason != "" {
		why = ": " + run.Reason
	}
	switch run.Result {
	case updater.AWGDryRun:
		if run.Path == updater.AWGPathKmod {
			return fmt.Sprintf("kernel module AmneziaWG %s for %s, %s%s%s", gen, where, awgKmodFlash, pkgs, why)
		}
		return fmt.Sprintf("userspace amneziawg-go (AmneziaWG %s)%s%s%s", gen, awgProfileText(run), pkgs, why)
	case updater.AWGInstalled:
		if run.Path == updater.AWGPathKmod {
			return fmt.Sprintf("AmneziaWG %s kernel module installed for %s%s; AmneziaWG connections take it the next time they start%s", gen, where, pkgs, why)
		}
		return fmt.Sprintf("amneziawg-go (AmneziaWG %s) installed from WayHop's feed%s%s%s", gen, awgProfileText(run), pkgs, why)
	case updater.AWGCurrent:
		return fmt.Sprintf("AmneziaWG %s from WayHop's feed is already installed here%s%s", gen, pkgs, why)
	case updater.AWGRemoved:
		return "WayHop's AmneziaWG packages were removed" + pkgs + why
	}
	if run.Reason != "" {
		return run.Reason
	}
	return "the installer gave no reason"
}

// awgProfileText is the userspace tuning the installer chose, with the RAM it chose it for.
func awgProfileText(run updater.AWGRun) string {
	if run.Profile == "" {
		return ""
	}
	s := ", " + run.Profile + " profile"
	if run.MemTotalKiB != nil && *run.MemTotalKiB > 0 {
		s += fmt.Sprintf(" for %d MiB of RAM", *run.MemTotalKiB>>10)
	}
	return s
}

// awgAnswer builds the row's answer for run.
func (s *Server) awgAnswer(run updater.AWGRun, probe awg.Probe) awgFeedAnswer {
	p := s.detectedPlatform()
	rel, _ := platform.DetectOpenWrtRelease()
	demo := s.config().Demo
	ans := awgFeedAnswer{Run: run, Summary: awgRunSummary(run, awgWhere(p, rel, demo)), Installable: run.Installable(), Demo: demo}
	ans.Fallback = !ans.Installable && (run.Result == updater.AWGRefused || run.Result == updater.AWGFailed) && probe.TUN
	if demo && run.OK() {
		// The demo's runner changes nothing; the sentence must not open by claiming it did.
		ans.Summary = "Demo mode, nothing was changed. On a router: " + ans.Summary
	}
	return ans
}

// handleAWGPlan answers GET /api/updater/awg/fit: the installer's dry run, which changes nothing.
func (s *Server) handleAWGPlan(w http.ResponseWriter, r *http.Request) {
	modes := s.awgFeedModes()
	if len(modes) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "WayHop's AmneziaWG installer supports OpenWrt and Entware, and this router is neither")
		return
	}
	// The dry run reads the package database and refreshes the feed index; a package operation running
	// meanwhile holds the lock both need. Answered at once rather than queued behind an install that can
	// take minutes.
	if !pmMu.TryLock() {
		writeErr(w, http.StatusConflict, "another package operation is running; try again when it finishes")
		return
	}
	defer pmMu.Unlock()
	mode := ""
	if len(modes) == 1 {
		mode = modes[0] // held to the one path this router may take
	}
	var netifd awgNetifdReport
	run := s.awgInstallerWith(false, &netifd).Plan(r.Context(), mode)
	ans := s.awgAnswer(run, s.awgHostProbe())
	ans.withNetifd(netifd)
	writeJSON(w, http.StatusOK, ans)
}

// handleAWGInstall answers POST /api/updater/awg/install.
func (s *Server) handleAWGInstall(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
		// RestartNetwork: restart netifd when the install adds or changes its AmneziaWG handler, which
		// briefly drops every link on the router. Off unless the operator ticked it.
		RestartNetwork bool `json:"restart_network"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	modes := s.awgFeedModes()
	if !containsString(modes, body.Mode) {
		if len(modes) == 0 {
			writeErr(w, http.StatusUnprocessableEntity, "WayHop's AmneziaWG installer supports OpenWrt and Entware, and this router is neither")
			return
		}
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("mode must be the path the plan showed: one of %s here", strings.Join(modes, ", ")))
		return
	}
	if body.RestartNetwork && !s.config().Demo && s.detectedPlatform() != platform.OpenWrt {
		writeErr(w, http.StatusBadRequest, "restart_network applies only to OpenWrt, whose netifd reads AmneziaWG's protocol handler")
		return
	}
	if !pmMu.TryLock() {
		writeErr(w, http.StatusConflict, "another package operation is running; try again when it finishes")
		return
	}
	defer pmMu.Unlock()
	// Detached from the request: a browser tab closed halfway must not kill opkg/apk in the middle of
	// writing packages. The installer's own timeout still bounds the run, and it rolls back on failure.
	ctx := context.WithoutCancel(r.Context())
	log.Printf("updater: installing AmneziaWG from WayHop's feed (%s path, restart the network service: %v)", body.Mode, body.RestartNetwork)
	var netifd awgNetifdReport
	run := s.awgInstallerWith(body.RestartNetwork, &netifd).Install(ctx, body.Mode)
	switch {
	case run.OK():
		s.setUpdErr("amneziawg-go", "")
		if run.Path == updater.AWGPathUserspace {
			// The feed's amneziawg-go is a package: a compressed copy WayHop kept from a release asset
			// would otherwise be what the restart below starts again.
			s.awgDropStaleStoreNow(ctx)
		}
		s.awgAfterChange(ctx, run.Result == updater.AWGInstalled && run.Path == updater.AWGPathUserspace)
		probe := s.awgHostProbe()
		ans := s.awgAnswer(run, probe)
		ans.withNetifd(netifd)
		switch {
		case ans.NetifdRestart:
			s.awgNetifdPending.Store(true)
		case ans.NetworkRestarted:
			s.awgNetifdPending.Store(false)
		}
		ans.Kernel = probe.Kernel.String()
		if probe.Err != "" {
			ans.Kernel = "unknown"
		}
		log.Printf("updater: AmneziaWG from WayHop's feed: %s (%s path); kernel module now %s", run.Result, body.Mode, ans.Kernel)
		writeJSON(w, http.StatusOK, ans)
	case run.Result == updater.AWGRefused:
		// A refusal is a property of this router (no space, no matching kmod), not an install failure:
		// it is answered, and not kept as the row's last error.
		ans := s.awgAnswer(run, s.awgHostProbe())
		writeJSON(w, http.StatusConflict, map[string]any{"error": ans.Summary, "answer": ans})
	default:
		ans := s.awgAnswer(run, s.awgHostProbe())
		log.Printf("updater: AmneziaWG from WayHop's feed failed (%s path): %s", body.Mode, ans.Summary)
		s.setUpdErr("amneziawg-go", "WayHop's feed: "+ans.Summary)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": ans.Summary, "answer": ans})
	}
}

// handleAWGUninstall answers DELETE /api/updater/awg: the installer removes what it installed.
func (s *Server) handleAWGUninstall(w http.ResponseWriter, r *http.Request) {
	if len(s.awgFeedModes()) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "WayHop's AmneziaWG installer supports OpenWrt and Entware, and this router is neither")
		return
	}
	if !pmMu.TryLock() {
		writeErr(w, http.StatusConflict, "another package operation is running; try again when it finishes")
		return
	}
	defer pmMu.Unlock()
	ctx := context.WithoutCancel(r.Context())
	// The removal may take amneziawg-go's package with it, and a deleted binary keeps running as an
	// orphan: stop its procs first, as the package path does, and bring them back if nothing was
	// removed after all.
	core := s.pmCore()
	stopped := 0
	if core.stopPlugin != nil {
		stopped = core.stopPlugin("amneziawg-go")
	}
	log.Printf("updater: removing WayHop's AmneziaWG packages (%d amneziawg-go proc(s) stopped first)", stopped)
	run := s.awgInstaller().Uninstall(ctx)
	ans := s.awgAnswer(run, s.awgHostProbe())
	if !run.OK() {
		if stopped > 0 && core.restorePlugin != nil {
			core.restorePlugin()
		}
		code := http.StatusBadGateway
		if run.Result == updater.AWGRefused {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"error": ans.Summary, "answer": ans})
		return
	}
	s.setUpdErr("amneziawg-go", "")
	s.awgNetifdPending.Store(false) // no handler left for netifd to catch up with
	s.awgAfterChange(ctx, false)
	writeJSON(w, http.StatusOK, map[string]any{"removed": awgFeedID, "stopped": stopped, "answer": ans})
}

// awgAfterChange is what follows a change to the router's AmneziaWG: the capability set is cached
// for minutes (capStaleAfter), and the native planner and the Components page must see the new
// module and tools at once, not after the cache ages out. The genl probe itself is never cached
// (awgHostProbe), so the engine's kernel-or-userspace choice reads the new module on its own.
//
// restartUserspace re-execs running amneziawg-go procs after the feed wrote its binary: a replaced
// file does not replace the process already running from it.
func (s *Server) awgAfterChange(ctx context.Context, restartUserspace bool) {
	if s.config().Demo {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s.capabilitySet(rctx, true)
	if restartUserspace {
		if core := s.pmCore(); core.restartPlugin != nil {
			if n := core.restartPlugin("amneziawg-go"); n > 0 {
				log.Printf("updater: restarted %d amneziawg-go proc(s) onto the feed's binary", n)
			}
		}
	}
}
