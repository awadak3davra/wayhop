package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wayhop/internal/localtz"
	"wayhop/internal/pm"
	"wayhop/internal/updater"
	"wayhop/internal/updatetx"
	"wayhop/internal/version"
)

// selfupdate_tx.go is the self-update as a transaction the daemon does not judge alone (see
// internal/updatetx): the update is recorded on flash before the swap, the restart is handed to a
// supervisor in its own session, and that supervisor restores the rollback copy when the new build
// does not answer in time. A package-owned WayHop is updated the same way, with the package manager
// run by the supervisor so that the restart its maintainer scripts do cannot kill it midway.

// updateDir is where the transaction's records live: beside the config, on the flash that survives a
// reboot. "" when the config came from nowhere (tests), where no update is judged.
func (s *Server) updateDir() string {
	if p := s.cfg.Path(); p != "" {
		return filepath.Dir(p)
	}
	return ""
}

func (s *Server) updateInit() string {
	if s.updInit != nil {
		return s.updInit()
	}
	return updatetx.InitScript()
}

func (s *Server) updateSpawn(etc string, args ...string) error {
	if s.updSpawn != nil {
		return s.updSpawn(etc, args...)
	}
	return updatetx.Spawn(etc, args...)
}

// updateZone is the zone update times are written in for the owner: the router's (localtz), since
// time.Local is UTC on Keenetic and OpenWrt; s.updZone replaces it in tests.
func (s *Server) updateZone() *time.Location {
	if s.updZone != nil {
		return s.updZone()
	}
	return localtz.Location()
}

// errUpdateInFlight refuses an update asked for while another is still being judged.
var errUpdateInFlight = errors.New("an update is still being judged")

// updateInFlight refuses a self-update while the supervisor is judging another one. Both paths make
// a rollback copy of whatever the binary is now and rewrite the marker, so a second update would turn
// the build under judgement into the copy the supervisor restores: if that build crashes on start,
// the "rollback" puts it back and the router is left without a working WayHop. The caller holds
// applyMu, so two queued requests cannot both pass.
//
// A live supervisor refuses on its own, marker or not. It drops the marker before it is done: a
// rollback then restores the copy and waits 60 s for the old build, a proven update compresses the
// copy (10-40 s on an AX3000T). A second update in that window relinked .bak to the build now
// running and deleted .bak.gz, and the compression then moved its gzip of the first build into place
// and deleted .bak: the second update's rollback copy was gone, and a crashing build crash-looped.
//
// A marker older than updatetx.PendingStale with no supervisor behind it is one nobody is finishing,
// which only the next boot acts on; it does not lock the panel out until then. With a supervisor
// behind it the age says nothing: the boot pass stamps the marker with the clock restored at boot,
// and NTP can move that forward by hours while the judgement is still running.
func (s *Server) updateInFlight() error {
	etc := s.updateDir()
	if etc == "" {
		return nil
	}
	pidFile := s.updPIDFile
	if pidFile == "" {
		pidFile = updatetx.SupervisorPIDFile
	}
	pid, alive := updatetx.SupervisorAlive(pidFile)
	since, marked := updatetx.PendingSince(etc)
	if marked && (alive || time.Since(since) <= updatetx.PendingStale) {
		// In the router's zone: time.Local is UTC on Keenetic and OpenWrt, and the owner reads this
		// against the router's clock.
		return fmt.Errorf("%w (recorded at %s): wait for its result, then retry", errUpdateInFlight, since.In(s.updateZone()).Format("15:04:05"))
	}
	if alive {
		return fmt.Errorf("%w (the update supervisor, pid %d, is still rolling back or compressing the rollback copy): wait for its result, then retry", errUpdateInFlight, pid)
	}
	return nil
}

// runningVersionLine is this build's --version line, which the supervisor compares the rolled-back
// build against.
func runningVersionLine() string { return "wayhop " + version.Get().String() }

// selfSwapAndJudge is the release-asset self-update shared by the panel, the bot and auto-update:
// the swap, recorded for the supervisor before it happens, then the restart through the supervisor.
// Without an init script to restart through (a dev host, the demo) it swaps and says so, as before.
func (s *Server) selfSwapAndJudge(ctx context.Context, repo, tag, exe, by string) (installed string, restarting bool, note string, err error) {
	etc, init := s.updateDir(), s.updateInit()
	judge := etc != "" && init != ""
	if judge {
		if _, ierr := updatetx.InstallScript(etc); ierr != nil {
			log.Printf("self-update: the update supervisor could not be written (%v); restarting without it", ierr)
			judge = false
		}
	}
	marked := false
	before := func(line string) error {
		if !judge {
			return nil
		}
		ver, commit := updatetx.ParseVersionLine(line)
		m := updatetx.Marker{Bin: exe, Init: init, Config: s.cfg.Path(), Rollback: exe + ".bak",
			WantCommit: commit, WantVersion: ver, From: runningVersionLine(), To: tag, By: by}
		if werr := m.Write(etc); werr != nil {
			return werr
		}
		marked = true
		return nil
	}
	swap := s.updater.SelfUpdateWith
	if s.selfSwap != nil {
		swap = s.selfSwap
	}
	s.applyMu.Lock()
	if err = s.updateInFlight(); err == nil {
		installed, err = swap(ctx, repo, tag, exe, before)
		if err != nil && marked {
			updatetx.Clear(etc) // under the lock: a request queued behind this one must not see it
		}
	}
	s.applyMu.Unlock()
	if err != nil {
		return "", false, "", err
	}
	if marked {
		if serr := s.updateSpawn(etc, "restart"); serr == nil {
			return installed, true, fmt.Sprintf("restarting onto %s; if it does not answer within %d s the previous build is put back automatically", installed, updatetx.DefaultWindow), nil
		} else {
			log.Printf("self-update: the update supervisor did not start (%v); restarting without it", serr)
		}
		updatetx.Clear(etc)
	}
	cmd := restartCommand()
	if cmd == nil {
		return installed, false, "binary swapped; restart the service manually to apply (or this is the demo)", nil
	}
	if serr := cmd.Start(); serr != nil {
		return installed, false, "restart failed: " + serr.Error(), nil
	}
	return installed, true, "", nil
}

// pkgVersionCore is a package version without its package revision ("0.5.8-r1", "0.5.8-1" -> "0.5.8"):
// the version the build itself reports on /api/health.
var pkgRevision = regexp.MustCompile(`-r?\d+$`)

func pkgVersionCore(v string) string { return pkgRevision.ReplaceAllString(strings.TrimSpace(v), "") }

// pmUpgradeLine is what the supervisor runs for kind, for the messages that name it.
func pmUpgradeLine(kind pm.Kind) string {
	if kind == pm.Apk {
		return "apk update && apk upgrade wayhop"
	}
	return "opkg update && opkg upgrade wayhop"
}

// selfInstallPM updates a package-owned WayHop through its package manager, from the panel. The
// package's maintainer scripts restart the service, so the package manager must not be this daemon's
// child: the supervisor runs it, in its own session, and judges the build it leaves running.
func (s *Server) selfInstallPM(ctx context.Context, exe string, st updater.PackageStatus) (int, map[string]any) {
	fail := func(code int, msg string) (int, map[string]any) { return code, map[string]any{"error": msg} }
	kind := st.Manager
	line := pmUpgradeLine(kind)
	if !st.OwnershipKnown {
		return fail(http.StatusConflict, "could not verify which package owns the running binary; retry once the package manager is idle")
	}
	if st.State != updater.PackageStateBehind || st.LatestVersion == "" {
		return http.StatusOK, map[string]any{"installed": st.InstalledVersion, "restarting": false,
			"note": "the feed offers nothing newer than " + st.InstalledVersion}
	}
	if s.cfg.Demo {
		return http.StatusOK, map[string]any{"installed": st.LatestVersion, "restarting": false,
			"note": "demo: would run " + line + " and judge the build it installs; nothing was changed"}
	}
	etc, init := s.updateDir(), s.updateInit()
	if etc == "" || init == "" {
		return fail(http.StatusConflict, "no WayHop init script here to restart through; update it with "+line+" over SSH")
	}
	// The same lock and the same check as selfSwapAndJudge, before anything here touches the rollback
	// copy, the marker, or the staging names the supervisor may be restoring through.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if err := s.updateInFlight(); err != nil {
		return fail(http.StatusConflict, err.Error())
	}
	if removed := s.updater.ReclaimSelfLeftovers(exe); len(removed) > 0 {
		log.Printf("self-update: removed what an earlier update left behind: %s", strings.Join(removed, ", "))
	}
	if sp := s.updater.SelfPMSpace(ctx, st); sp.Strategy == updater.PMSpaceBlocked {
		return fail(http.StatusInsufficientStorage, fmt.Sprintf("not enough free space for wayhop %s on %s: ~%d MiB free, the package needs ~%d MiB with head-room — free at least %d MiB more, then retry",
			st.LatestVersion, sp.Dir, sp.Avail>>20, (sp.Need+(4<<20))>>20, sp.ShortfallMiB))
	}
	m := updatetx.Marker{Bin: exe, Init: init, Config: s.cfg.Path(), WantVersion: pkgVersionCore(st.LatestVersion),
		From: runningVersionLine(), To: st.LatestVersion, By: string(kind), Window: updatetx.DefaultWindow + 30}
	// apk owns the file it ships under /usr/libexec, not the live path it is published at, so the live
	// binary can be put back without touching a file the package database describes. opkg owns the live
	// path itself: putting an old binary there would leave the database naming a build that is not on
	// disk, so the new build stays and the result says how to recover.
	if kind == pm.Apk && filepath.Clean(st.Path) != filepath.Clean(exe) {
		if _, err := updater.LinkRollback(exe); err != nil {
			m.NoRollback = "the rollback copy could not be made (" + err.Error() + "), so the new build was left in place"
		} else {
			m.Rollback = exe + ".bak"
		}
	} else {
		m.NoRollback = fmt.Sprintf("%s owns %s itself, so it was not rolled back (that would leave the package database describing a build that is not there) — reinstall a working build with %s or the installer", kind, exe, kind)
	}
	if _, err := updatetx.InstallScript(etc); err != nil {
		return fail(http.StatusInternalServerError, "the update supervisor could not be written: "+err.Error())
	}
	if err := m.Write(etc); err != nil {
		return fail(http.StatusInternalServerError, "the update could not be recorded: "+err.Error())
	}
	if err := s.updateSpawn(etc, "pm", string(kind)); err != nil {
		updatetx.Clear(etc)
		return fail(http.StatusInternalServerError, "the update supervisor did not start: "+err.Error())
	}
	return http.StatusOK, map[string]any{"installed": st.LatestVersion, "restarting": true,
		"note": fmt.Sprintf("updating through %s (%s); the package restarts WayHop, and the result is shown here when it is back", kind, line)}
}

// selfUpdateReport adds the transaction's state to the self-update status: the last judgement (and
// the sentence worth showing for a rollback or a failure), and whether an update is being judged now,
// with the supervisor's log while it is.
func (s *Server) selfUpdateReport(out map[string]any) {
	etc := s.updateDir()
	if etc == "" {
		return
	}
	if r, ok := updatetx.ReadResult(etc); ok {
		out["last_update"] = r
		if n := r.Note(time.Now().In(s.updateZone())); n != "" {
			out["last_update_note"] = n
		}
	}
	if updatetx.Pending(etc) {
		out["update_pending"] = true
		out["update_log"] = updatetx.LogTail(30)
	}
}
