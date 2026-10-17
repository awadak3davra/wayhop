package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/platform"
	"wayhop/internal/updater"
)

// awgnetifd.go is the netifd half of the kernel path on OpenWrt. netifd reads its protocol handlers
// (/lib/netifd/proto/*.sh) only when it starts, so after amneziawg-tools installs or changes
// amneziawg.sh the running netifd still has the old one - or none: an amneziawg interface written then
// does not come up, or comes up without the AmneziaWG 3.x options the old handler did not read. The
// installer says so (netifd_restart_needed) and restarts netifd only when asked (--restart-network),
// because a netifd restart takes every link on the router down for a few seconds.
//
// The Components row offers that restart as a button, and the alternative - the next reboot does it
// anyway. The Apply review warns while it is pending and an Apply would write an amneziawg interface.

// errNetworkRestartUnavailable: this host has no OpenWrt network service to restart.
var errNetworkRestartUnavailable = errors.New("this router has no /etc/init.d/network to restart")

// awgNetifdRestartPending reports whether netifd still runs an older amneziawg handler than the file on
// flash. Measured where it can be - the handler's change time against netifd's start - and otherwise
// what the last install reported, which is all the demo (or a router where netifd cannot be found) has.
func (s *Server) awgNetifdRestartPending() bool {
	if s.detectedPlatform() != platform.OpenWrt && !s.config().Demo {
		return false
	}
	stale, known := false, false
	switch {
	case s.netifdStaleOf != nil:
		stale, known = s.netifdStaleOf()
	case !s.config().Demo:
		stale, known = measureNetifdStale()
	}
	if known {
		return stale
	}
	return s.awgNetifdPending.Load()
}

// measureNetifdStale compares the handler's change time with netifd's start. ctime, not mtime: opkg and
// apk keep the package's own file times, so the mtime is when the package was built; the ctime is when
// this router wrote the file. known is false when either cannot be read.
func measureNetifdStale() (stale, known bool) {
	changed, ok := fileChangeTime(awgHandlerPath)
	if !ok {
		return false, false // no handler: nothing for netifd to read
	}
	started, ok := netifdStartTime("/proc")
	if !ok {
		return false, false
	}
	return netifdStale(changed, started), true
}

// netifdStale: the handler changed after netifd started. A second of slack absorbs the clock-tick
// rounding of a process start time; a handler written in the same second netifd started was read by it.
func netifdStale(handlerChanged, netifdStarted time.Time) bool {
	return handlerChanged.After(netifdStarted.Add(time.Second))
}

// netifdStartTime finds the running netifd under proc and returns when it started.
func netifdStartTime(proc string) (time.Time, bool) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return time.Time{}, false
	}
	stat, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return time.Time{}, false
	}
	boot, ok := parseBootTime(string(stat))
	if !ok {
		return time.Time{}, false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil || !e.IsDir() {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(proc, e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "netifd" {
			continue
		}
		pstat, err := os.ReadFile(filepath.Join(proc, e.Name(), "stat"))
		if err != nil {
			continue
		}
		if ticks, ok := parseProcStartTicks(string(pstat)); ok {
			// USER_HZ is 100 on every Linux the router builds target; /proc reports in it.
			return time.Unix(boot, 0).Add(time.Duration(ticks) * (time.Second / 100)), true
		}
	}
	return time.Time{}, false
}

// parseBootTime reads "btime <unix seconds>" from /proc/stat.
func parseBootTime(stat string) (int64, bool) {
	for _, line := range strings.Split(stat, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "btime" {
			v, err := strconv.ParseInt(f[1], 10, 64)
			return v, err == nil && v > 0
		}
	}
	return 0, false
}

// parseProcStartTicks reads starttime, field 22 of /proc/<pid>/stat, in clock ticks since boot. The
// command name (field 2) is in parentheses and may hold spaces, so fields are counted after its last ')'.
func parseProcStartTicks(stat string) (uint64, bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(stat[i+1:])
	const startTimeAfterComm = 22 - 3 // fields 3.. follow the name
	if len(f) <= startTimeAfterComm {
		return 0, false
	}
	v, err := strconv.ParseUint(f[startTimeAfterComm], 10, 64)
	return v, err == nil
}

// awgNetifdReport is the installer's netifd account, which the updater's verdict parser does not keep.
type awgNetifdReport struct {
	RestartNeeded *bool `json:"netifd_restart_needed"`
	Restarted     *bool `json:"network_restarted"`
}

// parseAWGNetifd reads the netifd fields from the verdict on the last non-empty line of stdout. The
// verdict itself is judged by updater.AWGInstaller; these fields are only read beside a run it accepted.
func parseAWGNetifd(stdout []byte) awgNetifdReport {
	lines := bytes.Split(bytes.TrimSpace(stdout), []byte("\n"))
	var r awgNetifdReport
	if len(lines) == 0 {
		return r
	}
	last := bytes.TrimSpace(lines[len(lines)-1])
	if len(last) == 0 || last[0] != '{' || json.Unmarshal(last, &r) != nil {
		return awgNetifdReport{}
	}
	return r
}

// awgInstallerWith is the embedded installer with --restart-network passed when the operator asked for
// it, recording the netifd account of the run in report.
func (s *Server) awgInstallerWith(restartNetwork bool, report *awgNetifdReport) updater.AWGInstaller {
	inst := s.awgInstaller()
	inner := inst.Run
	if inner == nil {
		inner = updater.ExecAWGRun
	}
	demo := s.config().Demo
	inst.Run = func(ctx context.Context, argv []string) (updater.AWGOutput, error) {
		if restartNetwork {
			argv = append(append([]string(nil), argv...), "--restart-network")
		}
		out, err := inner(ctx, argv)
		*report = parseAWGNetifd(out.Stdout)
		if demo && report.RestartNeeded == nil && strings.Contains(string(out.Stdout), `"path":"kmod"`) &&
			!strings.Contains(strings.Join(argv, " "), "--uninstall") {
			// The demo's runner predates the netifd fields. A kernel-module install on a real router adds
			// the handler, so the demo answers as one would - and changes nothing either way.
			needed := !restartNetwork || strings.Contains(strings.Join(argv, " "), "--dry-run")
			restarted := !needed
			report.RestartNeeded, report.Restarted = &needed, &restarted
		}
		return out, err
	}
	return inst
}

// netifdNote is what the row says about netifd after a run, appended to the run's summary; "" when the
// run did not touch the handler.
func netifdNote(run updater.AWGRun, r awgNetifdReport) string {
	switch {
	case r.Restarted != nil && *r.Restarted:
		return "; the network service was restarted, so netifd now uses the new AmneziaWG handler"
	case r.RestartNeeded == nil || !*r.RestartNeeded:
		return ""
	case run.Op == "plan":
		return "; it adds or changes netifd's AmneziaWG handler, which netifd reads only when the network service restarts"
	}
	return "; the network service must restart before AmneziaWG 3.x settings reach netifd's new handler: restart it now from this row " +
		"(every link on the router drops for a few seconds), or it happens at the next reboot"
}

// handleAWGRestartNetwork answers POST /api/updater/awg/restart-network: restart netifd so it reads the
// AmneziaWG handler the installer added or changed. The restart is started detached - its own session,
// not this request's context - so it outlives the request whose connection it may drop, and it waits a
// second so this answer is sent first.
func (s *Server) handleAWGRestartNetwork(w http.ResponseWriter, r *http.Request) {
	const effect = "every link on the router drops for a few seconds while netifd restarts"
	if s.config().Demo {
		s.awgNetifdPending.Store(false)
		writeJSON(w, http.StatusOK, map[string]any{"restarting": false, "demo": true,
			"summary": "Demo mode, nothing was changed. On a router the network service would restart now: " + effect + "."})
		return
	}
	if s.detectedPlatform() != platform.OpenWrt {
		writeErr(w, http.StatusUnprocessableEntity, "only OpenWrt's netifd reads AmneziaWG's protocol handler; there is no network service to restart here")
		return
	}
	// Not under a package operation: an install that is still writing the handler, or restarting netifd
	// itself, must finish first.
	if !pmMu.TryLock() {
		writeErr(w, http.StatusConflict, "another package operation is running; try again when it finishes")
		return
	}
	defer pmMu.Unlock()
	start := startNetworkRestart
	if s.networkRestartOf != nil {
		start = s.networkRestartOf
	}
	if err := start(); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNetworkRestartUnavailable) {
			code = http.StatusServiceUnavailable
		}
		writeErr(w, code, "could not restart the network service: "+err.Error())
		return
	}
	s.awgNetifdPending.Store(false)
	log.Printf("updater: restarting the network service for AmneziaWG's netifd handler, as the operator asked; %s", effect)
	writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true,
		"summary": "The network service is restarting: " + effect + ", then netifd uses the new AmneziaWG handler."})
}

// startNetworkRestart starts the detached restart (networkRestartCommand) and reaps it when it ends:
// unlike the service restart, this one does not take the daemon with it.
func startNetworkRestart() error {
	cmd := networkRestartCommand()
	if cmd == nil {
		return errNetworkRestartUnavailable
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
