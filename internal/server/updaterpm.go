package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"wayhop/internal/updater"
)

// updaterpm.go exposes the native package-manager delegation the panel already carried and could not
// reach: install, roll back and remove an engine that opkg or apk owns, instead of telling the
// operator to go and do it over SSH.
//
// Two endpoints, deliberately split, for the same reason the UCI writer previews its commands:
//
//	GET  /api/updater/{id}/pm/plan   — what WOULD run, and every precondition, having run nothing
//	POST /api/updater/{id}/pm/apply  — run the command that was shown, and only that one
//
// The GET answers 200 even when the plan is BLOCKED. The plan is the payload, not the outcome: a
// refusal carries the checks that produced it, and that list is the whole improvement over the
// paragraph of prose the page shows today. Making a blocked plan a 4xx would leave the UI with an
// error string and nothing to display, which is what it already has.
//
// The POST is where a refusal is a status code: it mutates the system package database.

// pmMu serializes package-manager operations. opkg and apk take a database lock of their own and a
// second concurrent run fails on it — but the failure surfaces halfway through, with the box in
// whatever state the first run reached. One at a time, from this daemon at least.
var pmMu sync.Mutex

// pmActions is the allow-list. The action arrives from the client, and PlanAction is a string type,
// so without this any string would reach the planner's switch and fall through to its default.
var pmActions = map[string]updater.PlanAction{
	"install":  updater.PlanInstall,
	"upgrade":  updater.PlanUpgrade,
	"rollback": updater.PlanRollback,
	"remove":   updater.PlanRemove,
}

// handleUpdaterPMRefreshPlan exposes the exact catalog-refresh command and runs nothing. Refreshing
// indexes is deliberately separate from upgrading packages: the first makes information current;
// the second replaces binaries and needs its own component-level review.
func (s *Server) handleUpdaterPMRefreshPlan(w http.ResponseWriter, r *http.Request) {
	argv := s.updater.PMRefreshArgv()
	if len(argv) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"manager": "", "blocked": "no supported package manager is available", "argv": []string{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manager": string(s.updater.PMKind()), "argv": argv,
		"note": "refreshes package indexes only; no installed package is changed",
	})
}

func (s *Server) handleUpdaterPMRefreshApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Argv []string `json:"argv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	want := s.updater.PMRefreshArgv()
	if !sameUpdaterArgv(body.Argv, want) {
		writeErr(w, http.StatusConflict, "the package refresh command changed; review it again")
		return
	}
	pmMu.Lock()
	defer pmMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	output, err := s.updater.RefreshPM(ctx)
	if err != nil {
		// opkg returns non-zero when ANY configured feed fails, even after other feeds were fetched
		// and installed successfully. Treating that as an all-or-nothing failure leaves the page on
		// stale data and lies about the useful work that did complete. Count only opkg's own fixed
		// success marker; never return command output or repository URLs to the browser.
		if s.updater.PMKind() == "opkg" {
			updated := strings.Count(output, "Updated list of available packages in ")
			if updated > 0 {
				writeJSON(w, http.StatusOK, map[string]any{
					"manager": string(s.updater.PMKind()), "refreshed": true,
					"partial": true, "updated_sources": updated,
					"warning": "some package repositories failed; check their configuration",
				})
				return
			}
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "package lists could not be refreshed; check the router's internet connection and repository configuration",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manager": string(s.updater.PMKind()), "refreshed": true,
	})
}

func sameUpdaterArgv(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) handleUpdaterPMPlan(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	action, ok := pmActions[r.URL.Query().Get("action")]
	if !ok {
		writeErr(w, http.StatusBadRequest, "action must be one of install, upgrade, rollback, remove")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	plan := s.updater.PlanPM(ctx, *e, action, r.URL.Query().Get("version"))
	writeJSON(w, http.StatusOK, plan)
}

// handleUpdaterPMCandidates lists the builds the FEED offers for this engine — what a rollback picker
// needs. Separate from /versions, which asks GitHub: these are two different sources and answering
// with one while the other is what will be installed is how a picker offers a build the box cannot
// get.
func (s *Server) handleUpdaterPMCandidates(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// Planning a no-op action is how the package name is resolved: it performs the same ownership and
	// file-list verification, so a candidate list can never be about a different package from the one
	// the buttons would act on.
	plan := s.updater.PlanPM(ctx, *e, updater.PlanUpgrade, "")
	// Blocked for want of DISK is not a reason to withhold the list of builds: a router too full to
	// take the feed's newest build is exactly the one whose operator is looking for an older, smaller
	// one. The plan is used here only to resolve and verify the package name, and it carries that as
	// soon as the ownership and file-list checks pass — so an empty Package is the honest test, and it
	// means the panel could not establish WHICH package these builds would belong to.
	if plan.Package == "" {
		writeJSON(w, http.StatusOK, map[string]any{"blocked": plan.Blocked, "checks": plan.Checks})
		return
	}
	// Whether a named build can be installed AT ALL is a property of the box, and the page asks here
	// because this is the call the rollback flow makes first. Without it the panel listed the feed's
	// builds on an opkg router, let the operator choose one, and only then answered that opkg cannot
	// install a named version — a menu with nothing behind it, and the refusal arriving after the
	// choice. The reason travels with the flag so the page states the daemon's sentence rather than
	// inventing its own.
	resp := map[string]any{"package": plan.Package, "can_pin": s.updater.PMCanPinVersion()}
	if !s.updater.PMCanPinVersion() {
		resp["cannot_pin_reason"] = "opkg cannot install a named version; rolling back needs that build's .ipk installed as a file"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	cands, err := s.updater.PMCandidates(ctx, plan.Package)
	if err != nil {
		// apk/opkg output can repeat configured repository URLs, including private feed tokens.
		writeErr(w, http.StatusBadGateway, "package catalog could not be read; refresh package lists and retry")
		return
	}
	resp["candidates"] = cands
	writeJSON(w, http.StatusOK, resp)
}

// pmCoreState is the routing core as this path needs it: is it up, and take it down. It is a pair of
// funcs rather than the *core.SingBox itself because a test cannot make one report Running() without
// starting a real process, and "the core IS running" is the entire case being guarded — the same
// arrangement other command-backed test seams use, for the same reason.
type pmCoreState struct {
	running func() bool
	stop    func() error
	// stopPlugin stops every supervised plugin proc launched from this engine binary, returning how
	// many. The core is not the only engine whose file `apk del` deletes.
	stopPlugin func(bin string) int
	// reload restarts the core onto the binary now on disk. Replacing a file does not change the
	// process already running from it: apk unlinks the old inode and writes a new one, and the
	// running sing-box keeps executing the old one until it is restarted.
	//
	// It reports whether it actually reloaded, which is NOT the same as "no error": a core that was
	// not running is nothing to reload, and answering `reloaded:true` there would be the same false
	// report of success this whole call exists to prevent.
	reload func() (bool, error)
	// restartPlugin is reload's counterpart for a plugin engine: the core is not the only process
	// that keeps running the file it was exec'd from. Returns how many procs were restarted.
	restartPlugin func(bin string) int
	// restore brings a core that this path STOPPED back up, after the package operation it was
	// stopped for was aborted (a second-preflight refusal or an apk/opkg failure). A remove that did
	// not happen must not leave the datapath down: the binary is still on disk, so the core can and
	// must be started again. Unlike reload (which only acts on an ALREADY-running core), restore
	// re-asserts desired=true and spawns — the mirror image of stop. It returns an error only when the
	// core could not be brought back, which is a separate, worse result than the abort that caused it.
	restore func() error
	// restorePlugin is restore's counterpart for a plugin engine: re-launch the desired plugin specs
	// after a removal was stopped-then-aborted. Best-effort and unconditional (the procs are already
	// stopped, so there is nothing to count first), mirroring how restartPlugin re-syncs.
	restorePlugin func()
}

// pmCore returns the injected state in tests, or the real core.
func (s *Server) pmCore() pmCoreState {
	if s.pmCoreHook != nil {
		return *s.pmCoreHook
	}
	return pmCoreState{
		running: func() bool { return s.singbox != nil && s.singbox.Running() },
		stop: func() error {
			if s.singbox == nil {
				return nil
			}
			// Stop() also clears Desired(), so the watchdog stands down instead of respawning onto a
			// binary that is about to stop existing. applyMu is the same lock handleUpdaterUninstall
			// takes around its stop.
			s.applyMu.Lock()
			defer s.applyMu.Unlock()
			return s.singbox.Stop()
		},
		stopPlugin: func(bin string) int {
			if s.plugins == nil {
				return 0
			}
			return s.plugins.StopByBin(bin)
		},
		reload: func() (bool, error) {
			if s.singbox == nil {
				return false, nil
			}
			// applyMu is the same gate handleApply holds end-to-end, and the same one the sibling
			// install path takes here: Reload drops the core's lock between Stop and Start, so two
			// concurrent reloads could each spawn a sing-box while the other's old process is still
			// draining — two instances both installing TUN auto_route rules. Running() is re-checked
			// under the lock so an in-flight apply's deliberate stop is not resurrected.
			s.applyMu.Lock()
			defer s.applyMu.Unlock()
			if !s.singbox.Running() {
				return false, nil
			}
			if err := s.singbox.Reload(); err != nil {
				return false, err
			}
			return true, nil
		},
		restartPlugin: func(bin string) int {
			if s.plugins == nil {
				return 0
			}
			// Stop deletes the proc entries, and Supervise only relaunches procs it still holds — so
			// stopping alone would leave the tunnel down until the next Apply. Re-Syncing the SAME
			// desired set is what brings them back, now exec'ing the file the package just wrote.
			// This is the manager's own API and nothing else: no regeneration, no kernel plane, no
			// core stop, none of which belong in a package upgrade.
			n := s.plugins.StopByBin(bin)
			if n > 0 {
				s.plugins.Sync(s.plugins.Specs())
			}
			return n
		},
		restore: func() error {
			if s.singbox == nil {
				return nil
			}
			// The compensation for an aborted remove: bring the core back the same way it was taken
			// down. Start() re-asserts desired=true (re-arming the watchdog stop() disarmed) and spawns
			// the process onto the binary still on disk — under the same applyMu the stop held, so it
			// cannot interleave with an in-flight apply. If the binary really is gone (a partial remove
			// that got far enough to unlink it), Start() fails and the caller reports that separately.
			s.applyMu.Lock()
			defer s.applyMu.Unlock()
			return s.singbox.Start()
		},
		restorePlugin: func() {
			if s.plugins == nil {
				return
			}
			// Re-launch the desired plugin specs after an aborted removal — the same re-sync
			// restartPlugin uses to bring a proc back, but unconditional: the procs were already
			// stopped on the way to a removal that did not happen, and the desired set still names them.
			s.plugins.Sync(s.plugins.Specs())
		},
	}
}

func (s *Server) handleUpdaterPMApply(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	var body struct {
		Action  string   `json:"action"`
		Version string   `json:"version"`
		Argv    []string `json:"argv"` // exactly what the operator was shown
		// Steps is the whole sequence when the plan had more than one command — the low-space upgrade
		// that removes the installed build before writing the new one. Sent back for the same reason
		// Argv is: consent is to the commands that were displayed, and the daemon re-plans and refuses
		// if they are no longer the commands it would run.
		Steps [][]string `json:"steps"`
		Stop  bool       `json:"stop"` // acknowledged: stopping the core is part of what was asked for
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	action, ok := pmActions[body.Action]
	if !ok {
		writeErr(w, http.StatusBadRequest, "action must be one of install, upgrade, rollback, remove")
		return
	}
	// The approved argv is REQUIRED. Without it a client could ask for "remove" and have whatever the
	// planner decides run unseen, which is precisely the confirmation this design exists to provide.
	if len(body.Argv) == 0 {
		writeErr(w, http.StatusBadRequest, "argv required: send back the command the plan showed you")
		return
	}

	pmMu.Lock()
	defer pmMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	approved := updater.PMPlan{Argv: body.Argv, Steps: body.Steps}
	// Removing the package removes the FILE. The panel's own uninstall path has stopped the process
	// first since the day it was written — a deleted binary keeps running as an orphan holding ports
	// and locks, and the watchdog, whose Desired() is still set, respawns onto a path that no longer
	// exists — and `apk del sing-box` is that same deletion reached through a different door. This
	// door had no guard at all: the operator could confirm the command and take the router's datapath
	// down with no warning that it was about to happen.
	//
	// The refusal is checked BEFORE the stop, which is the whole reason PreflightPM exists separately.
	// Stopping first and refusing second is the inversion that leaves the core down with nothing
	// removed: routing dead on a router whose sing-box belongs to the package manager.
	//
	// The core is not the only engine this applies to. A plugin's binary is deleted by the same
	// command and leaves the same orphan, which is why the sibling path stops plugin procs too — with
	// no acknowledgement gate, because removing a tunnel plugin obviously implies stopping it, while
	// stopping the routing core is a decision about the whole router.
	// What this remove took down before reaching the package manager, so a package operation that is
	// then refused or fails can put it back. The stop happens between the two preflights, and the
	// window between them is exactly where an external opkg/apk run (or a transient probe error) can
	// turn ExecutePM's re-check into a refusal — leaving the datapath down with nothing removed unless
	// we compensate. Tracked at handler scope because the compensation runs after ExecutePM returns.
	stoppedProcs := 0
	stoppedCore := false
	stoppedPluginBin := ""
	var core pmCoreState
	// Whether the datapath is about to go down is a property of the PLAN, not of the verb. A removal
	// deletes the binary; so does the first command of a low-space upgrade, which removes the
	// installed build because the new one fits only in the room it is holding. The gate used to ask
	// "is this action remove?", which would have walked an upgrade straight past the stop, the
	// acknowledgement and the compensation into deleting a running core's binary unannounced.
	prePlan, perr := s.updater.PreflightPM(ctx, *e, action, body.Version, approved)
	if perr != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": perr.Error(), "plan": prePlan})
		return
	}
	core = s.pmCore()
	if prePlan.DeletesInstalled() {
		switch e.ID {
		case "sing-box":
			if core.running() {
				if !body.Stop {
					writeJSON(w, http.StatusConflict, map[string]any{
						"error":      pmStopPrompt(action, prePlan),
						"needs_stop": true,
						"plan":       prePlan,
					})
					return
				}
				// Logged, because this is the moment the household's routing stops and until now it
				// left no trace at all: the whole package path wrote exactly one line, and only for a
				// FAILED reload. An operator whose internet died after pressing Remove had nothing in
				// the log saying the daemon had stopped the core on purpose — and the ordering this
				// code is careful about (stop, THEN delete) could not be confirmed after the fact by
				// anyone, including a test, without polling the device hard enough to change it.
				log.Printf("updater: stopping sing-box before %s (approved by the operator) — the VPN datapath is down from here until the binary is back", action)
				if err := core.stop(); err != nil {
					writeErr(w, http.StatusInternalServerError, "could not stop sing-box first: "+err.Error())
					return
				}
				log.Printf("updater: sing-box stopped")
				stoppedProcs++
				stoppedCore = true
			}
		default:
			if n := core.stopPlugin(e.BinName); n > 0 {
				stoppedProcs += n
				stoppedPluginBin = e.BinName
			}
		}
	}

	// compensate puts back whatever this remove stopped, when the package operation was aborted AFTER
	// the stop. It returns "" when there was nothing to undo or the core/plugin came back, or a
	// description when it could NOT be brought back — a state worse than the abort that triggered it,
	// which the caller reports on its own rather than folding into the package-manager error.
	compensate := func() string {
		switch {
		case stoppedCore && core.restore != nil:
			if err := core.restore(); err != nil {
				log.Printf("updater: %s %s was aborted AND sing-box could not be restarted: %v", action, e.ID, err)
				return "sing-box was stopped for the removal, the removal did not complete, and the core could not be restarted: " + err.Error()
			}
			log.Printf("updater: %s %s aborted; sing-box restarted, datapath restored", action, e.ID)
		case stoppedPluginBin != "" && core.restorePlugin != nil:
			core.restorePlugin()
			log.Printf("updater: %s %s aborted; %s plugin re-synced", action, e.ID, e.ID)
		}
		return ""
	}

	// Two lines around the package manager itself, for the same reason: this is where the binary is
	// written or deleted, and the pair of timestamps is what makes the stop-then-delete ordering
	// readable afterwards from the daemon's own record instead of from an observer standing over it.
	log.Printf("updater: %s %s via the package manager (%d proc(s) stopped first)", action, e.ID, stoppedProcs)
	out, plan, err := s.updater.ExecutePM(ctx, *e, action, body.Version, approved)
	if err != nil {
		// Whatever the classification below, the stop that preceded this must be undone: the package
		// operation did not happen, so a core or plugin taken down for it has to come back. Run the
		// compensation once and attach its outcome to whichever response is sent.
		rollbackErr := compensate()
		addDatapath := func(resp map[string]any) {
			if rollbackErr != "" {
				resp["rollback_error"] = rollbackErr // could not restore — a separate, worse result
			} else if stoppedCore || stoppedPluginBin != "" {
				resp["datapath_restored"] = true // stopped, then the abort was compensated
			}
		}
		// A refusal is a conflict, not a server failure, and it is not an install error either: it
		// must not be persisted as last_error, which nothing could then clear. Same reasoning as the
		// NativeManagedError path in handleUpdaterInstall.
		if !plan.Runnable() || errors.Is(err, updater.ErrPMRefused) || plan.Blocked != "" {
			resp := map[string]any{"error": err.Error(), "plan": plan}
			addDatapath(resp)
			writeJSON(w, http.StatusConflict, resp)
			return
		}
		// The command ran and the package manager failed. That IS an engine error worth remembering.
		s.setUpdErr(e.ID, err.Error())
		resp := map[string]any{"error": err.Error(), "output": out, "plan": plan}
		addDatapath(resp)
		writeJSON(w, http.StatusBadGateway, resp)
		return
	}
	s.setUpdErr(e.ID, "")
	// The closing half of the pair above. Together the two lines carry the ordering — stop, then the
	// package manager, then this — in the daemon's own timestamps.
	log.Printf("updater: %s %s finished", action, e.ID)

	// Replacing the file does not replace the PROCESS. apk unlinks the old inode and writes a new one,
	// so a running sing-box keeps executing the build that was there before — and the panel would then
	// read the version by exec'ing the NEW file and report the upgrade as done. A rollback is the worst
	// of it: the operator rolls back precisely because the current build misbehaves, and the
	// misbehaving process keeps running while the page says the older version is installed.
	//
	// The sibling install path has reloaded the core here since it was written; this is the same call
	// with the same lock. NOT after a removal — the binary is gone, and Reload re-asserts desired=true,
	// which would point the watchdog at a file that no longer exists, undoing the stop above.
	// Demo mode runs DemoPM, whose mutating verbs deliberately change nothing and say so in their
	// output — "so nobody reads the output as a real install". The panel read it as one anyway: it has
	// only the HTTP status to go on, so a simulated apk add rendered the same "Installed." block as a
	// real one, directly above a State column still reading "not installed" and a toast saying nothing
	// was installed. Say it in the response instead of leaving the page to parse English out of the
	// package manager's line.
	resp := map[string]any{"output": out, "plan": plan, "stopped": stoppedProcs, "demo": s.demoMode()}
	//
	// A plugin engine has the same problem and needed the same answer: olcRTC's proc was exec'd from
	// the old file too, and nothing respawns it on its own — the watchdog's Supervise only relaunches
	// procs that DIED, so an upgraded plugin would keep serving the previous build until the next
	// Apply, with the page showing the new version. The core is simply the half that was noticed
	// first.
	if action != updater.PlanRemove && e.ID != "sing-box" {
		// A plugin STOPPED to make room is a different case from one merely re-exec'd after its file
		// changed: restartPlugin re-syncs only when it finds procs to stop, and there are none left to
		// find, so on the two-command path it would have returned 0 and left the tunnel down.
		if stoppedPluginBin != "" && core.restorePlugin != nil {
			core.restorePlugin()
			resp["restarted"] = stoppedProcs
		} else if core.restartPlugin != nil {
			if n := core.restartPlugin(e.BinName); n > 0 {
				resp["restarted"] = n
			}
		}
	}
	if action != updater.PlanRemove && e.ID == "sing-box" {
		// Reload restarts a RUNNING core onto the new file. It answers (false, nil) for a core that is
		// not running — correctly, there is nothing to reload — and on the low-space path the core is
		// not running because this handler stopped it to free the disk. Reloading there would have
		// reported a clean success over a router whose datapath never came back up.
		reloaded, rerr := false, error(nil)
		if stoppedCore {
			if err := core.restore(); err != nil {
				rerr = err
			} else {
				reloaded = true
			}
		} else {
			reloaded, rerr = core.reload()
		}
		switch {
		case rerr != nil:
			// The package changed and the core did not come back. Reporting a bare success here would be
			// the same false report the reload exists to prevent. Both paths re-assert desired=true, so
			// the watchdog keeps retrying.
			log.Printf("updater: %s %s succeeded but sing-box did not come back: %s", e.ID, action, rerr)
			resp["reload_error"] = rerr.Error()
		case reloaded:
			resp["reloaded"] = true
		}
	}
	// The package manager said OK. Ask it what is installed NOW, because those are two different
	// claims and this panel has already shipped one standing in for the other: `apk add` on an
	// installed package prints "OK: 76.6 MiB in 189 packages" and changes nothing, which is how the
	// Update button spent its life reporting success over a core that never moved. A check that costs
	// one query is the difference between that and a defect nobody can see from the panel.
	//
	// Not in demo mode, whose package manager deliberately changes nothing and says so.
	if action != updater.PlanRemove && !s.demoMode() && plan.Space != nil && plan.Space.TargetVersion != "" {
		if got, known := s.updater.PMInstalledVersion(ctx, plan.Package); known && got != plan.Space.TargetVersion {
			log.Printf("updater: %s %s reported success but %s is installed at %s, not %s",
				e.ID, action, plan.Package, got, plan.Space.TargetVersion)
			resp["verify_error"] = "the package manager reported success, but " + plan.Package +
				" is still at " + got + " instead of " + plan.Space.TargetVersion
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// pmStopPrompt is the question the operator answers before the core's binary is taken away. The two
// cases are genuinely different and were never going to be served by one sentence: a removal ends
// with sing-box gone on purpose, while a low-space upgrade removes the installed build only to make
// room for the next one and puts it straight back — but it does mean a window with no core on disk,
// and if the install then fails the router is left without one. Both facts belong in front of the
// click, with the figures that forced the choice.
func pmStopPrompt(action updater.PlanAction, plan updater.PMPlan) string {
	if action == updater.PlanRemove {
		return "sing-box is running, and removing the package deletes the binary the router " +
			"is using right now. That stops the VPN datapath until sing-box is installed again."
	}
	target := plan.Version
	if plan.Space != nil && plan.Space.TargetVersion != "" {
		target = plan.Space.TargetVersion
	}
	msg := "There is not enough free space to write " + target + " beside the installed build"
	if plan.Space != nil && plan.Space.Measured {
		msg += " (" + updater.MiB(plan.Space.Need) + " needed, " + updater.MiB(plan.Space.Avail) +
			" free in " + plan.Space.Dir + ")"
	}
	return msg + ", so the panel will remove the installed build first and then install " + target +
		". sing-box is stopped and off the disk between the two commands — the VPN datapath is down " +
		"for that window, and if the install fails the router is left without sing-box until it succeeds."
}
