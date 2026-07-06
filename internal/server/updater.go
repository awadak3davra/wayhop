package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"wayhop/internal/updater"
	"wayhop/internal/version"
)

// handleUpdaterEngines lists managed engines with their installed status (no network).
func (s *Server) handleUpdaterEngines(w http.ResponseWriter, r *http.Request) {
	type item struct {
		updater.Engine
		Installed     updater.Installed `json:"installed"`
		LastError     string            `json:"last_error,omitempty"`
		NativeManaged bool              `json:"native_managed,omitempty"` // owned by opkg/apk at its path -> update via the PM, not the panel
		NativeOwner   string            `json:"native_owner,omitempty"`   // the owning package, for the UI hint ("apk upgrade <pkg>")
	}
	out := make([]item, 0, len(updater.Engines))
	for _, e := range updater.Engines {
		owner, managed := s.updater.NativeManagedInfo(e)
		out = append(out, item{Engine: e, Installed: s.updater.Installed(e), LastError: s.updErr(e.ID), NativeManaged: managed, NativeOwner: owner})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"arch":            s.updater.Arch,
		"mirrors":         s.updater.Mirrors,
		"package_manager": string(s.updater.PMKind()),
		"engines":         out,
	})
}

// handleUpdaterVersions returns the latest + recent release tags via mirrors.
func (s *Server) handleUpdaterVersions(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	if e.SourceOnly {
		resp := map[string]any{"source_only": true, "note": e.Note, "installed": s.updater.Installed(*e).Version}
		if tags, err := s.updater.Tags(ctx, *e, 15); err != nil {
			resp["error"] = err.Error()
		} else {
			resp["versions"] = tags
			if len(tags) > 0 {
				resp["latest"] = tags[0]
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	rels, err := s.updater.List(ctx, *e, 15)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not reach the release source (try a mirror in config): "+err.Error())
		return
	}
	tags := make([]string, 0, len(rels))
	for _, rl := range rels {
		tags = append(tags, rl.Tag)
	}
	// "latest" must be the newest STABLE release: GitHub returns newest-first, but the top entry can
	// be a prerelease (e.g. a sing-box 1.14.0-alpha that outranks the 1.12.x line the panel targets),
	// which must never be surfaced as the recommended version. LatestStable skips prereleases.
	latest := updater.LatestStable(rels)
	writeJSON(w, http.StatusOK, map[string]any{
		"latest":    latest,
		"versions":  tags,
		"installed": s.updater.Installed(*e).Version,
	})
}

// handleUpdaterInstall downloads + installs a chosen version (the side-effecting action).
func (s *Server) handleUpdaterInstall(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	var body struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Version == "" {
		writeErr(w, http.StatusBadRequest, "version required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	tag, err := s.updater.Install(ctx, *e, body.Version)
	if err != nil {
		// A native-PM policy refusal is a 409 (permanent state: "use opkg/apk"), NOT an install
		// failure — don't persist it as last_error, which nothing could ever clear for a PM-owned
		// engine (both clearing paths, a successful install or uninstall, are refused forever).
		var nm *updater.NativeManagedError
		if errors.As(err, &nm) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.setUpdErr(e.ID, err.Error())
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.setUpdErr(e.ID, "") // a successful install clears any prior failure reason
	// If we updated the running primary core, reload it — UNDER applyMu so it can't
	// interleave with handleApply's / the fail-safe's Stop+Start+Reload. Reload drops the
	// core's lock between Stop and Start, so two concurrent reloads could each spawn a
	// sing-box while the other's old process is still draining — two instances both
	// installing TUN auto_route / auto_redirect kernel rules. applyMu is the same gate the
	// apply path holds end-to-end, making the two mutually exclusive. Re-check Running()
	// under the lock so we don't resurrect a core an in-flight apply intentionally stopped.
	reloaded := false
	if e.ID == "sing-box" && s.singbox != nil {
		s.applyMu.Lock()
		if s.singbox.Running() {
			if err := s.singbox.Reload(); err == nil {
				reloaded = true
			}
		}
		s.applyMu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": tag, "engine": e.ID, "reloaded": reloaded})
}

// handleUpdaterUninstall deletes an installed engine binary from BinDir. A RUNNING engine's binary
// can't be cleanly removed — the deleted inode keeps running as an unmanageable orphan (holding
// ports/locks) — so we stop the process FIRST. For the core (sing-box) that stops the VPN datapath,
// so it needs an explicit stop:true; core.Stop() also clears Desired() so the watchdog leaves it
// down instead of respawning onto a now-missing binary. Plugin engines are stopped via
// plugins.StopByBin with no stop:true gate (removing a plugin implies stopping it; the gate is
// core-only by design). ORDER MATTERS: every reason Uninstall could refuse (PM-owned binary,
// source-only, nothing panel-installed) is prechecked BEFORE any process is stopped — otherwise a
// refusal would leave the core down (watchdog disarmed) with nothing removed: routing dead on a
// router whose sing-box belongs to opkg/apk.
func (s *Server) handleUpdaterUninstall(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	if err := s.updater.UninstallPrecheck(*e); err != nil {
		var nm *updater.NativeManagedError
		if errors.As(err, &nm) {
			writeErr(w, http.StatusConflict, err.Error()) // policy conflict: defer to opkg/apk
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var body struct {
		Stop bool `json:"stop"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	stopped := false
	if e.ID == "sing-box" && s.singbox != nil && s.singbox.Running() {
		if !body.Stop {
			writeErr(w, http.StatusConflict, "sing-box is running — resend with stop:true to stop the core and remove it (this stops the VPN datapath)")
			return
		}
		s.applyMu.Lock()
		err := s.singbox.Stop() // clears Desired() → watchdog won't respawn it
		s.applyMu.Unlock()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not stop sing-box before removal: "+err.Error())
			return
		}
		stopped = true
	}
	if e.ID != "sing-box" && s.plugins != nil {
		// Plugin engines (olcRTC etc.): stop the running plugin proc before removal so the removed
		// binary can't leave an orphan (no stop:true gate — removing a plugin implies stopping it;
		// the gate is only for the routing core). No-op if it isn't a running plugin.
		if n := s.plugins.StopByBin(e.BinName); n > 0 {
			stopped = true
		}
	}
	if err := s.updater.Uninstall(*e); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setUpdErr(e.ID, "") // a removed engine carries no stale failure reason
	writeJSON(w, http.StatusOK, map[string]any{"removed": e.ID, "stopped": stopped})
}

// setUpdErr records (msg != "") or clears (msg == "") an engine's last install-failure reason
// so the Updater UI can show WHY it failed even after the toast fades or the page reloads.
func (s *Server) setUpdErr(id, msg string) {
	s.updErrMu.Lock()
	defer s.updErrMu.Unlock()
	if s.updErrs == nil {
		s.updErrs = map[string]string{}
	}
	if msg == "" {
		delete(s.updErrs, id)
	} else {
		s.updErrs[id] = msg
	}
}

// updErr returns an engine's last recorded install-failure reason ("" if none).
func (s *Server) updErr(id string) string {
	s.updErrMu.Lock()
	defer s.updErrMu.Unlock()
	return s.updErrs[id]
}

// --- WayHop self-update ---------------------------------------------------

// handleSelfStatus reports WayHop's own version and whether a newer release exists.
func (s *Server) handleSelfStatus(w http.ResponseWriter, r *http.Request) {
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	out := map[string]any{
		"current":     version.Version,
		"repo":        repo,
		"arch":        s.updater.Arch,
		"auto_update": c.Updater.AutoUpdate,
	}
	if exe, err := os.Executable(); err == nil {
		out["native_managed"] = s.updater.SelfManaged(exe) // opkg/apk owns the wayhop binary -> upgrade via the PM, not the panel
	}
	out["package_manager"] = string(s.updater.PMKind())
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rel, err := s.updater.SelfLatest(ctx, repo)
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["latest"] = rel.Tag
		out["update_available"] = updater.Newer(version.Version, rel.Tag)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSelfUpdate downloads + swaps the WayHop binary for the latest (or a given)
// release, then restarts the service so the new binary takes over. The swap is guarded
// by a sanity-run of the new binary (see updater.SelfUpdate); the old binary is kept at
// <exe>.bak for manual rollback.
func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	tag := body.Version
	if tag == "" {
		rel, err := s.updater.SelfLatest(ctx, repo)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		tag = rel.Tag
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot locate the running binary: "+err.Error())
		return
	}
	installed, err := s.updater.SelfUpdate(ctx, repo, tag, exe)
	if err != nil {
		var nm *updater.NativeManagedError
		if errors.As(err, &nm) {
			writeErr(w, http.StatusConflict, err.Error()) // policy: wayhop is PM-owned — upgrade via opkg/apk
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	cmd := restartCommand()
	if cmd == nil {
		writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": false,
			"note": "binary swapped; restart the service manually to apply (or this is the demo)"})
		return
	}
	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": false, "note": "restart failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": true})
}

// handleSelfAuto toggles background auto-update of WayHop itself.
func (s *Server) handleSelfAuto(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	s.cfgMu.Lock()
	s.cfg.Updater.AutoUpdate = body.Enabled
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auto_update": body.Enabled})
}

// AutoUpdateLoop periodically (daily) checks for a newer WayHop release and, when
// Updater.AutoUpdate is enabled, installs it and restarts. Off by default; the first
// check is delayed so a crash-looping bad release can't hammer updates on boot.
func (s *Server) AutoUpdateLoop(ctx context.Context) {
	t := time.NewTimer(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(24 * time.Hour)
		}
		c := s.config()
		if !c.Updater.AutoUpdate {
			continue
		}
		repo := c.Updater.SelfRepo
		if repo == "" {
			repo = updater.DefaultSelfRepo
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		rel, err := s.updater.SelfLatest(cctx, repo)
		if err != nil || !updater.Newer(version.Version, rel.Tag) {
			cancel()
			continue
		}
		exe, err := os.Executable()
		if err != nil {
			cancel()
			continue
		}
		installed, err := s.updater.SelfUpdate(cctx, repo, rel.Tag, exe)
		cancel()
		if err != nil {
			log.Printf("auto-update: %v", err)
			continue
		}
		log.Printf("auto-update: installed wayhop %s, restarting", installed)
		if cmd := restartCommand(); cmd != nil {
			_ = cmd.Start()
		}
		return // being restarted
	}
}
