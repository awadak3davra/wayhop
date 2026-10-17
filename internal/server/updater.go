package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"wayhop/internal/platform"
	"wayhop/internal/updater"
	"wayhop/internal/version"
)

// handleUpdaterEngines lists managed engines with their installed status (no network).
func (s *Server) handleUpdaterEngines(w http.ResponseWriter, r *http.Request) {
	type item struct {
		updater.Engine
		Installed     updater.Installed     `json:"installed"`
		LastError     string                `json:"last_error,omitempty"`
		Package       updater.PackageStatus `json:"package_status"`
		NativeManaged bool                  `json:"native_managed,omitempty"` // owned by opkg/apk at its path -> update via the PM, not the panel
		NativeOwner   string                `json:"native_owner,omitempty"`   // the owning package, for the UI hint ("apk upgrade <pkg>")
		// Ownership could not be determined (package manager busy or absent). NOT the same as
		// "not owned": the install/remove path refuses in this state, so the UI must not offer
		// controls that will be refused. Sent explicitly rather than omitted, so a client can tell
		// "unknown" from a field that simply was not populated.
		OwnershipUnknown bool `json:"ownership_unknown"`
		// CarriedByKernel says the router carries this engine's protocol natively, so the engine
		// binary is not needed here. Both halves of this were already known and never put side by
		// side: the engine list said "AmneziaWG (userspace) — not installed" while
		// /api/native/capabilities said `"amneziawg": true`, on a router whose kernel module was
		// carrying the operator's tunnel at that moment. The page could only report a gap.
		CarriedByKernel bool `json:"carried_by_kernel,omitempty"`
		// UsedBy names the configured connections and features that need this engine. It is what turns
		// the page from a catalog into an answer: an empty list means removing it breaks nothing and
		// that "not installed" is the normal state here, while a non-empty one names exactly what
		// would stop working. Populated for the core only — the other entries have no equivalent
		// question yet (a plugin is used by the connection that names it, which the row already says).
		UsedBy []string `json:"used_by,omitempty"`
		// AWG is the AmneziaWG 3 component's own block (awgcomponent.go): the one engine whose
		// "needed here" depends on the configured connections, not only on the router.
		AWG *awgComponentStatus `json:"awg,omitempty"`
	}
	// One capability probe for the whole list rather than one per engine: it reads /proc, /lib and the
	// package database, and doing that seven times to answer the same question would show up as a
	// slow page.
	caps := platform.DetectCapabilities()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Read the profile once, for the same reason: coreDependents walks endpoints and DNS servers, and
	// that answer is identical for every engine in the list.
	prof := s.store.Profile()
	coreUsers := coreDependents(prof, caps)
	out := make([]item, 0, len(updater.Engines))
	for _, e := range updater.Engines {
		pkg := s.updater.EnginePackageStatus(ctx, e)
		if e.ID == awgGoEngine {
			// Where the page first learns that a package owns amneziawg-go, the copy WayHop kept
			// compressed goes, before the row reads what is installed.
			s.awgDropStaleStore(pkg)
		}
		// InstalledFor, not Installed: a binary opkg/apk owns is reported at the package's version and
		// with the package as its source - amneziawg-go's own --version is upstream's stale constant.
		it := item{Engine: e, Installed: s.updater.InstalledFor(e, pkg), LastError: s.updErr(e.ID),
			Package: pkg, NativeManaged: pkg.Managed, NativeOwner: pkg.Package, OwnershipUnknown: !pkg.OwnershipKnown,
			CarriedByKernel: e.Provides != "" && caps.Native[e.Provides]}
		if e.Role == "core" {
			it.UsedBy = coreUsers
		}
		if e.Provides == "amneziawg" {
			st := s.awgComponent(ctx, prof)
			it.AWG = &st
			it.CarriedByKernel = awgCarriedByKernel(it.CarriedByKernel, st)
		}
		out = append(out, it)
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
		writeErr(w, http.StatusBadGateway, s.releaseSourceUnreachable("could not reach the release source (try a mirror in config): ", err))
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
	resp := map[string]any{
		"latest":    latest,
		"versions":  tags,
		"installed": s.updater.Installed(*e).Version,
	}
	// A nightly-only engine (olcRTC): "latest" above is the newest nightly TAG (drives the version
	// picker + install). Also surface the newest build's DATE, parsed from its release NAME, so the UI
	// can compare it to the installed binary's stamped date and show up-to-date / newer-build.
	if e.Nightly && len(rels) > 0 {
		resp["latest_version"] = updater.ParseVersion(rels[0].Name)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUpdaterFit answers what an install would cost and whether it fits — before it runs.
//
// Read-only, and it exists because the refusal it mirrors used to arrive too late: the disk
// pre-flight lives inside Install, so on a small-flash router the operator picked a version, pressed
// Install and only then learned the binary could never have fit. Same predicate, same directory,
// same numbers — reported while the choice is still open.
func (s *Server) handleUpdaterFit(w http.ResponseWriter, r *http.Request) {
	// "self" is measured against the RUNNING binary's own directory and with the mandatory rollback
	// backup counted — SelfUpdate's numbers, not an engine's. Without this the panel could not ask
	// the question at all for WayHop's own row: EngineByID has no wayhop entry, so /fit answered 404
	// and the row offered "Update now" with no idea whether it fits. On a live AX3000T that
	// is not academic — 13 MiB free against ~27 MiB needed — and the refusal could only arrive after
	// the click.
	if r.PathValue("id") == "self" {
		s.handleSelfFit(w, r)
		return
	}
	// The AmneziaWG feed install answers the same question - what would an install do here, before it
	// runs - with the installer's own dry run (awgcomponent_install.go).
	if r.PathValue("id") == awgFeedID {
		s.handleAWGPlan(w, r)
		return
	}
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	tag := r.URL.Query().Get("version")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if tag == "" {
		rels, err := s.updater.List(ctx, *e, 15)
		if err != nil {
			writeErr(w, http.StatusBadGateway, s.releaseSourceUnreachable("could not reach the release source: ", err))
			return
		}
		// The same choice the page's primary button makes: newest STABLE, never a prerelease.
		tag = updater.LatestStable(rels)
		if tag == "" {
			writeErr(w, http.StatusBadGateway, "no stable release to measure")
			return
		}
	}
	fit, err := s.updater.Fit(ctx, *e, tag)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fit)
}

// downloadPathSuffix names the outbound a fetch was bound to, for the message that reports it failing.
//
// A download bound to a tunnel is the first thing to suspect when the release source cannot be
// reached, and the operator has no way to remember it from the error. Measured on a live
// Keenetic: version checks bound to a group answered "3 source(s) tried, all failed" for twelve
// seconds while the same request over the ordinary path succeeded immediately — and nothing in the
// message pointed at the setting that made the difference. Empty when downloads take the ordinary
// path, because then there is no extra suspect to name.
// releaseSourceUnreachable is the whole message for "the release list could not be fetched".
//
// One definition because there are two call sites and appending the bound-path note was optional at
// each: a first cut left the helper callable and both handlers free to forget it, which a mutation
// check caught immediately — deleting the append still compiled and still passed the test that
// exercised the helper directly. Callers now get the complete sentence or nothing.
func (s *Server) releaseSourceUnreachable(lead string, err error) string {
	msg := lead + err.Error()
	// Naming the bound download path is only worth doing when the path is a suspect. If the release
	// host ITSELF answered, the path carried a full TLS request there and the answer back, so it is
	// the one element that demonstrably works — and the message would send the operator to change a
	// setting that cannot help. Measured on a live Keenetic: downloads bound to
	// "grp-primary" (nwg3), direct answered HTTP 404 in 1.9 s because the self repository is
	// private, and the advice was still to change "Download components through".
	if st := directAnswered(err); st != 0 {
		return msg + fmt.Sprintf(" — the release host itself answered (HTTP %d), so the download path"+
			" carried the request; the failure is at the source, not on the way to it", st)
	}
	return msg + s.downloadPathSuffix()
}

// directAnswered reports the HTTP error status the DIRECT source answered with, or 0 when no such
// answer arrived. Two restrictions, each measured:
//
// Only the DIRECT attempt counts, for the reason selfChannelMissing gives at length: a mirror is a
// third party, so its status describes the mirror and not the release host.
//
// Only a status that is itself the refusal counts. A 200 that still ended in failure is the shape of
// a transfer dying part-way, and a tunnel dropping mid-body is exactly when the bound path IS the
// suspect. The first cut accepted any status and produced, live on a live router, "all
// failed ... the release host itself answered (HTTP 200), so the download path carried the request"
// — clearing the path on the strength of an answer that never finished arriving.
//
// The test is on the STATUS, not on the category: categorize() ends in `return CatHTTP` as its
// default, so a body that would not decode at 200 is filed under CatHTTP too. The condition here is
// deliberately the same one the fetcher uses to file a real refusal (updater.go: status != 0 &&
// status != 200), so the two cannot drift into disagreeing about what "the server refused" means.
func directAnswered(err error) int {
	var fe *updater.FetchError
	if !errors.As(err, &fe) {
		return 0
	}
	for _, a := range fe.Attempts {
		if a.Source == "direct" && a.Status != 0 && a.Status != http.StatusOK {
			return a.Status
		}
	}
	return 0
}

func (s *Server) downloadPathSuffix() string {
	if s == nil || s.updater == nil {
		return ""
	}
	iface := s.updater.BoundInterface()
	if iface == "" {
		return ""
	}
	return fmt.Sprintf(" — downloads are bound to %q (%s); if that path is down, change “Download components through” to the router's ordinary path", s.config().Updater.DownloadVia, iface)
}

// handleUpdaterInstall downloads + installs a chosen version (the side-effecting action).
func (s *Server) handleUpdaterInstall(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == awgFeedID {
		s.handleAWGInstall(w, r)
		return
	}
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
		// An engine with no prebuilt releases is the same shape of answer: a permanent property of
		// the engine, known before anything was attempted, not a download that failed. It was
		// answering 502 — "the upstream is broken" — for a request that never reached an upstream,
		// and persisting it as last_error meant the row carried an install FAILURE for a build that
		// was never going to be downloaded. Neither is true of "this one is built from source".
		if e.SourceOnly {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
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
	reloadErr := ""
	if e.ID == "sing-box" && s.singbox != nil {
		s.applyMu.Lock()
		if s.singbox.Running() {
			if err := s.singbox.Reload(); err == nil {
				reloaded = true
			} else {
				reloadErr = err.Error()
			}
		}
		s.applyMu.Unlock()
	}
	// The core was ABSENT and the committed plan expects one: start it the same way a restart does.
	//
	// Without this the install was a dead end. Measured on a live Keenetic after removing and
	// reinstalling sing-box: the binary was back, the core stayed down, encrypted DNS stayed dark, and
	// the page said "Open Review & Apply" — but nothing was pending (installing a binary changes
	// neither profile nor config), so no Apply control existed and there was nothing to click. The
	// only thing that fixed it was restarting the daemon, which converges to the committed
	// materialization. That is precisely the step to take here, and it needs no operator at all.
	//
	// converge takes applyMu itself, so it runs outside the reload block above.
	converged := false
	if e.ID == "sing-box" && s.singbox != nil && !reloaded && !s.singbox.Running() {
		if ok, cerr := s.convergeAfterInstall(ctx); cerr != nil {
			log.Printf("updater: %s installed %s but converging to the committed configuration failed: %v", e.ID, tag, cerr)
			resp := map[string]any{"installed": tag, "engine": e.ID, "reloaded": false, "converge_error": cerr.Error()}
			writeJSON(w, http.StatusOK, resp)
			return
		} else if ok {
			converged = true
			log.Printf("updater: %s installed %s; converged to the committed configuration", e.ID, tag)
		}
	}
	resp := map[string]any{"installed": tag, "engine": e.ID, "reloaded": reloaded, "converged": converged}
	if reloadErr != "" {
		// The install succeeded but the core didn't come back on this reload — surface it instead of
		// reporting a bare success, and log it. Reload re-asserts desired=true, so the watchdog retries.
		log.Printf("updater: %s installed %s but sing-box reload failed: %s", e.ID, tag, reloadErr)
		resp["reload_error"] = reloadErr
	}
	writeJSON(w, http.StatusOK, resp)
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
	if r.PathValue("id") == awgFeedID {
		s.handleAWGUninstall(w, r)
		return
	}
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
	// Hold applyMu across the WHOLE stop→delete, not just the stop. handleApply takes the same lock
	// end-to-end; the old code released it right after Stop(), leaving a window in which a concurrent
	// Apply could take the lock, restart the core onto the very binary about to be unlinked, and this
	// path would then delete the file and report removed:true while the old inode kept running as an
	// unmanageable orphan (LOOP-024, the sibling of the PM-remove race). Uninstall takes no lock of
	// its own, so this cannot deadlock. The read-only precheck above stays outside the lock.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	stopped := false
	if e.ID == "sing-box" && s.singbox != nil && s.singbox.Running() {
		if !body.Stop {
			// The same refusal the package path answers with, in the same shape. It used to be a bare
			// sentence telling the reader to "resend with stop:true" — an instruction to a program,
			// printed to a person holding a mouse, on the one control that has no other way forward.
			// needs_stop is what makes it a QUESTION the panel can ask and the operator can answer.
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "sing-box is running, and removing it deletes the binary the router is using " +
					"right now. That stops the VPN datapath until sing-box is installed again.",
				"needs_stop": true,
			})
			return
		}
		if err := s.singbox.Stop(); err != nil { // clears Desired() → watchdog won't respawn it
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

// selfChannelMissing reads "the release list is not published" out of the attempt list.
//
// Only the DIRECT attempt can establish it, and only with a 404. That is the request that reached
// GitHub itself, and 404 is the one answer meaning the release list is not there for us — the same
// answer whether the repository is private (this build's, for now) or simply has no releases. Either
// way there is nothing to update to, which is a property of the build rather than a fault to fix.
//
// Mirrors are deliberately ignored, in both directions. Measured on this build: direct answered 404
// while ghproxy.net answered 403 and a third mirror would not resolve — a mirror's refusal is about
// the mirror, and a mirror's 404 can equally mean it does not carry the path. Requiring every source
// to agree therefore never fires in the field, and trusting a mirror alone would let a proxy outage
// masquerade as "this build does not self-update".
//
// 403 is excluded even from the direct source: GitHub answers 403 for rate limiting, and calling a
// throttle "no update channel" would bury a check that succeeds again within the hour.
func selfChannelMissing(attempts []updater.Attempt) bool {
	for _, a := range attempts {
		if a.Source == "direct" && a.Status == http.StatusNotFound {
			return true
		}
	}
	return false
}

// handleSelfStatus reports WayHop's own version and whether a newer release exists.
func (s *Server) handleSelfStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.selfStatus(r.Context()))
}

// selfStatus is the self-update check behind the Components page and the Telegram bot.
func (s *Server) selfStatus(parent context.Context) map[string]any {
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
	out["package_manager"] = string(s.updater.PMKind())
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if exe, exeErr := os.Executable(); exeErr == nil {
		pkg := s.updater.SelfPackageStatus(ctx, exe)
		out["package_status"] = pkg
		out["native_managed"] = pkg.Managed
		out["ownership_unknown"] = !pkg.OwnershipKnown
		// A package-owned executable must use the package catalog as its only update authority. Asking
		// GitHub here produced a network error the UI called an update failure, then the same row said
		// the panel would refuse the update regardless. Return the complete apk/opkg state instead.
		if pkg.Managed || !pkg.OwnershipKnown {
			out["latest"] = pkg.LatestVersion
			out["update_available"] = pkg.State == updater.PackageStateBehind
			out["version_comparable"] = pkg.State == updater.PackageStateBehind ||
				pkg.State == updater.PackageStateCurrent || pkg.State == updater.PackageStateAhead
			return out
		}
	}
	rel, err := s.updater.SelfLatest(ctx, repo)
	if err != nil {
		out["error"] = err.Error()
		// The message is safe on its own — a *FetchError never carries a URL — but a chip cannot
		// render a sentence and a truncated one in a `title` is unreachable on touch. So the short
		// label and the per-source detail are separate fields: the chip shows the label, the details
		// panel shows each attempt with its redacted host, duration and category.
		var fe *updater.FetchError
		if errors.As(err, &fe) {
			out["error_summary"] = fe.Summary()
			out["attempts"] = fe.Attempts
			// A release endpoint that answers 404 is not a broken check — it is a build with nowhere to
			// update FROM, which is what a private repository (this one, for now) and a repository with
			// no releases both look like to an unauthenticated client. Reported apart from `error` so
			// the panel can say "this build does not self-update" instead of "the update check failed",
			// which sends an operator hunting a network fault that does not exist.
			if selfChannelMissing(fe.Attempts) {
				out["no_channel"] = true
				out["no_channel_reason"] = "the release list at " + repo + " answers 404 — a private repository, " +
					"or one with no published releases, answers exactly this"
			}
		}
	} else {
		out["latest"] = rel.Tag
		// Whether the comparison could be MADE is reported separately from its outcome. An
		// unparseable tag used to come back as update_available:false, which the panel rendered
		// as a confident "up to date".
		newer, decided := updater.Compare(version.Version, rel.Tag)
		out["version_comparable"] = decided
		if decided {
			out["update_available"] = newer
		}
	}
	return out
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
	code, out := s.selfInstall(r.Context(), body.Version)
	writeJSON(w, code, out)
}

// selfInstall is the self-update itself, for the Components page and the Telegram bot. An error
// comes back as {"error": ...} with its status, like writeErr writes it.
func (s *Server) selfInstall(parent context.Context, tag string) (int, map[string]any) {
	fail := func(code int, msg string) (int, map[string]any) { return code, map[string]any{"error": msg} }
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()
	if tag == "" {
		rel, err := s.updater.SelfLatest(ctx, repo)
		if err != nil {
			return fail(http.StatusBadGateway, err.Error())
		}
		tag = rel.Tag
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(http.StatusInternalServerError, "cannot locate the running binary: "+err.Error())
	}
	// The binary swap and a router Apply must never overlap. The currently running process remains
	// valid if restart fails, but no Apply may begin under one executable identity and finish after
	// its on-disk replacement has changed the next-boot recovery program.
	s.applyMu.Lock()
	installed, err := s.updater.SelfUpdate(ctx, repo, tag, exe)
	s.applyMu.Unlock()
	if err != nil {
		var nm *updater.NativeManagedError
		if errors.As(err, &nm) {
			return fail(http.StatusConflict, err.Error()) // policy: wayhop is PM-owned — upgrade via opkg/apk
		}
		return fail(http.StatusBadGateway, err.Error())
	}
	cmd := restartCommand()
	if cmd == nil {
		return http.StatusOK, map[string]any{"installed": installed, "restarting": false,
			"note": "binary swapped; restart the service manually to apply (or this is the demo)"}
	}
	if err := cmd.Start(); err != nil {
		return http.StatusOK, map[string]any{"installed": installed, "restarting": false, "note": "restart failed: " + err.Error()}
	}
	return http.StatusOK, map[string]any{"installed": installed, "restarting": true}
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
	if body.Enabled {
		if exe, err := os.Executable(); err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			pkg := s.updater.SelfPackageStatus(ctx, exe)
			cancel()
			if pkg.Managed {
				writeErr(w, http.StatusConflict, "WayHop is managed by "+string(pkg.Manager)+
					"; automatic updates must use that package channel")
				return
			}
			if !pkg.OwnershipKnown {
				writeErr(w, http.StatusServiceUnavailable, "could not verify WayHop package ownership; retry when the package manager is idle")
				return
			}
		}
	}
	s.cfgMu.Lock()
	prev := s.cfg.Updater.AutoUpdate
	s.cfg.Updater.AutoUpdate = body.Enabled
	err := s.cfg.Save()
	if err != nil {
		s.cfg.Updater.AutoUpdate = prev // roll back in-memory on a failed Save: keep memory == disk
	}
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
		s.applyMu.Lock()
		installed, err := s.updater.SelfUpdate(cctx, repo, rel.Tag, exe)
		s.applyMu.Unlock()
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

// handleSelfFit answers GET /api/updater/self/fit — the same shape /fit gives an engine, computed
// the way SelfUpdate computes it. Read-only: it lists a release and stats a directory, nothing more.
func (s *Server) handleSelfFit(w http.ResponseWriter, r *http.Request) {
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tag := r.URL.Query().Get("version")
	if tag == "" {
		rel, err := s.updater.SelfLatest(ctx, repo)
		if err != nil {
			// handleSelfStatus reads this exact failure as "this build has no release channel". Two
			// endpoints answering the same 404 with that and with "the release source is unreachable"
			// is a contradiction the operator has no way to settle, so the reading lives in one place.
			var fe *updater.FetchError
			if errors.As(err, &fe) && selfChannelMissing(fe.Attempts) {
				writeErr(w, http.StatusBadGateway, "this build has no release channel: the release list at "+
					repo+" answers 404 — a private repository, or one with no published releases, answers exactly this")
				return
			}
			writeErr(w, http.StatusBadGateway, s.releaseSourceUnreachable("could not reach the release source: ", err))
			return
		}
		tag = rel.Tag
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot locate the running binary: "+err.Error())
		return
	}
	fit, err := s.updater.SelfFit(ctx, repo, tag, exe)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fit)
}
