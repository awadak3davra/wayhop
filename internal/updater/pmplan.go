package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wayhop/internal/pm"
)

// pmplan.go turns "the operator wants to install / roll back / remove this engine" into an exact,
// path-verified package-manager command — WITHOUT running it.
//
// The gap this closes: internal/pm has had working Install, Upgrade, Remove and (now) Candidates and
// InstallVersion since it was written, and outside that package only Detect, Available and Owner are
// ever called. The panel recognises that opkg or apk owns a binary and then tells the operator to go
// do it over SSH, while carrying a complete implementation of the thing it declines. The package's
// own header says why it stayed unwired: the delegation has to be "path-verified, version-gated".
// This is that gate.
//
// Planning is separate from doing on purpose, and for the same reason the UCI writer shows its
// commands first: an operation that reaches into the system package database on a router the family
// is using deserves to be read before it is run. A Plan is a value the UI can render and a human can
// refuse.

// PlanAction is what the operator asked for.
type PlanAction string

const (
	PlanInstall  PlanAction = "install"  // the engine is absent; add the package
	PlanUpgrade  PlanAction = "upgrade"  // present; move to whatever the feed offers
	PlanRollback PlanAction = "rollback" // present; move to a NAMED older build
	PlanRemove   PlanAction = "remove"   // present; delete the package
)

// PlanCheck is one precondition and how it came out. Every plan carries the full list, passed or
// not, because "why is this refused" is the question the current UI answers with a paragraph of
// prose and no facts.
type PlanCheck struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"`
}

// PMPlan is a proposed package-manager operation.
type PMPlan struct {
	Action  PlanAction `json:"action"`
	Manager pm.Kind    `json:"manager"`
	Package string     `json:"package"`
	Version string     `json:"version,omitempty"`
	Path    string     `json:"path,omitempty"` // the binary the daemon actually runs
	Argv    []string   `json:"argv,omitempty"` // exactly what would execute; empty when blocked
	// What the package manager says the command WOULD do, asked with its own dry-run flag. Showing
	// the command is not the same as showing its effect: `apk del sing-box` reads as one package and,
	// on the AX3000T, removes two — kmod-inet-diag goes with it and nothing in the preview said so.
	Effect     string      `json:"effect,omitempty"`
	Collateral []string    `json:"collateral,omitempty"` // other packages the operation would remove
	Checks     []PlanCheck `json:"checks"`
	// Steps is the whole sequence, in order. It is normally one command and Argv is that command; the
	// low-space upgrade is two — remove the installed build, then install the new one — because on a
	// 60 MiB overlay the new build fits only in the space the old one is holding (see pmspace.go).
	// Argv stays Steps[0] so the approval protocol is unchanged, and because the first command is the
	// one whose effect is worth simulating: on the two-step path it is the removal.
	Steps [][]string `json:"steps,omitempty"`
	// Space is the disk arithmetic behind that choice, carried whether or not it changed anything, so
	// the panel can show the figures instead of announcing a verdict.
	Space *PMSpace `json:"space,omitempty"`
	// Non-empty: the reason this plan must not run. Argv may still be POPULATED beside it — a late
	// block (the simulation that could not preview the effect) lands after the argv is built and does
	// not clear it. Never read one field alone; Runnable() below is the only safe test.
	Blocked string `json:"blocked,omitempty"`
}

// Runnable reports whether the plan may proceed.
func (p PMPlan) Runnable() bool { return p.Blocked == "" && len(p.Argv) > 0 }

// DeletesInstalled reports whether running this plan takes the installed binary away, even
// temporarily. A remove obviously does; so does the low-space replace, whose first command is that
// same `apk del`. The acknowledgement gate and the stop that precedes it are about the datapath
// going down, not about which verb the operator picked, so both answer yes here.
func (p PMPlan) DeletesInstalled() bool {
	if p.Action == PlanRemove {
		return true
	}
	return p.Space != nil && p.Space.Strategy == PMSpaceReplace
}

// check records a precondition. note is the reason it would FAIL, which is why it is kept only when
// it does: every one of these strings is written in the past tense of something going wrong, so a
// check that passed and kept its note states something untrue about the box. The live endpoint used
// to answer `{"name":"package manager present","ok":true,"note":"no opkg or apk on this system…"}`.
//
// The renderer's only defence was to hide notes on passing checks, and that is what buried the one
// note worth reading — see noteOK.
func (p *PMPlan) check(name string, ok bool, note string) bool {
	c := PlanCheck{Name: name, OK: ok}
	if !ok {
		c.Note = note
	}
	p.Checks = append(p.Checks, c)
	if !ok && p.Blocked == "" {
		p.Blocked = note
	}
	return ok
}

// noteOK records a check that PASSED and still has something to say, which is a different thing from
// a check that failed and explains itself. One case exists: a package name that resolved through a
// virtual `Provides:`. Measured read-only on the family's Keenetic — `opkg list sing-box` empty,
// `opkg whatprovides sing-box` -> `sing-box-go`, /opt/bin/sing-box owned by `sing-box-go - 1.13.3-2`
// — so the plan asks the operator to confirm a command naming a package they never typed. The
// substitution is the plan's own doing and belongs on screen with it.
func (p *PMPlan) noteOK(name, note string) {
	p.Checks = append(p.Checks, PlanCheck{Name: name, OK: true, Note: note})
}

// enginePath resolves the binary the daemon would actually run for e: BinDir first, then PATH.
// It is the ONE resolution — Installed (what the panel shows), nativeManaged (what the package
// manager owns) and the package plan all call it. Two different answers to "which file is this
// engine" is how a delegation ends up upgrading a package that owns a different file from the one
// in use, and until these shared it the same six lines were written three times.
func (u *Updater) enginePath(e Engine) (string, bool) {
	if e.BinName == "" {
		return "", false
	}
	p := filepath.Join(u.BinDir, e.BinName)
	if _, err := os.Stat(p); err == nil {
		return p, true
	}
	if lp, err := exec.LookPath(e.BinName); err == nil {
		return lp, true
	}
	return p, false // the path it WOULD occupy; useful for an install plan
}

// PlanPM builds the plan for action on engine e. version is required for PlanRollback and ignored
// otherwise. It performs no mutation; every branch either returns a runnable plan or a blocked one
// carrying the reason.
func (u *Updater) PlanPM(ctx context.Context, e Engine, action PlanAction, version string) PMPlan {
	p := PMPlan{Action: action, Manager: u.pm.Kind}

	if !p.check("package manager present", u.pm.Available(),
		"no opkg or apk on this system, so there is nothing to delegate to") {
		return p
	}
	if !p.check("engine has a binary name", e.BinName != "",
		fmt.Sprintf("engine %q declares no binary, so no package can be matched to it", e.ID)) {
		return p
	}

	path, exists := u.enginePath(e)
	p.Path = path

	// Which package are we talking about? For anything but a fresh install the answer must come from
	// the package manager's own ownership record, never from a name table: a guessed package name is
	// how a remove takes out the wrong thing.
	var pkg string
	if action == PlanInstall && !exists {
		// Nothing on disk to ask about. The only defensible source for the name is the engine id,
		// and it is validated before it can become argv.
		pkg = e.ID
		if !p.check("package name is safe", pm.ValidPkgName(pkg),
			fmt.Sprintf("engine id %q is not a valid package name", e.ID)) {
			return p
		}
		// The engine id is a GUESS at the package name, and it is wrong more often than it is right.
		// Measured against the AX3000T's own feed: of the seven engines this panel knows, only
		// sing-box and dnscrypt-proxy exist as packages — mihomo, xray, hysteria, amneziawg-go and
		// olcrtc do not. Without this the plan reads as runnable, the operator confirms it, and apk
		// fails on a package that was never there. The rollback branch below already refuses a version
		// the feed does not carry; this is the same question asked one level up.
		cands, cerr := u.pm.Candidates(ctx, pkg)
		if !p.check("the feed could be listed", cerr == nil,
			fmt.Sprintf("could not ask %s what it offers for %s", u.pm.Kind, pkg)) {
			return p
		}
		if len(cands) == 0 {
			// An empty list is not the same as "absent". opkg lets a package answer to a VIRTUAL name
			// it declares in `Provides:` — measured on the Keenetic, `opkg list sing-box` is empty
			// while `opkg whatprovides sing-box` answers `sing-box-go` and `opkg install --noaction
			// sing-box` reports that package as already installed. Blocking on the empty list refused
			// an operation the package manager can perform, which is a regression this check itself
			// introduced by taking apk's behaviour (where empty really does mean absent) for both.
			if real, found, rerr := u.pm.Resolve(ctx, pkg); rerr == nil && found {
				p.noteOK("the name is virtual and resolves",
					fmt.Sprintf("%s is provided by package %s", pkg, real))
				pkg = real
			}
		}
		if len(cands) == 0 && pkg == e.ID {
			// check returns its ok argument, so wrapping a literal false in `if !` was a constant
			// condition with an unreachable fall-through. The three other false-checks in this file
			// already call it plainly and then proceed.
			p.check("the feed has this package", false,
				fmt.Sprintf("%s has no package called %q and nothing provides it, so there is nothing to install under that name", u.pm.Kind, pkg))
			return p
		}
	} else {
		owner, owned, err := u.pm.Owner(ctx, path)
		if !p.check("package manager could answer", err == nil,
			"the package database did not answer (it is often locked by a concurrent opkg or apk run) — retry in a moment") {
			return p
		}
		if !p.check("the package manager owns this binary", owned,
			fmt.Sprintf("%s is not owned by %s, so the package manager is not the right tool for it", path, u.pm.Kind)) {
			return p
		}
		// apk answers with name AND version glued ("sing-box-1.12.17-r1", verified on the test box),
		// so the raw token is not a package name and `apk add` on it would name something that does
		// not exist. opkg's search already answers bare.
		pkg = u.pm.PackageName(owner)
		if !p.check("package name is safe", pm.ValidPkgName(pkg),
			fmt.Sprintf("the package manager reported an unusable package name %q", owner)) {
			return p
		}
		// The check the package header asked for and nothing performed: the files the package owns
		// must actually include the path the daemon runs. Ownership of a path and the package's file
		// list can disagree after a manual copy, and acting on the disagreement is what clobbers a
		// binary that is in use.
		files, ferr := u.pm.Files(ctx, pkg)
		if !p.check("package file list could be read", ferr == nil,
			fmt.Sprintf("could not list the files of package %s", pkg)) {
			return p
		}
		if !p.check("the package installs the file in use", containsPath(files, path),
			fmt.Sprintf("package %s does not list %s among its files, so operating on the package would not act on the binary in use", pkg, path)) {
			return p
		}
	}
	p.Package = pkg

	switch action {
	case PlanInstall, PlanUpgrade:
		// WHICH build would be written? The verb does not say — the feed does — and the answer is what
		// the space assessment measures and what the operator is agreeing to. An unreadable catalogue
		// leaves it empty, which skips the guard rather than blocking on it.
		target := ""
		if cands, cerr := u.pm.Candidates(ctx, pkg); cerr == nil {
			for _, c := range cands {
				if c.Available {
					target = c.Version
					break
				}
			}
		}
		if action == PlanUpgrade {
			// The installed build is what a removal would give back, so an upgrade — and only an
			// upgrade — has something to reclaim. A fresh install reclaims nothing, which is why it can
			// never plan the two-command path however full the router is.
			installedVer, _ := u.pm.InstalledPackageVersion(ctx, pkg)
			u.planWrite(ctx, &p, pkg, path, installedVer, target, u.pm.UpgradeArgv(pkg), u.pm.InstallArgv(pkg))
		} else {
			u.planWrite(ctx, &p, pkg, path, "", target, u.pm.InstallArgv(pkg), u.pm.InstallArgv(pkg))
		}
	case PlanRemove:
		if rm := u.pm.RemoveArgv(pkg); len(rm) > 0 {
			p.Steps = [][]string{rm}
			p.Argv = rm
		}
	case PlanRollback:
		if !p.check("a version was named", version != "", "no version was given to roll back to") {
			return p
		}
		if !p.check("version is safe", pm.ValidVersion(version),
			fmt.Sprintf("%q is not a usable version token", version)) {
			return p
		}
		if !u.pm.CanPinVersion() {
			// Stated plainly rather than approximated. opkg install has no version pin, so honouring
			// this would mean installing whatever the feed currently holds — a different build from
			// the one the operator picked.
			p.check("this package manager can pin a version", false,
				"opkg cannot install a named version; rolling back needs that build's .ipk installed as a file")
			return p
		}
		cands, cerr := u.pm.Candidates(ctx, pkg)
		if !p.check("the feed could be listed", cerr == nil,
			fmt.Sprintf("could not list the builds %s offers for %s", u.pm.Kind, pkg)) {
			return p
		}
		if !p.check("the named build is in the feed", hasVersion(cands, version),
			fmt.Sprintf("%s %s is not offered by this feed, so the rollback would fail at the package manager", pkg, version)) {
			return p
		}
		p.Version = version
		installedVer, _ := u.pm.InstalledPackageVersion(ctx, pkg)
		// A rollback writes a build too, and on this hardware an older sing-box is the same order of
		// magnitude as a newer one — so it gets the same assessment and the same two-step path when the
		// only room for it is the room the current build occupies.
		pinned := u.pm.InstallVersionArgv(pkg, version)
		u.planWrite(ctx, &p, pkg, path, installedVer, version, pinned, pinned)
	default:
		p.check("action is known", false, fmt.Sprintf("unknown action %q", action))
		return p
	}

	if len(p.Argv) == 0 && p.Blocked == "" {
		p.Blocked = fmt.Sprintf("no command is defined for %s on %s", action, u.pm.Kind)
	}

	// Ask the package manager what the command would DO. This is its own dry run — verified on both
	// routers to leave them untouched — and it is asked of the argv just built rather than of a
	// reconstruction, so the effect shown can only be the effect of the command shown. Rebuilding it
	// here would create a second place for the two to drift, which is the failure ExecutePM's re-plan
	// guard already exists to catch.
	//
	// A failure to preview blocks. On apk this is also the reliable signal that repository indexes are
	// absent or the package is not offered: executing after a failed simulation turns a reviewed plan
	// into a blind mutation and is how the Updater offered commands that the router had already proved
	// it could not run.
	if p.Runnable() {
		if out, serr := u.pm.Simulate(ctx, p.Argv); serr == nil {
			p.Effect = strings.TrimSpace(out)
			p.Collateral = pm.CollateralPackages(u.pm.Kind, out, p.Package)
		} else {
			p.check("the effect could be previewed", false,
				fmt.Sprintf("could not ask %s what this would do; refresh package lists and retry", u.pm.Kind))
		}
	}
	return p
}

// ErrPMRefused marks a refusal — a policy decision, not a failure of the operation. Callers match it
// with errors.Is to answer 409 rather than 502, and to keep the refusal OUT of the engine's
// last_error: a permanent refusal recorded as an install failure is one nothing can ever clear.
var ErrPMRefused = errors.New("package-manager operation refused")

// PMCandidates lists the builds the package manager's feed offers for pkg, newest first. The caller
// is expected to have obtained pkg from a plan, so the name has already been through the ownership
// and file-list verification rather than being guessed.
// PMCanPinVersion reports whether this box's package manager can install a named build, so the page
// can decline to offer a rollback picker rather than refuse the choice after it is made.
func (u *Updater) PMCanPinVersion() bool { return u.pm.CanPinVersion() }

func (u *Updater) PMCandidates(ctx context.Context, pkg string) ([]pm.Candidate, error) {
	return u.pm.Candidates(ctx, pkg)
}

// PMInstalledVersion is what the package database says is installed RIGHT NOW, for the caller that
// has just run a package command and wants to know whether the build actually moved. "The command
// exited 0" and "the installed version changed" are separate facts, and treating the first as the
// second is the whole shape of the defect this path was fixed for.
func (u *Updater) PMInstalledVersion(ctx context.Context, pkg string) (string, bool) {
	return u.pm.InstalledPackageVersion(ctx, pkg)
}

// ExecutePM runs a plan that was already built and checked. It re-plans first and refuses if the
// answer changed: a plan the operator read a minute ago describes the box as it was, and a package
// database is shared with whatever else is running on the router.
// PreflightPM re-plans and checks the approved command, running NOTHING. ExecutePM opens with it, and
// the HTTP layer calls it separately for a reason the panel's own uninstall path documents: removing
// a package deletes a binary that may be in use, so the routing core has to be stopped first — and
// every reason to refuse has to be known BEFORE that, or a refusal leaves the datapath down with
// nothing removed. A guard that runs after the stop is not a guard.
func (u *Updater) PreflightPM(ctx context.Context, e Engine, action PlanAction, version string, approved PMPlan) (PMPlan, error) {
	now := u.PlanPM(ctx, e, action, version)
	if !now.Runnable() {
		return now, fmt.Errorf("%w: %s", ErrPMRefused, now.Blocked)
	}
	if !sameArgv(now.Argv, approved.Argv) {
		return now, fmt.Errorf("%w: the command changed since it was shown (%s -> %s)",
			ErrPMRefused, strings.Join(approved.Argv, " "), strings.Join(now.Argv, " "))
	}
	// A plan can be more than one command, and consent has to cover all of them. Comparing only the
	// first would let an approval of `apk del sing-box` — read as a removal — carry an install the
	// operator never saw, or the other way round.
	if len(approved.Steps) > 0 && !sameSteps(now.Steps, approved.Steps) {
		return now, fmt.Errorf("%w: the commands changed since they were shown (%s -> %s)",
			ErrPMRefused, joinSteps(approved.Steps), joinSteps(now.Steps))
	}
	// An approval that names no sequence at all can only have been given for a single command. If the
	// box now needs two — free space fell away between the plan and the click — that is a different
	// operation with a different cost, and it goes back for review rather than through.
	if len(approved.Steps) == 0 && len(now.Steps) > 1 {
		return now, fmt.Errorf("%w: this now takes %d commands (%s) and the approval covered one; review it again",
			ErrPMRefused, len(now.Steps), joinSteps(now.Steps))
	}
	return now, nil
}

func (u *Updater) ExecutePM(ctx context.Context, e Engine, action PlanAction, version string, approved PMPlan) (string, PMPlan, error) {
	now, err := u.PreflightPM(ctx, e, action, version, approved)
	if err != nil {
		return "", now, err
	}
	// Two commands can mean two package downloads on a line that manages a few hundred KiB/s, and the
	// budget is per call rather than per command.
	runCtx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	// The plan's own commands are what run. ExecutePM used to re-derive them from the action — calling
	// Install for an upgrade — so the argv that was shown, simulated and approved and the argv that
	// executed were built in two different places, and they disagreed for as long as the upgrade path
	// existed. There is no second derivation left to drift.
	var out strings.Builder
	for i, step := range now.Steps {
		stepOut, rerr := u.pm.RunPlanned(runCtx, step)
		if trimmed := strings.TrimSpace(stepOut); trimmed != "" {
			if out.Len() > 0 {
				out.WriteString("\n")
			}
			out.WriteString(trimmed)
		}
		if rerr != nil {
			if len(now.Steps) == 1 {
				return out.String(), now, rerr
			}
			// WHICH command failed is the difference between "nothing happened" and "the installed build
			// is gone and the new one never arrived". The caller decides what to tell the operator and
			// whether the datapath can be restored, and it cannot decide either from a bare error.
			return out.String(), now, fmt.Errorf("command %d of %d (%s) failed: %w",
				i+1, len(now.Steps), strings.Join(step, " "), rerr)
		}
	}
	return out.String(), now, nil
}

// joinSteps renders a sequence the way a refusal has to read it: one line, in order.
func joinSteps(steps [][]string) string {
	parts := make([]string, 0, len(steps))
	for _, s := range steps {
		parts = append(parts, strings.Join(s, " "))
	}
	return strings.Join(parts, " && ")
}

func sameSteps(a, b [][]string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if !sameArgv(a[i], b[i]) {
			return false
		}
	}
	return true
}

func containsPath(files []string, want string) bool {
	want = filepath.Clean(want)
	for _, f := range files {
		if filepath.Clean(strings.TrimSpace(f)) == want {
			return true
		}
	}
	return false
}

func hasVersion(cands []pm.Candidate, v string) bool {
	for _, c := range cands {
		if c.Version == v && c.Available {
			return true
		}
	}
	return false
}

func sameArgv(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
