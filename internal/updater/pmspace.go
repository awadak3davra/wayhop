package updater

import (
	"context"
	"fmt"
	"path/filepath"

	"wayhop/internal/pm"
)

// pmspace.go decides HOW a package write can be made to fit on a router that has no room for it.
//
// The problem is specific and measurable. apk installs an upgrade by writing the new files beside
// the old ones and renaming over them, so at the peak both builds are on disk. On the AX3000T the
// core is 38.7 MiB installed, the feed's next build is 42.4 MiB, and /overlay has 20.2 MiB free:
// `apk upgrade sing-box` cannot work there by any amount of retrying, and the only reason it has
// never been seen failing is that the panel was sending `apk add` and changing nothing at all.
//
// Removing the installed build first turns 20.2 MiB of headroom into 58.9 MiB, which fits. That is
// the whole trick, and it is worth doing only because the alternative is an operator who cannot
// update their proxy core from the panel at all. It costs something real — the datapath is down
// between the two commands and the removed build is not always still in the feed to go back to — so
// it is never chosen when the direct upgrade fits, it is stated in the plan before anything runs,
// and it goes through the same acknowledgement gate as a removal.
//
// Unmeasurable is not the same as refused. A manager that cannot report sizes (opkg) or a directory
// that cannot be statfs'd leaves Measured false and the strategy direct, which is exactly the
// behaviour that shipped before this file existed — the same rule AvailBytes sets for a failed stat.

// pmWriteMargin is the headroom left over and above the build being written: package scripts, the
// database transaction and the manager's own temporary files all land on the same filesystem. It is
// the 4 MiB tail peakInstallDisk already adds to the GitHub install path's estimate, kept equal so
// the two pre-flights cannot start disagreeing about what "it fits" means.
const pmWriteMargin = 4 << 20

// Strategies. Direct is one command. Replace is remove-then-install, for the case where the new
// build fits only in the space the old one is holding. Blocked is neither: the plan says how much
// must be freed instead of running a command that will fail halfway.
const (
	PMSpaceDirect  = "direct"
	PMSpaceReplace = "replace"
	PMSpaceBlocked = "blocked"
)

// PMSpace is the disk assessment for a package operation that writes files, and it is carried on
// the plan so the panel can show the arithmetic rather than a verdict.
type PMSpace struct {
	// Dir is the filesystem the decision is about: the directory holding the binary the daemon runs,
	// which is where the package's dominant file lands. Naming the package manager's root instead
	// would put a reassuring figure next to a disk the write never touches.
	Dir           string `json:"dir"`
	Avail         uint64 `json:"avail_bytes"`
	AvailKnown    bool   `json:"avail_known"`
	Need          uint64 `json:"need_bytes,omitempty"`    // unpacked size of the build to be written
	Reclaim       uint64 `json:"reclaim_bytes,omitempty"` // freed by removing the installed build first
	TargetVersion string `json:"target_version,omitempty"`
	// Measured says both figures are real. With it false, Strategy is direct because the guard was
	// skipped — never because a measurement said it fits.
	Measured bool   `json:"measured"`
	Strategy string `json:"strategy"`
	// ShortfallMiB is how much must be freed for the operation to become possible AT ALL, i.e. after
	// the installed build has already been counted as reclaimable. Set only when blocked.
	ShortfallMiB uint64 `json:"shortfall_mib,omitempty"`
}

// pmSpace measures what writing targetVersion of pkg would need at path, and picks the strategy.
// installedVersion may be empty (a fresh install reclaims nothing).
func (u *Updater) pmSpace(ctx context.Context, pkg, path, installedVersion, targetVersion string) PMSpace {
	sp := PMSpace{Dir: filepath.Dir(path), Strategy: PMSpaceDirect, TargetVersion: targetVersion}
	sp.Avail, sp.AvailKnown = u.availAt(sp.Dir)
	if !sp.AvailKnown || targetVersion == "" {
		return sp
	}
	sizes, err := u.pm.Sizes(ctx, pkg)
	if err != nil {
		return sp
	}
	need, ok := pm.SizeOf(sizes, targetVersion)
	if !ok {
		return sp
	}
	reclaim, _ := pm.SizeOf(sizes, installedVersion)
	sp.Need, sp.Reclaim, sp.Measured = need, reclaim, true
	switch {
	case sp.Avail >= need+pmWriteMargin:
		sp.Strategy = PMSpaceDirect
	case reclaim > 0 && sp.Avail+reclaim >= need+pmWriteMargin:
		sp.Strategy = PMSpaceReplace
	default:
		sp.Strategy = PMSpaceBlocked
		sp.ShortfallMiB = shortfallMiB(sp.Avail+reclaim, need+pmWriteMargin)
	}
	return sp
}

// planWrite fills in a plan's space assessment and its command sequence for an action that WRITES a
// build.
//
// It takes TWO commands because the second path is not the first with a removal bolted on front.
// `direct` acts on the package as it stands — on apk, an upgrade — while `afterRemoval` runs against
// a package that is no longer installed, where the only verb that means anything is an install.
// Reusing `direct` there plans `apk del sing-box && apk upgrade sing-box`: the second command finds
// nothing installed to upgrade, does nothing, and leaves the router with no core at all. Caught by
// the test, not by the reasoning that wrote the first version.
//
// The blocked case says the arithmetic rather than "not enough space". The operator is the only one
// who can decide WHAT to free on a router whose overlay holds their own configuration, and they can
// only decide it from figures — which is the same reason the GitHub install path's refusal was
// rewritten to name the shortfall and the directory instead of printing two rounded numbers.
func (u *Updater) planWrite(ctx context.Context, p *PMPlan, pkg, path, installedVersion, target string, direct, afterRemoval []string) {
	sp := u.pmSpace(ctx, pkg, path, installedVersion, target)
	p.Space = &sp
	if len(direct) == 0 || len(afterRemoval) == 0 {
		return // this manager has no such command; the caller's tail reports that
	}
	switch sp.Strategy {
	case PMSpaceBlocked:
		// What is reclaimable belongs in the sentence only when there IS something to reclaim. An
		// install has no installed build behind it, and "removing the installed build would give back
		// 0.0 MiB" is a true statement that reads as a broken one — seen on the AX3000T's own install
		// plan before this branch existed.
		room := fmt.Sprintf("%s is free in %s", MiB(sp.Avail), sp.Dir)
		if sp.Reclaim > 0 {
			room += fmt.Sprintf(", and removing the installed build would give back %s", MiB(sp.Reclaim))
		}
		p.check("the new build fits on this router", false, fmt.Sprintf(
			"%s %s unpacks to %s and needs %s with working room; %s — free at least %d MiB more and try again",
			pkg, target, MiB(sp.Need), MiB(sp.Need+pmWriteMargin), room, sp.ShortfallMiB))
	case PMSpaceReplace:
		rm := u.pm.RemoveArgv(pkg)
		if len(rm) == 0 {
			p.check("the installed build can be removed first", false, fmt.Sprintf(
				"%s cannot fit beside the installed build and %s has no removal command to make room", target, u.pm.Kind))
			return
		}
		p.Steps = [][]string{rm, afterRemoval}
	default:
		p.Steps = [][]string{direct}
	}
	if len(p.Steps) > 0 {
		p.Argv = p.Steps[0]
	}
}

// MiB formats bytes the way the refusals, the log and the panel all read them. One decimal: the
// difference between 20.2 and 20 MiB free is the difference between an upgrade fitting and not.
func MiB(b uint64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }
