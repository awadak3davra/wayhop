package updater

import (
	"context"
	"fmt"
	"path/filepath"
)

// fit.go answers "what would this install cost, and does it fit" BEFORE anything is downloaded.
//
// Install already refuses when the binary cannot fit (see Install's flash pre-flight and
// flashRefusal): the numbers are right and the message is actionable. What it cannot do is arrive in
// time. The operator learns the router is too small only after choosing a version and pressing
// Install, which on a 60 MiB overlay is the routine outcome rather than the edge case.
//
// So the same predicate is exported, reading the same asset the install would pick for this router's
// arch and the same free space from the same directory. It deliberately does NOT re-derive the rule:
// enoughFlashFor and peakInstallDisk are the install path's, so a page cannot promise what Install
// would refuse, and a change to the rule cannot leave the two disagreeing.

// InstallFit is the disk pre-flight for one version, answered without installing it.
type InstallFit struct {
	Version string `json:"version"`
	Asset   string `json:"asset,omitempty"`
	// Download is the asset's size on the wire. Need is what must be free on disk: an archive
	// inflates on the way out, so the two differ by up to 3x plus the staging margin.
	Download int64  `json:"download_bytes"`
	Need     uint64 `json:"need_bytes"`
	// Dir is where engine binaries actually land — the directory of the configured sing-box binary,
	// NOT the package manager's root. On a live Keenetic those are the same disk; they need
	// not be, and naming the wrong one would put a reassuring free-space figure next to a directory
	// the install never touches.
	Dir        string `json:"dir"`
	Avail      uint64 `json:"avail_bytes"`
	AvailKnown bool   `json:"avail_known"`
	// Fits is "the pre-flight would ALLOW this install", not "this was measured and fits". With
	// AvailKnown false it is true because the guard never blocks on a stat it could not take — so a
	// caller that renders a green "it fits" must check AvailKnown first, or it will report a
	// measurement that never happened.
	Fits bool `json:"fits"`
	// Shortfall is how many MiB must be freed before the install would be allowed. Zero when it fits,
	// or when the free space could not be measured — never a number invented from an unknown.
	ShortfallMiB uint64 `json:"shortfall_mib,omitempty"`
}

// Fit reports what installing `tag` of `e` would need on this router.
//
// The release metadata comes from the DIRECT GitHub API for the same reason Install uses it: a
// mirror does not get to define the size any decision is made on. A source-only engine (no prebuilt
// release) has no asset to measure and says so rather than reporting zeros.
func (u *Updater) Fit(ctx context.Context, e Engine, tag string) (InstallFit, error) {
	f := InstallFit{Version: tag, Dir: u.BinDir}
	if e.SourceOnly {
		return f, fmt.Errorf("%s has no prebuilt releases: %s", e.ID, e.Note)
	}
	rel, err := u.releaseDirect(ctx, e, tag)
	if err != nil {
		return f, fmt.Errorf("lookup %s %s: %w", e.ID, tag, err)
	}
	asset := pickAsset(rel.Assets, u.Arch)
	if asset == nil {
		return f, fmt.Errorf("no %s asset for arch %q in %s %s", e.ID, u.Arch, e.ID, tag)
	}
	f.Version = rel.Tag
	f.Asset, f.Download = asset.Name, asset.Size
	f.Need = peakInstallDisk(asset.Size, asset.Name, false)
	f.Avail, f.AvailKnown = AvailBytes(u.BinDir)
	f.Fits = enoughFlashFor(f.Avail, f.AvailKnown, asset.Size, asset.Name, false)
	if f.AvailKnown && !f.Fits {
		f.ShortfallMiB = shortfallMiB(f.Avail, f.Need)
	}
	return f, nil
}

// SelfFit answers "would updating WayHop ITSELF fit here", with the same numbers SelfUpdate
// enforces — not the engine ones.
//
// Fit above measures an engine: it looks at u.BinDir (where sing-box lands) and passes
// withBackup=false. Neither is right for the daemon replacing its own binary, which stages beside
// the RUNNING executable and must also write a complete .bak — the rollback is mandatory, so its
// bytes are part of the peak.
//
// The panel needs this before it offers the button. Measured on a live AX3000T (OpenWrt,
// /overlay 13 MiB free): a self-update there needs ~27 MiB, so the refusal is the routine outcome
// on that box, and until now it could only arrive after the click.
func (u *Updater) SelfFit(ctx context.Context, repo, tag, exePath string) (InstallFit, error) {
	dir := filepath.Dir(exePath)
	f := InstallFit{Version: tag, Dir: dir}
	if repo == "" {
		repo = DefaultSelfRepo
	}
	rel, err := u.releaseDirect(ctx, Engine{Repo: repo}, tag)
	if err != nil {
		return f, fmt.Errorf("lookup wayhop %s: %w", tag, err)
	}
	asset := selfAsset(rel.Assets, u.Arch)
	if asset == nil {
		return f, fmt.Errorf("no wayhop asset for arch %q in %s", u.Arch, tag)
	}
	f.Version = rel.Tag
	f.Asset, f.Download = asset.Name, asset.Size
	f.Need = peakInstallDisk(asset.Size, asset.Name, true)
	f.Avail, f.AvailKnown = AvailBytes(dir)
	f.Fits = enoughFlashFor(f.Avail, f.AvailKnown, asset.Size, asset.Name, true)
	if f.AvailKnown && !f.Fits {
		f.ShortfallMiB = shortfallMiB(f.Avail, f.Need)
	}
	return f, nil
}
