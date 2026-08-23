package updater

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"wayhop/internal/pm"
)

const (
	PackageStateUnmanaged      = "unmanaged"
	PackageStateUnknown        = "unknown"
	PackageStateCatalogError   = "catalog_error"
	PackageStateChannelMissing = "channel_missing"
	PackageStateCurrent        = "current"
	PackageStateBehind         = "behind"
	PackageStateAhead          = "ahead"
)

// PackageStatus is the package manager's answer for the exact binary WayHop runs. GitHub release
// tags are deliberately absent: once apk/opkg owns a path, only that manager's repository can say
// which build it would install without desynchronising its database.
type PackageStatus struct {
	Manager          pm.Kind        `json:"manager"`
	Managed          bool           `json:"managed"`
	OwnershipKnown   bool           `json:"ownership_known"`
	Package          string         `json:"package,omitempty"`
	Path             string         `json:"path,omitempty"`
	InstalledVersion string         `json:"installed_version,omitempty"`
	LatestVersion    string         `json:"latest_version,omitempty"`
	State            string         `json:"state"`
	Error            string         `json:"error,omitempty"`
	Candidates       []pm.Candidate `json:"candidates,omitempty"`
}

// PMRefreshArgv/RefreshPM expose only the package-index refresh operation. They do not expose the
// manager or its Runner, so the server cannot construct arbitrary package commands around this API.
func (u *Updater) PMRefreshArgv() []string {
	if u == nil {
		return nil
	}
	return u.pm.RefreshArgv()
}

func (u *Updater) RefreshPM(ctx context.Context) (string, error) {
	if u == nil {
		return "", fmt.Errorf("package updater unavailable")
	}
	return u.pm.Refresh(ctx)
}

// EnginePackageStatus resolves the same binary path as Installed/PlanPM and then asks the package
// manager about that exact file. An absent engine is not package-managed and is left to the install
// planner, which separately proves whether a package with that name exists.
func (u *Updater) EnginePackageStatus(ctx context.Context, e Engine) PackageStatus {
	if u == nil || !u.pm.Available() {
		return PackageStatus{State: PackageStateUnmanaged, OwnershipKnown: true}
	}
	path := filepath.Join(u.BinDir, e.BinName)
	if _, err := os.Stat(path); err != nil {
		resolved, lookErr := exec.LookPath(e.BinName)
		if lookErr != nil {
			return PackageStatus{Manager: u.pm.Kind, State: PackageStateUnmanaged, OwnershipKnown: true, Path: path}
		}
		path = resolved
	}
	return u.packageStatusForPath(ctx, path)
}

// SelfPackageStatus is EnginePackageStatus for the running WayHop executable. It lets the self row
// use apk/opkg as its source of truth instead of failing a GitHub check and then telling the operator
// that the panel refuses to touch the package anyway.
func (u *Updater) SelfPackageStatus(ctx context.Context, exePath string) PackageStatus {
	if u == nil || !u.pm.Available() {
		return PackageStatus{State: PackageStateUnmanaged, OwnershipKnown: true, Path: exePath}
	}
	return u.packageStatusForPath(ctx, exePath)
}

func (u *Updater) packageStatusForPath(ctx context.Context, path string) PackageStatus {
	u.pmStatusMu.Lock()
	defer u.pmStatusMu.Unlock()
	status := PackageStatus{Manager: u.pm.Kind, Path: path, State: PackageStateUnknown}
	owner, owned, err := u.pm.Owner(ctx, path)
	if err != nil {
		status.Error = "the package database could not verify ownership; retry after the package manager is idle"
		return status
	}
	status.OwnershipKnown = true
	if !owned {
		status.State = PackageStateUnmanaged
		return status
	}
	status.Managed = true
	status.Package = u.pm.PackageName(owner)
	if !pm.ValidPkgName(status.Package) {
		status.State = PackageStateUnknown
		status.Error = "the package manager returned an unusable package identity"
		return status
	}
	files, err := u.pm.Files(ctx, status.Package)
	if err != nil || !containsPath(files, path) {
		status.State = PackageStateUnknown
		status.Error = "the package record does not prove ownership of the binary WayHop is running"
		return status
	}
	if installed, present := u.pm.InstalledPackageVersion(ctx, status.Package); present {
		status.InstalledVersion = installed
	}
	candidates, err := u.pm.Candidates(ctx, status.Package)
	if err != nil {
		status.State = PackageStateCatalogError
		// Package-manager output can include configured repository URLs, including private feed
		// credentials. The status API needs an actionable category, not the raw command output.
		status.Error = fmt.Sprintf("%s package catalog could not be read; refresh package lists and retry", u.pm.Kind)
		return status
	}
	status.Candidates = candidates
	for _, candidate := range candidates {
		if candidate.Available {
			status.LatestVersion = candidate.Version
			break
		}
	}
	if status.LatestVersion == "" {
		status.State = PackageStateChannelMissing
		status.Error = fmt.Sprintf("no configured %s repository offers package %q", u.pm.Kind, status.Package)
		return status
	}
	if status.InstalledVersion == "" {
		status.State = PackageStateUnknown
		status.Error = "the package is recorded as owner but its installed version could not be read"
		return status
	}
	switch {
	case pm.NewerVersion(status.LatestVersion, status.InstalledVersion):
		status.State = PackageStateBehind
	case pm.NewerVersion(status.InstalledVersion, status.LatestVersion):
		status.State = PackageStateAhead
	default:
		status.State = PackageStateCurrent
	}
	return status
}
