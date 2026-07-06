// Package pm inspects and (optionally) drives the host's native package manager — opkg on
// Entware/older OpenWrt, apk on OpenWrt 24.10+. WayHop uses it READ-ONLY today: to recognise when
// an engine (e.g. sing-box) is owned by the package manager at the path the daemon actually runs,
// so the panel can defer to opkg/apk instead of clobbering the packaged binary with a raw download.
// The mutating methods (Install/Upgrade/Remove) are the package's API for a future, path-verified,
// version-gated delegation; they are NOT wired into the updater's install/remove path yet (that
// needs on-device validation — see docs). Everything is exec-argv (never a shell string), and every
// package name is validated against a strict charset before it can reach exec.
package pm

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Kind is the detected native package manager.
type Kind string

const (
	None Kind = ""     // no PM on PATH (dev host, CI)
	Opkg Kind = "opkg" // Entware / OpenWrt <= 23.x
	Apk  Kind = "apk"  // OpenWrt 24.10+
)

// pkgNameRe is the strict allow-list for a package name handed to exec. opkg/apk names are lowercase
// alnum plus - _ . + (e.g. "sing-box-go", "dnscrypt-proxy2", "xray-core"). No spaces, slashes, flags
// or shell metacharacters can pass; a name that fails is treated as "no package" (fail-closed).
var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)

// ValidPkgName reports whether s is a safe package token to pass to the PM.
func ValidPkgName(s string) bool { return pkgNameRe.MatchString(s) }

// Runner executes a PM command. Injected so tests use a mock; production uses ExecRunner. It MUST
// receive argv (name + args), never a shell line.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (out string, err error)
}

// ExecRunner is the real os/exec runner (argv, no shell).
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Manager wraps a detected PM Kind and a Runner. The zero value (Kind None) inspects/drives nothing.
type Manager struct {
	Kind   Kind
	Runner Runner
}

// Detect picks the host PM by PATH lookup, apk winning over opkg when both exist (a transitional
// OpenWrt system). lookPath is injectable for tests.
func Detect() Manager { return detect(exec.LookPath) }

func detect(lookPath func(string) (string, error)) Manager {
	if _, err := lookPath("apk"); err == nil {
		return Manager{Kind: Apk, Runner: ExecRunner{}}
	}
	if _, err := lookPath("opkg"); err == nil {
		return Manager{Kind: Opkg, Runner: ExecRunner{}}
	}
	return Manager{Kind: None, Runner: ExecRunner{}}
}

// Available reports whether a native PM was detected on this host.
func (m Manager) Available() bool { return m.Kind != None }

// Installed reports the version of pkg from the PM database and whether it is present.
// opkg: `opkg status <pkg>` -> "Version: X". apk: `apk list --installed <pkg>` -> "<pkg>-<ver> ...".
func (m Manager) Installed(ctx context.Context, pkg string) (version string, present bool) {
	if !ValidPkgName(pkg) || m.Kind == None {
		return "", false
	}
	switch m.Kind {
	case Opkg:
		out, err := m.run(ctx, "opkg", "status", pkg)
		if err != nil || strings.TrimSpace(out) == "" {
			return "", false
		}
		return parseOpkgVersion(out), true
	case Apk:
		out, err := m.run(ctx, "apk", "list", "--installed", pkg)
		if err != nil || strings.TrimSpace(out) == "" {
			return "", false
		}
		return parseApkVersion(out, pkg), true
	}
	return "", false
}

// Files returns the file paths a package owns (opkg: `opkg files`, apk: `apk info -L`). Used by the
// caller to verify the PM's install path equals the daemon's run path BEFORE trusting delegation.
func (m Manager) Files(ctx context.Context, pkg string) ([]string, error) {
	if !ValidPkgName(pkg) {
		return nil, fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	var out string
	var err error
	switch m.Kind {
	case Opkg:
		out, err = m.run(ctx, "opkg", "files", pkg)
	case Apk:
		out, err = m.run(ctx, "apk", "info", "-L", pkg)
	default:
		return nil, fmt.Errorf("pm: no package manager detected")
	}
	if err != nil {
		return nil, err
	}
	var files []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "/") {
			files = append(files, ln)
		}
	}
	return files, nil
}

// Owner returns the package that owns file path and whether one does. Path-based (opkg: `opkg
// search <path>`, apk: `apk info --who-owns <path>`) so the updater can recognise a PM-managed
// binary WITHOUT trusting a name map — this is how it refuses to clobber e.g. an opkg-owned
// /opt/bin/sing-box with a raw download. THREE-STATE: a non-nil err means the query could not be
// answered (PM database locked by a concurrent opkg/apk run, timeout, exec failure) — callers on a
// mutating path must treat that as FAIL-CLOSED (refuse + retry), never as "not owned", or the whole
// clobber protection silently disappears exactly when the PM is busy installing. A clean "no owner"
// (apk's "Could not find owner package" / opkg's empty search result) is (\"\", false, nil).
func (m Manager) Owner(ctx context.Context, path string) (pkg string, owned bool, err error) {
	if m.Kind == None || path == "" {
		return "", false, nil
	}
	switch m.Kind {
	case Opkg:
		out, err := m.run(ctx, "opkg", "search", path)
		if err != nil {
			return "", false, err // opkg search exits 0 even for no-match; non-zero = lock/timeout/real failure
		}
		if f := strings.Fields(strings.TrimSpace(out)); len(f) > 0 && ValidPkgName(f[0]) { // "sing-box-go - 1.12.22-r1"
			return f[0], true, nil
		}
	case Apk:
		out, err := m.run(ctx, "apk", "info", "--who-owns", path)
		if err != nil {
			// apk exits non-zero for a clean not-owned too ("ERROR: <path>: Could not find owner
			// package") — that is a definitive answer, not a failure.
			if strings.Contains(out, "Could not find owner") {
				return "", false, nil
			}
			return "", false, err
		}
		if i := strings.LastIndex(out, " owned by "); i >= 0 { // "<path> is owned by sing-box-1.11.15-r0"
			if owner := strings.TrimSpace(out[i+len(" owned by "):]); owner != "" {
				return owner, true, nil
			}
		}
	}
	return "", false, nil
}

// Install installs (opkg: also in-place upgrades) a package by name. argv only.
//
//	opkg: `opkg install <pkg>`   apk: `apk add <pkg>`
func (m Manager) Install(ctx context.Context, pkg string) (string, error) {
	if !ValidPkgName(pkg) {
		return "", fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	switch m.Kind {
	case Opkg:
		return m.run(ctx, "opkg", "install", pkg)
	case Apk:
		return m.run(ctx, "apk", "add", pkg)
	default:
		return "", fmt.Errorf("pm: no package manager detected")
	}
}

// Upgrade is the update path. opkg has no per-package upgrade verb (install upgrades in place); apk
// is a targeted `apk add`. Same argv as Install by design; kept distinct so call sites read clearly.
func (m Manager) Upgrade(ctx context.Context, pkg string) (string, error) { return m.Install(ctx, pkg) }

// Remove removes a package by name. argv only.  opkg: `opkg remove <pkg>`   apk: `apk del <pkg>`
func (m Manager) Remove(ctx context.Context, pkg string) (string, error) {
	if !ValidPkgName(pkg) {
		return "", fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	switch m.Kind {
	case Opkg:
		return m.run(ctx, "opkg", "remove", pkg)
	case Apk:
		return m.run(ctx, "apk", "del", pkg)
	default:
		return "", fmt.Errorf("pm: no package manager detected")
	}
}

func (m Manager) run(ctx context.Context, name string, args ...string) (string, error) {
	r := m.Runner
	if r == nil {
		r = ExecRunner{}
	}
	out, err := r.Run(ctx, name, args...)
	if err != nil {
		return out, fmt.Errorf("pm: %s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return out, nil
}
