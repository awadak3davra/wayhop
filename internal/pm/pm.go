// Package pm inspects and (optionally) drives the host's native package manager — opkg on
// Entware/older OpenWrt, apk on OpenWrt 24.10+. WayHop uses it READ-ONLY today: to recognise when
// an engine (e.g. sing-box) is owned by the package manager at the path the daemon actually runs,
// so the panel can defer to opkg/apk instead of clobbering the packaged binary with a raw download.
// The mutating methods (Install/Upgrade/Remove/InstallVersion) are reached through the updater's
// path-verified, version-gated plan (internal/updater/pmplan.go): the operator is shown an argv this
// package built and the daemon runs that same argv back through RunPlanned. Everything is exec-argv
// (never a shell string), and every package name is validated against a strict charset before it can
// reach exec.
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

// InstalledPackageVersion is Installed with the native package revision preserved. The generic
// Installed method intentionally returns the upstream version for compatibility with release-tag
// comparisons; repository state must instead compare exact package versions such as 1.12.17-r1.
func (m Manager) InstalledPackageVersion(ctx context.Context, pkg string) (version string, present bool) {
	if !ValidPkgName(pkg) || m.Kind == None {
		return "", false
	}
	switch m.Kind {
	case Opkg:
		out, err := m.run(ctx, "opkg", "status", pkg)
		if err != nil || strings.TrimSpace(out) == "" {
			return "", false
		}
		version = parseOpkgPackageVersion(out)
	case Apk:
		out, err := m.run(ctx, "apk", "list", "--installed", pkg)
		if err != nil || strings.TrimSpace(out) == "" {
			return "", false
		}
		version = parseApkPackageVersion(out, pkg)
	}
	return version, version != ""
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
		if ln == "" {
			continue
		}
		switch m.Kind {
		case Opkg:
			// `opkg files` prints absolute paths (e.g. /opt/bin/sing-box); keep those.
			if strings.HasPrefix(ln, "/") {
				files = append(files, ln)
			}
		case Apk:
			// `apk info -L` prints a "<pkg>-<ver> contains:" header (ends ':') followed by package-
			// RELATIVE paths (usr/bin/sing-box, no leading '/'). Skip the header and root-anchor each
			// path so Files() returns absolute paths on BOTH package managers (the caller compares the
			// PM install path to the daemon run path — a HasPrefix("/") filter dropped every apk line).
			if strings.HasSuffix(ln, ":") {
				continue
			}
			if !strings.HasPrefix(ln, "/") {
				ln = "/" + ln
			}
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

// InstallArgv, UpgradeArgv and RemoveArgv are the exact native commands for the three mutating
// verbs. They sit beside RefreshArgv for the reason its comment gives: the panel shows an argv,
// sends the same value back and the daemon runs it, so preview and operation must come from ONE
// source or they drift apart.
//
// They had drifted, and the drift was the whole defect. Upgrade was written as an alias of Install
// — "same argv as Install by design" — and on apk that is not an upgrade at all: `apk add <pkg>` on
// an already-installed package keeps the build that is there and exits 0. Measured on the AX3000T,
// where the panel's Update button ran `apk add sing-box` at 22:02:52 and apk answered
// "OK: 76.6 MiB in 189 packages" with sing-box still at 1.12.17-r1 while the feed offered
// 1.13.21-r1. The daemon logged an upgrade, the panel toasted a success, and nothing had changed.
// apk's own verb for this is `apk upgrade <pkg>`.
//
// opkg keeps `opkg install`, which does replace an installed package with a newer feed build — the
// one manager where the two verbs really are the same command.
//
// A nil return means "this manager has no such command", which every caller already treats as
// blocked; it is never a partially-built argv.
func (m Manager) InstallArgv(pkg string) []string {
	if !ValidPkgName(pkg) {
		return nil
	}
	switch m.Kind {
	case Opkg:
		return []string{"opkg", "install", pkg}
	case Apk:
		return []string{"apk", "add", pkg}
	}
	return nil
}

// UpgradeArgv moves an INSTALLED package to the build the feed offers.
func (m Manager) UpgradeArgv(pkg string) []string {
	if !ValidPkgName(pkg) {
		return nil
	}
	switch m.Kind {
	case Opkg:
		return []string{"opkg", "install", pkg}
	case Apk:
		return []string{"apk", "upgrade", pkg}
	}
	return nil
}

// RemoveArgv deletes an installed package.
func (m Manager) RemoveArgv(pkg string) []string {
	if !ValidPkgName(pkg) {
		return nil
	}
	switch m.Kind {
	case Opkg:
		return []string{"opkg", "remove", pkg}
	case Apk:
		return []string{"apk", "del", pkg}
	}
	return nil
}

// InstallVersionArgv installs one exact build. See ErrNoVersionPin for why opkg has none.
func (m Manager) InstallVersionArgv(pkg, version string) []string {
	if !ValidPkgName(pkg) || !ValidVersion(version) || m.Kind != Apk {
		return nil
	}
	// One argv token, `pkg=version`. Built here rather than by the caller so the two halves are both
	// validated above and cannot be spliced apart.
	return []string{"apk", "add", pkg + "=" + version}
}

// Install installs a package by name. argv only.
func (m Manager) Install(ctx context.Context, pkg string) (string, error) {
	return m.RunPlanned(ctx, m.InstallArgv(pkg))
}

// Upgrade is the update path: the installed package moves to the feed's build.
func (m Manager) Upgrade(ctx context.Context, pkg string) (string, error) {
	return m.RunPlanned(ctx, m.UpgradeArgv(pkg))
}

// Remove removes a package by name. argv only.
func (m Manager) Remove(ctx context.Context, pkg string) (string, error) {
	return m.RunPlanned(ctx, m.RemoveArgv(pkg))
}

// RunPlanned executes an argv this package itself built — the one the operator read and approved —
// instead of re-deriving a command from the action after the fact. Simulate has taken its argv this
// way since it was written; the execution path had not, and the gap between them is where the
// upgrade defect lived: plan and dry run agreed on a command while ExecutePM called a method on the
// side that built its own. There is now one command per step, built once, shown, simulated and run.
//
// The allow-list has the same shape as Simulate's, for the same reason: an argv that did not come
// from a planner must not become an arbitrary root command.
func (m Manager) RunPlanned(ctx context.Context, argv []string) (string, error) {
	if !m.Available() {
		return "", fmt.Errorf("pm: no package manager detected")
	}
	if len(argv) != 3 {
		return "", fmt.Errorf("pm: %q is not a package command this planner builds", strings.Join(argv, " "))
	}
	if argv[0] != string(m.Kind) {
		return "", fmt.Errorf("pm: refusing to run %q with %s", argv[0], m.Kind)
	}
	switch argv[1] {
	case "add", "del", "upgrade", "install", "remove":
	default:
		return "", fmt.Errorf("pm: %q is not a package operation", argv[1])
	}
	// `apk add <pkg>=<version>` is the one argument that is not a bare name, and both halves are
	// validated here rather than trusted because they arrived inside a slice.
	name, version, pinned := strings.Cut(argv[2], "=")
	if !ValidPkgName(name) || (pinned && !ValidVersion(version)) {
		return "", fmt.Errorf("pm: refusing unsafe package argument %q", argv[2])
	}
	return m.run(ctx, argv[0], argv[1:]...)
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
