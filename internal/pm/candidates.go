package pm

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rolling back to an older build is the one operation the two package managers genuinely differ on,
// and the difference has to be reported rather than papered over.
//
//	apk  — `apk add <pkg>=<version>` installs an exact feed version, so a rollback is one command.
//	opkg — `opkg install <pkg>` installs whatever the feed currently offers and has NO version pin.
//	       Rolling back means fetching that version's .ipk and installing the FILE, which is a
//	       different operation with different failure modes (a URL, a signature, a download).
//
// So InstallVersion answers with ErrNoVersionPin on opkg instead of silently installing the wrong
// build. A caller that offered the operator "roll back to 1.12.17" and then installed 1.13.4 would
// be worse than one that says it cannot.
var ErrNoVersionPin = errors.New("pm: this package manager cannot install a specific version")

// verTokenRe is the allow-list for a version handed to exec. Feed versions are digits, dots and a
// packaging suffix (1.12.17, 1.12.17-r1, 2.0.0_beta1). Anything else — a space, a slash, a shell
// metacharacter, an option-looking leading dash — is refused before it can reach argv.
var verTokenRe = regexp.MustCompile(`^[0-9][0-9A-Za-z._+~-]{0,63}$`)

// ValidVersion reports whether s is a safe version token to pass to the PM.
func ValidVersion(s string) bool { return verTokenRe.MatchString(s) }

// Candidate is one installable build of a package as the FEED reports it.
type Candidate struct {
	Version   string // as printed by the PM, packaging suffix included: "1.12.17-r1"
	Installed bool   // the PM says this exact build is the one on disk
	// Available says the build came from a configured package repository. apk prints the installed
	// database entry even when every repository index is missing, so Installed alone cannot answer
	// whether `apk add <pkg>` has anything to install. When apk prints the same version twice (one
	// repository row and one `[installed]` row), both flags are true after de-duplication.
	Available bool
}

// apkListRe matches a line of `apk list <pkg>`:
//
//	sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later) [installed]
//
// Interpolating the package name is necessary but NOT sufficient. `apk list sing-box` also returns
// sibling packages whose names extend it — sing-box-doc — and those start with the same "sing-box-"
// prefix, so cutting it leaves "doc-1.12.17-r1" and a docs package appears in the list as if it were
// a rollback target for the binary. The remainder must therefore begin with a DIGIT, which is what a
// version is and what "doc" is not. Caught by the test, not by the reasoning that wrote the line.
func apkCandidates(out, pkg string) []Candidate {
	var got []Candidate
	at := map[string]int{}
	prefix := pkg + "-"
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		rest, ok := strings.CutPrefix(ln, prefix)
		if !ok || rest == "" || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		ver, _, _ := strings.Cut(rest, " ")
		ver = strings.TrimSpace(ver)
		if ver == "" {
			continue
		}
		installed := strings.Contains(ln, "[installed]")
		available := !installed
		// apk prints ONE version on TWO lines — verbatim from the AX3000T, where `apk list sing-box`
		// answers `sing-box-1.12.17-r1 … [installed]` and then the same version again without the tag.
		// Deduplicating by keeping the first line threw away the tag whenever the untagged line came
		// first, and nothing guarantees the order: the build already running would then be offered as
		// something to roll back TO, which is an action that changes nothing dressed up as one that
		// does. A version is installed if ANY line says so.
		if i, dup := at[ver]; dup {
			got[i].Installed = got[i].Installed || installed
			got[i].Available = got[i].Available || available
			continue
		}
		at[ver] = len(got)
		got = append(got, Candidate{Version: ver, Installed: installed, Available: available})
	}
	return got
}

// opkgCandidates matches a line of `opkg list <pkg>`:
//
//	sing-box - 1.12.17-1 - A universal proxy platform
//
// opkg prints one line per package, so this normally yields a single candidate — which is exactly
// why a rollback cannot be expressed here: the feed offers what it offers.
func opkgCandidates(out, pkg string) []Candidate {
	var got []Candidate
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		name, rest, ok := strings.Cut(ln, " - ")
		if !ok || strings.TrimSpace(name) != pkg {
			continue
		}
		ver, _, _ := strings.Cut(strings.TrimSpace(rest), " - ")
		ver = strings.TrimSpace(ver)
		if ver == "" || seen[ver] {
			continue
		}
		seen[ver] = true
		got = append(got, Candidate{Version: ver, Available: true})
	}
	return got
}

// Candidates lists the builds the feed offers for pkg, newest first.
//
// This is what a rollback picker needs and what nothing here could answer before: the updater knew
// how to ask GitHub for tags, and nothing knew how to ask the package manager what IT has.
func (m Manager) Candidates(ctx context.Context, pkg string) ([]Candidate, error) {
	if !ValidPkgName(pkg) {
		return nil, fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	var out string
	var err error
	switch m.Kind {
	case Apk:
		out, err = m.run(ctx, "apk", "list", pkg)
	case Opkg:
		out, err = m.run(ctx, "opkg", "list", pkg)
	default:
		return nil, fmt.Errorf("pm: no package manager detected")
	}
	if err != nil {
		return nil, fmt.Errorf("pm: listing %s: %w", pkg, err)
	}
	// apk exits zero while printing an installed-database row even when every configured repository
	// index is absent. Treating that answer as a healthy catalog is what made the panel offer an
	// update that could only reinstall the already-installed build. Keep the raw repository URLs out
	// of the API response (custom feeds can contain credentials) and return one actionable condition.
	if m.Kind == Apk && strings.Contains(out, "WARNING: opening from cache") &&
		strings.Contains(out, "No such file or directory") {
		return nil, fmt.Errorf("apk package indexes are unavailable; refresh package lists and retry")
	}
	var got []Candidate
	if m.Kind == Apk {
		got = apkCandidates(out, pkg)
	} else {
		got = opkgCandidates(out, pkg)
	}
	sort.SliceStable(got, func(i, j int) bool { return newerVersion(got[i].Version, got[j].Version) })
	return got, nil
}

// NewerVersion reports whether candidate sorts above installed using the package-version ordering
// used by Candidates. It is exported for the updater status DTO so UI state and rollback ordering
// cannot disagree about versions such as 1.12.17 and 1.9.4.
func NewerVersion(candidate, installed string) bool {
	if candidate == "" || installed == "" || candidate == installed {
		return false
	}
	return newerVersion(candidate, installed)
}

// CanPinVersion reports whether this manager can install a NAMED build. It is a property of the box,
// not of any particular request, which is why callers ask it before offering a choice: a rollback
// picker on a manager that cannot pin is a menu with nothing behind it, and the operator finds out
// only after choosing. `opkg install <pkg>` takes whatever the feed currently holds.
//
// One source for the answer: the planner's refusal and the endpoint that warns ahead of it both read
// this, so they cannot come to different conclusions about the same box.
func (m Manager) CanPinVersion() bool { return m.Kind == Apk }

// InstallVersion installs one exact build. See ErrNoVersionPin for why opkg refuses.
func (m Manager) InstallVersion(ctx context.Context, pkg, version string) (string, error) {
	if !ValidPkgName(pkg) {
		return "", fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	if !ValidVersion(version) {
		return "", fmt.Errorf("pm: refusing unsafe version %q", version)
	}
	switch m.Kind {
	case Apk:
		// One argv token, `pkg=version`. Built here rather than by the caller so the two halves are
		// both validated above and cannot be spliced apart.
		return m.run(ctx, "apk", "add", pkg+"="+version)
	case Opkg:
		return "", ErrNoVersionPin
	default:
		return "", fmt.Errorf("pm: no package manager detected")
	}
}

// newerVersion orders two feed versions, digit group by digit group, so "1.12.17" sorts above
// "1.9.4" — which a plain string compare gets backwards, and which matters because the list it
// orders is what an operator picks a rollback target from.
func newerVersion(a, b string) bool {
	an, bn := verParts(a), verParts(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			return x > y
		}
	}
	return a > b // identical numerically: fall back to the raw token so the order is stable
}

var verPartRe = regexp.MustCompile(`\d+`)

func verParts(v string) []int {
	var out []int
	for _, s := range verPartRe.FindAllString(v, -1) {
		n, err := strconv.Atoi(s)
		if err != nil {
			// A group too long for int is not a version anyone ships; treat it as 0 rather than
			// letting the parse fail and the ordering become arbitrary.
			n = 0
		}
		out = append(out, n)
	}
	return out
}
