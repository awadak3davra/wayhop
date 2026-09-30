package pm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// size.go answers "how much disk would this build take", from the package manager's own index
// rather than from an estimate.
//
// The GitHub install path has had this since it was written (see the updater's Fit): it reads the
// release asset's size and refuses before downloading anything onto a 60 MiB overlay. The package
// path had nothing of the sort — it built a command, showed it, and let apk discover mid-write that
// the router is too small. On the AX3000T that is not an edge case: /overlay has 20.2 MiB free and
// the sing-box the feed offers unpacks to 42.4 MiB, so every upgrade of the core through the package
// manager is a decision that cannot be made without these numbers.
//
// apk-tools 3 answers exactly, in bytes, for every build it knows — the installed one from its
// database and the offered one from the repository index:
//
//	# apk query --format json --fields name,version,installed-size,file-size --all-matches sing-box
//	[{"name":"sing-box","version":"1.12.17-r1","installed-size":40537528,"file-size":14485215},
//	 {"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117}]
//
// opkg has no equivalent that can be trusted for a build it has not installed, so it says so with
// ErrNoSizes rather than guessing. Callers skip their space guard on that error — the same rule
// AvailBytes already sets for a failed statfs: an unknown is not a refusal.

// PkgSize is what one build of a package costs.
type PkgSize struct {
	Version string `json:"version"`
	// Installed is the unpacked size on disk. Download is the archive on the wire; they differ by
	// roughly 3x for a Go binary, and it is the unpacked figure a disk decision needs.
	Installed uint64 `json:"installed_bytes"`
	Download  uint64 `json:"download_bytes"`
}

// ErrNoSizes marks "this manager cannot answer", which is NOT "the answer is zero".
var ErrNoSizes = errors.New("pm: this package manager does not report package sizes")

// Sizes lists what each build of pkg would occupy, newest first is NOT guaranteed — callers look a
// version up rather than taking a position.
func (m Manager) Sizes(ctx context.Context, pkg string) ([]PkgSize, error) {
	if !ValidPkgName(pkg) {
		return nil, fmt.Errorf("pm: refusing unsafe package name %q", pkg)
	}
	if m.Kind != Apk {
		return nil, ErrNoSizes
	}
	out, err := m.run(ctx, "apk", "query", "--format", "json",
		"--fields", "name,version,installed-size,file-size", "--all-matches", pkg)
	if err != nil {
		return nil, fmt.Errorf("pm: sizes for %s: %w", pkg, err)
	}
	return parseApkSizes(out, pkg)
}

func parseApkSizes(out, pkg string) ([]PkgSize, error) {
	var rows []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Installed uint64 `json:"installed-size"`
		Download  uint64 `json:"file-size"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		// An apk too old for `query --fields` prints a usage error here. That is "cannot answer",
		// which is what ErrNoSizes says, and the caller then behaves exactly as it did before this
		// file existed rather than blocking on a version of apk it did not expect.
		return nil, ErrNoSizes
	}
	var got []PkgSize
	at := map[string]int{}
	for _, r := range rows {
		// `--all-matches` returns siblings that merely satisfy the same query, and the installed
		// database and a repository can both answer for one version. Keep the package asked about,
		// and keep the LARGER figure when a version is reported twice: a space guard that picks the
		// smaller of two answers is the one that lets a write start and fail halfway.
		if r.Name != pkg || r.Version == "" {
			continue
		}
		if i, dup := at[r.Version]; dup {
			if r.Installed > got[i].Installed {
				got[i].Installed = r.Installed
			}
			if r.Download > got[i].Download {
				got[i].Download = r.Download
			}
			continue
		}
		at[r.Version] = len(got)
		got = append(got, PkgSize{Version: r.Version, Installed: r.Installed, Download: r.Download})
	}
	if len(got) == 0 {
		return nil, ErrNoSizes
	}
	return got, nil
}

// SizeOf returns the installed size of one named build, and whether the list carried it at all.
func SizeOf(sizes []PkgSize, version string) (uint64, bool) {
	for _, s := range sizes {
		if s.Version == version && s.Installed > 0 {
			return s.Installed, true
		}
	}
	return 0, false
}
