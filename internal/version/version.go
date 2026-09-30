// Package version carries build-stamped identifiers for wayhop.
package version

import "strings"

// These defaults are overridden at build time via -ldflags. Only Version was ever injected, so every
// official binary reported `wayhop 0.5.5 (unknown, unknown)` — and a production router was found
// running a dirty build from a commit that no longer existed, with no way to tell from the binary
// itself. Commit, Date and Dirty exist so that question has an answer.
var (
	Version = "0.5.7"
	Commit  = "unknown"
	Date    = "unknown"
	// Dirty is "true" when the working tree carried uncommitted changes at build time, "false" when
	// it was clean, and "unknown" when the build path did not say. It is a string rather than a bool
	// because -ldflags can only set strings, and because "nobody said" is a third answer that a bool
	// would silently collapse into "clean".
	Dirty = "unknown"
)

// Unknown is the value a build path leaves behind when it stamps nothing.
const Unknown = "unknown"

// Info is the whole build identity in one shape, so a log line, an API response and a support report
// cannot describe the same binary differently.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Dirty   string `json:"dirty"`
}

// Get returns this binary's identity.
func Get() Info { return Info{Version: Version, Commit: Commit, Date: Date, Dirty: Dirty} }

// Complete reports whether this binary can be traced back to a specific, unmodified source tree.
// It is the property an official build must have: a release that cannot name its commit is one
// nobody can reproduce, diff or roll back with any confidence.
//
// A dirty build is deliberately NOT complete even though it names a commit — the commit describes
// what the tree was BEFORE the uncommitted changes, so reporting it alone would be a claim about
// code that is not the code running.
func (i Info) Complete() bool {
	return known(i.Commit) && known(i.Date) && i.Dirty == "false"
}

func known(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && s != Unknown
}

// ShortCommit is the first 12 characters of the commit, or the commit unchanged when it is shorter
// or unknown. Used where a full hash is noise: a log line, a UI footer.
func (i Info) ShortCommit() string {
	if !known(i.Commit) || len(i.Commit) <= 12 {
		return i.Commit
	}
	return i.Commit[:12]
}

// String is the one-line form used by --version and the startup log. The dirty marker is part of it
// because a dirty build that looks exactly like a clean one is the failure this package addresses.
func (i Info) String() string {
	s := i.Version + " (" + i.ShortCommit() + ", " + i.Date + ")"
	if i.Dirty == "true" {
		s += " DIRTY"
	}
	return s
}
