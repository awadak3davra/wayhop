package version

import "testing"

// The property that matters: a binary either can name the exact source it was built from, or it
// admits it cannot. The failure this replaces is the third state — a binary that names a commit
// while running code that commit does not contain.

func TestInfo_CompleteRequiresEveryPart(t *testing.T) {
	full := Info{Version: "0.5.5", Commit: "961103dc9d6c2cf9a2ab6b29ac3d0368deb4090b", Date: "2026-08-08T17:34:37Z", Dirty: "false"}
	if !full.Complete() {
		t.Fatal("a clean build that names its commit and date must be complete")
	}

	cases := map[string]Info{
		"no commit":         {Version: "0.5.5", Commit: "unknown", Date: full.Date, Dirty: "false"},
		"empty commit":      {Version: "0.5.5", Commit: "", Date: full.Date, Dirty: "false"},
		"whitespace commit": {Version: "0.5.5", Commit: "   ", Date: full.Date, Dirty: "false"},
		"no date":           {Version: "0.5.5", Commit: full.Commit, Date: "unknown", Dirty: "false"},
		"empty date":        {Version: "0.5.5", Commit: full.Commit, Date: "", Dirty: "false"},
		// The one that is easy to get wrong: the commit is known, so a naive check passes — but it
		// describes the tree BEFORE the uncommitted changes, which is not the code that is running.
		"dirty tree":        {Version: "0.5.5", Commit: full.Commit, Date: full.Date, Dirty: "true"},
		"dirtiness unknown": {Version: "0.5.5", Commit: full.Commit, Date: full.Date, Dirty: "unknown"},
		"nothing stamped":   {Version: "0.5.5", Commit: "unknown", Date: "unknown", Dirty: "unknown"},
	}
	for name, in := range cases {
		if in.Complete() {
			t.Errorf("%s: reported complete, but this binary cannot be traced to an exact source tree: %+v", name, in)
		}
	}
}

// A dirty build must be visibly dirty wherever the identity is printed. An operator reading a log
// line or a support bundle has no other way to tell.
func TestInfo_StringMarksDirty(t *testing.T) {
	dirty := Info{Version: "0.5.5", Commit: "961103dc9d6c2cf9a2ab6b29ac3d0368deb4090b", Date: "2026-08-08T17:34:37Z", Dirty: "true"}
	if got := dirty.String(); got[len(got)-5:] != "DIRTY" {
		t.Errorf("a dirty build prints %q with no marker", got)
	}
	clean := dirty
	clean.Dirty = "false"
	if got := clean.String(); got[len(got)-5:] == "DIRTY" {
		t.Errorf("a clean build is marked dirty: %q", got)
	}
	// The version and a readable commit must both be there: a line carrying only one of them sends
	// the reader to the wrong place.
	if s := clean.String(); s[:5] != "0.5.5" {
		t.Errorf("the version is missing from %q", s)
	}
}

func TestInfo_ShortCommit(t *testing.T) {
	long := Info{Commit: "961103dc9d6c2cf9a2ab6b29ac3d0368deb4090b"}
	if got := long.ShortCommit(); got != "961103dc9d6c" {
		t.Errorf("ShortCommit = %q, want 961103dc9d6c", got)
	}
	// An unknown commit must stay legible rather than become a meaningless slice of the word.
	for _, c := range []string{"unknown", "", "abc"} {
		if got := (Info{Commit: c}).ShortCommit(); got != c {
			t.Errorf("ShortCommit(%q) = %q, want it unchanged", c, got)
		}
	}
}

// The package defaults are what an unstamped build reports, and they must be honest: an unstamped
// binary claiming a commit would be worse than one admitting it has none.
func TestPackageDefaultsAreHonestlyUnknown(t *testing.T) {
	if Commit != Unknown || Date != Unknown || Dirty != Unknown {
		t.Fatalf("defaults must be unknown until a build path stamps them, got commit=%q date=%q dirty=%q",
			Commit, Date, Dirty)
	}
	if Get().Complete() {
		t.Error("an unstamped build reported a complete identity")
	}
}
