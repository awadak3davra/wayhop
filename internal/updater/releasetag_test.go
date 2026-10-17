package updater

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/pm"
)

// --- release hygiene: awg-v* releases share WayHop's repository ------------------------------

func TestIsWayHopReleaseTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.5.7": true, "v0.5.5-r2": true, "v0.6.0-rc1": true, "v1.0.0-beta.2": true, "v1.2.3+build.5": true,
		"awg-v3.1.20260906-1": false, "awg-v3.1.20260906": false, "v1": false, "v1.2": false, "0.5.7": false,
		"nightly-6fa08e7": false, "v0.5.7/../x": false, "": false, "V0.5.7": false, "v0.5.7-": false,
	} {
		if got := IsWayHopReleaseTag(tag); got != want {
			t.Errorf("IsWayHopReleaseTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

// An awg-v* release newer than every WayHop release, carrying an asset shaped like WayHop's own, is
// never the self-update - Newer would read it as version 3.1.
func TestSelfUpdatePassesOverAWGReleases(t *testing.T) {
	arm64 := []Asset{{Name: "wayhop-arm64.tar.gz"}}
	rels := []Release{
		{Tag: "awg-v3.1.20260906-1", Assets: arm64},
		{Tag: "v0.5.7", Assets: arm64},
	}
	if got, ok := pickSelfRelease(rels, "arm64"); !ok || got.Tag != "v0.5.7" {
		t.Errorf("picked %q (%v), want v0.5.7", got.Tag, ok)
	}
	if _, ok := pickSelfRelease(rels[:1], "arm64"); ok {
		t.Error("an awg-v* release alone was picked as a self-update")
	}
	u := New(t.TempDir(), "arm64", nil).WithPM(pm.Manager{Kind: pm.None})
	if _, err := u.SelfUpdate(context.Background(), "", "awg-v3.1.20260906-1", filepath.Join(t.TempDir(), "wayhop")); err == nil ||
		!strings.Contains(err.Error(), "not a WayHop release") {
		t.Errorf("SelfUpdate to an awg tag: %v", err)
	}
	if _, err := u.SelfFit(context.Background(), "", "awg-v3.1.20260906-1", filepath.Join(t.TempDir(), "wayhop")); err == nil ||
		!strings.Contains(err.Error(), "not a WayHop release") {
		t.Errorf("SelfFit of an awg tag: %v", err)
	}
}

// The companion listing reads amneziawg-go only out of WayHop's own releases, even when an awg-v*
// release carries an asset with the companion's name.
func TestCompanionListingPassesOverAWGReleases(t *testing.T) {
	asset := func(v string) []Asset { return []Asset{{Name: "amneziawg-go-" + v + "-linux-arm64.gz"}} }
	rels := []Release{
		{Tag: "awg-v3.1.20260906-1", Assets: asset("v9.9.9")},
		{Tag: "v0.5.7", Assets: asset("v3.1.20260828")},
		{Tag: "awg-v3.1.20260812-1"},
	}
	got := companionReleases(rels, "amneziawg-go-")
	if len(got) != 1 || got[0].Tag != "v3.1.20260828" || LatestStable(got) != "v3.1.20260828" {
		t.Errorf("companion versions %+v", got)
	}
}
