package updater

import (
	"fmt"
	"strings"
)

// offline.go answers release metadata from a built-in catalogue instead of GitHub.
//
// The demo exists so the panel can be clicked through without touching anything — it fakes the
// platform, the interfaces, and the whole apply path. Release lookups were the one hole left: the
// Components page and the diagnostics page both ask what version is available, and in demo that
// reached the live api.github.com from whatever machine happened to be running the panel.
//
// That made the verification suite depend on a third party. Two of three full runs on 2026-08-19
// failed with `502 /api/updater/sing-box/fit` — once on the diagnostics page, once on Components —
// while nothing in the panel was wrong: GitHub had simply not answered inside the 20s budget. A
// gate that fails for reasons outside the code under test teaches its operator to ignore red, which
// is worse than having no gate.
//
// The seam is deliberately at the METADATA layer, not at the handlers. Everything above it — asset
// selection for the arch, peak-disk arithmetic, "fits"/shortfall, stable-vs-prerelease choice, the
// version picker — keeps running against this data, so the demo still exercises that code. Only the
// network call is replaced.
//
// Downloads are NOT served offline: Install still refuses without the network, because pretending a
// binary was fetched would fake the one part of the updater that touches the router's flash.

// offlineTags is the catalogue an ENGINE reports in demo. Three descending versions give the version
// picker something to pick, a "newer than installed" case for update detection, and an older tag to
// roll back to — the three shapes the Components page has branches for.
var offlineTags = []string{"v1.13.19", "v1.13.18", "v1.13.16"}

// WayHop's OWN repository reports nothing. Handing an engine's version line to every repo made the
// demo announce a WayHop 1.13.19 over a daemon at 0.5.6 — a self-update to a release that does not
// exist, offered by the one control that replaces the running binary. A demo may stand in for the
// world; it may not invent a newer version of itself. With no release the self row reads "could not
// be checked", which is what the demo showed back when the lookup simply failed.
func repoHasOfflineReleases(repo string) bool { return repo != DefaultSelfRepo }

// offlineAssetSize is a plausible engine tarball. It is large enough that peakInstallDisk lands in
// the tens of megabytes, so the demo shows the same "will this fit" arithmetic a router does.
const offlineAssetSize int64 = 24_753_732

// offlineReleases builds the catalogue for one repository. Asset names follow the convention every
// engine this project installs actually uses (<name>-<version>-linux-<arch>.tar.gz), so matchAsset
// and assetScore pick one exactly as they would from a real listing.
func offlineReleases(repo, arch string, limit int) []Release {
	base := repo
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if base == "" {
		base = "engine"
	}
	if arch == "" {
		arch = "amd64"
	}
	if !repoHasOfflineReleases(repo) {
		return nil
	}
	out := make([]Release, 0, len(offlineTags))
	for _, tag := range offlineTags {
		out = append(out, offlineRelease(base, arch, tag))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// offlineRelease is one entry of the catalogue. Prerelease stays false so LatestStable has a stable
// tag to return: an all-prerelease catalogue would make every engine look like it has no release,
// which is a state the demo should not invent.
func offlineRelease(base, arch, tag string) Release {
	ver := strings.TrimPrefix(tag, "v")
	name := fmt.Sprintf("%s-%s-linux-%s.tar.gz", base, ver, arch)
	return Release{
		Tag:  tag,
		Name: base + " " + tag,
		Assets: []Asset{{
			Name: name,
			URL:  "https://example.invalid/" + name, // never fetched: Install does not run offline
			Size: offlineAssetSize,
		}},
	}
}

// offlineCompanionVersion is the demo's companion version: the upstream tag
// scripts/build-amneziawg-go.sh pins (a test holds the two equal), because unlike an engine's
// invented v1.13.x line, this one names a real build.
const offlineCompanionVersion = "v3.1.20260828"

// offlineCompanionAssetSize is the real armv7 asset of that build, so the demo's fit arithmetic is a
// router's.
const offlineCompanionAssetSize int64 = 1_406_834

// offlineCompanionReleases is a companion's catalogue in demo: one WayHop release carrying the build,
// named as the build script names it, so companionReleases and pickAsset run exactly as they would.
func offlineCompanionReleases(prefix, arch string) []Release {
	if arch == "" {
		arch = "amd64"
	}
	token := arch
	if arch == "arm" {
		token = "armv7" // the name the build script gives its GOARM=7 build
	}
	name := prefix + offlineCompanionVersion + "-linux-" + token + ".gz"
	return companionReleases([]Release{{
		Tag:    "v0.5.7",
		Name:   "WayHop v0.5.7",
		Assets: []Asset{{Name: name, URL: "https://example.invalid/" + name, Size: offlineCompanionAssetSize}},
	}}, prefix)
}

// offlineReleaseByTag answers a single-tag lookup. An unknown tag is a genuine miss rather than a
// synthesized hit, so the "no such version" path stays reachable in the demo.
func offlineReleaseByTag(repo, arch, tag string) (Release, error) {
	base := repo
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if !repoHasOfflineReleases(repo) {
		return Release{}, fmt.Errorf("no releases for %s in the demo catalogue", repo)
	}
	for _, t := range offlineTags {
		if t == tag {
			return offlineRelease(base, arch, t), nil
		}
	}
	return Release{}, fmt.Errorf("no release %s for %s in the demo catalogue", tag, repo)
}
