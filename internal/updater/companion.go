package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wayhop/internal/binstore"
)

// A companion is a binary WayHop builds itself and attaches to every one of its own releases, because
// its upstream publishes none: amneziawg-go ships source tags only. scripts/build-amneziawg-go.sh
// builds it at a pinned commit and packs one asset per arch, named
//
//	<prefix><upstream version>-linux-<arch>.gz     e.g. amneziawg-go-v3.1.20260828-linux-arm64.gz
//
// and the release workflow attaches those to the WayHop release. Two things follow for the updater.
// The releases are WayHop's (Engine.Repo), but what the operator chooses is the upstream version, so
// the listing is re-keyed by the version in the asset name. And the binary cannot say which version it
// is - amneziawg-go reports "0.0.20250522" at v3.1.20260828 - so the installed version is recorded
// beside it at install time (binstore), together with whether it is stored unpacked or, on a flash too
// small for that, as the gzip itself.

// companionVersion reads the upstream version out of a companion asset name; ok is false for every
// other asset of the release (WayHop's own tarballs and packages).
func companionVersion(name, prefix string) (string, bool) {
	if prefix == "" || !strings.HasPrefix(name, prefix) {
		return "", false
	}
	rest := name[len(prefix):]
	i := strings.Index(rest, "-linux-")
	if i <= 0 {
		return "", false
	}
	v := rest[:i]
	if strings.Contains(v, "/") || validateTag(v) != nil {
		return "", false
	}
	return v, true
}

// companionReleases re-keys WayHop's releases (newest first, as GitHub lists them) by the companion
// version they carry. A version shipped in several WayHop releases is taken from the newest STABLE one
// - a prerelease is used only when no stable release carries it - so installing a version never pulls
// its bytes from a WayHop build that was not released. The result keeps GitHub's order: the version in
// the newest release comes first, which is what LatestStable reads.
func companionReleases(rels []Release, prefix string) []Release {
	type pick struct {
		rel    Release
		stable bool
	}
	picks := map[string]*pick{}
	var order []string
	for _, r := range rels {
		// Only WayHop's own builds carry the companion. An awg-v* release (an AmneziaWG package set for
		// the feed) shares the repository and must never be read for one, whatever its assets are named.
		if !IsWayHopReleaseTag(r.Tag) {
			continue
		}
		byVer := map[string][]Asset{}
		var vers []string // in asset order, so one release carrying two versions still lists stably
		for _, a := range r.Assets {
			if v, ok := companionVersion(a.Name, prefix); ok {
				if _, dup := byVer[v]; !dup {
					vers = append(vers, v)
				}
				byVer[v] = append(byVer[v], a)
			}
		}
		for _, v := range vers {
			assets := byVer[v]
			p, seen := picks[v]
			if seen && (p.stable || r.Prerelease) {
				continue // already have a stable pick, or this one is no better
			}
			syn := Release{
				Tag:        v,
				Name:       fmt.Sprintf("%s%s (shipped with WayHop %s)", prefix, v, r.Tag),
				Prerelease: r.Prerelease,
				Assets:     assets,
			}
			if !seen {
				order = append(order, v)
			}
			picks[v] = &pick{rel: syn, stable: !r.Prerelease}
		}
	}
	out := make([]Release, 0, len(order))
	for _, v := range order {
		out = append(out, picks[v].rel)
	}
	return out
}

// companionReleasesPage is how many WayHop releases are read to build the companion listing: each
// carries one companion version, and fifteen reach back past any pin change the panel would offer.
const companionReleasesPage = 15

// companionList reads WayHop's releases through fetch (mirrored or direct) and re-keys them.
func (u *Updater) companionList(ctx context.Context, e Engine, fetch func(ctx context.Context, path string, v any) error) ([]Release, error) {
	if u.Offline {
		return offlineCompanionReleases(e.Companion, u.Arch), nil
	}
	var rs []Release
	if err := fetch(ctx, fmt.Sprintf("/repos/%s/releases?per_page=%d", e.Repo, companionReleasesPage), &rs); err != nil {
		return nil, err
	}
	return companionReleases(rs, e.Companion), nil
}

// companionRelease finds one companion version among WayHop's releases.
func (u *Updater) companionRelease(ctx context.Context, e Engine, tag string, fetch func(ctx context.Context, path string, v any) error) (Release, error) {
	if err := validateTag(tag); err != nil {
		return Release{}, err
	}
	rs, err := u.companionList(ctx, e, fetch)
	if err != nil {
		return Release{}, err
	}
	for _, r := range rs {
		if r.Tag == tag {
			return r, nil
		}
	}
	return Release{}, fmt.Errorf("no WayHop release carries %s %s", e.ID, tag)
}

// compressedNeed is what keeping a companion as its gzip costs on the target filesystem: the asset
// itself, written beside the old copy and renamed over it, plus the margin peakInstallDisk keeps.
func compressedNeed(assetSize int64) uint64 { return uint64(assetSize) + 4<<20 }

// installCompressed keeps a companion as the gzip it was published as, for a flash too small for the
// unpacked binary. It is downloaded verbatim with its digest checked, unpacked once into RAM so the
// --version check can prove it runs here, then renamed into place and recorded - the record carries
// the gzip's digest, which binstore.Unpack checks before every start.
func (u *Updater) installCompressed(ctx context.Context, e Engine, rel Release, asset Asset) (string, error) {
	gz := binstore.Stored(u.BinDir, e.BinName, true)
	tmp := gz + ".new"
	if err := u.streamAssetVerbatim(ctx, asset, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("download %s: %w", asset.Name, err)
	}
	fail := func(err error) (string, error) {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.MkdirAll(u.RunDir, 0o755); err != nil {
		return fail(err)
	}
	probe := filepath.Join(u.RunDir, e.BinName+".probe")
	if err := binstore.Gunzip(tmp, probe); err != nil {
		return fail(fmt.Errorf("unpack %s: %w", asset.Name, err))
	}
	_, verr := binaryRunnable(probe, e.VersionArgs)
	_ = os.Remove(probe)
	if verr != nil {
		return fail(fmt.Errorf("downloaded %s but it %v — wrong arch or corrupt asset; nothing was replaced, retry or install over SSH", e.ID, verr))
	}
	if err := u.engineManagedErr(e, "update"); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, gz); err != nil {
		return fail(err)
	}
	// An unpacked binary left from an earlier install is no longer the copy that runs, and its space is
	// what the compressed form exists to save.
	_ = os.Remove(binstore.Stored(u.BinDir, e.BinName, false))
	if err := binstore.Write(u.BinDir, e.BinName, rel.Tag, true); err != nil {
		return "", fmt.Errorf("%s is stored, but its record could not be written, so it cannot be unpacked to run: %w", e.ID, err)
	}
	return rel.Tag, nil
}

// companionInstalled is Installed for a companion: the recorded version of whichever form is stored,
// and "present, version unknown" for a binary the panel did not put there or that was replaced since.
func (u *Updater) companionInstalled(e Engine) Installed {
	if rec, ok := binstore.Read(u.BinDir, e.BinName); ok {
		return Installed{Present: true, Path: binstore.Stored(u.BinDir, e.BinName, rec.Compressed), Version: rec.Version,
			Source: SourceRelease}
	}
	if path, exists := u.enginePath(e); exists {
		return Installed{Present: true, Path: path, Source: SourceOther}
	}
	if gz := binstore.Stored(u.BinDir, e.BinName, true); fileExists(gz) {
		return Installed{Present: true, Path: gz, Source: SourceOther}
	}
	return Installed{Present: false}
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// companionFlashRefusal is flashRefusal for a companion that does not fit even kept compressed: the
// need it names is the gzip's, so the sentence must not call it the unpacked binary's. The need is
// rounded UP: the gzip's need sits a fraction of a MiB above what is free, and flooring both printed
// "~5 MiB free, need ~5 MiB" on a simulated 5 MiB overlay - a refusal that reads like a contradiction.
func companionFlashRefusal(id, dir string, avail uint64, assetSize int64) error {
	need := compressedNeed(assetSize)
	return fmt.Errorf("not enough free space to install %s in %s even kept compressed (~%d MiB free, need ~%d MiB for its %d KiB gzip plus the install margin — free at least %d MiB more there) — or point the “sing-box binary” setting at a directory with room, since the panel installs engines beside it, or install over SSH",
		id, dir, avail>>20, (need+(1<<20)-1)>>20, assetSize>>10, shortfallMiB(avail, need))
}
