package updater

import (
	"context"
	"net/http"
	"testing"
)

// The pre-flight the page shows must be the pre-flight the install enforces. These assert the two
// agree on the numbers that decide it: the asset picked for THIS arch, the unpacked size an archive
// needs (not its download size), and the directory engines actually land in.
func TestFitMeasuresTheAssetInstallWouldPick(t *testing.T) {
	const gz = 10 << 20 // a 10 MiB archive inflates to a 30 MiB binary, plus the staging margin
	body := []byte(`{"tag_name":"v1.2.3","name":"1.2.3","assets":[
		{"name":"sing-box-1.2.3-linux-amd64.tar.gz","browser_download_url":"https://x/amd64.tgz","size":999},
		{"name":"sing-box-1.2.3-linux-arm64.tar.gz","browser_download_url":"https://x/arm64.tgz","size":10485760}]}`)
	rt := &updater_jsonRT{routes: []updater_route{{suffix: "/releases/tags/v1.2.3", status: 200, body: body}}}

	dir := t.TempDir()
	u := New(dir, "arm64", nil)
	u.hc = &http.Client{Transport: rt}

	f, err := u.Fit(context.Background(), Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}, "v1.2.3")
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if f.Asset != "sing-box-1.2.3-linux-arm64.tar.gz" || f.Download != gz {
		t.Fatalf("picked the wrong asset for arm64: %+v", f)
	}
	// The number that matters is what has to be FREE, not what is downloaded: reporting the download
	// size would tell a 60 MiB overlay that a binary needing 34 MiB costs 10.
	if want := peakInstallDisk(gz, f.Asset, false); f.Need != want {
		t.Fatalf("Need = %d, want %d (the install path's own figure)", f.Need, want)
	}
	if f.Need <= uint64(f.Download) {
		t.Fatalf("an archive must need more disk than it downloads: need %d, download %d", f.Need, f.Download)
	}
	if f.Dir != dir {
		t.Fatalf("Dir = %q, want the engine bin dir %q", f.Dir, dir)
	}
	// Same predicate as the install path, on the same directory — the page must never promise what
	// Install would refuse.
	if f.Fits != enoughFlashFor(f.Avail, f.AvailKnown, gz, f.Asset, false) {
		t.Fatalf("Fits disagrees with enoughFlashFor: %+v", f)
	}
	if f.Fits && f.ShortfallMiB != 0 {
		t.Fatalf("a fitting install must not report a shortfall: %+v", f)
	}
	// The release lookup must go DIRECT to GitHub, never a mirror: a mirror does not get to define
	// the size a refusal is decided on.
	if len(rt.fetched) == 0 || rt.fetched[0][:len("https://api.github.com")] != "https://api.github.com" {
		t.Fatalf("Fit fetched %v, want the direct GitHub API", rt.fetched)
	}
}

// A source-only engine has no asset to measure. It must say so rather than answer with zeros, which
// would render as "0 B download, fits".
func TestFitRefusesSourceOnlyEngine(t *testing.T) {
	u := New(t.TempDir(), "arm64", nil)
	if _, err := u.Fit(context.Background(), Engine{ID: "amneziawg-go", SourceOnly: true, Note: "build from source"}, "v1"); err == nil {
		t.Fatal("Fit accepted a source-only engine")
	}
}

// An arch with no matching asset is not a fit of zero — it is "there is nothing to install here",
// and saying otherwise puts an Install button over a release this router cannot use.
func TestFitRefusesWhenNoAssetMatchesTheArch(t *testing.T) {
	body := []byte(`{"tag_name":"v1.2.3","assets":[{"name":"sing-box-1.2.3-linux-amd64.tar.gz","browser_download_url":"https://x/a.tgz","size":10}]}`)
	u := New(t.TempDir(), "mipsle", nil)
	u.hc = &http.Client{Transport: &updater_jsonRT{routes: []updater_route{{suffix: "/releases/tags/v1.2.3", status: 200, body: body}}}}
	if _, err := u.Fit(context.Background(), Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}, "v1.2.3"); err == nil {
		t.Fatal("Fit accepted a release with no asset for this arch")
	}
}

// The shortfall is what the operator is told to free. It must be rounded UP: freeing the floored
// difference leaves the same guard refusing, turning an instruction into a second dead end.
func TestFitShortfallRoundsUp(t *testing.T) {
	if got := shortfallMiB(0, (1<<20)+1); got != 2 {
		t.Fatalf("shortfallMiB(0, 1MiB+1) = %d, want 2", got)
	}
	if got := shortfallMiB(10<<20, 5<<20); got != 0 {
		t.Fatalf("no shortfall when it fits, got %d", got)
	}
}
