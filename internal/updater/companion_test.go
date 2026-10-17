package updater

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"wayhop/internal/binstore"
)

// The five names scripts/build-amneziawg-go.sh packs for v3.1.20260828 - the contract between the
// build and this package.
var companionScriptNames = map[string]string{
	"amd64":  "amneziawg-go-v3.1.20260828-linux-amd64.gz",
	"arm64":  "amneziawg-go-v3.1.20260828-linux-arm64.gz",
	"arm":    "amneziawg-go-v3.1.20260828-linux-armv7.gz",
	"mips":   "amneziawg-go-v3.1.20260828-linux-mips.gz",
	"mipsle": "amneziawg-go-v3.1.20260828-linux-mipsle.gz",
}

func TestCompanionVersion(t *testing.T) {
	for _, name := range companionScriptNames {
		if v, ok := companionVersion(name, "amneziawg-go-"); !ok || v != "v3.1.20260828" {
			t.Errorf("%s: version %q, %v", name, v, ok)
		}
	}
	for _, name := range []string{
		"wayhop-0.5.6-arm64.tar.gz",                  // WayHop's own asset
		"amneziawg-go-linux-arm64.gz",                // no version
		"amneziawg-go-../x-linux-arm64.gz",           // a path in the version
		"amneziawg-go-v3.1 x-linux-arm64.gz",         // not a tag
		"other-v3.1.20260828-linux-arm64.gz",         // another companion's prefix
		"amneziawg-go-v3.1.20260828-darwin-arm64.gz", // not linux
	} {
		if v, ok := companionVersion(name, "amneziawg-go-"); ok {
			t.Errorf("%s: read as companion version %q", name, v)
		}
	}
}

// Each arch gets exactly its own asset from a release holding all five - mips must not take mipsle,
// arm must not take arm64, and amd64 takes neither.
func TestCompanionAssetForEveryArch(t *testing.T) {
	var assets []Asset
	for _, n := range companionScriptNames {
		assets = append(assets, Asset{Name: n})
	}
	assets = append(assets, Asset{Name: "wayhop-0.5.6-arm64.tar.gz"}, Asset{Name: "SHA256SUMS.txt"})
	for arch, want := range companionScriptNames {
		got := pickAsset(companionReleases([]Release{{Tag: "v0.5.6", Assets: assets}}, "amneziawg-go-")[0].Assets, arch)
		if got == nil || got.Name != want {
			t.Errorf("%s: picked %v, want %s", arch, got, want)
		}
	}
}

func companionRel(tag string, pre bool, versions ...string) Release {
	r := Release{Tag: tag, Prerelease: pre, Assets: []Asset{{Name: "wayhop-" + strings.TrimPrefix(tag, "v") + "-arm64.tar.gz"}}}
	for _, v := range versions {
		r.Assets = append(r.Assets, Asset{Name: "amneziawg-go-" + v + "-linux-arm64.gz", URL: "https://x/" + tag + "/" + v})
	}
	return r
}

// Keyed by the upstream version; a version shipped several times comes from the newest STABLE
// release, and from a prerelease only when nothing stable carries it.
func TestCompanionReleases(t *testing.T) {
	rs := companionReleases([]Release{
		companionRel("v0.5.9", true, "v3.2.0"),
		companionRel("v0.5.8", true, "v3.1.20260828"),
		companionRel("v0.5.7", false, "v3.1.20260828"),
		companionRel("v0.5.6", false, "v3.1.20260828"),
		companionRel("v0.5.5", false),
		companionRel("v0.5.4", false, "v3.1.20260814"),
	}, "amneziawg-go-")
	var got []string
	for _, r := range rs {
		got = append(got, r.Tag+"@"+strings.TrimPrefix(r.Assets[0].URL, "https://x/"))
		if len(r.Assets) != 1 {
			t.Errorf("%s carries %d assets; WayHop's own must not be among them", r.Tag, len(r.Assets))
		}
	}
	want := "v3.2.0@v0.5.9/v3.2.0 v3.1.20260828@v0.5.7/v3.1.20260828 v3.1.20260814@v0.5.4/v3.1.20260814"
	if strings.Join(got, " ") != want {
		t.Fatalf("companion listing\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	if !rs[0].Prerelease || rs[1].Prerelease {
		t.Errorf("prerelease flags: %v %v", rs[0].Prerelease, rs[1].Prerelease)
	}
	if LatestStable(rs) != "v3.1.20260828" {
		t.Errorf("latest stable = %q", LatestStable(rs))
	}
}

// The whole install: WayHop's release listing over the direct API, the companion asset picked for the
// arch, its digest checked, the binary unpacked into place, and the version recorded beside it.
func TestCompanionInstallEndToEnd(t *testing.T) {
	e := Engine{ID: "amneziawg-go", Repo: DefaultSelfRepo, BinName: "amneziawg-go", Companion: "amneziawg-go-"}
	payload := []byte("AMNEZIAWG-GO-arm64")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	name := companionScriptNames["arm64"]
	url := "https://github.com/" + DefaultSelfRepo + "/releases/download/v0.5.7/" + name
	listing, err := json.Marshal([]Release{
		{Tag: "v0.5.7", Name: "WayHop v0.5.7", Assets: []Asset{
			{Name: "wayhop-0.5.7-arm64.tar.gz", URL: "https://github.com/x/wayhop.tgz", Size: 10},
			{Name: name, URL: url, Digest: updaterinstall_sha256(gz.Bytes()), Size: int64(gz.Len())},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rt := &updaterinstall_rt{
		relPathSuffix: "/repos/" + DefaultSelfRepo + "/releases?per_page=15",
		relJSON:       listing,
		assets:        map[string][]byte{"/" + name: gz.Bytes()},
	}
	binDir := t.TempDir()
	u := New(binDir, "arm64", nil)
	u.hc = &http.Client{Transport: rt}

	rels, err := u.List(context.Background(), e, 0)
	if err != nil || len(rels) != 1 || rels[0].Tag != "v3.1.20260828" {
		t.Fatalf("List = %v, %v", rels, err)
	}
	got, err := u.Install(context.Background(), e, "v3.1.20260828")
	if err != nil || got != "v3.1.20260828" {
		t.Fatalf("Install = %q, %v", got, err)
	}
	if b, _ := os.ReadFile(filepath.Join(binDir, "amneziawg-go")); !bytes.Equal(b, payload) {
		t.Errorf("installed %q, want the unpacked payload", b)
	}
	if v := u.Installed(e).Version; v != "v3.1.20260828" {
		t.Errorf("installed version %q, want the recorded upstream version", v)
	}
	if _, err := u.Install(context.Background(), e, "v9.9.9"); err == nil || !strings.Contains(err.Error(), "no WayHop release carries") {
		t.Errorf("a version no release carries: %v", err)
	}
}

// Latest is the newest version a STABLE WayHop release carries - a newer one shipped only in a
// prerelease is listed, but never offered as the one to install.
func TestCompanionLatestIsStable(t *testing.T) {
	e := Engine{ID: "amneziawg-go", Repo: DefaultSelfRepo, BinName: "amneziawg-go", Companion: "amneziawg-go-"}
	listing, _ := json.Marshal([]Release{
		companionRel("v0.5.9", true, "v3.2.0"),
		companionRel("v0.5.7", false, "v3.1.20260828"),
	})
	u := New(t.TempDir(), "arm64", nil)
	u.hc = &http.Client{Transport: &updaterinstall_rt{relPathSuffix: "/releases?per_page=15", relJSON: listing}}
	rel, err := u.Latest(context.Background(), e)
	if err != nil || rel.Tag != "v3.1.20260828" {
		t.Fatalf("Latest = %q, %v; want the stable v3.1.20260828 over the prerelease v3.2.0", rel.Tag, err)
	}
}

// The record describes one file. A binary replaced by other means reads as unknown, not as the
// version installed before it; removal takes the record along.
func TestCompanionRecord(t *testing.T) {
	e := Engine{ID: "amneziawg-go", Repo: DefaultSelfRepo, BinName: "amneziawg-go", Companion: "amneziawg-go-"}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, e.BinName)
	u := New(binDir, "arm64", nil)
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if v := u.Installed(e).Version; v != "" {
		t.Errorf("no record, version %q", v)
	}
	if err := binstore.Write(binDir, e.BinName, "v3.1.20260828", false); err != nil {
		t.Fatal(err)
	}
	if v := u.Installed(e).Version; v != "v3.1.20260828" {
		t.Errorf("recorded version read as %q", v)
	}
	if err := os.WriteFile(bin, []byte("replaced"), 0o755); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(bin, later, later)
	if v := u.Installed(e).Version; v != "" {
		t.Errorf("a replaced binary kept the old version %q", v)
	}
	if err := u.Uninstall(e); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(binDir, "."+e.BinName+".version")); !os.IsNotExist(err) {
		t.Errorf("the record outlived the binary: %v", err)
	}
}

// The demo names the real pinned build, and the whole chain - listing, pick, fit - runs on it for
// every arch without the network.
func TestCompanionOfflineMatchesThePinnedBuild(t *testing.T) {
	// The build script reads its pins from VERSIONS, the one place they are written.
	pins, err := os.ReadFile(filepath.Join("..", "..", "packaging", "awg", "VERSIONS"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^AWG_GO_TAG="([^"]+)"`).FindSubmatch(pins)
	if m == nil || string(m[1]) != offlineCompanionVersion {
		t.Fatalf("VERSIONS pins %q, the demo catalogue names %q", m, offlineCompanionVersion)
	}
	e := *EngineByID("amneziawg-go")
	for arch := range companionScriptNames {
		u := New(t.TempDir(), arch, nil)
		u.Offline = true
		rel, err := u.Latest(context.Background(), e)
		if err != nil || rel.Tag != offlineCompanionVersion {
			t.Fatalf("%s: Latest = %v, %v", arch, rel, err)
		}
		if a := pickAsset(rel.Assets, arch); a == nil || a.Name != companionScriptNames[arch] {
			t.Errorf("%s: demo asset %v", arch, a)
		}
		if _, err := u.Fit(context.Background(), e, offlineCompanionVersion); err != nil {
			t.Errorf("%s: fit: %v", arch, err)
		}
	}
}

// companionRig serves one WayHop release carrying the arm64 companion asset (payload, gzipped), with
// an updater whose free-space reading the test sets.
func companionRig(t *testing.T, payload []byte) (*Updater, Engine, []byte) {
	t.Helper()
	e := Engine{ID: "amneziawg-go", Repo: DefaultSelfRepo, BinName: "amneziawg-go", Companion: "amneziawg-go-"}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	name := companionScriptNames["arm64"]
	listing, _ := json.Marshal([]Release{{Tag: "v0.5.7", Assets: []Asset{{
		Name: name, URL: "https://github.com/" + DefaultSelfRepo + "/releases/download/v0.5.7/" + name,
		Digest: updaterinstall_sha256(b.Bytes()), Size: int64(b.Len()),
	}}}})
	u := New(t.TempDir(), "arm64", nil)
	u.RunDir = t.TempDir()
	u.hc = &http.Client{Transport: &updaterinstall_rt{
		relPathSuffix: "/releases?per_page=15", relJSON: listing, assets: map[string][]byte{"/" + name: b.Bytes()},
	}}
	return u, e, b.Bytes()
}

func avail(n uint64) func(string) (uint64, bool) {
	return func(string) (uint64, bool) { return n, true }
}

// Where the unpacked binary does not fit but the gzip does, the gzip is stored as published and
// recorded compressed; Fit, asked first, promises exactly that.
func TestCompanionCompressedInstall(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	u.WithAvail(avail(compressedNeed(int64(len(gz)))))
	fit, err := u.Fit(context.Background(), e, "v3.1.20260828")
	if err != nil || !fit.Fits || fit.Mode != "compressed" || fit.Need != compressedNeed(int64(len(gz))) {
		t.Fatalf("Fit = %+v, %v; want it to fit compressed", fit, err)
	}
	got, err := u.Install(context.Background(), e, "v3.1.20260828")
	if err != nil || got != "v3.1.20260828" {
		t.Fatalf("Install = %q, %v", got, err)
	}
	if fileExists(filepath.Join(u.BinDir, "amneziawg-go")) {
		t.Error("an unpacked binary was written to the flash it does not fit")
	}
	if b, _ := os.ReadFile(binstore.Stored(u.BinDir, "amneziawg-go", true)); !bytes.Equal(b, gz) {
		t.Error("the stored gzip is not the published asset")
	}
	if rec, ok := binstore.Read(u.BinDir, "amneziawg-go"); !ok || !rec.Compressed || rec.Version != "v3.1.20260828" {
		t.Errorf("record %+v, %v", rec, ok)
	}
	if inst := u.Installed(e); inst.Path != binstore.Stored(u.BinDir, "amneziawg-go", true) || inst.Version != "v3.1.20260828" {
		t.Errorf("Installed %+v", inst)
	}
	if left, _ := os.ReadDir(u.RunDir); len(left) != 0 {
		t.Errorf("the install left %d file(s) in the RAM directory", len(left))
	}
}

// The form follows the room each install finds, and the form it replaces is removed - it is the space
// the switch was for, or no longer the copy that runs.
func TestCompanionModeSwitch(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	raw, packed := filepath.Join(u.BinDir, "amneziawg-go"), binstore.Stored(u.BinDir, "amneziawg-go", true)
	for i, step := range []struct {
		free       uint64
		raw, gzipd bool
	}{
		{1 << 30, true, false},
		{compressedNeed(int64(len(gz))), false, true},
		{1 << 30, true, false},
	} {
		u.WithAvail(avail(step.free))
		if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
		if fileExists(raw) != step.raw || fileExists(packed) != step.gzipd {
			t.Errorf("install %d: unpacked %v, gzip %v; want %v, %v", i, fileExists(raw), fileExists(packed), step.raw, step.gzipd)
		}
	}
}

// Too little room for even the gzip: refused before any download, with the gzip's need in the
// sentence and in Fit.
func TestCompanionNeitherFits(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	need := compressedNeed(int64(len(gz)))
	u.WithAvail(avail(need - 1))
	fit, err := u.Fit(context.Background(), e, "v3.1.20260828")
	if err != nil || fit.Fits || fit.Mode != "" || fit.Need != need || fit.ShortfallMiB == 0 {
		t.Fatalf("Fit = %+v, %v", fit, err)
	}
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err == nil || !strings.Contains(err.Error(), "even kept compressed") {
		t.Fatalf("Install: %v", err)
	}
	if fileExists(binstore.Stored(u.BinDir, "amneziawg-go", true)) {
		t.Error("something was stored")
	}
}

// Removing a compressed install takes the gzip, the record and the copy unpacked to run.
func TestCompanionCompressedUninstall(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	u.WithAvail(avail(compressedNeed(int64(len(gz)))))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
		t.Fatal(err)
	}
	running, err := binstore.Unpack(u.BinDir, "amneziawg-go", u.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.UninstallPrecheck(e); err != nil {
		t.Fatalf("a compressed install could not be removed: %v", err)
	}
	if err := u.Uninstall(e); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{binstore.Stored(u.BinDir, "amneziawg-go", true), running} {
		if fileExists(p) {
			t.Errorf("%s survived", p)
		}
	}
	if u.Installed(e).Present {
		t.Error("still reported installed")
	}
}
