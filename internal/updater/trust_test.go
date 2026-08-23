package updater

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSelfUpdate_DigestFetchedDirect: the root self-update must fetch its digest-bearing release JSON
// over the DIRECT api.github.com endpoint, never through a mirror — otherwise a hostile mirror could
// serve a backdoored tarball together with a matching FORGED digest and it would run as root. A
// mirror is configured (and used for the binary download), but the release/digest lookup must stay
// direct.
func TestSelfUpdate_DigestFetchedDirect(t *testing.T) {
	const tag = "v0.2.0"
	arch := "amd64"
	bin := selfUpdateFakeBinary(t)
	tgz := updaterinstall_tarGz(t, "wayhop-0.2.0-amd64", "wayhop-"+arch, bin)
	assetName := "wayhop-0.2.0-" + arch + ".tar.gz"
	assetURL := "https://github.com/awadak3davra/wayhop/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{"/" + assetName: tgz},
	}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "wayhop")
	if err := os.WriteFile(exePath, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatalf("seed exe: %v", err)
	}

	u := New(dir, arch, nil)
	u.hc = &http.Client{Transport: rt}
	u.Mirrors = []string{"https://mirror.example/", ""} // a mirror IS configured (used for the binary)

	if _, err := u.SelfUpdate(context.Background(), "awadak3davra/wayhop", tag, exePath); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}

	var relReq string
	for _, f := range rt.fetched {
		if strings.Contains(f, "/releases/tags/") {
			relReq = f
		}
	}
	if relReq == "" {
		t.Fatal("no release/digest lookup was recorded")
	}
	if strings.Contains(relReq, "mirror.example") || !strings.HasPrefix(relReq, "https://api.github.com/") {
		t.Fatalf("release/digest lookup must be DIRECT api.github.com (a mirror can't forge the digest), got %q", relReq)
	}
}

// TestStreamAsset_RejectsHTTPMirrorForDigest: a digest-mandatory download (every executable install)
// must refuse a plaintext http:// mirror (a passive MITM could rewrite the binary). The second half
// characterises the shared primitive itself: with requireDigest=false it still permits an http://
// mirror — no PRODUCTION executable path passes false after LOOP-010 (both self-update and engine
// installs pass true), the flag is exercised here only as the documented primitive behaviour.
func TestStreamAsset_RejectsHTTPMirrorForDigest(t *testing.T) {
	tgz := updaterinstall_tarGz(t, "sing-box-1.0-amd64", "sing-box", []byte("SINGBOX-BINARY-BYTES"))
	assetName := "sing-box-1.0-amd64.tar.gz"
	asset := Asset{
		Name:   assetName,
		URL:    "https://github.com/x/y/releases/download/v1.0/" + assetName,
		Digest: updaterinstall_sha256(tgz),
		Size:   int64(len(tgz)),
	}
	rt := &updaterinstall_rt{assets: map[string][]byte{"/" + assetName: tgz}}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	u.Mirrors = []string{"http://plain.example/"} // ONLY a plaintext mirror

	dst := filepath.Join(t.TempDir(), "out")
	if err := u.streamAssetToFile(context.Background(), asset, "wayhop-amd64", dst, true); err == nil {
		t.Fatal("digest-required download must refuse a plaintext http:// mirror")
	} else if !strings.Contains(err.Error(), "http://") {
		t.Fatalf("want an http:// refusal, got %v", err)
	}
	// The shared primitive with requireDigest=false still permits the http:// mirror. This is not a
	// production path any more (LOOP-010 made engine installs pass true); it pins the primitive's
	// documented behaviour so a future non-executable use of it is a deliberate choice, not a drift.
	if err := u.streamAssetToFile(context.Background(), asset, "sing-box", dst, false); err != nil {
		t.Fatalf("non-digest download should still use an http:// mirror: %v", err)
	}
}
