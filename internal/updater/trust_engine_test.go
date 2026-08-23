package updater

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LOOP-010: an engine binary is installed with router privileges, so it is held to the SAME trust
// contract as the root self-update — the digest is MANDATORY and comes from a channel a mirror
// cannot forge. These tests pin the two halves of that contract that regressed before the fix:
// (1) a release whose asset carries no digest is refused rather than installed on trust, and
// (2) the digest-bearing release metadata is fetched over the DIRECT GitHub API, never a mirror.

// TestInstall_RefusesEngineAssetWithoutDigest: before LOOP-010 the engine install streamed with
// requireDigest=false, so a release asset that declares no sha256 digest was accepted and an
// unverified binary was written into BinDir and later run as root. It must now fail closed and leave
// nothing behind.
func TestInstall_RefusesEngineAssetWithoutDigest(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	// A perfectly valid tarball — the ONLY defect is that the release advertises no digest for it.
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, []byte("UNVERIFIED-BINARY"))
	assetName := "sing-box-1.0.0-linux-amd64.tar.gz"
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Size: int64(len(tgz))}, // Digest deliberately absent
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{"/" + assetName: tgz},
	}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.Install(context.Background(), e, tag)
	if err == nil {
		t.Fatal("Install accepted an engine asset with NO digest — an unverified root binary")
	}
	if !strings.Contains(err.Error(), "no sha256 digest") {
		t.Errorf("error = %v, want a 'no sha256 digest' refusal", err)
	}
	// Fail-closed means nothing is written and no .new temp survives.
	if _, err := os.Stat(filepath.Join(binDir, e.BinName)); !os.IsNotExist(err) {
		t.Errorf("binary written despite missing digest (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName+".new")); !os.IsNotExist(err) {
		t.Errorf("leftover .new after a refused install")
	}
}

// TestInstall_MetadataFetchedDirect: the digest the install verifies against must come from the
// DIRECT api.github.com release lookup, never through a configured mirror — otherwise a hostile
// mirror could serve a backdoored tarball together with a matching FORGED digest and it would run as
// root, exactly the hole self-update's releaseDirect closes. A mirror IS configured (and legitimately
// carries the asset bytes); only the release/digest lookup must stay direct.
func TestInstall_MetadataFetchedDirect(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	payload := []byte("VERIFIED-SINGBOX-amd64")
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, payload)
	assetName := "sing-box-1.0.0-linux-amd64.tar.gz"
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{"/" + assetName: tgz},
	}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	u.Mirrors = []string{"https://mirror.example/", ""} // a mirror IS configured (used for the bytes)

	if _, err := u.Install(context.Background(), e, tag); err != nil {
		t.Fatalf("Install: %v", err)
	}

	var relReq string
	for _, f := range rt.fetched {
		if strings.Contains(f, "/releases/tags/") {
			relReq = f
			break
		}
	}
	if relReq == "" {
		t.Fatal("no release/digest lookup was recorded")
	}
	if strings.Contains(relReq, "mirror.example") || !strings.HasPrefix(relReq, "https://api.github.com/") {
		t.Fatalf("engine release/digest lookup must be DIRECT api.github.com (a mirror can't forge the digest), got %q", relReq)
	}
	// Sanity: the install actually completed from the mirror-carried bytes.
	if onDisk, err := os.ReadFile(filepath.Join(binDir, e.BinName)); err != nil {
		t.Fatalf("installed binary missing: %v", err)
	} else if string(onDisk) != string(payload) {
		t.Errorf("installed bytes = %q, want %q", onDisk, payload)
	}
}

// TestInstall_RefusesPlaintextHTTPMirror: with only a plaintext http:// mirror available, the engine
// install must refuse (the bytes could be rewritten on-path) rather than fall back to an unverifiable
// transport — even though the direct release lookup over TLS succeeds.
func TestInstall_RefusesPlaintextHTTPMirror(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, []byte("BYTES"))
	assetName := "sing-box-1.0.0-linux-amd64.tar.gz"
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{"/" + assetName: tgz},
	}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	u.Mirrors = []string{"http://plain.example/"} // ONLY a plaintext mirror for the bytes

	_, err := u.Install(context.Background(), e, tag)
	if err == nil {
		t.Fatal("Install used a plaintext http:// mirror for an engine binary")
	}
	if !strings.Contains(err.Error(), "http://") {
		t.Errorf("error = %v, want a plaintext http:// refusal", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName)); !os.IsNotExist(err) {
		t.Errorf("binary written despite an http-only transport")
	}
}
