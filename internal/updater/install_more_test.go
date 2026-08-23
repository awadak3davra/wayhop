package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// updaterinstall_tarGz builds a real .tar.gz in memory whose single regular entry is
// "<dir>/<binName>" with the given payload. fromTarGz matches on filepath.Base(name), so
// the leading directory component is intentional (mirrors how real release tarballs nest
// the binary under a versioned folder).
func updaterinstall_tarGz(t *testing.T, dir, binName string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     dir + "/" + binName,
		Mode:     0o755,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// updaterinstall_sha256 returns "sha256:<hex>" for data, the digest form Install verifies.
func updaterinstall_sha256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// updaterinstall_rt is a canned http.RoundTripper that serves a GitHub
// releases/tags/<tag> JSON document for any URL ending in "/releases/tags/" + tag, and
// raw asset bytes for any URL whose path matches a registered asset path. Everything else
// 404s. It records the set of fetched URLs so a test can assert mirror fall-through.
//
// Matching is by URL *suffix* so mirror-prefixed URLs (e.g.
// "https://mirror/https://api.github.com/...") still resolve to the same canned response.
type updaterinstall_rt struct {
	relPathSuffix string            // e.g. "/releases/tags/v1.0.0"
	relJSON       []byte            // the release document
	assets        map[string][]byte // URL suffix -> bytes (keyed by the asset path)
	fetched       []string          // every URL the transport saw
}

func (rt *updaterinstall_rt) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.fetched = append(rt.fetched, req.URL.String())
	mk := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	u := req.URL.String()
	if rt.relJSON != nil && strings.HasSuffix(u, rt.relPathSuffix) {
		return mk(http.StatusOK, rt.relJSON)
	}
	for suffix, body := range rt.assets {
		if strings.HasSuffix(u, suffix) {
			return mk(http.StatusOK, body)
		}
	}
	return mk(http.StatusNotFound, []byte("not found"))
}

// updaterinstall_releaseJSON marshals a Release with the given tag + assets.
func updaterinstall_releaseJSON(t *testing.T, tag string, assets []Asset) []byte {
	t.Helper()
	b, err := json.Marshal(Release{Tag: tag, Name: tag, Assets: assets})
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}
	return b
}

// TestUpdaterinstall_InstallAmd64EndToEnd injects a canned transport so Install fetches a
// release listing one linux-amd64 .tar.gz asset, downloads it, verifies its sha256 digest,
// extracts the binary, and writes it to BinDir/<BinName> with 0755. Asserts the returned
// tag, the on-disk bytes, and that the .new temp file did not survive the atomic rename.
func TestUpdaterinstall_InstallAmd64EndToEnd(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	payload := []byte("REAL-SINGBOX-BINARY-amd64")
	assetURL := "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/sing-box-1.0.0-linux-amd64.tar.gz"
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, payload)

	assetPathSuffix := "/sing-box-1.0.0-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "sing-box-1.0.0-linux-amd64.tar.gz", URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{assetPathSuffix: tgz},
	}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.Install(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got != tag {
		t.Errorf("Install returned tag %q, want %q", got, tag)
	}

	dst := filepath.Join(binDir, e.BinName)
	onDisk, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("installed bytes = %q, want %q", onDisk, payload)
	}
	// Install writes the binary with 0755. The Unix executable bit is only
	// meaningful (and preserved) on a Unix filesystem; on Windows os.WriteFile
	// reports rw-rw-rw- regardless, so only assert the exec bit off-Windows.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(dst); err != nil {
			t.Fatalf("stat installed: %v", err)
		} else if fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("installed mode = %v, want executable", fi.Mode().Perm())
		}
	}
	// The atomic-rename temp file must not survive.
	if _, err := os.Stat(dst + ".new"); !os.IsNotExist(err) {
		t.Errorf("leftover %s.new after install", dst)
	}
}

// TestUpdaterinstall_InstallArmPrefersBareLinuxArm gives the release THREE arm assets
// (-linux-arm, -linux-armv5, -linux-arm64) and asserts Install (arch="arm") downloads and
// installs the bare "-linux-arm" build — the ARMv7-safe baseline pickAsset prefers over
// armv5, and never the 64-bit one. The installed bytes prove which asset was chosen.
func TestUpdaterinstall_InstallArmPrefersBareLinuxArm(t *testing.T) {
	const tag = "app/v2.0.0"
	e := Engine{ID: "hysteria", Repo: "apernet/hysteria", BinName: "hysteria"}

	// Distinct payloads so the installed bytes identify the chosen asset.
	bareArm := []byte("CHOSEN-bare-linux-arm")
	armv5 := []byte("WRONG-armv5")
	arm64 := []byte("WRONG-arm64")

	tgzBare := updaterinstall_tarGz(t, "hysteria-linux-arm", e.BinName, bareArm)
	tgzV5 := updaterinstall_tarGz(t, "hysteria-linux-armv5", e.BinName, armv5)
	tgz64 := updaterinstall_tarGz(t, "hysteria-linux-arm64", e.BinName, arm64)

	base := "https://github.com/apernet/hysteria/releases/download/v2.0.0/"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "hysteria-linux-armv5.tar.gz", URL: base + "hysteria-linux-armv5.tar.gz", Digest: updaterinstall_sha256(tgzV5)},
		{Name: "hysteria-linux-arm.tar.gz", URL: base + "hysteria-linux-arm.tar.gz", Digest: updaterinstall_sha256(tgzBare)},
		{Name: "hysteria-linux-arm64.tar.gz", URL: base + "hysteria-linux-arm64.tar.gz", Digest: updaterinstall_sha256(tgz64)},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets: map[string][]byte{
			"/hysteria-linux-armv5.tar.gz": tgzV5,
			"/hysteria-linux-arm.tar.gz":   tgzBare,
			"/hysteria-linux-arm64.tar.gz": tgz64,
		},
	}

	binDir := t.TempDir()
	u := New(binDir, "arm", nil)
	u.hc = &http.Client{Transport: rt}

	if _, err := u.Install(context.Background(), e, tag); err != nil {
		t.Fatalf("Install (arm): %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(binDir, e.BinName))
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if !bytes.Equal(onDisk, bareArm) {
		t.Errorf("installed bytes = %q, want the bare -linux-arm payload %q", onDisk, bareArm)
	}
}

// TestUpdaterinstall_InstallDigestMismatchRejected serves a tarball whose advertised digest
// does NOT match the bytes. Install must refuse with a sha256 mismatch and write nothing.
func TestUpdaterinstall_InstallDigestMismatchRejected(t *testing.T) {
	const tag = "v1.2.3"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	tgz := updaterinstall_tarGz(t, "d", e.BinName, []byte("payload"))

	assetURL := "https://example.invalid/sing-box-1.2.3-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "sing-box-1.2.3-linux-amd64.tar.gz", URL: assetURL,
			Digest: "sha256:" + strings.Repeat("00", 32)}, // wrong digest
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{"/sing-box-1.2.3-linux-amd64.tar.gz": tgz},
	}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.Install(context.Background(), e, tag)
	if err == nil {
		t.Fatal("Install accepted a digest mismatch")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("error = %v, want sha256 mismatch", err)
	}
	// Nothing should be written on a rejected install.
	if _, err := os.Stat(filepath.Join(binDir, e.BinName)); !os.IsNotExist(err) {
		t.Errorf("binary written despite digest mismatch (stat err=%v)", err)
	}
}

// TestUpdaterinstall_InstallNoAssetForArch serves a release that has only an amd64 asset
// while the updater targets mipsle: pickAsset returns nil and Install fails with a clear
// "no <id> asset for arch" error, without downloading anything.
func TestUpdaterinstall_InstallNoAssetForArch(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "sing-box-1.0.0-linux-amd64.tar.gz", URL: "https://x/sing-box-1.0.0-linux-amd64.tar.gz"},
	})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel}

	u := New(t.TempDir(), "mipsle", nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.Install(context.Background(), e, tag)
	if err == nil {
		t.Fatal("Install succeeded with no matching asset")
	}
	if !strings.Contains(err.Error(), "no sing-box asset for arch") {
		t.Errorf("error = %v, want a no-asset-for-arch message", err)
	}
}

// TestUpdaterinstall_DownloadMirrorFallThrough exercises the asset transport's mirror loop: the
// first mirror is unreachable (the transport 502s for it) and the second serves the asset. We model
// this with one transport that 502s any URL containing "dead-mirror" but serves the real asset for
// the direct URL. Both mirrors are tried in order; the install succeeds on the second, proving
// fall-through. The dead mirror is HTTPS: after LOOP-010 an executable download runs with a
// mandatory digest, which refuses plaintext http:// mirrors outright (they would never be attempted,
// so an http:// dead mirror could not demonstrate fall-through) — the mirror still carries the bytes,
// it just has to be TLS.
func TestUpdaterinstall_DownloadMirrorFallThrough(t *testing.T) {
	const tag = "v3.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	payload := []byte("MIRROR-FALLTHROUGH-OK")
	tgz := updaterinstall_tarGz(t, "sing-box-3.0.0-linux-amd64", e.BinName, payload)
	assetName := "sing-box-3.0.0-linux-amd64.tar.gz"
	assetURL := "https://api.github.com/SagerNet/sing-box/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(tgz)},
	})

	rt := &updaterinstall_mirrorRT{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assetSuffix:   "/" + assetName,
		assetBody:     tgz,
		deadToken:     "dead-mirror",
	}

	binDir := t.TempDir()
	// First mirror is dead (TLS), second is direct ("").
	u := New(binDir, "amd64", []string{"https://dead-mirror", ""})
	u.hc = &http.Client{Transport: rt}

	got, err := u.Install(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("Install with dead first mirror: %v", err)
	}
	if got != tag {
		t.Errorf("tag = %q, want %q", got, tag)
	}
	onDisk, err := os.ReadFile(filepath.Join(binDir, e.BinName))
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("installed bytes = %q, want %q", onDisk, payload)
	}
	// The dead mirror must have been attempted for the asset download before the
	// direct URL succeeded.
	sawDead := false
	for _, fu := range rt.fetched {
		if strings.Contains(fu, "dead-mirror") && strings.Contains(fu, assetName) {
			sawDead = true
			break
		}
	}
	if !sawDead {
		t.Errorf("dead mirror was never attempted for the asset; fetched=%v", rt.fetched)
	}
}

// updaterinstall_mirrorRT serves the release JSON for both mirror-prefixed and direct
// URLs, but for the asset it 404s any URL containing deadToken and serves assetBody for
// the rest. This lets us prove download()'s fall-through from a dead mirror to a working
// one. The release lookup is served regardless of mirror so Install reaches the download
// stage.
type updaterinstall_mirrorRT struct {
	relPathSuffix string
	relJSON       []byte
	assetSuffix   string
	assetBody     []byte
	deadToken     string
	fetched       []string
}

func (rt *updaterinstall_mirrorRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.fetched = append(rt.fetched, req.URL.String())
	u := req.URL.String()
	mk := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	// Release lookup: serve for the first reachable (direct) attempt. The release
	// apiGet uses the same mirror list, so a dead-mirror release URL must 404 to force
	// apiGet itself to fall through to the direct URL too.
	if strings.HasSuffix(u, rt.relPathSuffix) {
		if strings.Contains(u, rt.deadToken) {
			return mk(http.StatusBadGateway, []byte("dead"))
		}
		return mk(http.StatusOK, rt.relJSON)
	}
	if strings.HasSuffix(u, rt.assetSuffix) {
		if strings.Contains(u, rt.deadToken) {
			return mk(http.StatusBadGateway, []byte("dead"))
		}
		return mk(http.StatusOK, rt.assetBody)
	}
	return mk(http.StatusNotFound, []byte("not found"))
}

// TestUpdaterinstall_ReleaseAndPickAsset exercises release()+pickAsset() directly against
// the injected transport, independent of the download/extract stages. This is the targeted
// unit-level check the task asks for as a fallback, kept alongside the end-to-end tests.
func TestUpdaterinstall_ReleaseAndPickAsset(t *testing.T) {
	const tag = "v9.9.9"
	e := Engine{ID: "xray", Repo: "XTLS/Xray-core", BinName: "xray"}
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: "Xray-linux-64.zip", URL: "https://x/Xray-linux-64.zip"},
		{Name: "Xray-linux-arm64-v8a.zip", URL: "https://x/arm64.zip"},
		{Name: "Xray-linux-64.zip.dgst", URL: "https://x/dgst"}, // must be ignored
	})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel}

	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.release(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if got.Tag != tag || len(got.Assets) != 3 {
		t.Fatalf("release decoded wrong: tag=%q assets=%d", got.Tag, len(got.Assets))
	}
	a := pickAsset(got.Assets, "amd64")
	if a == nil || a.Name != "Xray-linux-64.zip" {
		t.Errorf("pickAsset(amd64) = %v, want Xray-linux-64.zip", a)
	}
	// The .dgst checksum file must never be selected even though it contains "linux-64".
	if a != nil && strings.HasSuffix(a.Name, ".dgst") {
		t.Errorf("pickAsset selected a checksum file: %q", a.Name)
	}
}
