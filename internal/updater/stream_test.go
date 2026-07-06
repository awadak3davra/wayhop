package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// streamtest_multiTarGz builds a .tar.gz with THREE entries — a decoy before the wanted binary and
// a sizeable file AFTER it — so the binary is NOT the last entry. The streaming installer's tar
// reader stops at the binary, so the digest can only match if the install then drains the trailing
// bytes through the hash. This pins that drain.
func streamtest_multiTarGz(t *testing.T, binName string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	write := func(name string, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	write("pkg/LICENSE", bytes.Repeat([]byte("L"), 300))    // decoy BEFORE
	write("pkg/"+binName, payload)                          // the wanted binary (middle)
	write("pkg/README.md", bytes.Repeat([]byte("R"), 5000)) // trailing entry AFTER -> drain matters
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestStreamInstall_BinaryNotLastTarEntry installs a tar.gz whose binary is in the middle. Success
// proves the streaming path (a) extracts the right entry and (b) hashes the WHOLE asset (draining
// the trailing entry) so the sha256 digest verifies.
func TestStreamInstall_BinaryNotLastTarEntry(t *testing.T) {
	const tag = "v1.2.3"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	payload := []byte("BINARY-IN-THE-MIDDLE-of-the-tar")
	tgz := streamtest_multiTarGz(t, e.BinName, payload)

	suffix := "/sing-box-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{{
		Name:   "sing-box-linux-amd64.tar.gz",
		URL:    "https://github.com/SagerNet/sing-box/releases/download/" + tag + suffix,
		Digest: updaterinstall_sha256(tgz),
		Size:   int64(len(tgz)),
	}})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel, assets: map[string][]byte{suffix: tgz}}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.Install(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got != tag {
		t.Errorf("tag = %q, want %q", got, tag)
	}
	onDisk, err := os.ReadFile(filepath.Join(binDir, e.BinName))
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("installed bytes = %q, want %q", onDisk, payload)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName+".new")); !os.IsNotExist(err) {
		t.Errorf(".new temp survived the atomic rename: %v", err)
	}
}

// TestStreamInstall_DigestMismatch: a wrong digest must block the install AND leave no binary (nor a
// stray .new) behind — the streamed file is removed when verification fails.
func TestStreamInstall_DigestMismatch(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, []byte("payload"))
	suffix := "/sing-box-1.0.0-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{{
		Name:   "sing-box-1.0.0-linux-amd64.tar.gz",
		URL:    "https://github.com/x" + suffix,
		Digest: "sha256:" + strings.Repeat("ab", 32), // deliberately wrong
		Size:   int64(len(tgz)),
	}})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel, assets: map[string][]byte{suffix: tgz}}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	if _, err := u.Install(context.Background(), e, tag); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName)); !os.IsNotExist(err) {
		t.Errorf("binary installed despite digest mismatch")
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName+".new")); !os.IsNotExist(err) {
		t.Errorf(".new temp survived a digest mismatch")
	}
}

// TestStreamInstall_Zip exercises the zip path: zip needs random access, so the streaming install
// stages the (hashed) archive to a temp file, extracts, then cleans the temp up.
func TestStreamInstall_Zip(t *testing.T) {
	const tag = "v25.1.0"
	e := Engine{ID: "xray", Repo: "XTLS/Xray-core", BinName: "xray"}
	payload := []byte("XRAY-BINARY-FROM-ZIP")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("xray")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	zb := zbuf.Bytes()

	suffix := "/Xray-linux-64.zip"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{{
		Name:   "Xray-linux-64.zip",
		URL:    "https://github.com/XTLS/Xray-core/releases/download/" + tag + suffix,
		Digest: updaterinstall_sha256(zb),
		Size:   int64(len(zb)),
	}})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel, assets: map[string][]byte{suffix: zb}}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	if _, err := u.Install(context.Background(), e, tag); err != nil {
		t.Fatalf("Install zip: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(binDir, e.BinName))
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("zip-installed bytes = %q, want %q", onDisk, payload)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName+".new.zip")); !os.IsNotExist(err) {
		t.Errorf("staged .zip temp survived")
	}
}

// TestStreamInstall_HTMLRejected: a mirror that answers 200 with an HTML interstitial must be
// rejected by the body peek, not written out as the "binary".
func TestStreamInstall_HTMLRejected(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	html := []byte("<!DOCTYPE html><html><body>captcha</body></html>")
	suffix := "/sing-box-1.0.0-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{{
		Name: "sing-box-1.0.0-linux-amd64.tar.gz",
		URL:  "https://github.com/x" + suffix,
		Size: int64(len(html)),
	}})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel, assets: map[string][]byte{suffix: html}}

	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	if _, err := u.Install(context.Background(), e, tag); err == nil || !strings.Contains(err.Error(), "HTML") {
		t.Fatalf("want HTML rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, e.BinName)); !os.IsNotExist(err) {
		t.Errorf("an HTML page was written out as the binary")
	}
}

func TestLatestStable(t *testing.T) {
	if got := LatestStable(nil); got != "" {
		t.Errorf("empty rels: got %q, want \"\"", got)
	}
	// Newest-first as GitHub returns them: skip the leading prerelease.
	rels := []Release{
		{Tag: "v1.14.0-alpha.37", Prerelease: true},
		{Tag: "v1.13.0", Prerelease: false},
		{Tag: "v1.12.22", Prerelease: false},
	}
	if got := LatestStable(rels); got != "v1.13.0" {
		t.Errorf("skip prerelease: got %q, want v1.13.0", got)
	}
	// All prereleases -> fall back to the newest so the UI still shows something.
	allPre := []Release{{Tag: "v2.0.0-rc1", Prerelease: true}, {Tag: "v2.0.0-beta", Prerelease: true}}
	if got := LatestStable(allPre); got != "v2.0.0-rc1" {
		t.Errorf("all-prerelease fallback: got %q, want v2.0.0-rc1", got)
	}
}

func TestEnoughFlashFor(t *testing.T) {
	const MiB = 1 << 20
	cases := []struct {
		avail  uint64
		known  bool
		size   int64
		name   string
		backup bool
		want   bool
	}{
		{0, false, 100 * MiB, "core.tar.gz", false, true},       // unknown avail -> never block
		{50 * MiB, true, 0, "core.tar.gz", false, true},         // unknown size -> never block
		{50 * MiB, true, 10 * MiB, "core.tar.gz", false, true},  // compressed: 10*3+4=34 <= 50 -> ok
		{20 * MiB, true, 10 * MiB, "core.tar.gz", false, false}, // 34 > 20 -> block (tight overlay)
		{50 * MiB, true, 10 * MiB, "core.tar.gz", true, false},  // backup doubles: 10*3*2+4=64 > 50 -> block
		{70 * MiB, true, 10 * MiB, "core.tar.gz", true, true},   // 64 <= 70 -> ok
		// BARE binary (no archive ext) is NOT inflated 3x: a 27 MiB olcrtc needs ~27+4, not ~85.
		{40 * MiB, true, 27 * MiB, "olcrtc-linux-arm64", false, true},  // 27+4=31 <= 40 -> ok (3x would wrongly block: 85 > 40)
		{20 * MiB, true, 27 * MiB, "olcrtc-linux-arm64", false, false}, // 31 > 20 -> still block (genuinely too big, e.g. AX3000T overlay)
	}
	for i, c := range cases {
		if got := enoughFlashFor(c.avail, c.known, c.size, c.name, c.backup); got != c.want {
			t.Errorf("case %d: enoughFlashFor(%d,%v,%d,%q,%v) = %v, want %v", i, c.avail, c.known, c.size, c.name, c.backup, got, c.want)
		}
	}
}
