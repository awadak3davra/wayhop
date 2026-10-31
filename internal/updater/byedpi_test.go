package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// byedpi v0.17.3's real asset list (gh api repos/hufrea/byedpi/releases/latest, 2026-10-29).
var byedpiAssets = []string{
	"byedpi-17.3-aarch64.tar.gz", "byedpi-17.3-armv6.tar.gz", "byedpi-17.3-armv7l.tar.gz",
	"byedpi-17.3-i686-w64.zip", "byedpi-17.3-i686.tar.gz", "byedpi-17.3-mips.tar.gz",
	"byedpi-17.3-mipsel.tar.gz", "byedpi-17.3-powerpc.tar.gz", "byedpi-17.3-x86_64-w64.zip",
	"byedpi-17.3-x86_64.tar.gz",
}

// Asset names carry only the arch; every router arch gets its Linux build, never the Windows one, and
// 32-bit ARM the ARMv7 build over ARMv6.
func TestByeDPIAssetPick(t *testing.T) {
	e := EngineByID("byedpi")
	if e == nil || e.BinName != "ciadpi" || e.Role != "socks-plugin" {
		t.Fatalf("catalog entry = %+v", e)
	}
	assets := make([]Asset, len(byedpiAssets))
	for i, n := range byedpiAssets {
		assets[i] = Asset{Name: n}
	}
	for arch, want := range map[string]string{
		"arm64": "byedpi-17.3-aarch64.tar.gz", "arm": "byedpi-17.3-armv7l.tar.gz",
		"mips": "byedpi-17.3-mips.tar.gz", "mipsle": "byedpi-17.3-mipsel.tar.gz",
		"amd64": "byedpi-17.3-x86_64.tar.gz",
	} {
		got := pickAssetFor(*e, assets, arch)
		if got == nil || got.Name != want {
			t.Errorf("%s: picked %v, want %s", arch, got, want)
		}
	}
	// The generic matcher still requires the OS token: nothing here is "linux" to it.
	if pickAsset(assets, "arm64") != nil {
		t.Error("an engine without BareArch must not take these names")
	}
}

// The archive member is ciadpi-<arch>; it installs as ciadpi.
func TestByeDPIMemberExtract(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("\x7fELF fake ciadpi")
	_ = tw.WriteHeader(&tar.Header{Name: "ciadpi-aarch64", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	e := EngineByID("byedpi")
	got, err := extractBinary("byedpi-17.3-aarch64.tar.gz", buf.Bytes(), e.member())
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("extract = %q, %v", got, err)
	}
	if _, err := extractBinary("byedpi-17.3-aarch64.tar.gz", buf.Bytes(), "ciadpi"); err == nil {
		t.Error("the exact name must not match ciadpi-aarch64")
	}
	for base, want := range map[string]bool{"ciadpi-mips": true, "ciadpi": false, "xciadpi-mips": false} {
		if memberIs(base, "ciadpi-*") != want {
			t.Errorf("memberIs(%q) != %v", base, want)
		}
	}
	if memberIs("anything", "*") {
		t.Error("a bare '*' must not match everything")
	}
}

// ciadpi --version prints MAJOR.MINOR of the 0.MAJOR.MINOR tag.
func TestByeDPIShortVersion(t *testing.T) {
	for out, want := range map[string]string{"17.3\n": "0.17.3", "ciadpi 18.0": "0.18.0", "unknown": ""} {
		if got := parseShortVersion(out); got != want {
			t.Errorf("parseShortVersion(%q) = %q, want %q", out, got, want)
		}
	}
}
