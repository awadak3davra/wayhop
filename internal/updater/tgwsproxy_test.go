package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tg-ws-proxy-rs v2.5.8's real asset list (gh api repos/valnesfjord/tg-ws-proxy-rs/releases/latest,
// 2026-10-29): the release the Components entry was written against.
var tgwsAssets258 = []string{
	"luci-app-tg-ws-proxy-rs-2.5.8-r1.apk", "luci-app-tg-ws-proxy-rs_2.5.8-r1_all.ipk", "SHA256SUMS",
	"tg-ws-proxy-aarch64-apple-darwin.tar.gz", "tg-ws-proxy-aarch64-unknown-linux-musl-upx.tar.gz",
	"tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz", "tg-ws-proxy-armv7-unknown-linux-musleabi-upx.tar.gz",
	"tg-ws-proxy-armv7-unknown-linux-musleabi.tar.gz", "tg-ws-proxy-armv7-unknown-linux-musleabihf-upx.tar.gz",
	"tg-ws-proxy-armv7-unknown-linux-musleabihf.tar.gz", "tg-ws-proxy-mips-unknown-linux-musl-upx.tar.gz",
	"tg-ws-proxy-mips-unknown-linux-musl.tar.gz", "tg-ws-proxy-mipsel-unknown-linux-musl-upx.tar.gz",
	"tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz", "tg-ws-proxy-rs-android-2.5.8-arm64-v8a.apk",
	"tg-ws-proxy-rs-android-2.5.8-armeabi-v7a.apk", "tg-ws-proxy-rs-android-2.5.8-universal.apk",
	"tg-ws-proxy-rs-android-2.5.8-x86_64.apk", "tg-ws-proxy-universal-apple-darwin.tar.gz",
	"tg-ws-proxy-x86_64-apple-darwin.tar.gz", "tg-ws-proxy-x86_64-pc-windows-gnu.zip",
	"tg-ws-proxy-x86_64-unknown-linux-musl-upx.tar.gz", "tg-ws-proxy-x86_64-unknown-linux-musl.tar.gz",
}

// v2.5.0 had no soft-float ARM build yet: the hard-float one is still the ARMv7 answer there.
var tgwsAssets250 = []string{
	"SHA256SUMS", "tg-ws-proxy-aarch64-unknown-linux-musl-upx.tar.gz", "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz",
	"tg-ws-proxy-armv7-unknown-linux-musleabihf-upx.tar.gz", "tg-ws-proxy-armv7-unknown-linux-musleabihf.tar.gz",
	"tg-ws-proxy-rs-android-2.5.0-armeabi-v7a.apk", "tg-ws-proxy-x86_64-pc-windows-gnu.zip",
}

func tgwsAssetList(names []string) []Asset {
	out := make([]Asset, len(names))
	for i, n := range names {
		out[i] = Asset{Name: n}
	}
	return out
}

// Every router arch gets its static musl Linux build: never the -upx twin, never a macOS, Windows
// or Android build, never the LuCI package; ARMv7 the soft-float build.
func TestTGWSProxyAssetPick(t *testing.T) {
	e := EngineByID("tg-ws-proxy")
	if e == nil || e.BinName != "tg-ws-proxy" || e.Role != "service" || e.SumsAsset != "SHA256SUMS" || !e.RouterUsed() {
		t.Fatalf("catalog entry = %+v", e)
	}
	assets := tgwsAssetList(tgwsAssets258)
	for arch, want := range map[string]string{
		"arm64":  "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz",
		"arm":    "tg-ws-proxy-armv7-unknown-linux-musleabi.tar.gz",
		"mips":   "tg-ws-proxy-mips-unknown-linux-musl.tar.gz",
		"mipsle": "tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz",
		"amd64":  "tg-ws-proxy-x86_64-unknown-linux-musl.tar.gz",
	} {
		got := pickAssetFor(*e, assets, arch)
		if got == nil || got.Name != want {
			t.Errorf("%s: picked %v, want %s", arch, got, want)
		}
	}
	// The soft-float preference must not depend on listing order.
	rev := make([]Asset, len(assets))
	for i := range assets {
		rev[len(assets)-1-i] = assets[i]
	}
	if got := pickAssetFor(*e, rev, "arm"); got == nil || got.Name != "tg-ws-proxy-armv7-unknown-linux-musleabi.tar.gz" {
		t.Errorf("arm, reversed listing: picked %v", got)
	}
	old := tgwsAssetList(tgwsAssets250)
	if got := pickAssetFor(*e, old, "arm"); got == nil || got.Name != "tg-ws-proxy-armv7-unknown-linux-musleabihf.tar.gz" {
		t.Errorf("arm on v2.5.0: picked %v, want the hard-float build it has", got)
	}
}

// The archive member is tg-ws-proxy at the top level; it installs under the same name.
func TestTGWSProxyMemberExtract(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("\x7fELF fake tg-ws-proxy")
	_ = tw.WriteHeader(&tar.Header{Name: "tg-ws-proxy", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	e := EngineByID("tg-ws-proxy")
	got, err := extractBinary("tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz", buf.Bytes(), e.member())
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("extract = %q, %v", got, err)
	}
}

// v2.5.8's SHA256SUMS in its own layout (gh release download v2.5.8 -p SHA256SUMS: "<hex>  <name>",
// one line per asset, sha256sum's "*" binary-mode marker accepted too), with placeholder digests:
// the real ones agree with GitHub's for every asset there, and a long hex value in the source is
// what scripts/check-pii.mjs refuses as a secret.
var (
	tgwsDigestA = strings.Repeat("a", 64)
	tgwsDigestB = strings.Repeat("b", 64)
	tgwsDigestC = strings.Repeat("c", 64)
	tgwsDigestD = strings.Repeat("d", 64)
	tgwsSums258 = tgwsDigestA + "  luci-app-tg-ws-proxy-rs_2.5.8-r1_all.ipk\n" +
		tgwsDigestB + "  tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz\n" +
		tgwsDigestC + "  tg-ws-proxy-armv7-unknown-linux-musleabi.tar.gz\n" +
		tgwsDigestD + " *tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz\n"
)

func TestTGWSProxySumsAgree(t *testing.T) {
	ok := []Asset{
		{Name: "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz", Digest: "sha256:" + tgwsDigestB},
		// GitHub's digest compared case-blind.
		{Name: "tg-ws-proxy-armv7-unknown-linux-musleabi.tar.gz", Digest: "sha256:" + strings.ToUpper(tgwsDigestC)},
		// sha256sum's binary-mode marker.
		{Name: "tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz", Digest: "sha256:" + tgwsDigestD},
	}
	for _, a := range ok {
		if err := sumsAgree([]byte(tgwsSums258), "SHA256SUMS", a); err != nil {
			t.Errorf("%s: %v", a.Name, err)
		}
	}
	for name, a := range map[string]Asset{
		// The file on the release no longer matches what the list says was published.
		"replaced": {Name: "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz", Digest: "sha256:" + strings.Repeat("0", 64)},
		// An asset the list does not name is not installed on the digest alone.
		"unlisted": {Name: "tg-ws-proxy-mips-unknown-linux-musl.tar.gz", Digest: "sha256:" + tgwsDigestB},
		// No GitHub digest: nothing to compare the list with.
		"no digest": {Name: "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz"},
		// A name that only ends like a listed one is not that one.
		"suffix": {Name: "musl.tar.gz", Digest: "sha256:" + tgwsDigestB},
	} {
		if err := sumsAgree([]byte(tgwsSums258), "SHA256SUMS", a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Install end to end with the release's SHA256SUMS: a list that agrees with GitHub's digest lets the
// install through; one that disagrees, or a release without a list, refuses it before a byte of the
// binary is written.
func TestTGWSProxyInstallChecksSums(t *testing.T) {
	const tag = "v2.5.8"
	e := *EngineByID("tg-ws-proxy")
	e.VersionArgs = nil // the payload below is not a binary this host can run
	name := "tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz"
	payload := []byte("REAL-TG-WS-PROXY-arm64")
	tgz := updaterinstall_tarGz(t, ".", e.BinName, payload)
	digest := updaterinstall_sha256(tgz)
	base := "https://github.com/valnesfjord/tg-ws-proxy-rs/releases/download/" + tag + "/"
	run := func(t *testing.T, sums string, withSums bool) (string, string, error) {
		t.Helper()
		assets := []Asset{{Name: name, URL: base + name, Digest: digest, Size: int64(len(tgz))}}
		served := map[string][]byte{"/" + name: tgz}
		if withSums {
			assets = append(assets, Asset{Name: "SHA256SUMS", URL: base + "SHA256SUMS", Size: int64(len(sums))})
			served["/SHA256SUMS"] = []byte(sums)
		}
		rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: updaterinstall_releaseJSON(t, tag, assets), assets: served}
		binDir := t.TempDir()
		u := New(binDir, "arm64", nil)
		u.hc = &http.Client{Transport: rt}
		got, err := u.Install(context.Background(), e, tag)
		return got, binDir, err
	}
	hexOf := strings.TrimPrefix(digest, "sha256:")

	t.Run("agree", func(t *testing.T) {
		got, binDir, err := run(t, hexOf+"  "+name+"\n", true)
		if err != nil || got != tag {
			t.Fatalf("Install = %q, %v", got, err)
		}
		if b, err := os.ReadFile(filepath.Join(binDir, "tg-ws-proxy")); err != nil || !bytes.Equal(b, payload) {
			t.Fatalf("installed %q, %v", b, err)
		}
	})
	for label, c := range map[string]struct {
		sums     string
		withSums bool
		want     string
	}{
		"disagree": {strings.Repeat("ab", 32) + "  " + name + "\n", true, "replaced after the list was published"},
		"no line":  {hexOf + "  some-other-asset.tar.gz\n", true, "has no line for"},
		"no list":  {"", false, "publishes no SHA256SUMS"},
	} {
		t.Run(label, func(t *testing.T) {
			_, binDir, err := run(t, c.sums, c.withSums)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Install err = %v, want %q", err, c.want)
			}
			if _, statErr := os.Stat(filepath.Join(binDir, "tg-ws-proxy")); !os.IsNotExist(statErr) {
				t.Fatal("a refused install left a binary behind")
			}
		})
	}
}
