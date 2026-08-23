package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file exercises 10 version-selection scenarios in PARALLEL (t.Parallel) —
// both upgrades (installing a newer tag over an older one) and downgrades
// (installing an OLDER tag over a newer one) — against a canned release server.
// The updater has no upgrade/downgrade distinction in code (Install just installs
// the selected tag), so the real risk surface these probe is: arch-asset matching,
// archive format/layout, digest present/absent/corrupt, and missing-arch handling
// VARYING across versions. Each scenario pre-places an "old" binary where relevant
// so a failed install is also checked for non-destructiveness (the good binary and
// the .new temp must survive/not-survive correctly).

// udZip builds a .zip whose single entry is "<dir>/<binName>" (some tools shipped
// zips for older releases; fromZip matches on filepath.Base).
func udZip(t *testing.T, dir, binName string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(dir + "/" + binName)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// udAsset is one release asset for a scenario. digest: "" none, "ok" correct,
// "bad" deliberately wrong (tamper detection).
type udAsset struct {
	name   string
	bytes  []byte
	digest string
}

type udCase struct {
	name      string
	arch      string
	tag       string
	assets    []udAsset
	pre       []byte // pre-existing installed binary (preservation check on failure)
	wantBytes []byte // expected installed payload on success
	wantTag   string
	wantErr   string // non-empty => expect Install to fail with this substring
}

func udRun(t *testing.T, c udCase) {
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	assets := make([]Asset, 0, len(c.assets))
	served := map[string][]byte{}
	for _, a := range c.assets {
		dg := ""
		switch a.digest {
		case "ok":
			dg = updaterinstall_sha256(a.bytes)
		case "bad":
			dg = updaterinstall_sha256([]byte("tampered-" + a.name)) // hash of OTHER bytes
		}
		assets = append(assets, Asset{
			Name:   a.name,
			URL:    "https://github.com/SagerNet/sing-box/releases/download/" + c.tag + "/" + a.name,
			Digest: dg,
			Size:   int64(len(a.bytes)),
		})
		served["/"+a.name] = a.bytes
	}
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + c.tag,
		relJSON:       updaterinstall_releaseJSON(t, c.tag, assets),
		assets:        served,
	}

	binDir := t.TempDir()
	dst := filepath.Join(binDir, e.BinName)
	if c.pre != nil {
		if err := os.WriteFile(dst, c.pre, 0o755); err != nil {
			t.Fatalf("pre-place binary: %v", err)
		}
	}
	u := New(binDir, c.arch, nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.Install(context.Background(), e, c.tag)

	if c.wantErr != "" {
		if err == nil {
			t.Fatalf("Install: want error containing %q, got nil (returned tag %q)", c.wantErr, got)
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("Install error = %v, want substring %q", err, c.wantErr)
		}
		// A rejected install must NOT clobber an existing (good) binary...
		if c.pre != nil {
			if b, rerr := os.ReadFile(dst); rerr != nil || !bytes.Equal(b, c.pre) {
				t.Errorf("failed install altered the existing binary: got %q (err %v), want %q", b, rerr, c.pre)
			}
		}
		// ...and must leave no half-written temp behind.
		if _, serr := os.Stat(dst + ".new"); !os.IsNotExist(serr) {
			t.Errorf("leftover %s.new after a failed install", dst)
		}
		return
	}

	if err != nil {
		t.Fatalf("Install: unexpected error: %v", err)
	}
	if got != c.wantTag {
		t.Errorf("returned tag = %q, want %q", got, c.wantTag)
	}
	onDisk, rerr := os.ReadFile(dst)
	if rerr != nil {
		t.Fatalf("installed binary missing: %v", rerr)
	}
	if !bytes.Equal(onDisk, c.wantBytes) {
		t.Errorf("installed bytes = %q, want %q (wrong asset/version installed)", onDisk, c.wantBytes)
	}
	if _, serr := os.Stat(dst + ".new"); !os.IsNotExist(serr) {
		t.Errorf("leftover %s.new after install", dst)
	}
}

func TestUpgradeDowngrade_TenScenarios(t *testing.T) {
	// Distinct payloads so the installed bytes prove exactly which version/asset landed.
	v112 := []byte("singbox-1.12.0-payload")
	v18 := []byte("singbox-1.8.0-payload")
	v09 := []byte("singbox-0.9.0-payload")
	armv7p := []byte("singbox-armv7-payload")
	armv5p := []byte("singbox-armv5-payload")
	arm64p := []byte("singbox-arm64-payload")
	mipslep := []byte("singbox-mipsle-raw-payload")
	tgz := func(dir string, p []byte) []byte { return updaterinstall_tarGz(t, dir, "sing-box", p) }

	cases := []udCase{
		// 1. UPGRADE: newer tag over older, amd64 tar.gz, sha256-verified.
		{name: "01_upgrade_amd64_targz_digest", arch: "amd64", tag: "v1.12.0", pre: v18, wantBytes: v112, wantTag: "v1.12.0",
			assets: []udAsset{{"sing-box-1.12.0-linux-amd64.tar.gz", tgz("sing-box-1.12.0-linux-amd64", v112), "ok"}}},
		// 2. DOWNGRADE: OLDER tag over newer — must be allowed (no downgrade block).
		{name: "02_downgrade_amd64_targz_digest", arch: "amd64", tag: "v1.8.0", pre: v112, wantBytes: v18, wantTag: "v1.8.0",
			assets: []udAsset{{"sing-box-1.8.0-linux-amd64.tar.gz", tgz("sing-box-1.8.0-linux-amd64", v18), "ok"}}},
		// 3. DOWNGRADE to a pre-digest-era release (no Digest field) — REFUSED (LOOP-010). An engine
		//    binary runs as root, so a release with nothing to verify against is not installed on
		//    trust; the existing good binary must survive untouched.
		{name: "03_downgrade_no_digest_refused", arch: "amd64", tag: "v0.9.0", pre: v112, wantErr: "no sha256 digest",
			assets: []udAsset{{"sing-box-0.9.0-linux-amd64.tar.gz", tgz("sing-box-0.9.0-linux-amd64", v09), ""}}},
		// 4. UPGRADE where the asset uses the x86_64 naming variant (vs amd64).
		{name: "04_upgrade_x86_64_naming", arch: "amd64", tag: "v1.12.0", wantBytes: v112, wantTag: "v1.12.0",
			assets: []udAsset{{"sing-box-1.12.0-linux-x86_64.tar.gz", tgz("sing-box-1.12.0-linux-x86_64", v112), "ok"}}},
		// 5. DOWNGRADE to a version packaged as .zip (not .tar.gz).
		{name: "05_downgrade_zip", arch: "amd64", tag: "v1.8.0", pre: v112, wantBytes: v18, wantTag: "v1.8.0",
			assets: []udAsset{{"sing-box-1.8.0-linux-amd64.zip", udZip(t, "sing-box-1.8.0-linux-amd64", "sing-box", v18), "ok"}}},
		// 6. UPGRADE arm64 where the asset is named aarch64.
		{name: "06_upgrade_arm64_aarch64", arch: "arm64", tag: "v1.12.0", wantBytes: v112, wantTag: "v1.12.0",
			assets: []udAsset{{"sing-box-1.12.0-linux-aarch64.tar.gz", tgz("sing-box-1.12.0-linux-aarch64", v112), "ok"}}},
		// 7. DOWNGRADE on 32-bit arm with armv7/armv5/arm64 assets — must pick armv7 (never arm64).
		{name: "07_downgrade_arm_prefers_armv7", arch: "arm", tag: "v1.8.0", wantBytes: armv7p, wantTag: "v1.8.0",
			assets: []udAsset{
				{"sing-box-1.8.0-linux-armv7", armv7p, "ok"},
				{"sing-box-1.8.0-linux-armv5", armv5p, "ok"},
				{"sing-box-1.8.0-linux-arm64", arm64p, "ok"},
			}},
		// 8. UPGRADE mipsle delivered as a raw (un-archived) binary.
		{name: "08_upgrade_mipsle_raw", arch: "mipsle", tag: "v1.12.0", wantBytes: mipslep, wantTag: "v1.12.0",
			assets: []udAsset{{"sing-box-linux-mipsle", mipslep, "ok"}}},
		// 9. SAFETY: selected version's asset is corrupted (sha256 mismatch) — must REFUSE
		//    and leave the existing binary untouched.
		{name: "09_safety_sha_mismatch_preserves", arch: "amd64", tag: "v1.12.0", pre: v18, wantErr: "sha256 mismatch",
			assets: []udAsset{{"sing-box-1.12.0-linux-amd64.tar.gz", tgz("sing-box-1.12.0-linux-amd64", v112), "bad"}}},
		// 10. SAFETY: selected version publishes no asset for the running arch (mips) — must
		//     error cleanly and preserve the existing binary.
		{name: "10_safety_no_asset_for_arch_preserves", arch: "mips", tag: "v1.12.0", pre: v18, wantErr: "no sing-box asset for arch",
			assets: []udAsset{
				{"sing-box-1.12.0-linux-amd64.tar.gz", tgz("sing-box-1.12.0-linux-amd64", v112), "ok"},
				{"sing-box-1.12.0-linux-arm64.tar.gz", tgz("sing-box-1.12.0-linux-arm64", v112), "ok"},
			}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			udRun(t, c)
		})
	}
}

// TestVersionParseAcrossTags guards the version string parsed off a (possibly
// up/downgraded) binary — verRe must extract x.y.z regardless of "v" prefix,
// monorepo "app/v" tags, or two-digit minors (so 1.10 isn't read as 1.1).
func TestVersionParseAcrossTags(t *testing.T) {
	for in, want := range map[string]string{
		"sing-box version 1.12.0 (go1.22)": "1.12.0",
		"v1.10.0":                          "1.10.0",
		"1.9.10":                           "1.9.10",
		"app/v2.0.0":                       "2.0.0",
		"0.9.0":                            "0.9.0",
	} {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
