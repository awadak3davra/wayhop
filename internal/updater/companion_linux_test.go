//go:build linux

package updater

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
)

// The catalogue's own amneziawg-go entry, whose --version check executes the download before it
// replaces anything. A shell script stands in for the binary and answers --version the way upstream's
// does, with a version that is not the release's; Install must report and record the release's.
func TestCompanionInstallReportsTheReleaseNotTheBinary(t *testing.T) {
	e := *EngineByID("amneziawg-go")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("#!/bin/sh\necho 'amneziawg-go v0.0.20250522'\n"))
	_ = zw.Close()
	token := runtime.GOARCH
	if token == "arm" {
		token = "armv7"
	}
	name := "amneziawg-go-v3.1.20260828-linux-" + token + ".gz"
	listing, _ := json.Marshal([]Release{{Tag: "v0.5.7", Assets: []Asset{{
		Name: name, URL: "https://github.com/" + DefaultSelfRepo + "/releases/download/v0.5.7/" + name,
		Digest: updaterinstall_sha256(gz.Bytes()), Size: int64(gz.Len()),
	}}}})
	u := New(t.TempDir(), runtime.GOARCH, nil)
	u.hc = &http.Client{Transport: &updaterinstall_rt{
		relPathSuffix: "/releases?per_page=15", relJSON: listing, assets: map[string][]byte{"/" + name: gz.Bytes()},
	}}
	got, err := u.Install(context.Background(), e, "v3.1.20260828")
	if err != nil || got != "v3.1.20260828" {
		t.Fatalf("Install = %q, %v; want the release's version, not the binary's 0.0.20250522", got, err)
	}
	if v := u.Installed(e).Version; v != "v3.1.20260828" {
		t.Errorf("installed version %q", v)
	}
}

// Kept compressed, the download is still proven to run before it is stored: unpacked into RAM, its
// --version run, and only then renamed into place. A download that does not execute leaves nothing.
func TestCompanionCompressedInstallRunsTheProbe(t *testing.T) {
	probed := filepath.Join(t.TempDir(), "probed")
	t.Setenv("WAYHOP_TEST_PROBED", probed)
	script := "#!/bin/sh\n: > \"$WAYHOP_TEST_PROBED\"\necho 'amneziawg-go v0.0.20250522'\n"
	for _, c := range []struct {
		payload string
		ok      bool
	}{{script, true}, {"not an executable", false}} {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write([]byte(c.payload))
		_ = zw.Close()
		token := runtime.GOARCH
		if token == "arm" {
			token = "armv7"
		}
		name := "amneziawg-go-v3.1.20260828-linux-" + token + ".gz"
		listing, _ := json.Marshal([]Release{{Tag: "v0.5.7", Assets: []Asset{{
			Name: name, URL: "https://github.com/" + DefaultSelfRepo + "/releases/download/v0.5.7/" + name,
			Digest: updaterinstall_sha256(gz.Bytes()), Size: int64(gz.Len()),
		}}}})
		u := New(t.TempDir(), runtime.GOARCH, nil)
		u.RunDir = t.TempDir()
		u.WithAvail(func(string) (uint64, bool) { return compressedNeed(int64(gz.Len())), true })
		u.hc = &http.Client{Transport: &updaterinstall_rt{
			relPathSuffix: "/releases?per_page=15", relJSON: listing, assets: map[string][]byte{"/" + name: gz.Bytes()},
		}}
		got, err := u.Install(context.Background(), *EngineByID("amneziawg-go"), "v3.1.20260828")
		stored := fileExists(filepath.Join(u.BinDir, "amneziawg-go.gz"))
		if c.ok && (err != nil || got != "v3.1.20260828" || !stored || !fileExists(probed)) {
			t.Errorf("runnable download: %q, %v, stored %v, probe ran %v", got, err, stored, fileExists(probed))
		}
		if !c.ok && (err == nil || stored) {
			t.Errorf("a download that does not execute: err %v, stored %v", err, stored)
		}
	}
}
