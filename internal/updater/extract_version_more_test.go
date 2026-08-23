package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- shared in-memory archive + transport helpers -------------------------

// updater_gz returns a gzip stream of payload (a bare ".gz" asset body).
func updater_gz(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// updater_tarGzMulti builds a .tar.gz containing every (name->payload) entry as a
// regular file plus one directory entry, so tests can prove fromTarGz skips
// non-matching / non-regular members and matches on filepath.Base.
func updater_tarGzMulti(t *testing.T, entries map[string][]byte, dirEntry string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if dirEntry != "" {
		if err := tw.WriteHeader(&tar.Header{
			Name:     dirEntry,
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}); err != nil {
			t.Fatalf("tar dir header: %v", err)
		}
	}
	for name, payload := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %q: %v", name, err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatalf("tar write %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// updater_zip builds a .zip whose members are the given (name->payload) entries.
func updater_zip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, payload := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// updater_jsonRT is a minimal RoundTripper that maps each request URL *suffix* to a
// canned (status, body). It records fetched URLs. Unmatched URLs 404. Matching by
// suffix means mirror-prefixed URLs resolve to the same canned response.
type updater_jsonRT struct {
	routes  []updater_route
	fetched []string
}

type updater_route struct {
	suffix string // matched against the URL suffix
	reject string // if non-empty, the route only matches when the URL does NOT contain this token
	status int
	body   []byte
}

func (rt *updater_jsonRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.fetched = append(rt.fetched, req.URL.String())
	u := req.URL.String()
	for _, r := range rt.routes {
		if r.reject != "" && strings.Contains(u, r.reject) {
			continue
		}
		if strings.HasSuffix(u, r.suffix) {
			return &http.Response{
				StatusCode: r.status,
				Body:       io.NopCloser(bytes.NewReader(r.body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// updater_errRT fails every request at the transport layer (connection-style error),
// to drive apiGet/download's per-mirror error path (resp==nil, lastErr set).
type updater_errRT struct{ n int }

func (rt *updater_errRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.n++
	return nil, fmt.Errorf("dial fail #%d to %s", rt.n, req.URL.Host)
}

// --- EngineByID + registry shape ------------------------------------------

func TestUpdater_EngineByIDHitMissAndRegistry(t *testing.T) {
	// Hit: every registered id resolves to a non-nil engine carrying that id, and
	// the returned pointer is into the package registry (mutating Engines would be
	// reflected, but we only read here).
	if len(Engines) == 0 {
		t.Fatal("Engines registry is empty")
	}
	seen := map[string]bool{}
	for _, want := range Engines {
		got := EngineByID(want.ID)
		if got == nil {
			t.Fatalf("EngineByID(%q) = nil, want the registered engine", want.ID)
		}
		if got.ID != want.ID {
			t.Errorf("EngineByID(%q).ID = %q", want.ID, got.ID)
		}
		if got.Repo == "" || got.BinName == "" || got.Name == "" {
			t.Errorf("engine %q has an empty Name/Repo/BinName: %+v", want.ID, *got)
		}
		if !strings.Contains(got.Repo, "/") {
			t.Errorf("engine %q repo %q is not owner/name form", want.ID, got.Repo)
		}
		if seen[got.ID] {
			t.Errorf("duplicate engine id in registry: %q", got.ID)
		}
		seen[got.ID] = true
	}

	// Miss: an unregistered id yields nil.
	if got := EngineByID("definitely-not-an-engine"); got != nil {
		t.Errorf("EngineByID(miss) = %+v, want nil", *got)
	}
	if got := EngineByID(""); got != nil {
		t.Errorf("EngineByID(\"\") = %+v, want nil", *got)
	}

	// The two source-only engines are flagged as such, and at least one
	// asset-bearing engine is not.
	if e := EngineByID("amneziawg-go"); e == nil || !e.SourceOnly || e.Note == "" {
		t.Errorf("amneziawg-go should be SourceOnly with a Note: %+v", e)
	}
	if e := EngineByID("sing-box"); e == nil || e.SourceOnly {
		t.Errorf("sing-box should not be SourceOnly: %+v", e)
	}
}

// --- extractBinary: all four code paths -----------------------------------

func TestUpdater_ExtractBinaryAllFormats(t *testing.T) {
	bin := "sing-box"

	// .tar.gz (nested under a versioned dir, plus a decoy file + a dir entry).
	tgzPayload := []byte("TARGZ-PAYLOAD")
	tgz := updater_tarGzMulti(t, map[string][]byte{
		"sing-box-1.0.0-linux-amd64/sing-box": tgzPayload,
		"sing-box-1.0.0-linux-amd64/LICENSE":  []byte("license-text"),
	}, "sing-box-1.0.0-linux-amd64/")
	if got, err := extractBinary("sing-box-1.0.0-linux-amd64.tar.gz", tgz, bin); err != nil || !bytes.Equal(got, tgzPayload) {
		t.Errorf(".tar.gz: got=%q err=%v want=%q", got, err, tgzPayload)
	}
	// .tgz alias hits the same branch.
	if got, err := extractBinary("sing-box.tgz", tgz, bin); err != nil || !bytes.Equal(got, tgzPayload) {
		t.Errorf(".tgz: got=%q err=%v want=%q", got, err, tgzPayload)
	}

	// .zip (with a decoy member so the loop must skip past it).
	zipPayload := []byte("ZIP-PAYLOAD")
	zb := updater_zip(t, map[string][]byte{
		"README.md":  []byte("readme"),
		"bin/xrayNO": []byte("decoy"),
		"xray":       zipPayload,
	})
	if got, err := extractBinary("Xray-linux-64.zip", zb, "xray"); err != nil || !bytes.Equal(got, zipPayload) {
		t.Errorf(".zip: got=%q err=%v want=%q", got, err, zipPayload)
	}

	// bare .gz
	gzPayload := []byte("GZ-PAYLOAD")
	if got, err := extractBinary("mihomo-linux-amd64.gz", updater_gz(t, gzPayload), "mihomo"); err != nil || !bytes.Equal(got, gzPayload) {
		t.Errorf(".gz: got=%q err=%v want=%q", got, err, gzPayload)
	}

	// raw binary (no recognized suffix): returned verbatim.
	raw := []byte("RAW-ELF-BYTES")
	if got, err := extractBinary("hysteria-linux-amd64", raw, "hysteria"); err != nil || !bytes.Equal(got, raw) {
		t.Errorf("raw: got=%q err=%v want=%q", got, err, raw)
	}
	// Uppercase suffix is lowercased before matching.
	if got, err := extractBinary("MIHOMO-LINUX-AMD64.GZ", updater_gz(t, gzPayload), "mihomo"); err != nil || !bytes.Equal(got, gzPayload) {
		t.Errorf(".GZ upper: got=%q err=%v want=%q", got, err, gzPayload)
	}
}

// --- extractBinary / from* error paths ------------------------------------

func TestUpdater_ExtractBinaryErrorPaths(t *testing.T) {
	bin := "sing-box"

	// tar.gz that does not contain the wanted binary -> "not found in archive".
	tgz := updater_tarGzMulti(t, map[string][]byte{
		"some/other-file": []byte("x"),
	}, "")
	if _, err := extractBinary("x.tar.gz", tgz, bin); err == nil || !strings.Contains(err.Error(), "not found in archive") {
		t.Errorf("tar.gz missing-bin err = %v, want 'not found in archive'", err)
	}

	// zip without the wanted member -> "not found in zip".
	zb := updater_zip(t, map[string][]byte{"other": []byte("x")})
	if _, err := extractBinary("x.zip", zb, bin); err == nil || !strings.Contains(err.Error(), "not found in zip") {
		t.Errorf("zip missing-bin err = %v, want 'not found in zip'", err)
	}

	// Corrupt gzip for .gz -> gzip header error surfaces.
	if _, err := extractBinary("x.gz", []byte("not-gzip-at-all"), bin); err == nil {
		t.Error(".gz on non-gzip data: want error, got nil")
	}
	// Corrupt gzip for .tar.gz (gzip.NewReader fails before tar parsing).
	if _, err := extractBinary("x.tar.gz", []byte("not-gzip"), bin); err == nil {
		t.Error(".tar.gz on non-gzip data: want error, got nil")
	}
	// Not a real zip archive.
	if _, err := extractBinary("x.zip", []byte("PK-not-really"), bin); err == nil {
		t.Error(".zip on non-zip data: want error, got nil")
	}
	// A valid gzip stream that is NOT a tar -> tar.Next reports an error (not EOF
	// at offset 0 for a non-empty, non-tar body).
	if _, err := extractBinary("x.tar.gz", updater_gz(t, bytes.Repeat([]byte("A"), 2048)), bin); err == nil {
		t.Error(".tar.gz wrapping non-tar gzip: want error, got nil")
	}
}

// fromGz/fromTarGz/fromZip directly, to pin their signatures + happy paths.
func TestUpdater_FromHelpersDirect(t *testing.T) {
	payload := []byte("DIRECT")
	if got, err := fromGz(updater_gz(t, payload)); err != nil || !bytes.Equal(got, payload) {
		t.Errorf("fromGz: got=%q err=%v", got, err)
	}
	tgz := updater_tarGzMulti(t, map[string][]byte{"d/bin": payload}, "d/")
	if got, err := fromTarGz(tgz, "bin"); err != nil || !bytes.Equal(got, payload) {
		t.Errorf("fromTarGz: got=%q err=%v", got, err)
	}
	zb := updater_zip(t, map[string][]byte{"bin": payload})
	if got, err := fromZip(zb, "bin"); err != nil || !bytes.Equal(got, payload) {
		t.Errorf("fromZip: got=%q err=%v", got, err)
	}
}

// --- verifyDigest: accept / reject / skip variants ------------------------

func TestUpdater_VerifyDigestVariants(t *testing.T) {
	data := []byte("install-me")
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])

	// Accept (exact + case-insensitive hex).
	if err := verifyDigest(data, "sha256:"+hexsum); err != nil {
		t.Errorf("matching digest rejected: %v", err)
	}
	if err := verifyDigest(data, "sha256:"+strings.ToUpper(hexsum)); err != nil {
		t.Errorf("uppercase-hex digest rejected: %v", err)
	}

	// Reject (wrong hex).
	if err := verifyDigest(data, "sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Error("mismatched digest accepted")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("reject err = %v, want 'sha256 mismatch'", err)
	}

	// Skip (best-effort): empty, no colon, and unknown algorithm all return nil.
	for _, d := range []string{"", "deadbeef", "sha512:" + hexsum, "md5:abc"} {
		if err := verifyDigest(data, d); err != nil {
			t.Errorf("verifyDigest(%q) = %v, want nil (skip)", d, err)
		}
	}
}

// --- assetScore: the armv6 branch (score 1) -------------------------------

func TestUpdater_AssetScoreArmv6(t *testing.T) {
	// armv6 scores 1, the bare "-linux-arm" baseline scores 2, so when both are
	// present pickAsset must choose the bare arm — and never the armv6.
	assets := []Asset{
		{Name: "app-linux-armv6"},
		{Name: "app-linux-arm"},
	}
	if got := pickAsset(assets, "arm"); got == nil || got.Name != "app-linux-arm" {
		t.Fatalf("pickAsset(armv6,bare-arm) = %v, want bare app-linux-arm", got)
	}
	// armv6 alone is still installable (score 1 > initial -1).
	only := []Asset{{Name: "app-linux-armv6"}}
	if got := pickAsset(only, "arm"); got == nil || got.Name != "app-linux-armv6" {
		t.Fatalf("pickAsset(armv6 only) = %v, want app-linux-armv6", got)
	}
	// armv6 beats armv5 (1 > 0).
	v5v6 := []Asset{{Name: "app-linux-armv5"}, {Name: "app-linux-armv6"}}
	if got := pickAsset(v5v6, "arm"); got == nil || got.Name != "app-linux-armv6" {
		t.Fatalf("pickAsset(armv5,armv6) = %v, want app-linux-armv6", got)
	}
}

// --- Install: SourceOnly + early error branches ---------------------------

func TestUpdater_InstallSourceOnlyRefused(t *testing.T) {
	e := *EngineByID("amneziawg-go") // SourceOnly
	u := New(t.TempDir(), "amd64", nil)
	// No transport needed: SourceOnly is rejected before any network call.
	_, err := u.Install(context.Background(), e, "v1.0.0")
	if err == nil {
		t.Fatal("Install of a SourceOnly engine succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "no prebuilt releases") || !strings.Contains(err.Error(), e.Note) {
		t.Errorf("SourceOnly err = %v, want 'no prebuilt releases' + the engine Note", err)
	}
}

func TestUpdater_InstallReleaseLookupError(t *testing.T) {
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	// Transport 404s the release lookup (no matching route) -> apiGet errors ->
	// Install wraps it as "lookup <id> <tag>".
	rt := &updater_jsonRT{}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.Install(context.Background(), e, "v9.9.9")
	if err == nil || !strings.Contains(err.Error(), "lookup sing-box v9.9.9") {
		t.Fatalf("Install release-lookup err = %v, want 'lookup sing-box v9.9.9'", err)
	}
}

func TestUpdater_InstallDownloadError(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	assetName := "sing-box-1.0.0-linux-amd64.tar.gz"
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: "https://github.com/x/" + assetName},
	})
	// Serve the release JSON, but 404 the asset download.
	rt := &updater_jsonRT{routes: []updater_route{
		{suffix: "/releases/tags/" + tag, status: http.StatusOK, body: rel},
		// asset path falls through to the default 404
	}}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.Install(context.Background(), e, tag)
	if err == nil || !strings.Contains(err.Error(), "download "+assetName) {
		t.Fatalf("Install download err = %v, want 'download %s'", err, assetName)
	}
}

// Install a raw (no-suffix) asset end-to-end: exercises extractBinary's default
// branch through the full Install path and the on-disk write.
func TestUpdater_InstallRawBinary(t *testing.T) {
	const tag = "v2.5.0"
	e := Engine{ID: "hysteria", Repo: "apernet/hysteria", BinName: "hysteria"}
	payload := []byte("RAW-HYSTERIA-amd64")
	assetName := "hysteria-linux-amd64"
	assetURL := "https://github.com/apernet/hysteria/releases/download/" + tag + "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(payload)},
	})
	rt := &updater_jsonRT{routes: []updater_route{
		{suffix: "/releases/tags/" + tag, status: http.StatusOK, body: rel},
		{suffix: "/" + assetName, status: http.StatusOK, body: payload},
	}}
	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.Install(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("Install raw: %v", err)
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
}

// --- release() / Latest / List / Tags via injected transport --------------

func TestUpdater_ReleaseJSONUnmarshal(t *testing.T) {
	const tag = "v1.11.0"
	// Canned GitHub release payload, including fields the struct cares about and
	// extras it must ignore.
	raw := []byte(`{
		"tag_name": "` + tag + `",
		"name": "Release ` + tag + `",
		"prerelease": true,
		"draft": false,
		"assets": [
			{"name":"sing-box-1.11.0-linux-amd64.tar.gz","browser_download_url":"https://x/amd64.tgz","digest":"sha256:abc","size":12345},
			{"name":"sing-box-1.11.0-linux-arm64.tar.gz","browser_download_url":"https://x/arm64.tgz","size":222}
		]
	}`)
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	rt := &updater_jsonRT{routes: []updater_route{
		{suffix: "/releases/tags/" + tag, status: http.StatusOK, body: raw},
	}}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	r, err := u.release(context.Background(), e, tag)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if r.Tag != tag || r.Name != "Release "+tag || !r.Prerelease {
		t.Errorf("release fields wrong: %+v", r)
	}
	if len(r.Assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(r.Assets))
	}
	a0 := r.Assets[0]
	if a0.Name != "sing-box-1.11.0-linux-amd64.tar.gz" || a0.URL != "https://x/amd64.tgz" ||
		a0.Digest != "sha256:abc" || a0.Size != 12345 {
		t.Errorf("asset[0] decoded wrong: %+v", a0)
	}
}

func TestUpdater_LatestListTags(t *testing.T) {
	e := Engine{ID: "mihomo", Repo: "MetaCubeX/mihomo", BinName: "mihomo"}

	latest := updaterinstall_releaseJSON(t, "v1.18.0", []Asset{{Name: "mihomo-linux-amd64.gz", URL: "https://x/a.gz"}})
	listJSON, err := json.Marshal([]Release{
		{Tag: "v1.18.0", Name: "v1.18.0"},
		{Tag: "v1.17.0", Name: "v1.17.0"},
	})
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	tagsJSON, err := json.Marshal([]tag{{Name: "v1.18.0"}, {Name: "v1.17.0"}, {Name: "v1.16.0"}})
	if err != nil {
		t.Fatalf("marshal tags: %v", err)
	}

	rt := &updater_jsonRT{routes: []updater_route{
		{suffix: "/releases/latest", status: http.StatusOK, body: latest},
		// List uses "/releases?per_page=N"; match on the path segment before the query
		// by using a suffix that ignores the query. The transport matches the full URL
		// string suffix, so include the query.
		{suffix: "/releases?per_page=5", status: http.StatusOK, body: listJSON},
		{suffix: "/tags?per_page=3", status: http.StatusOK, body: tagsJSON},
	}}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	ctx := context.Background()

	// Latest
	lr, err := u.Latest(ctx, e)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if lr.Tag != "v1.18.0" {
		t.Errorf("Latest tag = %q, want v1.18.0", lr.Tag)
	}

	// List (explicit limit -> per_page=5)
	rs, err := u.List(ctx, e, 5)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rs) != 2 || rs[0].Tag != "v1.18.0" || rs[1].Tag != "v1.17.0" {
		t.Errorf("List = %+v, want two releases newest-first", rs)
	}

	// Tags (explicit limit -> per_page=3) returns just the names.
	ts, err := u.Tags(ctx, e, 3)
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(ts) != 3 || ts[0] != "v1.18.0" || ts[2] != "v1.16.0" {
		t.Errorf("Tags = %v, want [v1.18.0 v1.17.0 v1.16.0]", ts)
	}
}

// New: empty arch autodetects to runtime.GOARCH; empty mirrors defaults to {""}.
func TestUpdater_NewDefaults(t *testing.T) {
	u := New(t.TempDir(), "", nil)
	if u.Arch != runtime.GOARCH {
		t.Errorf("New(arch=\"\").Arch = %q, want runtime.GOARCH %q", u.Arch, runtime.GOARCH)
	}
	if len(u.Mirrors) != 1 || u.Mirrors[0] != "" {
		t.Errorf("New(nil mirrors).Mirrors = %v, want [\"\"]", u.Mirrors)
	}
	if u.hc == nil {
		t.Error("New left a nil http.Client")
	}
	// Explicit values are preserved (the non-default branch).
	u2 := New("/x", "mipsle", []string{"http://m"})
	if u2.Arch != "mipsle" || len(u2.Mirrors) != 1 || u2.Mirrors[0] != "http://m" {
		t.Errorf("New preserved-args wrong: arch=%q mirrors=%v", u2.Arch, u2.Mirrors)
	}
}

// List/Tags default their per_page to 15 when limit<=0. Assert the request URL
// carries per_page=15 by routing exactly on that suffix.
func TestUpdater_ListDefaultLimit(t *testing.T) {
	e := Engine{ID: "xray", Repo: "XTLS/Xray-core", BinName: "xray"}
	listJSON, err := json.Marshal([]Release{{Tag: "v1.8.4"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rt := &updater_jsonRT{routes: []updater_route{
		{suffix: "/releases?per_page=15", status: http.StatusOK, body: listJSON},
	}}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	rs, err := u.List(context.Background(), e, 0) // 0 -> default 15
	if err != nil {
		t.Fatalf("List default limit: %v", err)
	}
	if len(rs) != 1 || rs[0].Tag != "v1.8.4" {
		t.Errorf("List = %+v, want one release v1.8.4 (proves per_page=15 was requested)", rs)
	}
}

func TestUpdater_TagsErrorPropagates(t *testing.T) {
	e := Engine{ID: "mihomo", Repo: "MetaCubeX/mihomo", BinName: "mihomo"}
	// No route matches -> apiGet 404s -> Tags returns the error and a nil slice.
	rt := &updater_jsonRT{}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	ts, err := u.Tags(context.Background(), e, 0) // limit<=0 -> default 15
	if err == nil {
		t.Fatal("Tags with no route succeeded, want error")
	}
	if ts != nil {
		t.Errorf("Tags returned %v on error, want nil", ts)
	}
}

// --- apiGet branches ------------------------------------------------------

func TestUpdater_APIGetNoMirrorsConfigured(t *testing.T) {
	// An Updater with an empty Mirrors slice never enters the loop, so apiGet must
	// report "no mirrors configured". (New() would default to {""}; we construct
	// directly to hit the lastErr==nil branch.)
	u := &Updater{BinDir: t.TempDir(), Arch: "amd64", Mirrors: nil, hc: &http.Client{}}
	var r Release
	err := u.apiGet(context.Background(), "/repos/x/y/releases/latest", &r)
	if err == nil || !strings.Contains(err.Error(), "no mirrors configured") {
		t.Fatalf("apiGet(no mirrors) err = %v, want 'no mirrors configured'", err)
	}
}

func TestUpdater_APIGetAllMirrorsFailTransport(t *testing.T) {
	// Every mirror errors at the transport layer; apiGet returns the last error.
	rt := &updater_errRT{}
	u := New(t.TempDir(), "amd64", []string{"http://m1", "http://m2", ""})
	u.hc = &http.Client{Transport: rt}
	var r Release
	err := u.apiGet(context.Background(), "/repos/x/y/releases/latest", &r)
	if err == nil {
		t.Fatal("apiGet with all-failing transport succeeded, want error")
	}
	// One attempt per mirror (3).
	if rt.n != 3 {
		t.Errorf("transport attempts = %d, want 3 (one per mirror)", rt.n)
	}
}

func TestUpdater_APIGetMirrorFallThroughToSecond(t *testing.T) {
	// First mirror returns a non-200, second serves the JSON: apiGet must fall
	// through and decode from the second.
	rel := updaterinstall_releaseJSON(t, "v1.0.0", nil)
	rt := &updater_jsonRT{routes: []updater_route{
		// Serve OK only for the direct URL; reject any "dead"-prefixed URL so the
		// dead mirror 404s and apiGet must fall through. (Both URLs share the same
		// suffix, so the reject token is what distinguishes them.)
		{suffix: "https://api.github.com/repos/x/y/releases/latest", reject: "dead", status: http.StatusOK, body: rel},
	}}
	// First mirror prefixes the URL with http://dead/ -> rejected -> 404 -> fall
	// through to the direct "" mirror.
	u := New(t.TempDir(), "amd64", []string{"http://dead", ""})
	u.hc = &http.Client{Transport: rt}
	var r Release
	if err := u.apiGet(context.Background(), "/repos/x/y/releases/latest", &r); err != nil {
		t.Fatalf("apiGet fall-through: %v", err)
	}
	if r.Tag != "v1.0.0" {
		t.Errorf("decoded tag = %q, want v1.0.0", r.Tag)
	}
	// The dead mirror must have been attempted first.
	if len(rt.fetched) < 2 || !strings.Contains(rt.fetched[0], "dead") {
		t.Errorf("expected dead mirror attempted first; fetched=%v", rt.fetched)
	}
}

func TestUpdater_APIGetBadJSONFallsThrough(t *testing.T) {
	// First mirror serves OK but with undecodable JSON (decode error sets lastErr
	// and continues); second serves valid JSON.
	good := updaterinstall_releaseJSON(t, "v2.0.0", nil)
	rt := &updater_jsonRT{routes: []updater_route{
		// Mirror m1 (prefixed) path ends with the api path too; serve broken JSON for it.
		{suffix: "://m1/https://api.github.com/repos/x/y/releases/latest", status: http.StatusOK, body: []byte("{not json")},
		{suffix: "https://api.github.com/repos/x/y/releases/latest", status: http.StatusOK, body: good},
	}}
	u := New(t.TempDir(), "amd64", []string{"http://m1", ""})
	u.hc = &http.Client{Transport: rt}
	var r Release
	if err := u.apiGet(context.Background(), "/repos/x/y/releases/latest", &r); err != nil {
		t.Fatalf("apiGet bad-json fall-through: %v", err)
	}
	if r.Tag != "v2.0.0" {
		t.Errorf("decoded tag = %q, want v2.0.0", r.Tag)
	}
}

// --- Installed: present / absent / version-less / PATH lookup -------------

// updater_helperEnv re-execs the test binary as a fake engine. When set, TestMain's
// equivalent guard in TestUpdater_InstalledHelperProcess prints a version line and
// exits, so Installed() can run a real subprocess deterministically and offline.
const updater_helperEnv = "UPDATER_HELPER_VERSION"

// TestUpdater_InstalledHelperProcess is not a real test: when the guard env var is
// set it acts as the fake engine binary that Installed() executes, printing a
// version string and exiting 0. Go test binaries support being re-invoked with -run
// targeting a single test, which is the standard helper-process pattern.
func TestUpdater_InstalledHelperProcess(t *testing.T) {
	v := os.Getenv(updater_helperEnv)
	if v == "" {
		return // ordinary (no-op) test run
	}
	// Behave like `<engine> version`: emit a line containing a semver.
	fmt.Printf("fake-engine version %s (built offline)\n", v)
	os.Exit(0)
}

// updater_installFakeEngine copies the current test executable into dir under
// binName (adding .exe on Windows so it is runnable), returning the engine whose
// VersionArgs re-trigger the helper-process test. The copied binary, when run,
// re-executes this package's test binary with -run=TestUpdater_InstalledHelperProcess
// and the helper env set, so it prints a version and exits.
func updater_installFakeEngine(t *testing.T, dir, binName, version string) (Engine, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	name := binName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatalf("write fake engine: %v", err)
	}
	e := Engine{
		ID:      "fake",
		Name:    "fake",
		Repo:    "x/y",
		BinName: name,
		// Re-run only the helper test inside the copied binary.
		VersionArgs: []string{"-test.run=TestUpdater_InstalledHelperProcess"},
	}
	return e, dst
}

func TestUpdater_InstalledPresentRunsVersion(t *testing.T) {
	dir := t.TempDir()
	e, _ := updater_installFakeEngine(t, dir, "fakeengine", "3.2.1")
	t.Setenv(updater_helperEnv, "3.2.1")

	u := New(dir, "amd64", nil)
	in := u.Installed(e)
	if !in.Present {
		t.Fatalf("Installed.Present = false, want true (path should resolve in BinDir)")
	}
	if in.Path == "" {
		t.Error("Installed.Path empty for a present binary")
	}
	if in.Version != "3.2.1" {
		t.Errorf("Installed.Version = %q, want 3.2.1 (parsed from the helper output)", in.Version)
	}
}

func TestUpdater_InstalledAbsent(t *testing.T) {
	dir := t.TempDir() // empty
	// A binary name that won't be on PATH either.
	e := Engine{ID: "nope", Name: "nope", Repo: "x/y", BinName: "wayhop-nonexistent-engine-xyz", VersionArgs: []string{"version"}}
	u := New(dir, "amd64", nil)
	in := u.Installed(e)
	if in.Present {
		t.Errorf("Installed.Present = true for a missing binary: %+v", in)
	}
	if in.Version != "" || in.Path != "" {
		t.Errorf("absent engine should have empty Version/Path: %+v", in)
	}
}

func TestUpdater_InstalledPresentNoVersionArgs(t *testing.T) {
	dir := t.TempDir()
	// Present on disk but no VersionArgs -> Present true, Version stays empty (the
	// version command is skipped entirely).
	name := "noargs"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, []byte("not-really-executable"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	e := Engine{ID: "noargs", Name: "noargs", Repo: "x/y", BinName: name} // VersionArgs nil
	u := New(dir, "amd64", nil)
	in := u.Installed(e)
	if !in.Present {
		t.Fatalf("Installed.Present = false, want true")
	}
	if in.Version != "" {
		t.Errorf("Installed.Version = %q, want empty (no VersionArgs)", in.Version)
	}
	if in.Path != dst {
		t.Errorf("Installed.Path = %q, want %q", in.Path, dst)
	}
}

func TestUpdater_InstalledViaPATHLookup(t *testing.T) {
	// BinDir does not contain the binary, but it is resolvable via PATH. Installed()
	// must fall back to exec.LookPath and report the PATH location. We add a fresh
	// dir holding the fake engine to PATH so the lookup is deterministic.
	pathDir := t.TempDir()
	e, dst := updater_installFakeEngine(t, pathDir, "pathengine", "9.0.1")
	t.Setenv(updater_helperEnv, "9.0.1")

	// Prepend pathDir to PATH for this test only.
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	emptyBinDir := t.TempDir() // does NOT contain the binary
	u := New(emptyBinDir, "amd64", nil)
	in := u.Installed(e)
	if !in.Present {
		t.Fatalf("Installed.Present = false, want true via PATH lookup")
	}
	// LookPath resolves to the on-PATH copy.
	if in.Path == "" {
		t.Fatal("Installed.Path empty after PATH lookup")
	}
	// On Windows LookPath may return either the exact path or one with a resolved
	// extension; just require it points at our pathDir copy.
	if filepath.Dir(in.Path) != filepath.Dir(dst) {
		t.Errorf("Installed.Path = %q, want a file in %q", in.Path, filepath.Dir(dst))
	}
	if in.Version != "9.0.1" {
		t.Errorf("Installed.Version = %q, want 9.0.1", in.Version)
	}
}
