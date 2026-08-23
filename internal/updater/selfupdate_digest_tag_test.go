package updater

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain lets the test binary double as a sanity-runnable WayHop binary: SelfUpdate
// stages the downloaded binary and runs `<staged> -version`, requiring a parseable version
// in the output. When this process is re-exec'd with a leading "-version" arg we print a
// version and exit, so a full SelfUpdate (present-digest) path can install + sanity-check the
// staged binary deterministically and offline on any host OS. Without "-version" we run the
// ordinary test suite.
func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if a == "-version" || a == "--version" {
			os.Stdout.WriteString("wayhop 9.9.9 (self-update test stub)\n")
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// selfUpdateFakeBinary returns the current test executable's bytes, which are runnable on
// this host. When SelfUpdate stages and runs it with "-version", TestMain above answers, so
// the sanity-run passes and the swap completes.
func selfUpdateFakeBinary(t *testing.T) []byte {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	return b
}

// TestSelfUpdate_PresentDigestVerifiesAndInstalls drives the whole SelfUpdate path with a
// real, matching sha256 digest on the chosen asset: download -> verifyDigestRequired ->
// extract -> sanity-run -> backup -> atomic swap. The asset's digest matches the tarball
// bytes, so verification passes and the new binary is installed.
func TestSelfUpdate_PresentDigestVerifiesAndInstalls(t *testing.T) {
	const tag = "v0.2.0"
	arch := "amd64"
	bin := selfUpdateFakeBinary(t)
	tgz := updaterinstall_tarGz(t, "wayhop-0.2.0-amd64", "wayhop-"+arch, bin)

	assetName := "wayhop-0.2.0-" + arch + ".tar.gz"
	assetURL := "https://github.com/awadak3davra/wayhop/releases/download/" + tag + "/" + assetName
	assetPathSuffix := "/" + assetName
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{assetPathSuffix: tgz},
	}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "wayhop")
	if err := os.WriteFile(exePath, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatalf("seed current exe: %v", err)
	}

	u := New(dir, arch, nil)
	u.hc = &http.Client{Transport: rt}

	got, err := u.SelfUpdate(context.Background(), "awadak3davra/wayhop", tag, exePath)
	if err != nil {
		t.Fatalf("SelfUpdate (present digest): %v", err)
	}
	if got != tag {
		t.Errorf("SelfUpdate returned tag %q, want %q", got, tag)
	}
	// New binary is in place...
	onDisk, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read swapped exe: %v", err)
	}
	if string(onDisk) == "OLD-BINARY" {
		t.Error("binary was not swapped (still the old bytes)")
	}
	// ...and the mandatory rollback backup holds the previous bytes.
	bak, err := os.ReadFile(exePath + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bak) != "OLD-BINARY" {
		t.Errorf("backup = %q, want OLD-BINARY", bak)
	}
	if _, err := os.Stat(filepath.Join(dir, ".wayhop.new")); !os.IsNotExist(err) {
		t.Errorf("leftover .wayhop.new after swap")
	}
}

// TestSelfUpdate_EmptyDigestRefused asserts the SCOPED #2 fix: a self-update asset with NO
// digest is refused (the new binary would run as root unverified), and nothing is installed.
// The refusal must happen before the binary is staged/swapped.
func TestSelfUpdate_EmptyDigestRefused(t *testing.T) {
	const tag = "v0.2.0"
	arch := "amd64"
	bin := selfUpdateFakeBinary(t)
	tgz := updaterinstall_tarGz(t, "wayhop-0.2.0-amd64", "wayhop-"+arch, bin)

	assetName := "wayhop-0.2.0-" + arch + ".tar.gz"
	assetURL := "https://github.com/awadak3davra/wayhop/releases/download/" + tag + "/" + assetName
	assetPathSuffix := "/" + assetName
	// Digest intentionally empty -> mirror channel is the only trust root -> refuse.
	rel := updaterinstall_releaseJSON(t, tag, []Asset{
		{Name: assetName, URL: assetURL, Digest: "", Size: int64(len(tgz))},
	})
	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/" + tag,
		relJSON:       rel,
		assets:        map[string][]byte{assetPathSuffix: tgz},
	}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "wayhop")
	if err := os.WriteFile(exePath, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatalf("seed current exe: %v", err)
	}

	u := New(dir, arch, nil)
	u.hc = &http.Client{Transport: rt}

	_, err := u.SelfUpdate(context.Background(), "awadak3davra/wayhop", tag, exePath)
	if err == nil {
		t.Fatal("SelfUpdate accepted an asset with no digest; want refusal")
	}
	if !strings.Contains(err.Error(), "no sha256 digest") {
		t.Errorf("error = %v, want a 'no sha256 digest' refusal", err)
	}
	// Nothing must have been swapped or staged.
	if onDisk, _ := os.ReadFile(exePath); string(onDisk) != "OLD-BINARY" {
		t.Errorf("current binary changed despite refusal: %q", onDisk)
	}
	if _, err := os.Stat(exePath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("a backup was written despite refusal")
	}
	if _, err := os.Stat(filepath.Join(dir, ".wayhop.new")); !os.IsNotExist(err) {
		t.Errorf("a staged .wayhop.new was written despite refusal")
	}
}

// TestVerifyDigestRequired covers the self-update digest gate in isolation: a matching digest
// verifies; an empty, prefix-only, wrong-scheme, or absent digest is refused (vs the
// best-effort verifyDigest, which SKIPS those for engine updates).
func TestVerifyDigestRequired(t *testing.T) {
	data := []byte("the-binary-bytes")
	good := updaterinstall_sha256(data)

	if err := verifyDigestRequired(data, good); err != nil {
		t.Errorf("verifyDigestRequired(matching) = %v, want nil", err)
	}
	for _, d := range []string{"", "sha256:", "sha256", "md5:abc", "deadbeef"} {
		if err := verifyDigestRequired(data, d); err == nil {
			t.Errorf("verifyDigestRequired(%q) = nil, want refusal", d)
		}
	}
	// A present-but-wrong digest must still be a mismatch, not a "missing" error.
	if err := verifyDigestRequired(data, "sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Error("verifyDigestRequired(wrong) = nil, want mismatch")
	} else if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("verifyDigestRequired(wrong) = %v, want sha256 mismatch", err)
	}
	// Sanity: the engine-update path STILL skips an empty digest (non-breaking preserved).
	if err := verifyDigest(data, ""); err != nil {
		t.Errorf("verifyDigest(empty) = %v, want nil (engine best-effort preserved)", err)
	}
}

// TestValidateTag covers the #8 tag validator: good tags pass; empty, traversal, slash,
// and reserved/whitespace characters are rejected before the tag reaches the API path.
func TestValidateTag(t *testing.T) {
	good := []string{
		"v0.2.0", "v1.2.3-rc1", "nightly-9822def", "0.1.0", "release_2026.06+ci", "a",
		"app/v2.0.0", // apernet/hysteria genuinely tags with a slash — must stay valid
	}
	for _, g := range good {
		if err := validateTag(g); err != nil {
			t.Errorf("validateTag(%q) = %v, want nil", g, err)
		}
	}
	bad := []string{
		"",             // empty
		".",            // current dir
		"..",           // parent dir
		"../../etc",    // traversal
		"v1.0/../../x", // traversal via slash
		"a//b",         // empty segment (double slash)
		"/v1.0",        // leading slash
		"v1.0/",        // trailing slash
		"v1 0",         // space
		"v1.0\n",       // newline
		"tag?x=1",      // query injection
		"tag#frag",     // fragment
		"v1.0%2e%2e",   // pre-encoded percent
		"таг",          // non-ASCII
	}
	for _, b := range bad {
		if err := validateTag(b); err == nil {
			t.Errorf("validateTag(%q) = nil, want error", b)
		}
	}
}

// TestApiGetLimitsMetadataBody asserts the #4 cap: apiGet decodes through an 8 MiB
// LimitReader, so a hostile/misbehaving mirror that streams a huge metadata body cannot be
// fully buffered. We serve a valid small JSON prefix followed by megabytes of junk inside one
// giant string field; the LimitReader truncates mid-value, so Decode fails (truncated JSON)
// rather than the process buffering the whole oversized body.
func TestApiGetLimitsMetadataBody(t *testing.T) {
	// Build a single JSON object far larger than 8 MiB: {"tag_name":"v1","name":"<10MiB>"}.
	var b strings.Builder
	b.WriteString(`{"tag_name":"v1","name":"`)
	b.WriteString(strings.Repeat("A", 10<<20))
	b.WriteString(`"}`)
	huge := []byte(b.String())

	rt := &updaterinstall_rt{
		relPathSuffix: "/releases/tags/v1",
		relJSON:       huge,
		assets:        map[string][]byte{},
	}
	u := New(t.TempDir(), "amd64", nil)
	u.hc = &http.Client{Transport: rt}

	var r Release
	err := u.apiGet(context.Background(), "/repos/x/y/releases/tags/v1", &r)
	if err == nil {
		t.Fatalf("apiGet decoded a >8MiB body without error; LimitReader cap not applied (got tag %q)", r.Tag)
	}
	// The failure should be a decode/truncation error from the capped reader, surfaced as
	// the last mirror error.
	if !strings.Contains(err.Error(), "unexpected EOF") &&
		!strings.Contains(err.Error(), "unexpected end") {
		t.Logf("apiGet capped-body error = %v", err) // any decode error is acceptable
	}
}
