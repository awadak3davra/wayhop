package initserver

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBuildScriptMirrorFetch: the install script downloads sing-box through the wr_fetch
// mirror chain (so provisioning works from a censored region), with the configured prefixes
// baked in and an atom-feed fallback for the version lookup when the GitHub API is blocked.
func TestBuildScriptMirrorFetch(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "", "", "https://ghproxy.net/", "https://mirror.ghproxy.com/")

	if !strings.Contains(s, "wr_fetch() {") {
		t.Fatal("generated script is missing the wr_fetch helper")
	}
	if !strings.Contains(s, `wr_fetch "https://github.com/SagerNet/sing-box/releases/download/`) {
		t.Errorf("sing-box binary download not routed through wr_fetch:\n%s", s)
	}
	for _, want := range []string{"''", "'https://ghproxy.net/'", "'https://mirror.ghproxy.com/'"} {
		if !strings.Contains(s, want) {
			t.Errorf("mirror prefix %s missing from the wr_fetch chain", want)
		}
	}
	if !strings.Contains(s, "releases.atom") {
		t.Errorf("version lookup is missing the atom-feed fallback:\n%s", s)
	}
	// The old un-mirrored bare-curl download must be gone.
	if strings.Contains(s, `curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/`) {
		t.Errorf("an un-mirrored bare-curl sing-box download survived:\n%s", s)
	}
}

// TestBuildScriptMirrorFetch_NilAndGarbage: a nil mirror list degrades to a direct-only
// fetch (historical behaviour), and a hostile/garbage mirror is dropped, never injected.
func TestBuildScriptMirrorFetch_NilAndGarbage(t *testing.T) {
	s := BuildScript([]string{ProtoReality}, "")
	if !strings.Contains(s, "wr_fetch() {") || !strings.Contains(s, "for __pre in ''") {
		t.Errorf("nil mirrors should yield a direct-only wr_fetch:\n%s", s)
	}
	g := BuildScript([]string{ProtoReality}, "", "https://ok.example/", "https://evil/$(touch_pwned)/", "ftp://nope/")
	if !strings.Contains(g, "'https://ok.example/'") {
		t.Error("a safe mirror was dropped")
	}
	if strings.Contains(g, "touch_pwned") || strings.Contains(g, "ftp://") {
		t.Errorf("an unsafe mirror leaked into the generated script:\n%s", g)
	}
}

func TestSafeMirrorPrefix(t *testing.T) {
	ok := []string{"https://ghproxy.net/", "http://mirror.example/gh/", "https://a.b.c:8443/x/"}
	bad := []string{"", "ghproxy.net/", "ftp://x/", "https://x/$(id)", "https://x/`id`", "https://x/ y", "https://x/'q"}
	for _, m := range ok {
		if !safeMirrorPrefix(m) {
			t.Errorf("safeMirrorPrefix(%q) = false, want true", m)
		}
	}
	for _, m := range bad {
		if safeMirrorPrefix(m) {
			t.Errorf("safeMirrorPrefix(%q) = true, want false", m)
		}
	}
}

// TestUpdateSingBoxScriptMirrorFetch: the per-server sing-box UPDATE script also downloads
// through the wr_fetch mirror chain, so a server in a censored region can be updated, not just
// provisioned. (No atom fallback here — the version is resolved by the router and passed in.)
func TestUpdateSingBoxScriptMirrorFetch(t *testing.T) {
	s := UpdateSingBoxScript("1.12.17", "", "https://ghproxy.net/")
	if !strings.Contains(s, "wr_fetch() {") {
		t.Fatal("update script is missing the wr_fetch helper")
	}
	if !strings.Contains(s, `wr_fetch "$URL" sb.tgz`) {
		t.Errorf("update download not routed through wr_fetch:\n%s", s)
	}
	if !strings.Contains(s, "'https://ghproxy.net/'") {
		t.Error("configured mirror prefix missing from the update script")
	}
	if strings.Contains(s, `curl -fsSL "$URL" -o sb.tgz`) {
		t.Errorf("an un-mirrored bare-curl download survived in the update script:\n%s", s)
	}
}

// TestBuildScriptShellSyntax runs the generated install script through `sh -n` (parse-only)
// so the wr_fetch helper + the atom-feed version fallback can't ship a shell typo to a VPS.
// Skips where sh is absent (e.g. a bare Windows CI shard).
func TestBuildScriptShellSyntax(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH — skipping shell syntax check")
	}
	s := BuildScript([]string{ProtoReality, ProtoAmneziaWG, ProtoHysteria2}, "1.2.3.4", "", "https://ghproxy.net/", "https://mirror.ghproxy.com/")
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(s)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n rejected the generated install script: %v\n%s", err, out)
	}
}
