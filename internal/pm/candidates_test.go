package pm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner records the argv it was handed and replays canned output. Recording the argv is half
// the point: a package manager call is a mutation of the box, so "what exactly would run" is the
// thing under test, not just what came back.
type fakeRunner struct {
	out  string
	err  error
	argv []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.argv = append([]string{name}, args...)
	return f.out, f.err
}

// Verbatim `apk list sing-box` output from an OpenWrt 24.10+ feed, two builds available and one of
// them on disk. Written out in full rather than trimmed, because the parser's whole job is to
// survive the columns after the version.
const apkListOut = `sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later) [installed]
sing-box-1.11.4-r2 aarch64 {sing-box} (GPL-3.0-or-later)
sing-box-doc-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later)
`

func TestCandidates_Apk_ParsesVersionsNewestFirst(t *testing.T) {
	f := &fakeRunner{out: apkListOut}
	m := Manager{Kind: Apk, Runner: f}
	got, err := m.Candidates(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 candidates, got %d: %+v", len(got), got)
	}
	if got[0].Version != "1.12.17-r1" || got[1].Version != "1.11.4-r2" {
		t.Fatalf("wrong order/versions: %+v", got)
	}
	if !got[0].Installed || got[1].Installed {
		t.Fatalf("installed flag wrong: %+v", got)
	}
	if got[0].Available || !got[1].Available {
		t.Fatalf("repository availability wrong: %+v", got)
	}
	// sing-box-doc must NOT be folded into sing-box: the prefix is "<pkg>-", and "sing-box-doc-…"
	// starts with it. If this ever regresses the picker offers a docs package as a rollback target.
	for _, c := range got {
		if strings.HasPrefix(c.Version, "doc") {
			t.Fatalf("a different package leaked into the candidate list: %+v", got)
		}
	}
	if want := []string{"apk", "list", "sing-box"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

func TestApkCandidates_InstalledDatabaseRowIsNotAnAvailableBuild(t *testing.T) {
	got := apkCandidates("sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", "sing-box")
	if len(got) != 1 || !got[0].Installed || got[0].Available {
		t.Fatalf("installed-only row = %+v", got)
	}
}

func TestCandidates_Opkg_ParsesItsOwnFormat(t *testing.T) {
	f := &fakeRunner{out: "sing-box - 1.12.17-1 - A universal proxy platform\nsing-box-doc - 1.12.17-1 - docs\n"}
	m := Manager{Kind: Opkg, Runner: f}
	got, err := m.Candidates(context.Background(), "sing-box")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 1 || got[0].Version != "1.12.17-1" {
		t.Fatalf("want the one sing-box build, got %+v", got)
	}
	if want := []string{"opkg", "list", "sing-box"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

// Numeric ordering, not lexical. "1.9.4" > "1.12.17" as strings, and a picker sorted that way offers
// the wrong build at the top of the list.
func TestCandidates_OrdersNumerically(t *testing.T) {
	f := &fakeRunner{out: "x-1.9.4-r1 aarch64\nx-1.12.17-r1 aarch64\nx-1.10.0-r1 aarch64\n"}
	m := Manager{Kind: Apk, Runner: f}
	got, err := m.Candidates(context.Background(), "x")
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	want := []string{"1.12.17-r1", "1.10.0-r1", "1.9.4-r1"}
	for i := range want {
		if got[i].Version != want[i] {
			t.Fatalf("order = %+v, want %v", got, want)
		}
	}
}

func TestInstallVersion_Apk_PinsExactBuild(t *testing.T) {
	f := &fakeRunner{out: "OK"}
	m := Manager{Kind: Apk, Runner: f}
	if _, err := m.InstallVersion(context.Background(), "sing-box", "1.11.4-r2"); err != nil {
		t.Fatalf("InstallVersion: %v", err)
	}
	if want := []string{"apk", "add", "sing-box=1.11.4-r2"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

// opkg must SAY it cannot pin rather than install whatever the feed currently holds. A caller that
// offered "roll back to 1.11.4" and silently installed 1.12.17 would be worse than one that refuses.
func TestInstallVersion_Opkg_RefusesRatherThanInstallTheWrongBuild(t *testing.T) {
	f := &fakeRunner{out: "OK"}
	m := Manager{Kind: Opkg, Runner: f}
	_, err := m.InstallVersion(context.Background(), "sing-box", "1.11.4-1")
	if !errors.Is(err, ErrNoVersionPin) {
		t.Fatalf("err = %v, want ErrNoVersionPin", err)
	}
	if f.argv != nil {
		t.Fatalf("opkg must not run anything when it cannot honour the request; ran %v", f.argv)
	}
}

// Everything reaching exec is argv, so the guards are about what can become a token — not about
// quoting. Each of these must be refused BEFORE the runner is touched.
func TestInstallVersion_RefusesUnsafeTokens(t *testing.T) {
	bad := []struct{ pkg, ver, why string }{
		{"sing-box", "1.0; reboot", "a shell metacharacter in the version"},
		{"sing-box", "--force-overwrite", "an option pretending to be a version"},
		{"sing box", "1.0", "a space in the package name"},
		{"sing-box", "", "an empty version"},
		{"sing-box", "../../etc/passwd", "a path in the version"},
		{"-rf", "1.0", "an option pretending to be a package"},
	}
	for _, c := range bad {
		f := &fakeRunner{out: "OK"}
		m := Manager{Kind: Apk, Runner: f}
		if _, err := m.InstallVersion(context.Background(), c.pkg, c.ver); err == nil {
			t.Fatalf("%s was accepted (%s)", c.why, c.pkg+"="+c.ver)
		}
		if f.argv != nil {
			t.Fatalf("%s reached the runner as %v", c.why, f.argv)
		}
	}
}

// apk prints ONE version on TWO lines. Verbatim from the AX3000T:
//
//	sing-box-1.12.17-r1 aarch64_cortex-a53 {feeds/…/net/sing-box} (GPL-3.0-or-later) [installed]
//	sing-box-1.12.17-r1 aarch64_cortex-a53 {feeds/…/net/sing-box} (GPL-3.0-or-later)
//
// Deduplicating by keeping the FIRST line threw the tag away whenever the untagged line came first,
// and nothing in apk guarantees that order — the rollback picker filters on exactly this flag, so the
// build already running would be offered as something to roll back TO. Both orders, because a parser
// that only survives the order the device happened to print today is not a parser.
func TestApkCandidates_TheInstalledTagSurvivesTheDuplicateLine(t *testing.T) {
	const line = "sing-box-1.12.17-r1 aarch64_cortex-a53 {feeds/packages/net/sing-box} (GPL-3.0-or-later)"
	for _, tc := range []struct {
		why string
		out string
	}{
		{"tagged line first, as the device printed it", line + " [installed]\n" + line + "\n"},
		{"tagged line second", line + "\n" + line + " [installed]\n"},
	} {
		got := apkCandidates(tc.out, "sing-box")
		if len(got) != 1 {
			t.Fatalf("%s: %d candidates for one version: %+v", tc.why, len(got), got)
		}
		if !got[0].Installed {
			t.Errorf("%s: the build already installed is not marked as such, so the picker would offer it as a rollback target", tc.why)
		}
	}
}

func TestCandidates_NoPackageManager_SaysSo(t *testing.T) {
	m := Manager{Kind: None, Runner: &fakeRunner{}}
	if _, err := m.Candidates(context.Background(), "sing-box"); err == nil {
		t.Fatal("want an error with no PM detected")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
