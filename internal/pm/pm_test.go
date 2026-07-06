package pm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recRunner records every (name, args) invocation and returns canned output/err.
type recRunner struct {
	calls [][]string
	out   string
	err   error
}

func (r *recRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.out, r.err
}

func (r *recRunner) last() []string {
	if len(r.calls) == 0 {
		return nil
	}
	return r.calls[len(r.calls)-1]
}

func TestValidPkgName(t *testing.T) {
	for _, s := range []string{"sing-box-go", "dnscrypt-proxy2", "xray-core", "mihomo", "a", "lib.so+1"} {
		if !ValidPkgName(s) {
			t.Errorf("ValidPkgName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "foo bar", "foo;rm", "../x", "-rf", "Foo", "a/b", "$(x)", "a&&b", strings.Repeat("a", 100)} {
		if ValidPkgName(s) {
			t.Errorf("ValidPkgName(%q) = true, want false", s)
		}
	}
}

func TestDetect(t *testing.T) {
	has := func(names ...string) func(string) (string, error) {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return func(n string) (string, error) {
			if set[n] {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		}
	}
	if got := detect(has("apk", "opkg")).Kind; got != Apk {
		t.Errorf("apk+opkg -> %q, want apk (apk wins)", got)
	}
	if got := detect(has("opkg")).Kind; got != Opkg {
		t.Errorf("opkg only -> %q, want opkg", got)
	}
	if got := detect(has()).Kind; got != None {
		t.Errorf("none -> %q, want None", got)
	}
	if detect(has()).Available() {
		t.Error("None must not be Available()")
	}
}

func TestMutationArgv_NoShell(t *testing.T) {
	cases := []struct {
		kind Kind
		op   string
		want []string
	}{
		{Opkg, "install", []string{"opkg", "install", "sing-box-go"}},
		{Apk, "install", []string{"apk", "add", "sing-box-go"}},
		{Opkg, "remove", []string{"opkg", "remove", "sing-box-go"}},
		{Apk, "remove", []string{"apk", "del", "sing-box-go"}},
		{Opkg, "upgrade", []string{"opkg", "install", "sing-box-go"}}, // upgrade == install for opkg
	}
	for _, c := range cases {
		r := &recRunner{}
		m := Manager{Kind: c.kind, Runner: r}
		var err error
		switch c.op {
		case "install":
			_, err = m.Install(context.Background(), "sing-box-go")
		case "remove":
			_, err = m.Remove(context.Background(), "sing-box-go")
		case "upgrade":
			_, err = m.Upgrade(context.Background(), "sing-box-go")
		}
		if err != nil {
			t.Fatalf("%s/%s: %v", c.kind, c.op, err)
		}
		got := r.last()
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Fatalf("%s/%s argv = %v, want %v", c.kind, c.op, got, c.want)
		}
		if got[0] == "sh" || got[0] == "/bin/sh" || got[0] == "bash" {
			t.Errorf("%s/%s went through a shell: %v", c.kind, c.op, got)
		}
		for _, a := range got {
			if strings.ContainsAny(a, " ;&|$`") {
				t.Errorf("%s/%s arg has a shell metachar: %q", c.kind, c.op, a)
			}
		}
	}
}

func TestMutation_RejectsBadName(t *testing.T) {
	r := &recRunner{}
	m := Manager{Kind: Opkg, Runner: r}
	if _, err := m.Install(context.Background(), "foo; rm -rf /"); err == nil {
		t.Error("Install must reject an unsafe package name")
	}
	if _, err := m.Remove(context.Background(), "../etc"); err == nil {
		t.Error("Remove must reject an unsafe package name")
	}
	if len(r.calls) != 0 {
		t.Errorf("a rejected name still reached the runner: %v", r.calls)
	}
}

func TestMutation_NoPMErrors(t *testing.T) {
	m := Manager{Kind: None, Runner: &recRunner{}}
	if _, err := m.Install(context.Background(), "sing-box-go"); err == nil {
		t.Error("Install with no PM must error")
	}
}

func TestInstalled(t *testing.T) {
	opkg := Manager{Kind: Opkg, Runner: &recRunner{out: "Package: sing-box-go\nVersion: 1.12.22-r1\nStatus: install ok installed\n"}}
	if v, ok := opkg.Installed(context.Background(), "sing-box-go"); !ok || v != "1.12.22" {
		t.Errorf("opkg Installed = %q,%v want 1.12.22,true", v, ok)
	}
	apk := Manager{Kind: Apk, Runner: &recRunner{out: "sing-box-1.11.15-r0 aarch64 {sing-box} (Apache-2.0) [installed]\n"}}
	if v, ok := apk.Installed(context.Background(), "sing-box"); !ok || v != "1.11.15" {
		t.Errorf("apk Installed = %q,%v want 1.11.15,true", v, ok)
	}
	miss := Manager{Kind: Opkg, Runner: &recRunner{out: "", err: errors.New("not installed")}}
	if _, ok := miss.Installed(context.Background(), "nope"); ok {
		t.Error("absent package must report present=false")
	}
}

func TestFiles(t *testing.T) {
	m := Manager{Kind: Opkg, Runner: &recRunner{out: "/opt/bin/sing-box\n/opt/etc/init.d/S99sing-box\n"}}
	files, err := m.Files(context.Background(), "sing-box-go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "/opt/bin/sing-box" {
		t.Errorf("Files = %v, want [/opt/bin/sing-box ...]", files)
	}
}

func TestOwner(t *testing.T) {
	opkg := Manager{Kind: Opkg, Runner: &recRunner{out: "sing-box-go - 1.12.22-r1\n"}}
	if pkg, ok, err := opkg.Owner(context.Background(), "/opt/bin/sing-box"); !ok || pkg != "sing-box-go" || err != nil {
		t.Errorf("opkg Owner = %q,%v,%v want sing-box-go,true,nil", pkg, ok, err)
	}
	if _, ok, err := (Manager{Kind: Opkg, Runner: &recRunner{out: ""}}).Owner(context.Background(), "/usr/bin/sing-box"); ok || err != nil {
		t.Errorf("empty opkg search must be clean not-owned, got ok=%v err=%v", ok, err)
	}
	apk := Manager{Kind: Apk, Runner: &recRunner{out: "/usr/bin/sing-box is owned by sing-box-1.11.15-r0\n"}}
	if pkg, ok, err := apk.Owner(context.Background(), "/usr/bin/sing-box"); !ok || pkg != "sing-box-1.11.15-r0" || err != nil {
		t.Errorf("apk Owner = %q,%v,%v want sing-box-1.11.15-r0,true,nil", pkg, ok, err)
	}
	if _, ok, err := (Manager{Kind: None}).Owner(context.Background(), "/x"); ok || err != nil {
		t.Error("None must be clean not-owned")
	}
}

// TestOwner_ThreeState: apk's non-zero "Could not find owner package" is a DEFINITIVE not-owned
// (nil err); any other failure (db lock, timeout) must surface as err so mutating callers fail
// CLOSED instead of treating a busy PM as "not owned" (which would disable the clobber guard).
func TestOwner_ThreeState(t *testing.T) {
	notOwned := Manager{Kind: Apk, Runner: &recRunner{
		out: "ERROR: /usr/sbin/wayhop: Could not find owner package\n", err: errors.New("exit status 1")}}
	if _, ok, err := notOwned.Owner(context.Background(), "/usr/sbin/wayhop"); ok || err != nil {
		t.Errorf("apk 'Could not find owner' must be clean not-owned, got ok=%v err=%v", ok, err)
	}
	locked := Manager{Kind: Apk, Runner: &recRunner{
		out: "ERROR: Unable to lock database\n", err: errors.New("exit status 99")}}
	if _, _, err := locked.Owner(context.Background(), "/usr/bin/sing-box"); err == nil {
		t.Error("apk db-lock failure must return err (fail-closed), not a silent not-owned")
	}
	opkgLocked := Manager{Kind: Opkg, Runner: &recRunner{
		out: "Could not lock /opt/tmp/opkg.lock\n", err: errors.New("exit status 255")}}
	if _, _, err := opkgLocked.Owner(context.Background(), "/opt/bin/sing-box"); err == nil {
		t.Error("opkg lock failure must return err (fail-closed)")
	}
}

// TestOwner_RealEntwareGoldens pins the opkg parse against VERBATIM output captured from the live
// Keenetic Hopper SE (Entware opkg 2024-10-16, 2026-07-01) — the opkg branch was previously only
// exercised by hand-authored mock strings (a review finding). Covers: owned (sing-box-go), clean
// not-owned (EMPTY output, rc=0 — unlike apk, which errors), and a version containing '~'.
func TestOwner_RealEntwareGoldens(t *testing.T) {
	owned := Manager{Kind: Opkg, Runner: &recRunner{out: "sing-box-go - 1.13.3-2\n"}}
	if pkg, ok, err := owned.Owner(context.Background(), "/opt/bin/sing-box"); !ok || pkg != "sing-box-go" || err != nil {
		t.Errorf("real 'opkg search /opt/bin/sing-box' output: got %q,%v,%v want sing-box-go,true,nil", pkg, ok, err)
	}
	notOwned := Manager{Kind: Opkg, Runner: &recRunner{out: ""}} // real: empty stdout, exit 0
	if _, ok, err := notOwned.Owner(context.Background(), "/opt/sbin/wakeroute"); ok || err != nil {
		t.Errorf("real not-owned (empty, rc=0) must be clean not-owned: ok=%v err=%v", ok, err)
	}
	tilde := Manager{Kind: Opkg, Runner: &recRunner{out: "opkg - 2024.10.16~38eccbb1-1\n"}}
	if pkg, ok, err := tilde.Owner(context.Background(), "/opt/bin/opkg"); !ok || pkg != "opkg" || err != nil {
		t.Errorf("tilde-versioned real output: got %q,%v,%v want opkg,true,nil", pkg, ok, err)
	}
}

// TestFiles_RealEntwareHeader: real `opkg files` output begins with a prose header line
// ("Package sing-box-go (1.13.3-2) is installed on root and has the following files:") — the
// parser must keep only the / paths. Verbatim from the live Keenetic.
func TestFiles_RealEntwareHeader(t *testing.T) {
	m := Manager{Kind: Opkg, Runner: &recRunner{out: "Package sing-box-go (1.13.3-2) is installed on root and has the following files:\n/opt/etc/sing-box/config.json\n/opt/etc/init.d/S99sing-box\n/opt/bin/sing-box\n"}}
	files, err := m.Files(context.Background(), "sing-box-go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 || files[2] != "/opt/bin/sing-box" {
		t.Errorf("Files = %v, want 3 paths ending with /opt/bin/sing-box (header dropped)", files)
	}
}

// TestInstalled_RealEntwareStatus: verbatim `opkg status sing-box-go` head from the live Keenetic —
// multi-field block, Version with a plain numeric rev ("-2", not "-rN").
func TestInstalled_RealEntwareStatus(t *testing.T) {
	m := Manager{Kind: Opkg, Runner: &recRunner{out: "Package: sing-box-go\nVersion: 1.13.3-2\nDepends: libatomic, libc, libgcc, libpthread, librt\nProvides: sing-box-go-any, sing-box\nStatus: install user installed\nArchitecture: aarch64-3.10\n"}}
	if v, ok := m.Installed(context.Background(), "sing-box-go"); !ok || v != "1.13.3" {
		t.Errorf("Installed = %q,%v want 1.13.3,true (rev '-2' stripped)", v, ok)
	}
}

func TestParseVersion_StripsRev(t *testing.T) {
	if got := parseOpkgVersion("Version: 1.12.22-r1\n"); got != "1.12.22" {
		t.Errorf("parseOpkgVersion = %q, want 1.12.22", got)
	}
	if got := parseApkVersion("sing-box-1.19.27-1 aarch64\n", "sing-box"); got != "1.19.27" {
		t.Errorf("parseApkVersion = %q, want 1.19.27", got)
	}
}
