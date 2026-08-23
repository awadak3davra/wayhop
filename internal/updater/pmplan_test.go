package updater

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wayhop/internal/pm"
)

// scriptRunner answers each package-manager call by its argv, so one test can set up a whole
// consistent box: who owns the binary, what files the package holds, what the feed offers. A call it
// has no answer for returns an error rather than an empty string, because "the PM said nothing" and
// "the PM said no" are the two states this planner is required to tell apart.
type scriptRunner struct {
	answers map[string]string
	errs    map[string]error
	seen    [][]string
}

func (s *scriptRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	s.seen = append(s.seen, append([]string{name}, args...))
	if e, ok := s.errs[key]; ok {
		return "", e
	}
	if out, ok := s.answers[key]; ok {
		return out, nil
	}
	if strings.Contains(key, " --simulate ") || strings.Contains(key, " --noaction ") {
		return "OK", nil
	}
	return "", errors.New("scriptRunner: no answer for " + key)
}

// ran reports whether a MUTATING run happened. The dry-run forms — `apk add --simulate`,
// `opkg install --noaction` — carry the same verb and change nothing, so matching on the verb alone
// counted the planner's own preview as an execution and failed three tests that were right. Matching
// on the verb AND the absence of a dry-run flag keeps the assertion sharp: a real execution in a path
// that should only plan still fails it.
func (s *scriptRunner) ran(verb string) bool {
	for _, argv := range s.seen {
		if len(argv) < 2 || argv[1] != verb {
			continue
		}
		dry := false
		for _, a := range argv[2:] {
			if a == "--simulate" || a == "-s" || a == "--noaction" {
				dry = true
			}
		}
		if !dry {
			return true
		}
	}
	return false
}

// binDir is where a router keeps engine binaries. Nothing is created on disk: every check here is
// about what the package manager SAYS about a path, not about the file.
//
// The ownership key is built from the path the planner itself resolves rather than written out by
// hand. The first version of this harness hard-coded "/usr/bin/sing-box" and every test failed
// against a correct planner, because filepath.Join on the Windows dev host yields
// `\usr\bin\sing-box` — the harness was describing a path shape the code never produces here.
const binDir = "/usr/bin"

func newBox(t *testing.T, kind pm.Kind, answers map[string]string) (*Updater, Engine, *scriptRunner, string) {
	t.Helper()
	e := Engine{ID: "sing-box", Name: "sing-box", BinName: "sing-box", Role: "core"}
	u := &Updater{BinDir: binDir}
	r := &scriptRunner{answers: map[string]string{}, errs: map[string]error{}}
	u.WithPM(pm.Manager{Kind: kind, Runner: r})
	path, _ := u.enginePath(e)
	for k, v := range answers {
		r.answers[strings.ReplaceAll(k, "<bin>", path)] = v
	}
	return u, e, r, path
}

// apkBox: the engine binary is owned by apk and the package lists that exact file — the state in
// which delegation is legitimate. The who-owns answer is the real format, read off the OpenWrt
// 25.12.2 test box: name and version glued together.
func apkBox(t *testing.T, extra map[string]string) (*Updater, Engine, *scriptRunner, string) {
	t.Helper()
	answers := map[string]string{
		"apk info --who-owns <bin>": "<bin> is owned by sing-box-1.12.17-r1",
		"apk info -L sing-box":      "sing-box-1.12.17-r1 contains:\nusr/bin/sing-box\n",
		"apk list sing-box": "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n" +
			"sing-box-1.11.4-r2 aarch64 {sing-box} (GPL-3.0)\n",
	}
	for k, v := range extra {
		answers[k] = v
	}
	return newBox(t, pm.Apk, answers)
}

func TestPlanPM_Rollback_BuildsTheExactPinnedCommand(t *testing.T) {
	u, e, _, _ := apkBox(t, nil)
	p := u.PlanPM(context.Background(), e, PlanRollback, "1.11.4-r2")
	if !p.Runnable() {
		t.Fatalf("blocked: %s\nchecks: %+v", p.Blocked, p.Checks)
	}
	want := []string{"apk", "add", "sing-box=1.11.4-r2"}
	if !sameArgv(p.Argv, want) {
		t.Fatalf("argv = %v, want %v", p.Argv, want)
	}
	// The package name must be the BARE name. apk reports the owner as "sing-box-1.12.17-r1", and
	// feeding that straight to `apk add` would name a package that does not exist.
	if p.Package != "sing-box" {
		t.Fatalf("package = %q, want the bare name", p.Package)
	}
	if p.Version != "1.11.4-r2" {
		t.Fatalf("version = %q", p.Version)
	}
}

// The version the operator picked has to exist in the feed. Without this the command is built, run,
// and fails at the package manager with a message nobody planned for.
func TestPlanPM_Rollback_RefusesAVersionTheFeedDoesNotHave(t *testing.T) {
	u, e, r, _ := apkBox(t, nil)
	p := u.PlanPM(context.Background(), e, PlanRollback, "9.9.9-r1")
	if p.Runnable() {
		t.Fatalf("a version absent from the feed was accepted: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "not offered by this feed") {
		t.Fatalf("blocked reason = %q", p.Blocked)
	}
	if r.ran("add") {
		t.Fatalf("planning must not run anything; it ran %v", r.seen)
	}
}

func TestPlanPM_Rollback_RefusesAnInstalledOnlyApkRow(t *testing.T) {
	u, e, r, _ := apkBox(t, map[string]string{
		"apk list sing-box": "sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n",
	})
	p := u.PlanPM(context.Background(), e, PlanRollback, "1.12.17-r1")
	if p.Runnable() {
		t.Fatalf("an installed-database row was treated as an available rollback: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "not offered by this feed") {
		t.Fatalf("blocked reason = %q", p.Blocked)
	}
	if r.ran("add") {
		t.Fatalf("installed-only rollback reached apk: %v", r.seen)
	}
}

// opkg has no version pin. Saying so is the whole point: installing "whatever the feed has" in
// answer to "roll back to 1.11.4" would be a different build than the one asked for.
func TestPlanPM_Rollback_OpkgSaysItCannotPin(t *testing.T) {
	u, e, r, _ := newBox(t, pm.Opkg, map[string]string{
		"opkg search <bin>": "sing-box - 1.12.17-1",
		"opkg files sing-box": "Package sing-box (1.12.17-1) is installed on root and has the following files:\n" +
			"/usr/bin/sing-box\n",
	})
	p := u.PlanPM(context.Background(), e, PlanRollback, "1.11.4-1")
	if p.Runnable() {
		t.Fatalf("opkg accepted a pinned rollback: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "cannot install a named version") {
		t.Fatalf("blocked reason = %q\nchecks: %+v", p.Blocked, p.Checks)
	}
	if r.ran("install") {
		t.Fatal("opkg must not install anything when it cannot honour the version")
	}
}

// The check internal/pm's own header asked for and nothing performed. Ownership of a path and the
// package's file list can disagree — after a manual copy over a packaged binary, for instance — and
// acting on the package would then not act on the binary in use.
func TestPlanPM_RefusesWhenThePackageDoesNotListTheRunningBinary(t *testing.T) {
	u, e, r, _ := apkBox(t, map[string]string{
		"apk info -L sing-box": "sing-box-1.12.17-r1 contains:\nopt/sbin/sing-box\n",
	})
	p := u.PlanPM(context.Background(), e, PlanRemove, "")
	if p.Runnable() {
		t.Fatalf("removed a package that does not own the running binary: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "among its files") {
		t.Fatalf("blocked reason = %q", p.Blocked)
	}
	if r.ran("del") {
		t.Fatal("nothing may run from a blocked plan")
	}
}

// Fail closed. A locked package database is the normal case on a busy router, and "could not answer"
// must never read as "not owned" on a mutating path.
func TestPlanPM_FailsClosedWhenTheDatabaseWillNotAnswer(t *testing.T) {
	u, e, r, path := apkBox(t, nil)
	r.errs["apk info --who-owns "+path] = errors.New("database locked")
	p := u.PlanPM(context.Background(), e, PlanRemove, "")
	if p.Runnable() {
		t.Fatalf("proceeded on an unanswerable ownership probe: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "did not answer") {
		t.Fatalf("blocked reason = %q", p.Blocked)
	}
}

func TestPlanPM_Remove_And_Upgrade_Argv(t *testing.T) {
	u, e, _, _ := apkBox(t, nil)
	rm := u.PlanPM(context.Background(), e, PlanRemove, "")
	if !rm.Runnable() || !sameArgv(rm.Argv, []string{"apk", "del", "sing-box"}) {
		t.Fatalf("remove plan = %+v", rm)
	}
	up := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if !up.Runnable() || !sameArgv(up.Argv, []string{"apk", "add", "sing-box"}) {
		t.Fatalf("upgrade plan = %+v", up)
	}
}

// A plan is shown to a human and then run. Between those two moments the box can change — another
// process installs something, the ownership answer moves. Executing the command the operator read
// rather than the one that is now correct is the failure this guards.
func TestExecutePM_RefusesWhenTheCommandChangedSinceItWasShown(t *testing.T) {
	u, e, r, _ := apkBox(t, nil)
	approved := PMPlan{Argv: []string{"apk", "add", "sing-box=1.11.4-r2"}}
	_, _, err := u.ExecutePM(context.Background(), e, PlanRemove, "", approved)
	if err == nil {
		t.Fatal("executed a plan whose command no longer matches what was approved")
	}
	if !strings.Contains(err.Error(), "changed since it was shown") {
		t.Fatalf("err = %v", err)
	}
	if r.ran("del") {
		t.Fatal("the mismatched command must not run")
	}
}

// And the same guard must not block the honest case, or it is just a way of never executing.
func TestExecutePM_RunsThePlanItWasShown(t *testing.T) {
	u, e, r, _ := apkBox(t, map[string]string{"apk del sing-box": "OK: removed"})
	approved := u.PlanPM(context.Background(), e, PlanRemove, "")
	if !approved.Runnable() {
		t.Fatalf("the plan under test is blocked: %s", approved.Blocked)
	}
	out, _, err := u.ExecutePM(context.Background(), e, PlanRemove, "", approved)
	if err != nil {
		t.Fatalf("ExecutePM: %v", err)
	}
	if !strings.Contains(out, "removed") {
		t.Fatalf("out = %q", out)
	}
	if !r.ran("del") {
		t.Fatalf("nothing ran; calls were %v", r.seen)
	}
}

func TestPlanPM_NoPackageManager_IsBlockedNotCrashing(t *testing.T) {
	u, e, _, _ := newBox(t, pm.None, nil)
	p := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if p.Runnable() {
		t.Fatalf("planned a command with no package manager: %v", p.Argv)
	}
	if len(p.Checks) == 0 {
		t.Fatal("a blocked plan must still say what it checked")
	}
}

// The install branch names the package from the engine ID, because with nothing on disk there is no
// owner to ask. That guess is wrong for most of this panel's engines: measured against the AX3000T's
// own feed, only sing-box and dnscrypt-proxy exist as packages — mihomo, xray, hysteria, amneziawg-go
// and olcrtc do not. A plan built on the guess reads as runnable, the operator confirms it, and apk
// fails on a package that was never there.
func TestPlanPM_Install_RefusesAPackageTheFeedDoesNotHave(t *testing.T) {
	// An engine whose binary is absent, and a feed that has never heard of it. `apk list` answers
	// empty for an unknown package rather than failing, which is exactly how the real one behaves.
	u, _, r, _ := newBox(t, pm.Apk, map[string]string{"apk list mihomo": "\n"})
	e := Engine{ID: "mihomo", Name: "Mihomo", BinName: "mihomo-not-on-this-host", Role: "standalone"}
	p := u.PlanPM(context.Background(), e, PlanInstall, "")
	if p.Runnable() {
		t.Fatalf("planned an install of a package the feed does not carry: %v", p.Argv)
	}
	if !strings.Contains(p.Blocked, "no package called") {
		t.Fatalf("blocked reason = %q\nchecks: %+v", p.Blocked, p.Checks)
	}
	if r.ran("add") {
		t.Fatalf("planning ran an install: %v", r.seen)
	}
}

// And the honest case still goes through, or the guard is only a way of never installing anything.
func TestPlanPM_Install_ProceedsWhenTheFeedHasIt(t *testing.T) {
	u, _, _, _ := newBox(t, pm.Apk, map[string]string{
		"apk list dnscrypt-proxy": "dnscrypt-proxy-2019.08.20~07ac3825-r3 aarch64 {dnscrypt-proxy} (ISC)\n",
	})
	e := Engine{ID: "dnscrypt-proxy", Name: "dnscrypt-proxy", BinName: "dnscrypt-proxy-not-on-this-host"}
	p := u.PlanPM(context.Background(), e, PlanInstall, "")
	if !p.Runnable() {
		t.Fatalf("blocked: %s\nchecks: %+v", p.Blocked, p.Checks)
	}
	if !sameArgv(p.Argv, []string{"apk", "add", "dnscrypt-proxy"}) {
		t.Fatalf("argv = %v", p.Argv)
	}
}

// The Keenetic's real answers. `sing-box-go` declares `Provides: sing-box`, so `opkg list sing-box`
// is empty while the name resolves and `opkg install sing-box` works — measured with
// `opkg install --noaction`, which reported the providing package as already installed. Refusing on
// the empty list was a regression introduced by taking apk's behaviour, where an empty list really
// does mean absent, and applying it to both managers.
func TestPlanPM_Install_Opkg_ResolvesAVirtualName(t *testing.T) {
	u, _, _, _ := newBox(t, pm.Opkg, map[string]string{
		"opkg list sing-box":         "",
		"opkg whatprovides sing-box": "What provides sing-box\n    sing-box-go\n",
	})
	e := Engine{ID: "sing-box", Name: "sing-box", BinName: "sing-box-not-on-this-host"}
	p := u.PlanPM(context.Background(), e, PlanInstall, "")
	if !p.Runnable() {
		t.Fatalf("refused an install opkg can perform: %s\nchecks: %+v", p.Blocked, p.Checks)
	}
	if !sameArgv(p.Argv, []string{"opkg", "install", "sing-box-go"}) {
		t.Fatalf("argv = %v, want the PROVIDING package", p.Argv)
	}
}

// And a name nothing provides is still refused, or the resolution would have turned the guard off.
func TestPlanPM_Install_Opkg_StillRefusesWhenNothingProvidesIt(t *testing.T) {
	u, _, r, _ := newBox(t, pm.Opkg, map[string]string{
		"opkg list zzz-nothing":         "",
		"opkg whatprovides zzz-nothing": "What provides zzz-nothing\n",
	})
	e := Engine{ID: "zzz-nothing", Name: "nothing", BinName: "zzz-not-on-this-host"}
	p := u.PlanPM(context.Background(), e, PlanInstall, "")
	if p.Runnable() {
		t.Fatalf("planned an install of a name nothing provides: %v", p.Argv)
	}
	if r.ran("install") {
		t.Fatalf("planning ran an install: %v", r.seen)
	}
}

// The plan must carry what the command WOULD do, not just the command. Verbatim
// `apk del --simulate sing-box` from the AX3000T: the operator reads one package and two go.
//
// Without this the earlier tests all still pass — the scripted runner has no answer for the dry run,
// Simulate fails, and the failure is deliberately non-blocking — so the whole preview path would sit
// there untested and empty, which is the shape of every hole this row has already found.
func TestPlanPM_CarriesTheSimulatedEffect(t *testing.T) {
	u, e, _, _ := apkBox(t, map[string]string{
		"apk del --simulate sing-box": "(1/2) Purging sing-box (1.12.17-r1)\n" +
			"(2/2) Purging kmod-inet-diag (6.12.74-r1)\nOK: 25.6 MiB in 186 packages\n",
	})
	p := u.PlanPM(context.Background(), e, PlanRemove, "")
	if !p.Runnable() {
		t.Fatalf("blocked: %s", p.Blocked)
	}
	if !strings.Contains(p.Effect, "kmod-inet-diag") {
		t.Fatalf("effect = %q — the preview does not say what else goes", p.Effect)
	}
	if len(p.Collateral) != 1 || p.Collateral[0] != "kmod-inet-diag" {
		t.Fatalf("collateral = %v, want [kmod-inet-diag]", p.Collateral)
	}
	// The package being acted on is not collateral; listing it would bury the surprise.
	for _, c := range p.Collateral {
		if c == "sing-box" {
			t.Fatal("the package asked about was reported as collateral")
		}
	}
}

// A failed dry run is a refusal, not an advisory note. The live AX3000 had no apk indexes; `apk`
// could still report installed packages but could not execute the proposed install. Running after
// that failed preview would turn the reviewed command into a blind mutation.
func TestPlanPM_AnUnavailablePreviewBlocks(t *testing.T) {
	u, e, runner, _ := apkBox(t, nil)
	runner.errs["apk del --simulate sing-box"] = errors.New("catalog unavailable")
	p := u.PlanPM(context.Background(), e, PlanRemove, "")
	if p.Runnable() {
		t.Fatal("a failed preview left the plan runnable")
	}
	if p.Effect != "" {
		t.Fatalf("effect = %q, want empty", p.Effect)
	}
	var said bool
	for _, c := range p.Checks {
		if c.Name == "the effect could be previewed" && !c.OK {
			said = true
		}
	}
	if !said {
		t.Fatal("the plan did not record the failed preview")
	}
	if !strings.Contains(p.Blocked, "refresh package lists") {
		t.Fatalf("blocked = %q, want refresh remedy", p.Blocked)
	}
}

// Every note this planner writes is the reason a check would FAIL, so a check that PASSED and kept
// its note states something untrue about the box. Verbatim from the live plan endpoint before this
// was fixed:
//
//	{"name":"package manager present","ok":true,
//	 "note":"no opkg or apk on this system, so there is nothing to delegate to"}
//
// The renderer coped by hiding notes on passing checks — the only defence available while they lied —
// and that is what made the one note worth reading unreachable (the test below).
func TestPlanPM_APassingCheckDoesNotCarryItsFailureText(t *testing.T) {
	u, e, _, _ := apkBox(t, nil)
	p := u.PlanPM(context.Background(), e, PlanRemove, "")
	if !p.Runnable() {
		t.Fatalf("the healthy box did not produce a runnable plan: %s", p.Blocked)
	}
	for _, c := range p.Checks {
		if c.OK && c.Note != "" {
			t.Errorf("check %q passed but carries %q — on a pass that text describes a failure that did not happen", c.Name, c.Note)
		}
	}
}

// The exception, and the reason the fix above cannot simply drop every passing note: one check passes
// AND has something the operator needs. Measured read-only on the family's Keenetic, today:
// `opkg list sing-box` is empty, `opkg whatprovides sing-box` answers `sing-box-go`, and
// /opt/bin/sing-box is owned by `sing-box-go - 1.13.3-2`. So the plan asks the operator to confirm
// `opkg install sing-box-go` for a name they never typed, and the sentence explaining the
// substitution is the plan's own. This test exists to fail if that sentence is ever swept up by a
// blanket "passing checks have no notes" rule.
func TestPlanPM_AResolvedVirtualNameSaysSoOnAPassingCheck(t *testing.T) {
	u, _, _, _ := newBox(t, pm.Opkg, map[string]string{
		"opkg list sing-box":         "",
		"opkg whatprovides sing-box": "What provides sing-box\n    sing-box-go\n",
	})
	e := Engine{ID: "sing-box", Name: "sing-box", BinName: "sing-box-not-on-this-host"}
	p := u.PlanPM(context.Background(), e, PlanInstall, "")
	if !p.Runnable() {
		t.Fatalf("refused an install opkg can perform: %s", p.Blocked)
	}
	var said string
	for _, c := range p.Checks {
		if c.OK && c.Note != "" {
			said = c.Note
		}
	}
	if !strings.Contains(said, "sing-box-go") {
		t.Fatalf("the plan renames the package to sing-box-go and no passing check says so; notes were %+v", p.Checks)
	}
}
