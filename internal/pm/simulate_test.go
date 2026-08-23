package pm

import (
	"context"
	"strings"
	"testing"
)

// Verbatim `apk del --simulate sing-box` from the AX3000T. The second line is the whole point: the
// plan the operator reads says `apk del sing-box` and a kernel module goes with it.
const apkDelSim = "(1/2) Purging sing-box (1.12.17-r1)\n(2/2) Purging kmod-inet-diag (6.12.74-r1)\nOK: 25.6 MiB in 186 packages\n"

// Verbatim `opkg remove --noaction sing-box-go` from the Keenetic.
const opkgRemoveSim = "Removing package sing-box-go from root...\nNot deleting modified conffile /opt/etc/sing-box/config.json.\n"

func TestSimulate_ApkInsertsTheFlagAfterTheVerb(t *testing.T) {
	f := &fakeRunner{out: apkDelSim}
	m := Manager{Kind: Apk, Runner: f}
	out, err := m.Simulate(context.Background(), []string{"apk", "del", "sing-box"})
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if !strings.Contains(out, "kmod-inet-diag") {
		t.Fatalf("out = %q", out)
	}
	if want := []string{"apk", "del", "--simulate", "sing-box"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

func TestSimulate_OpkgUsesItsOwnFlag(t *testing.T) {
	f := &fakeRunner{out: opkgRemoveSim}
	m := Manager{Kind: Opkg, Runner: f}
	if _, err := m.Simulate(context.Background(), []string{"opkg", "remove", "sing-box-go"}); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if want := []string{"opkg", "remove", "--noaction", "sing-box-go"}; !equal(f.argv, want) {
		t.Fatalf("argv = %v, want %v", f.argv, want)
	}
}

// A dry-run flag bolted onto an arbitrary command is not a simulation, it is running that command.
func TestSimulate_RefusesArgvItDidNotBuild(t *testing.T) {
	for _, argv := range [][]string{
		{"rm", "-rf", "/"},
		{"apk", "info", "sing-box"}, // a read, not an operation that changes anything
		{"apk"},                     // nothing to simulate
	} {
		f := &fakeRunner{out: "should not run"}
		m := Manager{Kind: Apk, Runner: f}
		if _, err := m.Simulate(context.Background(), argv); err == nil {
			t.Fatalf("accepted %v", argv)
		}
		if f.argv != nil {
			t.Fatalf("%v reached the runner as %v", argv, f.argv)
		}
	}
}

// The collateral is what the preview was missing. The package asked about is not collateral — listing
// it would bury the surprise among the expected.
func TestCollateralPackages_ApkNamesWhatElseGoes(t *testing.T) {
	got := CollateralPackages(Apk, apkDelSim, "sing-box")
	if len(got) != 1 || got[0] != "kmod-inet-diag" {
		t.Fatalf("collateral = %v, want [kmod-inet-diag]", got)
	}
}

func TestCollateralPackages_OpkgSeesNoneHere(t *testing.T) {
	got := CollateralPackages(Opkg, opkgRemoveSim, "sing-box-go")
	if len(got) != 0 {
		t.Fatalf("collateral = %v, want none — the only package named is the one asked about", got)
	}
}

// An install that takes nothing with it must report nothing, or every plan would grow a warning and
// the real ones would stop standing out.
func TestCollateralPackages_NothingToReport(t *testing.T) {
	if got := CollateralPackages(Apk, "OK: 64.4 MiB in 188 packages\n", "sing-box"); len(got) != 0 {
		t.Fatalf("collateral = %v, want none", got)
	}
}
