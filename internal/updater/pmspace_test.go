package updater

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The AX3000T figures, which is the point of using them: /overlay 20.2 MiB free, the installed
// sing-box 38.7 MiB, the build the feed offers 42.4 MiB. No arrangement of those numbers lets apk
// write the new build beside the old one, and every one of them came off the live box.
const (
	axFree      = 21178368 // 20.2 MiB
	axInstalled = 40537528 // 1.12.17-r1
	axOffered   = 44466473 // 1.13.21-r1
)

// tightBox is an apk router that knows sizes and is nearly full. howFree is what its statfs reports,
// injected rather than arranged on disk.
func tightBox(t *testing.T, howFree uint64) (*Updater, Engine, *scriptRunner) {
	t.Helper()
	u, e, r, _ := apkBox(t, map[string]string{
		"apk list --available sing-box": "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n" +
			"sing-box-1.13.21-r1 aarch64 {sing-box} (GPL-3.0)\n",
		"apk list --installed sing-box": "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n",
		"apk query --format json --fields name,version,installed-size,file-size --all-matches sing-box": `[` +
			`{"name":"sing-box","version":"1.12.17-r1","installed-size":40537528,"file-size":14485215},` +
			`{"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117}]`,
		"apk del sing-box":     "(1/2) Purging sing-box (1.12.17-r1)\nOK: 37.9 MiB in 187 packages",
		"apk add sing-box":     "(1/2) Installing sing-box (1.13.21-r1)\nOK: 80.4 MiB in 189 packages",
		"apk upgrade sing-box": "(1/1) Upgrading sing-box (1.12.17-r1 -> 1.13.21-r1)",
	})
	u.availBytes = func(string) (uint64, bool) { return howFree, true }
	return u, e, r
}

// The case the panel could not do at all: the build the feed offers does not fit beside the
// installed one, but it fits in the room the installed one is holding. The plan says so, in two
// commands and in the order that makes them work.
func TestPlanPM_LowSpaceUpgradeRemovesTheInstalledBuildFirst(t *testing.T) {
	u, e, _ := tightBox(t, axFree)
	p := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if !p.Runnable() {
		t.Fatalf("blocked with room available after the removal: %s\n%+v", p.Blocked, p.Checks)
	}
	if p.Space == nil || p.Space.Strategy != PMSpaceReplace {
		t.Fatalf("space = %+v, want the replace strategy", p.Space)
	}
	if p.Space.Need != axOffered || p.Space.Reclaim != axInstalled || p.Space.TargetVersion != "1.13.21-r1" {
		t.Fatalf("the arithmetic does not come from the feed: %+v", p.Space)
	}
	want := [][]string{{"apk", "del", "sing-box"}, {"apk", "add", "sing-box"}}
	if !sameSteps(p.Steps, want) {
		t.Fatalf("steps = %v, want %v", p.Steps, want)
	}
	// Argv stays the first command so the approval protocol is unchanged, and because the effect
	// worth simulating on this path is the removal.
	if !sameArgv(p.Argv, want[0]) {
		t.Fatalf("argv = %v, want the first command", p.Argv)
	}
	// This plan takes the core binary off the disk. The handler stop-and-acknowledge gate keys off
	// exactly this, and it used to ask whether the action was a remove, which an upgrade is not.
	if !p.DeletesInstalled() {
		t.Fatal("a plan that removes the installed build must announce that it does")
	}
}

// Room for both: one command, and no removal anywhere near it.
func TestPlanPM_UpgradeStaysOneCommandWhenItFits(t *testing.T) {
	u, e, _ := tightBox(t, 200<<20)
	p := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if !p.Runnable() || len(p.Steps) != 1 || !sameArgv(p.Steps[0], []string{"apk", "upgrade", "sing-box"}) {
		t.Fatalf("steps = %v (blocked: %q)", p.Steps, p.Blocked)
	}
	if p.Space == nil || p.Space.Strategy != PMSpaceDirect || !p.Space.Measured {
		t.Fatalf("space = %+v", p.Space)
	}
}

// Not even the two-command path fits. The refusal has to carry the arithmetic: the operator is the
// only one who can decide what to delete on a router holding their own configuration, and they can
// only decide it from figures.
func TestPlanPM_UpgradeBlocksWithTheShortfallWhenNothingFits(t *testing.T) {
	u, e, r := tightBox(t, 1<<20)
	p := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if p.Runnable() {
		t.Fatalf("planned %v on a router that cannot hold it", p.Steps)
	}
	if p.Space == nil || p.Space.Strategy != PMSpaceBlocked || p.Space.ShortfallMiB == 0 {
		t.Fatalf("space = %+v", p.Space)
	}
	for _, want := range []string{"1.13.21-r1", "42.4 MiB", "free at least"} {
		if !strings.Contains(p.Blocked, want) {
			t.Fatalf("refusal %q does not say %q", p.Blocked, want)
		}
	}
	if r.ran("del") || r.ran("add") || r.ran("upgrade") {
		t.Fatal("planning ran a command")
	}
}

// A package manager that cannot be asked for sizes, or a directory that cannot be measured, leaves
// the guard OUT of the way instead of blocking. That is the rule AvailBytes already sets for a
// failed statfs, and it is what keeps an unexpected apk from making the panel useless.
func TestPlanPM_UnmeasurableSpaceDoesNotBlockTheUpgrade(t *testing.T) {
	u, e, _ := tightBox(t, axFree)
	u.availBytes = func(string) (uint64, bool) { return 0, false }
	p := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	if !p.Runnable() || len(p.Steps) != 1 {
		t.Fatalf("an unmeasured router must plan the ordinary upgrade: %v %q", p.Steps, p.Blocked)
	}
	if p.Space == nil || p.Space.Measured || p.Space.Strategy != PMSpaceDirect {
		t.Fatalf("space = %+v, want an honest unmeasured direct plan", p.Space)
	}
}

// Both commands run, in the planned order, and the output of each reaches the caller.
func TestExecutePM_RunsEveryStepInOrder(t *testing.T) {
	u, e, r := tightBox(t, axFree)
	plan := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	out, _, err := u.ExecutePM(context.Background(), e, PlanUpgrade, "", plan)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var order []string
	for _, argv := range r.seen {
		joined := strings.Join(argv, " ")
		if len(argv) > 1 && (argv[1] == "del" || argv[1] == "add") && !strings.Contains(joined, "--simulate") {
			order = append(order, joined)
		}
	}
	if len(order) != 2 || order[0] != "apk del sing-box" || order[1] != "apk add sing-box" {
		t.Fatalf("ran %v: the removal must come first, and the install must follow it", order)
	}
	if !strings.Contains(out, "Purging sing-box") || !strings.Contains(out, "Installing sing-box") {
		t.Fatalf("output lost a step: %q", out)
	}
}

// The failure that matters on this path is the SECOND one: the installed build is already gone. A
// bare error cannot tell the handler whether the datapath can be brought back, so the step is named.
func TestExecutePM_NamesTheStepThatFailed(t *testing.T) {
	u, e, r := tightBox(t, axFree)
	plan := u.PlanPM(context.Background(), e, PlanUpgrade, "")
	r.errs["apk add sing-box"] = errors.New("network unreachable")
	_, _, err := u.ExecutePM(context.Background(), e, PlanUpgrade, "", plan)
	if err == nil {
		t.Fatal("a failed install reported success")
	}
	if !strings.Contains(err.Error(), "command 2 of 2") || !strings.Contains(err.Error(), "apk add sing-box") {
		t.Fatalf("err = %v: it must say which command failed", err)
	}
}

// An approval that named one command cannot carry two. Free space can fall away between the plan and
// the click, and an operator who approved one command did not approve a removal in front of it.
func TestPreflightPM_RefusesASingleCommandApprovalForATwoCommandPlan(t *testing.T) {
	u, e, _ := tightBox(t, axFree)
	approved := PMPlan{Argv: []string{"apk", "del", "sing-box"}} // right first command, no sequence
	_, err := u.PreflightPM(context.Background(), e, PlanUpgrade, "", approved)
	if err == nil {
		t.Fatal("ran a two-command plan on an approval that covered one")
	}
	if !strings.Contains(err.Error(), "takes 2 commands") {
		t.Fatalf("err = %v", err)
	}
}

// And a sequence that no longer matches is refused, the same way a changed single command already was.
func TestPreflightPM_RefusesAChangedSequence(t *testing.T) {
	u, e, _ := tightBox(t, axFree)
	approved := PMPlan{
		Argv:  []string{"apk", "del", "sing-box"},
		Steps: [][]string{{"apk", "del", "sing-box"}, {"apk", "add", "sing-box=1.11.4-r2"}},
	}
	_, err := u.PreflightPM(context.Background(), e, PlanUpgrade, "", approved)
	if err == nil || !strings.Contains(err.Error(), "changed since they were shown") {
		t.Fatalf("err = %v", err)
	}
}
