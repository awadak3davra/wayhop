package pm

import (
	"context"
	"strings"
	"testing"
)

// The defect this file exists for, stated as a test: on apk, `apk add <pkg>` for a package that is
// already installed keeps the installed build. Upgrade and Install are therefore NOT the same
// command, however alike they looked when Upgrade was written as an alias of Install.
func TestUpgradeArgv_IsNotInstallArgvOnApk(t *testing.T) {
	apk := Manager{Kind: Apk, Runner: &recordRunner{}}
	if got := strings.Join(apk.UpgradeArgv("sing-box"), " "); got != "apk upgrade sing-box" {
		t.Fatalf("apk upgrade argv = %q", got)
	}
	if got := strings.Join(apk.InstallArgv("sing-box"), " "); got != "apk add sing-box" {
		t.Fatalf("apk install argv = %q", got)
	}
	// opkg is the manager where they really are one command: `opkg install` replaces an installed
	// package with a newer feed build. Stated here so a future change cannot quietly assume apk's
	// shape for both.
	opkg := Manager{Kind: Opkg, Runner: &recordRunner{}}
	if got := strings.Join(opkg.UpgradeArgv("sing-box"), " "); got != "opkg install sing-box" {
		t.Fatalf("opkg upgrade argv = %q", got)
	}
}

// The command that was planned is the command that runs. Upgrade goes through the same builder the
// plan showed, so the two cannot drift again.
func TestUpgrade_RunsTheCommandItsArgvNames(t *testing.T) {
	r := &recordRunner{answers: map[string]string{"apk upgrade sing-box": "(1/1) Upgrading sing-box"}}
	m := Manager{Kind: Apk, Runner: r}
	if _, err := m.Upgrade(context.Background(), "sing-box"); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if len(r.seen) != 1 || r.seen[0] != "apk upgrade sing-box" {
		t.Fatalf("ran %v", r.seen)
	}
}

// RunPlanned is the one door to a mutating package command, so it is also the place an argv from
// anywhere else has to be stopped.
func TestRunPlanned_RefusesAnythingItDidNotBuild(t *testing.T) {
	r := &recordRunner{answers: map[string]string{}}
	m := Manager{Kind: Apk, Runner: r}
	for _, argv := range [][]string{
		{"sh", "-c", "rm -rf /"},              // not this manager's binary
		{"apk", "index", "sing-box"},          // not an operation
		{"apk", "add", "--allow-untrusted"},   // an option smuggled in as a package name
		{"apk", "add", "sing-box; reboot"},    // a shell line in the package slot
		{"apk", "add", "sing-box=; rm"},       // a bad version pin
		{"apk", "add"},                        // nothing to act on
		{"apk", "add", "sing-box", "--force"}, // an extra token the planner never emits
	} {
		if _, err := m.RunPlanned(context.Background(), argv); err == nil {
			t.Fatalf("ran %v", argv)
		}
	}
	if len(r.seen) != 0 {
		t.Fatalf("a refused argv reached the runner: %v", r.seen)
	}
	// The pinned form the rollback planner builds IS allowed, because it builds it.
	if _, err := m.RunPlanned(context.Background(), []string{"apk", "add", "sing-box=1.11.4-r2"}); err != nil {
		t.Fatalf("refused its own rollback command: %v", err)
	}
}
