//go:build linux

package plugin

import (
	"os/exec"
	"syscall"
	"testing"
)

// asRoot makes runAs and runServiceAs see a root daemon for the test.
func asRoot(t *testing.T, root bool) {
	t.Helper()
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int {
		if root {
			return 0
		}
		return 1000
	}
}

// A uid-confined child keeps none of the daemon's supplementary groups. With NoSetGroups it kept
// them all: a daemon restarted from a root SSH shell has group 0, and so had ciadpi and the bridge.
func TestRunAsDropsSupplementaryGroups(t *testing.T) {
	asRoot(t, true)
	for name, start := range map[string]func(*exec.Cmd, int){"runAs": runAs, "runServiceAs": runServiceAs} {
		cmd := exec.Command("true")
		start(cmd, 65531)
		if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
			t.Fatalf("%s: no credential for a root daemon", name)
		}
		c := cmd.SysProcAttr.Credential
		if c.Uid != 65531 || c.Gid != 65531 {
			t.Fatalf("%s: uid/gid %d/%d", name, c.Uid, c.Gid)
		}
		if c.NoSetGroups || len(c.Groups) != 0 {
			t.Fatalf("%s: supplementary groups kept (NoSetGroups %v, Groups %v)", name, c.NoSetGroups, c.Groups)
		}
	}
}

// A service dies with the daemon (Pdeathsig), root or not; only a root daemon changes its uid.
// Connection plugins (runAs) are not services and get no Pdeathsig.
func TestRunServiceAsDiesWithTheDaemon(t *testing.T) {
	for _, root := range []bool{true, false} {
		asRoot(t, root)
		cmd := exec.Command("true")
		runServiceAs(cmd, 65531)
		if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
			t.Fatalf("root=%v: Pdeathsig not SIGKILL: %+v", root, cmd.SysProcAttr)
		}
		if got := cmd.SysProcAttr.Credential != nil; got != root {
			t.Fatalf("root=%v: credential set = %v", root, got)
		}
	}
	asRoot(t, true)
	cmd := exec.Command("true")
	runAs(cmd, 65530)
	if cmd.SysProcAttr.Pdeathsig != 0 {
		t.Fatal("runAs set Pdeathsig for a connection plugin")
	}
}
