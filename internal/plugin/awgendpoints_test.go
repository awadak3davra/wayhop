package plugin

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The connections on amneziawg-go now, by id: running procs of that binary only, not one that died, one
// stopped, or another engine's. The procs here stand in with this test's own process, so nothing is
// started and nothing may be stopped.
func TestUserspaceAWGEndpoints(t *testing.T) {
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(bin string, running, died bool) *proc {
		p := &proc{binName: bin, running: running, cmd: &exec.Cmd{Process: self}, done: make(chan struct{})}
		if died {
			close(p.done)
		}
		return p
	}
	m := New(t.TempDir(), t.TempDir())
	m.procs = map[string]*proc{
		"b": mk("amneziawg-go", true, false), "a": mk("amneziawg-go", true, false),
		"olc": mk("olcrtc", true, false), "stopped": mk("amneziawg-go", false, false),
		"dead": mk("amneziawg-go", true, true), "kernel": {running: true},
	}
	if got := strings.Join(m.UserspaceAWGEndpoints(), ","); got != "a,b" {
		t.Errorf("endpoints %q", got)
	}
}
