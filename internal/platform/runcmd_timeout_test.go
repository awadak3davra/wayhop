package platform

import (
	"os"
	"testing"
	"time"
)

// TestHelperSleep is not a real test — it is a helper subprocess (re-exec of this test binary) that
// sleeps when passed the sentinel arg, giving TestRunCmdTimeout a portable, direct-child slow command
// with no shell/grandchild pipe quirks. A normal `go test` run never passes the sentinel, so it
// returns immediately.
func TestHelperSleep(t *testing.T) {
	for _, a := range os.Args {
		if a == "--platform-helper-sleep" {
			time.Sleep(3 * time.Second)
			os.Exit(0)
		}
	}
}

// TestRunCmdTimeout_KillsSlowCommand: runCmd must enforce a hard deadline so a wedged tool (a blocked
// ndmc on Keenetic) can't hang the caller or leak a child. A 3s helper run with a 300ms timeout must
// be killed — returning "" well before its natural duration.
func TestRunCmdTimeout_KillsSlowCommand(t *testing.T) {
	start := time.Now()
	out := runCmdTimeout(300*time.Millisecond, os.Args[0], "-test.run=^TestHelperSleep$", "--", "--platform-helper-sleep")
	elapsed := time.Since(start)
	if out != "" {
		t.Errorf("expected empty output when the command is killed by the deadline, got %q", out)
	}
	if elapsed > 2*time.Second {
		t.Errorf("runCmdTimeout did not enforce its 300ms deadline: took %v (a wedged ndmc would hang)", elapsed)
	}
}
