package updatetx

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// exitedPID is the pid of a process that has run and been reaped: what a supervisor killed with
// SIGKILL leaves in its pid file, since its EXIT trap never runs.
func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// The daemon refuses a second update while the supervisor lives, and the supervisor outlives the
// marker it drops first. A pid file naming a process that is gone, or holding nothing usable, is
// no supervisor.
func TestSupervisorAliveReadsThePidFileTheWayTheInitDoes(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "verify.pid")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(pf, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, alive := SupervisorAlive(pf); alive {
		t.Error("no pid file reads as a live supervisor")
	}
	write(strconv.Itoa(os.Getpid()) + "\n") // verify.sh: echo "$$" > "$PIDF"
	if pid, alive := SupervisorAlive(pf); !alive || pid != os.Getpid() {
		t.Errorf("a live process reads as no supervisor (pid %d, alive %v)", pid, alive)
	}
	write(strconv.Itoa(exitedPID(t)) + "\n")
	if _, alive := SupervisorAlive(pf); alive {
		t.Error("a process that has exited reads as a live supervisor")
	}
	for _, junk := range []string{"", "\n", "0\n", "-1\n", "verify\n"} {
		write(junk)
		if _, alive := SupervisorAlive(pf); alive {
			t.Errorf("pid file %q reads as a live supervisor", junk)
		}
	}
}

// The pid file is named in three places: verify.sh writes it, the init script reads it at boot, and
// the daemon reads it before an update. A rename in one leaves the daemon reading a file nobody writes.
func TestSupervisorPIDFileIsTheOneTheSupervisorWrites(t *testing.T) {
	if !strings.Contains(string(Script()), "\nPIDF="+SupervisorPIDFile+"\n") {
		t.Errorf("verify.sh does not write its pid to %s", SupervisorPIDFile)
	}
	b, err := os.ReadFile("../../packaging/S99wayhop")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "cat "+SupervisorPIDFile) {
		t.Errorf("S99wayhop does not read %s", SupervisorPIDFile)
	}
}
