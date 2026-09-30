package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A child the daemon spawns must not receive LD_LIBRARY_PATH. Checked by spawning a real child - this
// test binary re-executed as a helper - with the DEFAULT environment inheritance every exec site in
// the daemon relies on, and asking it what it got. That is the behaviour that broke on the Keenetic:
// /bin/ndmc inherited Entware's /opt/lib first and failed to start, so every Apply stopped at capture.
func TestChildrenDoNotInheritLoaderPath(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "/opt/lib:/opt/usr/lib:/lib:/usr/lib") // what Entware's init hands the daemon
	t.Setenv("WAYHOP_LOADERENV_HELPER", "1")

	dropInheritedLoaderPath()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLoaderPathHelperProcess$")
	// cmd.Env deliberately left nil: the child gets os.Environ(), exactly like ndmc does.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); !strings.Contains(got, "LD_LIBRARY_PATH=<unset>") {
		t.Fatalf("a child inherited the loader path, so a firmware binary would load Entware's libraries: %q", got)
	}
}

// TestLoaderPathHelperProcess is not a test on its own: it is the child the test above spawns.
func TestLoaderPathHelperProcess(t *testing.T) {
	if os.Getenv("WAYHOP_LOADERENV_HELPER") != "1" {
		t.Skip("helper process for TestChildrenDoNotInheritLoaderPath")
	}
	if v, ok := os.LookupEnv("LD_LIBRARY_PATH"); ok {
		fmt.Printf("LD_LIBRARY_PATH=%s\n", v)
	} else {
		fmt.Println("LD_LIBRARY_PATH=<unset>")
	}
	os.Exit(0)
}
