package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
)

// service_test.go holds RunService to its contract with the same stub-executable approach as
// run_real_test.go, the stub installed under a service's binary name.

// svcStubSource prints its argv's first value and whether the secret arrived in its environment,
// then blocks; with SVC_STUB_EXIT set it says why and exits 1, as a bridge that cannot bind does.
const svcStubSource = `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if msg := os.Getenv("SVC_STUB_EXIT"); msg != "" {
		fmt.Fprintln(os.Stderr, "starting")
		fmt.Fprintln(os.Stderr, msg+" "+os.Getenv("TG_SECRET"))
		os.Exit(1)
	}
	fmt.Println("up", len(os.Args))
	for {
		time.Sleep(time.Hour)
	}
}
`

const svcBin = "svc-stub"

// svcBuildStub builds the stub into binDir as svcBin, and puts binDir on PATH for Windows (see
// pluginrun_buildStubFrom).
func svcBuildStub(t *testing.T, binDir string) {
	t.Helper()
	goBin := pluginrun_goTool(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(svcStubSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module svcstub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, "build", "-o", filepath.Join(binDir, svcBin+pluginrun_exeSuffix()), ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build the service stub: %v\n%s", err, out)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func svcProc(m *Manager, name string) *proc {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.services[name]
}

// A service runs, is left alone by Sync (which an Apply drives), and the same spec again is a no-op;
// a changed spec restarts it, and nil stops it.
func TestServiceRunsOutsideSync(t *testing.T) {
	binDir := t.TempDir()
	svcBuildStub(t, binDir)
	m := New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)

	spec := &ServiceSpec{Bin: svcBin, Args: []string{"--port", "1443"}, Env: []string{"TG_SECRET=x"}}
	m.RunService("bridge", spec)
	st, ok := m.ServiceStatus("bridge")
	if !ok || !st.Running || st.NeedsBinary {
		t.Fatalf("status after RunService = %+v, %v", st, ok)
	}
	first := svcProc(m, "bridge").cmd.Process.Pid

	// An Apply's Sync, with and without connections, must not stop it.
	m.Sync(nil)
	m.Sync([]Spec{{ID: "awg1", Endpoint: model.Endpoint{ID: "awg1", Engine: model.EngineAmneziaWG}}})
	if st, _ := m.ServiceStatus("bridge"); !st.Running {
		t.Fatal("Sync stopped the service")
	}
	for _, ps := range m.Status() {
		if ps.ID == "bridge" {
			t.Fatal("the service is listed among the connection plugins")
		}
	}

	m.RunService("bridge", &ServiceSpec{Bin: svcBin, Args: []string{"--port", "1443"}, Env: []string{"TG_SECRET=x"}})
	if p := svcProc(m, "bridge"); p.cmd.Process.Pid != first {
		t.Fatal("the same spec restarted the process")
	}
	m.RunService("bridge", &ServiceSpec{Bin: svcBin, Args: []string{"--port", "1444"}, Env: []string{"TG_SECRET=x"}})
	if p := svcProc(m, "bridge"); p == nil || p.cmd == nil || p.cmd.Process.Pid == first {
		t.Fatal("a changed spec did not restart the process")
	}
	m.RunService("bridge", nil)
	if _, ok := m.ServiceStatus("bridge"); ok {
		t.Fatal("nil did not stop and forget the service")
	}
}

// A missing binary is reported, and the next RunService with the same spec tries again (the binary
// may have been installed since); StopByBin stops a running service so its binary can be replaced.
func TestServiceNeedsBinaryAndStopByBin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	binDir := t.TempDir()
	m := New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)
	spec := &ServiceSpec{Bin: svcBin}
	m.RunService("bridge", spec)
	if st, _ := m.ServiceStatus("bridge"); st.Running || !st.NeedsBinary {
		t.Fatalf("status without a binary = %+v", st)
	}
	if m.BinaryPresent(svcBin) {
		t.Fatal("BinaryPresent with nothing installed")
	}
	svcBuildStub(t, binDir)
	m.RunService("bridge", spec)
	if st, _ := m.ServiceStatus("bridge"); !st.Running {
		t.Fatalf("not retried once the binary is there: %+v", st)
	}
	if !m.BinaryPresent(svcBin) {
		t.Fatal("BinaryPresent with the binary installed")
	}
	if n := m.StopByBin(svcBin); n != 1 {
		t.Fatalf("StopByBin = %d, want 1", n)
	}
	if _, ok := m.ServiceStatus("bridge"); ok {
		t.Fatal("StopByBin left the service behind")
	}
}

// A service that exits is restarted by Supervise, and its status says how it ended - the last line
// it wrote, with the secret masked - which is what the API shows as the bridge's last error.
func TestServiceExitIsRecordedAndScrubbed(t *testing.T) {
	binDir := t.TempDir()
	svcBuildStub(t, binDir)
	t.Setenv("SVC_STUB_EXIT", "failed to bind 192.0.2.1:1443: Address in use")
	m := New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)
	secret := "0123456789abcdef0123456789abcdef"
	m.RunService("bridge", &ServiceSpec{Bin: svcBin, Env: []string{"TG_SECRET=" + secret}, Scrub: []string{secret}})

	for i := 0; i < 3; i++ {
		pluginrun_waitFor(t, "the stub to exit", func() bool {
			p := svcProc(m, "bridge")
			m.mu.Lock()
			defer m.mu.Unlock()
			return p.running && procDied(p)
		})
		m.Supervise()
	}
	st, _ := m.ServiceStatus("bridge")
	if st.Exits != 3 || st.LastExit.IsZero() {
		t.Fatalf("exits = %d at %v, want 3", st.Exits, st.LastExit)
	}
	if !strings.Contains(st.LastOutput, "Address in use") || !strings.Contains(st.LastOutput, "exit status 1") {
		t.Fatalf("last output = %q", st.LastOutput)
	}
	if strings.Contains(st.LastOutput, secret) || !strings.Contains(st.LastOutput, "***") {
		t.Fatalf("the secret was not masked: %q", st.LastOutput)
	}
	// The same spec while Supervise owns the restarts is a no-op: a timer calling RunService must
	// not reset the crash count the backoff and the review's finding are built on.
	m.RunService("bridge", &ServiceSpec{Bin: svcBin, Env: []string{"TG_SECRET=" + secret}, Scrub: []string{secret}})
	if st, _ := m.ServiceStatus("bridge"); st.Exits != 3 {
		t.Fatalf("RunService with the same spec reset the exits to %d", st.Exits)
	}
}

// After StopAll a RunService starts nothing. The daemon's shutdown ends with StopAll, but a handler
// that outlived the HTTP shutdown could still sync the bridge; the process it started was tracked by
// nobody and outlived the daemon, holding the port and serving the old secret.
func TestServiceNotStartedAfterStopAll(t *testing.T) {
	binDir := t.TempDir()
	svcBuildStub(t, binDir)
	m := New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)
	m.RunService("bridge", &ServiceSpec{Bin: svcBin})
	if st, _ := m.ServiceStatus("bridge"); !st.Running {
		t.Fatalf("not running before StopAll: %+v", st)
	}
	m.StopAll()
	m.RunService("bridge", &ServiceSpec{Bin: svcBin, Args: []string{"--port", "2443"}})
	if p := svcProc(m, "bridge"); p != nil {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		t.Fatal("RunService after StopAll started the service")
	}
}

// strayEntry is one process of a strayFixture: its comm, real uid, state and argv[0].
type strayEntry struct {
	comm  string
	uid   int
	state string
	argv0 string
}

// strayFixture is a /proc holding procs by pid.
func strayFixture(t *testing.T, procs map[int]strayEntry) string {
	t.Helper()
	root := t.TempDir()
	for pid, e := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		state := e.state
		if state == "" {
			state = "S (sleeping)"
		}
		status := fmt.Sprintf("Name:\t%s\nState:\t%s\nPid:\t%d\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n",
			e.comm, state, pid, e.uid, e.uid, e.uid, e.uid, e.uid, e.uid, e.uid, e.uid)
		files := map[string]string{"comm": e.comm + "\n", "status": status, "cmdline": e.argv0 + "\x00--quiet\x00"}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Not processes: what else lives in /proc.
	_ = os.WriteFile(filepath.Join(root, "uptime"), []byte("1.0 1.0\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "self"), 0o755)
	return root
}

// ReapStrays kills the leftover service processes an earlier daemon left - its binary, its uid - and
// nothing else: not the same binary run as root (upstream's own service), not another binary run as
// the uid, not a zombie, not a process this manager started. It waits for the killed one to go.
func TestReapStraysKillsOnlyLeftoverServices(t *testing.T) {
	const uid = 65531
	root := strayFixture(t, map[int]strayEntry{
		101: {comm: "tg-ws-proxy", uid: uid, argv0: "/tmp/wayhop/uid-65531/tg-ws-proxy"},     // the leftover
		102: {comm: "tg-ws-proxy", uid: 0, argv0: "/usr/bin/tg-ws-proxy"},                    // upstream's service, as root
		103: {comm: "ciadpi", uid: uid, argv0: "ciadpi"},                                     // another binary
		104: {comm: "tg-ws-proxy", uid: uid, state: "Z (zombie)", argv0: ""},                 // already dead
		105: {comm: "tokio-runtime-w", uid: uid, argv0: "/tmp/wayhop/uid-65531/tg-ws-proxy"}, // renamed main thread
	})
	m := New(t.TempDir(), t.TempDir())
	m.procRoot = root
	var killed []int
	m.killPID = func(pid int) error {
		killed = append(killed, pid)
		// The kernel reaps it: its /proc entry goes, which is what the wait watches for.
		return os.RemoveAll(filepath.Join(root, strconv.Itoa(pid)))
	}
	start := time.Now()
	if n := m.ReapStrays("tg-ws-proxy", uid); n != 2 {
		t.Fatalf("ReapStrays = %d, want 2", n)
	}
	slices.Sort(killed)
	if !slices.Equal(killed, []int{101, 105}) {
		t.Fatalf("killed %v, want [101 105]", killed)
	}
	if time.Since(start) >= strayWait {
		t.Fatal("waited out strayWait for processes that were gone")
	}
	// uid 0 marks nothing as WayHop's.
	killed = nil
	if n := m.ReapStrays("tg-ws-proxy", 0); n != 0 || len(killed) != 0 {
		t.Fatalf("uid 0 reaped %d (%v)", n, killed)
	}
}

// A process this manager started is not a leftover, even with the binary and uid of one.
func TestReapStraysSparesItsOwn(t *testing.T) {
	binDir := t.TempDir()
	svcBuildStub(t, binDir)
	m := New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)
	m.RunService("bridge", &ServiceSpec{Bin: svcBin})
	pid := svcProc(m, "bridge").cmd.Process.Pid
	m.procRoot = strayFixture(t, map[int]strayEntry{pid: {comm: svcBin, uid: 65531, argv0: svcBin}})
	m.killPID = func(pid int) error { t.Errorf("killed its own process %d", pid); return nil }
	if n := m.ReapStrays(svcBin, 65531); n != 0 {
		t.Fatalf("ReapStrays = %d", n)
	}
}

func TestTailWriterKeepsTheEnd(t *testing.T) {
	w := newTailWriter(16)
	_, _ = w.Write([]byte("first line that is long\nsecond\n"))
	_, _ = w.Write([]byte("third\n\n"))
	if got := w.lastLine(); got != "third" {
		t.Fatalf("lastLine = %q", got)
	}
	if len(w.buf) > 16 {
		t.Fatalf("kept %d bytes, cap 16", len(w.buf))
	}
}
