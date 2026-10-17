package plugin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/binstore"
	"wayhop/internal/model"
	"wayhop/internal/util"
)

// The userspace path end to end inside the plugin: path choice, a real amneziawg-go-named process
// that blocks like the real one, a real `ip`-named process that records its argv, and an in-process
// socket that answers the way amneziawg-go's does - only while the proc's process is alive. The
// real binary, real `ip` and a real TUN device are exercised separately in the WSL sandbox.

// The blocker logs "pid=N args" once it is running; the fake socket answers only after that line,
// the way amneziawg-go's socket exists only once the process has got that far. It logs the GC target
// it was started with to a second file.
const awgus_blockerSource = `package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if f := os.Getenv("WAYHOP_TEST_AWGLOG"); f != "" {
		if h, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			h.WriteString("pid=" + strconv.Itoa(os.Getpid()) + " " + strings.Join(os.Args[1:], " ") + "\n")
			h.Close()
		}
	}
	if f := os.Getenv("WAYHOP_TEST_AWGENV"); f != "" {
		if h, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			h.WriteString("GOGC=" + os.Getenv("GOGC") + "\n")
			h.Close()
		}
	}
	if f := os.Getenv("WAYHOP_TEST_AWGTIER"); f != "" {
		if h, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			var kv []string
			for _, k := range []string{"AWG_GO_BUFFERS_PER_POOL", "AWG_GO_QUEUE_SIZE", "GOMEMLIMIT", "GOMAXPROCS", "AWG_SOCKET_DIR"} {
				kv = append(kv, k+"="+os.Getenv(k))
			}
			h.WriteString(strings.Join(kv, " ") + "\n")
			h.Close()
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}
`

const awgus_ipSource = `package main

import (
	"os"
	"strings"
)

func main() {
	args := strings.Join(os.Args[1:], " ")
	if f := os.Getenv("WAYHOP_TEST_IPLOG"); f != "" {
		if h, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			h.WriteString(args + "\n")
			h.Close()
		}
	}
	if os.Getenv("WAYHOP_TEST_IPFAIL_UP") != "" && strings.HasSuffix(args, " up") {
		os.Exit(2)
	}
	if r := os.Getenv("WAYHOP_TEST_IPROUTE"); r != "" && strings.HasPrefix(args, "route get ") {
		os.Stdout.WriteString(r + "\n")
	}
}
`

const awgus_dieSource = `package main

import "os"

func main() { os.Exit(1) }
`

func awgus_build(t *testing.T, dir, name, src string) {
	t.Helper()
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module awgusstub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(pluginrun_goTool(t), "build", "-o", filepath.Join(dir, name+pluginrun_exeSuffix()), ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the %s stub: %v\n%s", name, err, out)
	}
}

// awgus_socket stands in for amneziawg-go's UAPI socket.
type awgus_socket struct {
	p     *proc
	rec   *awgus_recorder
	awLog string
}

type awgus_recorder struct {
	mu     sync.Mutex
	sets   [][]awg.KV
	setErr error
}

func (s awgus_socket) alive() bool {
	if s.p.cmd == nil || procDied(s.p) {
		return false
	}
	b, _ := os.ReadFile(s.awLog)
	return strings.Contains(string(b), "pid="+strconv.Itoa(s.p.cmd.Process.Pid)+" ")
}

func (s awgus_socket) Get(context.Context) (awg.Snapshot, error) {
	if !s.alive() {
		return awg.Snapshot{}, errors.New("connect: no such file or directory")
	}
	return awg.Snapshot{}, nil
}

func (s awgus_socket) Set(_ context.Context, lines []awg.KV) error {
	if !s.alive() {
		return errors.New("connect: no such file or directory")
	}
	s.rec.mu.Lock()
	defer s.rec.mu.Unlock()
	s.rec.sets = append(s.rec.sets, lines)
	return s.rec.setErr
}

func (r *awgus_recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sets)
}

func awgus_endpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "192.0.2.1", Port: 51820,
		Params: map[string]any{
			"private_key": b64Key(1, base64.StdEncoding), "peer_public_key": b64Key(2, base64.StdEncoding),
			"jc": 4, "jmin": 40, "jmax": 70, "local_address": []any{"10.8.0.2/32"},
		},
	}
}

// awgus_meminfo stands in /proc/meminfo for the rest of the test.
func awgus_meminfo(t *testing.T, content string) {
	t.Helper()
	old := awgMeminfo
	awgMeminfo = func() ([]byte, error) { return []byte(content), nil }
	t.Cleanup(func() { awgMeminfo = old })
}

func awgus_lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestAWGUserspace(t *testing.T) {
	binDir := t.TempDir()
	awgus_build(t, binDir, "amneziawg-go", awgus_blockerSource)
	awgus_build(t, binDir, "ip", awgus_ipSource)
	onlyIP := t.TempDir()
	awgus_build(t, onlyIP, "ip", awgus_ipSource)
	dying := t.TempDir()
	awgus_build(t, dying, "ip", awgus_ipSource)
	awgus_build(t, dying, "amneziawg-go", awgus_dieSource)
	kernel := t.TempDir() // ip and awg, both recording into the same log
	awgus_build(t, kernel, "ip", awgus_ipSource)
	awgus_build(t, kernel, "awg", awgus_ipSource)
	both := t.TempDir() // the kernel tools and amneziawg-go side by side, as on a router that has both
	awgus_build(t, both, "ip", awgus_ipSource)
	awgus_build(t, both, "awg", awgus_ipSource)
	awgus_build(t, both, "amneziawg-go", awgus_blockerSource)
	// resolve() looks in binDir, then on PATH; on Windows only the PATH lookup adds .exe. An empty
	// directory on PATH first keeps a host's real awg or ip out of the way.
	pathWith := func(dir string) string { return dir + string(os.PathListSeparator) + t.TempDir() }

	type rig struct {
		m            *Manager
		rec          *awgus_recorder
		ipLog, awLog string
		envLog       string
		tierLog      string
	}
	newRig := func(t *testing.T, bins string, probe awg.Probe) rig {
		t.Setenv("PATH", pathWith(bins))
		logs := t.TempDir()
		r := rig{rec: &awgus_recorder{}, ipLog: filepath.Join(logs, "ip.log"), awLog: filepath.Join(logs, "awg.log"),
			envLog: filepath.Join(logs, "awgenv.log"), tierLog: filepath.Join(logs, "awgtier.log")}
		t.Setenv("WAYHOP_TEST_IPLOG", r.ipLog)
		t.Setenv("WAYHOP_TEST_AWGLOG", r.awLog)
		t.Setenv("WAYHOP_TEST_AWGENV", r.envLog)
		t.Setenv("WAYHOP_TEST_AWGTIER", r.tierLog)
		t.Setenv("GOGC", "") // the daemon started without one
		for _, k := range []string{"GOMEMLIMIT", "GOMAXPROCS", "AWG_GO_BUFFERS_PER_POOL", "AWG_GO_QUEUE_SIZE", "AWG_SOCKET_DIR"} {
			t.Setenv(k, "") // nor any of these
		}
		// A router with 239 MiB, the AX3000T's MemTotal, unless a subtest sets another.
		awgus_meminfo(t, "MemTotal:         244736 kB\nMemFree:           53000 kB\n")
		r.m = New(t.TempDir(), bins)
		r.m.awgProbe = func() awg.Probe { return probe }
		r.m.awgDial = func(p *proc) (awgSocket, error) { return awgus_socket{p: p, rec: r.rec, awLog: r.awLog}, nil }
		r.m.awgLookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no DNS in tests") }
		t.Cleanup(r.m.StopAll)
		return r
	}
	userspace := awg.Probe{Kernel: awg.GenNone, TUN: true}
	status := func(m *Manager, id string) Status { return pluginrun_statusByID(m.Status())[id] }

	t.Run("the probe selects amneziawg-go and it is configured and brought up", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.m.Sync([]Spec{{ID: "a", Endpoint: awgus_endpoint("a")}})
		if s := status(r.m, "a"); !s.Running || s.NeedsBinary || s.Reason != "" {
			t.Fatalf("status %+v", s)
		}
		iface := util.AWGIface("a")
		if got := awgus_lines(t, r.awLog); len(got) != 1 || !strings.HasSuffix(got[0], " -f "+iface) {
			t.Errorf("amneziawg-go started as %q", got)
		}
		if r.rec.count() != 1 || r.rec.sets[0][0].Key != "private_key" {
			t.Errorf("UAPI sets: %v", r.rec.sets)
		}
		want := []string{"route get 192.0.2.1", "link del " + iface, "addr add 10.8.0.2/32 dev " + iface, "link set " + iface + " mtu 1280", "link set " + iface + " up"}
		if got := awgus_lines(t, r.ipLog); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("ip calls:\n%q\nwant\n%q", got, want)
		}
		if got := awgus_lines(t, r.envLog); strings.Join(got, "|") != "GOGC="+awgGOGC {
			t.Errorf("amneziawg-go started with %q, want GOGC=%s", got, awgGOGC)
		}
	})

	// The path is read from the route to the server; a padding that would push a full-size packet past
	// it lowers the device's MTU, and the status says so.
	t.Run("a padded config is lowered to fit the path to the server", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		t.Setenv("WAYHOP_TEST_IPROUTE", "192.0.2.1 via 10.0.0.1 dev wan0 src 10.0.0.2 uid 0\n    cache mtu 1492")
		e := awgus_endpoint("m")
		e.MTU = 1420
		e.Params["s4"] = 50
		r.m.Sync([]Spec{{ID: "m", Endpoint: e}})
		s := status(r.m, "m")
		if !s.Running || !strings.Contains(s.Note, "MTU 1420 lowered to 1382") {
			t.Fatalf("status %+v", s)
		}
		if got := awgus_lines(t, r.ipLog); !slices.Contains(got, "link set "+util.AWGIface("m")+" mtu 1382") {
			t.Errorf("ip calls %q; want the device at 1492 - 28 - 32 - 50 = 1382", got)
		}
	})

	t.Run("a padding that leaves no room on the path starts nothing", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		e := awgus_endpoint("w")
		e.Params["s4"] = 1000
		r.m.Sync([]Spec{{ID: "w", Endpoint: e}})
		if s := status(r.m, "w"); s.Running || !strings.Contains(s.Reason, "S4 1000 leaves 440 bytes of a 1500-byte path") {
			t.Fatalf("status %+v", s)
		}
		if got := awgus_lines(t, r.awLog); got[0] != "" {
			t.Errorf("amneziawg-go was started: %q", got)
		}
	})

	t.Run("a GOGC the daemon was started with is left to amneziawg-go", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		t.Setenv("GOGC", "80")
		r.m.Sync([]Spec{{ID: "g", Endpoint: awgus_endpoint("g")}})
		if got := awgus_lines(t, r.envLog); strings.Join(got, "|") != "GOGC=80" {
			t.Errorf("amneziawg-go started with %q, want the operator's GOGC=80", got)
		}
	})

	// The tier comes from MemTotal, and the socket directory is always the one the daemon dials.
	// The line the stub writes for a tier's settings, with the operator's own values over them.
	tierLine := func(env []string, operator map[string]string) string {
		var parts []string
		for _, k := range []string{"AWG_GO_BUFFERS_PER_POOL", "AWG_GO_QUEUE_SIZE", "GOMEMLIMIT", "GOMAXPROCS"} {
			v := operator[k]
			for _, kv := range env {
				if tv, ok := strings.CutPrefix(kv, k+"="); ok && v == "" {
					v = tv
				}
			}
			parts = append(parts, k+"="+v)
		}
		return strings.Join(parts, " ") + " AWG_SOCKET_DIR=" + awgSocketDir
	}
	for _, c := range []struct {
		name     string
		meminfo  string
		tier     int
		gomemlim string
	}{
		{"a 64 MB router", "MemTotal:   59392 kB\n", 0, ""},
		{"a 128 MB router", "MemTotal:  124000 kB\n", 0, ""},
		{"a 256 MB router", "MemTotal:  244736 kB\n", 1, ""},
		{"a 512 MB router", "MemTotal:  503316 kB\n", 2, ""},
		{"a router whose meminfo cannot be read", "", awgTierUnknown, ""},
		{"an operator's GOMEMLIMIT", "MemTotal:  124000 kB\n", 0, "48MiB"},
	} {
		t.Run("the memory tier reaches amneziawg-go: "+c.name, func(t *testing.T) {
			r := newRig(t, binDir, userspace)
			awgus_meminfo(t, c.meminfo)
			t.Setenv("AWG_SOCKET_DIR", "/var/run/elsewhere") // inherited, and overridden
			operator := map[string]string{}
			if c.gomemlim != "" {
				t.Setenv("GOMEMLIMIT", c.gomemlim)
				operator["GOMEMLIMIT"] = c.gomemlim
			}
			want := tierLine(awgTiers[c.tier].env, operator)
			r.m.Sync([]Spec{{ID: "t", Endpoint: awgus_endpoint("t")}})
			if s := status(r.m, "t"); !s.Running {
				t.Fatalf("status %+v", s)
			}
			if got := awgus_lines(t, r.tierLog); strings.Join(got, "|") != want {
				t.Errorf("amneziawg-go started with\n%q\nwant\n%q", got, want)
			}
		})
	}

	t.Run("a module new enough for the config keeps the kernel path", func(t *testing.T) {
		r := newRig(t, binDir, awg.Probe{Kernel: awg.Gen31, TUN: true, GenlVersion: 3, GenlMaxAttr: 34})
		r.m.Sync([]Spec{{ID: "k", Endpoint: awgus_endpoint("k")}})
		s := status(r.m, "k")
		if !s.NeedsBinary || !strings.Contains(s.Reason, "awg up") || strings.Contains(s.Reason, "amneziawg-go") {
			t.Fatalf("status %+v; want the kernel path asking for awg", s)
		}
		if got := awgus_lines(t, r.awLog); got[0] != "" {
			t.Errorf("amneziawg-go was started on the kernel path: %q", got)
		}
	})

	// The kernel path's order survives awgLinkUp being shared: link, setconf, then the ip-layer half;
	// and a link that does not come up is deleted rather than left half-made.
	t.Run("the kernel path runs as before", func(t *testing.T) {
		r := newRig(t, kernel, awg.Probe{Kernel: awg.Gen31, TUN: true})
		r.m.Sync([]Spec{{ID: "kp", Endpoint: awgus_endpoint("kp")}})
		if s := status(r.m, "kp"); !s.Running {
			t.Fatalf("status %+v", s)
		}
		iface := util.AWGIface("kp")
		got := awgus_lines(t, r.ipLog)
		want := []string{"link del " + iface, "link add dev " + iface + " type amneziawg", "setconf " + iface,
			"addr add 10.8.0.2/32 dev " + iface, "link set " + iface + " mtu 1280", "link set " + iface + " up"}
		if len(got) != len(want) {
			t.Fatalf("calls %q, want %q", got, want)
		}
		for i := range want {
			if !strings.HasPrefix(got[i], want[i]) {
				t.Errorf("call %d = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("the kernel path deletes a link that does not come up", func(t *testing.T) {
		r := newRig(t, kernel, awg.Probe{Kernel: awg.Gen31, TUN: true})
		t.Setenv("WAYHOP_TEST_IPFAIL_UP", "1")
		r.m.Sync([]Spec{{ID: "kf", Endpoint: awgus_endpoint("kf")}})
		got := awgus_lines(t, r.ipLog)
		if s := status(r.m, "kf"); s.Running || got[len(got)-1] != "link del "+util.AWGIface("kf") {
			t.Fatalf("status %+v, calls %q", s, got)
		}
	})

	t.Run("an amneziawg-go that dies at start is reported at once", func(t *testing.T) {
		r := newRig(t, dying, userspace)
		start := time.Now()
		r.m.Sync([]Spec{{ID: "z", Endpoint: awgus_endpoint("z")}})
		if s := status(r.m, "z"); s.Running || !strings.Contains(s.Reason, "exited before") {
			t.Fatalf("status %+v", s)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %v; a dead process must not wait out awgStartTimeout", d)
		}
	})

	t.Run("a failed probe keeps the kernel path it had before", func(t *testing.T) {
		r := newRig(t, binDir, awg.Probe{Err: "no generic netlink"})
		r.m.Sync([]Spec{{ID: "f", Endpoint: awgus_endpoint("f")}})
		if s := status(r.m, "f"); !strings.Contains(s.Reason, "awg up") {
			t.Fatalf("status %+v", s)
		}
	})

	// KeeneticOS: NDM owns the module, so even one new enough for the config - or a probe that failed,
	// which elsewhere keeps the kernel path - never gets a link added on it.
	t.Run("a firmware-owned module is never used", func(t *testing.T) {
		for _, probe := range []awg.Probe{
			{Kernel: awg.Gen31, TUN: true, GenlVersion: 3, GenlMaxAttr: 34},
			{Err: "no generic netlink", TUN: true},
		} {
			r := newRig(t, binDir, probe)
			r.m.FirmwareOwnsAWGKernel()
			r.m.Sync([]Spec{{ID: "fw", Endpoint: awgus_endpoint("fw")}})
			if s := status(r.m, "fw"); !s.Running || s.Reason != "" {
				t.Fatalf("probe %+v: status %+v", probe, s)
			}
			if got := awgus_lines(t, r.awLog); len(got) != 1 || !strings.HasSuffix(got[0], " -f "+util.AWGIface("fw")) {
				t.Errorf("probe %+v: amneziawg-go started as %q", probe, got)
			}
			r.m.StopAll()
		}
		r := newRig(t, binDir, awg.Probe{Kernel: awg.Gen31, TUN: false})
		r.m.FirmwareOwnsAWGKernel()
		r.m.Sync([]Spec{{ID: "fwt", Endpoint: awgus_endpoint("fwt")}})
		if s := status(r.m, "fwt"); s.Running || !strings.Contains(s.Reason, "/dev/net/tun") {
			t.Fatalf("no TUN: status %+v", s)
		}
	})

	// What the Components page counts as the component's resident memory: the running amneziawg-go
	// processes, and none once they are stopped.
	t.Run("the running userspace processes are listed", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.m.Sync([]Spec{{ID: "p", Endpoint: awgus_endpoint("p")}})
		pids := r.m.UserspaceAWGProcesses()
		if len(pids) != 1 || pids[0] <= 0 {
			t.Fatalf("pids %v", pids)
		}
		// A process that died is out of the list before the supervisor notices: its pid is not ours.
		r.m.mu.Lock()
		p := r.m.procs["p"]
		r.m.mu.Unlock()
		_ = p.cmd.Process.Kill()
		<-p.done
		if pids := r.m.UserspaceAWGProcesses(); len(pids) != 0 {
			t.Fatalf("a dead process is still listed: %v", pids)
		}
		r.m.StopAll()
		if pids := r.m.UserspaceAWGProcesses(); len(pids) != 0 {
			t.Fatalf("pids after stop %v", pids)
		}
	})

	t.Run("no module and no TUN says so", func(t *testing.T) {
		r := newRig(t, binDir, awg.Probe{Kernel: awg.GenNone, TUN: false})
		r.m.Sync([]Spec{{ID: "u", Endpoint: awgus_endpoint("u")}})
		if s := status(r.m, "u"); s.Running || s.NeedsBinary || !strings.Contains(s.Reason, "/dev/net/tun") {
			t.Fatalf("status %+v", s)
		}
	})

	t.Run("no amneziawg-go binary is needs_binary", func(t *testing.T) {
		r := newRig(t, onlyIP, userspace)
		r.m.Sync([]Spec{{ID: "n", Endpoint: awgus_endpoint("n")}})
		if s := status(r.m, "n"); !s.NeedsBinary || !strings.Contains(s.Reason, "amneziawg-go") {
			t.Fatalf("status %+v", s)
		}
	})

	t.Run("a config the translator refuses starts nothing", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		e := awgus_endpoint("x")
		e.Params["jc"] = 129
		r.m.Sync([]Spec{{ID: "x", Endpoint: e}})
		if s := status(r.m, "x"); s.Running || !strings.Contains(s.Reason, "Jc") {
			t.Fatalf("status %+v", s)
		}
		if a, i := awgus_lines(t, r.awLog), awgus_lines(t, r.ipLog); a[0] != "" || i[0] != "" {
			t.Errorf("something ran: amneziawg-go %q, ip %q", a, i)
		}
	})

	t.Run("a refused set ends the process", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.rec.setErr = &awg.UAPIError{Op: "set", Errno: -22}
		r.m.Sync([]Spec{{ID: "r", Endpoint: awgus_endpoint("r")}})
		s := status(r.m, "r")
		if s.Running || !strings.Contains(s.Reason, "errno -22") {
			t.Fatalf("status %+v", s)
		}
		if p := r.m.procs["r"]; p.cmd != nil {
			t.Error("the process of a refused config is still there")
		}
	})

	t.Run("a link that does not come up ends the process", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		t.Setenv("WAYHOP_TEST_IPFAIL_UP", "1")
		r.m.Sync([]Spec{{ID: "d", Endpoint: awgus_endpoint("d")}})
		if s := status(r.m, "d"); s.Running || !strings.Contains(s.Reason, "ip link set up") {
			t.Fatalf("status %+v", s)
		}
		if p := r.m.procs["d"]; p.cmd != nil {
			t.Error("the process is still there")
		}
	})

	t.Run("a changed 3.x key gets a fresh process", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		e := awgus_endpoint("c")
		e.Params["rekey_timeout"] = "5"
		r.m.Sync([]Spec{{ID: "c", Endpoint: e}})
		first := r.m.procs["c"]
		if first == nil || first.cmd == nil {
			t.Fatalf("not started: %+v", status(r.m, "c"))
		}
		pid, done := first.cmd.Process.Pid, first.done
		e2 := awgus_endpoint("c")
		e2.Params["rekey_timeout"] = "7"
		r.m.Sync([]Spec{{ID: "c", Endpoint: e2}})
		second := r.m.procs["c"]
		if second == nil || second.cmd == nil || second.cmd.Process.Pid == pid {
			t.Fatalf("no fresh process after the change: %+v", status(r.m, "c"))
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the old amneziawg-go is still running")
		}
		if r.rec.count() != 2 {
			t.Errorf("%d sets, want one per process", r.rec.count())
		}
	})

	// The config text is the same on both paths, so the choice itself has to restart the connection:
	// without that, a connection set to amneziawg-go kept running on the kernel module until the
	// daemon restarted, and the panel said otherwise.
	t.Run("choosing amneziawg-go moves a running connection, and Automatic moves it back", func(t *testing.T) {
		r := newRig(t, both, awg.Probe{Kernel: awg.Gen31, TUN: true, GenlVersion: 3, GenlMaxAttr: 34})
		iface := util.AWGIface("e")
		r.m.Sync([]Spec{{ID: "e", Endpoint: awgus_endpoint("e")}})
		if s := status(r.m, "e"); !s.Running || r.m.procs["e"].cmd != nil {
			t.Fatalf("automatic on a 3.1 module: %+v; want the kernel path", s)
		}
		chosen := awgus_endpoint("e")
		chosen.AWGUserspace = true
		r.m.Sync([]Spec{{ID: "e", Endpoint: chosen}})
		p := r.m.procs["e"]
		if s := status(r.m, "e"); !s.Running || p == nil || p.cmd == nil {
			t.Fatalf("after choosing amneziawg-go: %+v", s)
		}
		if got := awgus_lines(t, r.awLog); len(got) != 1 || !strings.HasSuffix(got[0], " -f "+iface) {
			t.Errorf("amneziawg-go started as %q", got)
		}
		done := p.done
		r.m.Sync([]Spec{{ID: "e", Endpoint: awgus_endpoint("e")}})
		if s := status(r.m, "e"); !s.Running || r.m.procs["e"].cmd != nil {
			t.Fatalf("back to automatic: %+v; want the kernel path again", s)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("amneziawg-go still runs after the connection went back to the kernel path")
		}
	})

	t.Run("a crash is relaunched and configured again", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.m.Sync([]Spec{{ID: "s", Endpoint: awgus_endpoint("s")}})
		p := r.m.procs["s"]
		if p == nil || p.cmd == nil {
			t.Fatalf("not started: %+v", status(r.m, "s"))
		}
		pid := p.cmd.Process.Pid
		_ = p.cmd.Process.Kill()
		<-p.done
		r.m.Supervise()
		if !p.running || p.cmd == nil || p.cmd.Process.Pid == pid {
			t.Fatalf("not relaunched: %+v", status(r.m, "s"))
		}
		if r.rec.count() != 2 {
			t.Errorf("%d sets; the relaunch must configure the new process", r.rec.count())
		}
		ups := 0
		for _, l := range awgus_lines(t, r.ipLog) {
			if strings.HasSuffix(l, " up") {
				ups++
			}
		}
		if ups != 2 {
			t.Errorf("link brought up %d times, want 2", ups)
		}
		if got := awgus_lines(t, r.envLog); strings.Join(got, "|") != "GOGC="+awgGOGC+"|GOGC="+awgGOGC {
			t.Errorf("the relaunch lost the runtime settings: %q", got)
		}
	})

	t.Run("a relaunch that cannot be configured ends the new process", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.m.Sync([]Spec{{ID: "q", Endpoint: awgus_endpoint("q")}})
		p := r.m.procs["q"]
		if p == nil || p.cmd == nil {
			t.Fatalf("not started: %+v", status(r.m, "q"))
		}
		r.rec.setErr = &awg.UAPIError{Op: "set", Errno: -5}
		_ = p.cmd.Process.Kill()
		<-p.done
		r.m.Supervise()
		if p.running || p.cmd != nil || !strings.Contains(p.reason, "restart amneziawg-go") {
			t.Fatalf("after a failed relaunch: running %v, process %v, reason %q", p.running, p.cmd != nil, p.reason)
		}
	})

	t.Run("removing the endpoint ends the process", func(t *testing.T) {
		r := newRig(t, binDir, userspace)
		r.m.Sync([]Spec{{ID: "e", Endpoint: awgus_endpoint("e")}})
		p := r.m.procs["e"]
		if p == nil || p.cmd == nil {
			t.Fatalf("not started: %+v", status(r.m, "e"))
		}
		done := p.done
		r.m.Sync(nil)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("amneziawg-go outlived its endpoint")
		}
	})
}

// The peer's address for UAPI: a literal passes through, a name prefers IPv4, and a name with only
// IPv6 still resolves.
func TestAWGEndpoint(t *testing.T) {
	lookup := func(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
		return func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
	cases := []struct {
		host string
		look func(context.Context, string) ([]netip.Addr, error)
		want string
	}{
		{"192.0.2.1", nil, "192.0.2.1:51820"},
		{"2001:db8::1", nil, "[2001:db8::1]:51820"},
		{"[2001:db8::1]", nil, "[2001:db8::1]:51820"},
		{"vpn.example.test", lookup("2001:db8::7", "192.0.2.7"), "192.0.2.7:51820"},
		{"vpn.example.test", lookup("2001:db8::7"), "[2001:db8::7]:51820"},
		{"vpn.example.test", lookup("::ffff:192.0.2.9"), "192.0.2.9:51820"},
	}
	for _, c := range cases {
		got, err := awgEndpoint(context.Background(), c.look, c.host, 51820)
		if err != nil || got.String() != c.want {
			t.Errorf("awgEndpoint(%q) = %v, %v; want %s", c.host, got, err, c.want)
		}
	}
	if _, err := awgEndpoint(context.Background(), lookup(), "vpn.example.test", 51820); err == nil {
		t.Error("a name with no address resolved")
	}
	if _, err := awgEndpoint(context.Background(), nil, "192.0.2.1", 0); err == nil {
		t.Error("port 0 was accepted")
	}
}

// awgConfig carries the 3.x keys: the kernel path needs them once the module takes them, and Sync
// needs them to notice a change. The switches appear only when on, which older tools can parse.
func TestAWGConfig_V3Params(t *testing.T) {
	e := awg31Endpoint()
	e.Params["max_handshake_attempts"] = "3-5"
	c := awgConfig(e)
	for _, want := range []string{
		"HeaderProtectionKey = " + b64Key(4, base64.StdEncoding), "RekeyTimeout = 5-5",
		"MaxHandshakeAttempts = 3-5", "DisableCookies = on",
	} {
		if !strings.Contains(c, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, c)
		}
	}
	if strings.Contains(c, "RandomTrailers") {
		t.Errorf("RandomTrailers = off was written:\n%s", c)
	}
	e.Params["random_trailers"] = "on"
	if !strings.Contains(awgConfig(e), "RandomTrailers = on\n") {
		t.Error("RandomTrailers = on was not written")
	}
}

// A binary the updater kept compressed is unpacked into runDir - digest checked - and that copy is
// what resolve hands to a start; an unpacked binary in binDir still wins, and a corrupt store is not
// run at all.
func TestResolveUnpacksACompressedStore(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // nothing from the host
	binDir, runDir := t.TempDir(), t.TempDir()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte("amneziawg-go stand-in"))
	_ = zw.Close()
	gzPath := binstore.Stored(binDir, "amneziawg-go", true)
	if err := os.WriteFile(gzPath, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := binstore.Write(binDir, "amneziawg-go", "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	m := New(t.TempDir(), binDir)
	m.runDir = runDir
	p, ok := m.resolve("amneziawg-go")
	if !ok || p != filepath.Join(runDir, "amneziawg-go") {
		t.Fatalf("resolve = %q, %v; want the copy unpacked into runDir", p, ok)
	}
	if got, _ := os.ReadFile(p); string(got) != "amneziawg-go stand-in" {
		t.Errorf("unpacked %q", got)
	}

	raw := filepath.Join(binDir, "amneziawg-go")
	if err := os.WriteFile(raw, []byte("raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p, ok := m.resolve("amneziawg-go"); !ok || p != raw {
		t.Errorf("with an unpacked binary in binDir, resolve = %q, %v", p, ok)
	}
	_ = os.Remove(raw)

	// Worn flash: same size and time, different bytes.
	fi, _ := os.Stat(gzPath)
	bad := append([]byte(nil), b.Bytes()...)
	bad[len(bad)/2] ^= 0xff
	_ = os.WriteFile(gzPath, bad, 0o644)
	_ = os.Chtimes(gzPath, fi.ModTime(), fi.ModTime())
	_ = os.Remove(p)
	_ = os.Remove(p + ".src")
	if p, ok := m.resolve("amneziawg-go"); ok {
		t.Errorf("a corrupt store resolved to %q", p)
	}
}

// AWGDecision is the plugin's rule as a pure function - what the Components page shows is what the
// plugin does.
func TestAWGDecision(t *testing.T) {
	e := awg31Endpoint()
	for _, c := range []struct {
		name     string
		probe    awg.Probe
		firmware bool
		want     awg.Path
	}{
		{"a module new enough", awg.Probe{Kernel: awg.Gen31, TUN: true}, false, awg.PathKernel},
		{"a module too old", awg.Probe{Kernel: awg.Gen2, TUN: true}, false, awg.PathUserspace},
		{"the firmware's module, however new", awg.Probe{Kernel: awg.Gen31, TUN: true}, true, awg.PathUserspace},
		{"the firmware's module and no TUN", awg.Probe{Kernel: awg.Gen31}, true, awg.PathUnavailable},
		{"a probe that failed keeps the kernel path", awg.Probe{Err: "no netlink"}, false, awg.PathKernel},
		{"no module and no TUN", awg.Probe{Kernel: awg.GenNone}, false, awg.PathUnavailable},
	} {
		if got := AWGDecision(c.probe, c.firmware, e); got.Path != c.want || got.Reason == "" {
			t.Errorf("%s: %+v, want %v", c.name, got, c.want)
		}
	}

	// A connection set to run on amneziawg-go takes it wherever /dev/net/tun is, however new the
	// module - and says why, since the module could have carried it.
	chosen := awg31Endpoint()
	chosen.AWGUserspace = true
	for _, c := range []struct {
		name     string
		probe    awg.Probe
		firmware bool
		want     awg.Path
	}{
		{"a module new enough", awg.Probe{Kernel: awg.Gen31, TUN: true}, false, awg.PathUserspace},
		{"the firmware's module", awg.Probe{Kernel: awg.Gen2, TUN: true}, true, awg.PathUserspace},
		{"a probe that failed", awg.Probe{Err: "no netlink", TUN: true}, false, awg.PathUserspace},
		{"no TUN", awg.Probe{Kernel: awg.Gen31}, false, awg.PathUnavailable},
	} {
		got := AWGDecision(c.probe, c.firmware, chosen)
		if got.Path != c.want || !strings.Contains(got.Reason, "set to run on amneziawg-go") {
			t.Errorf("chosen, %s: %+v, want %v", c.name, got, c.want)
		}
	}
}

// Each tier setting is added unless the daemon's environment already names it (an empty value is no
// choice); the socket directory is added always, over an inherited one.
func TestAWGRuntimeEnv(t *testing.T) {
	for _, mem := range []int64{0, 100 << 10, 200 << 10, 1 << 20} {
		tier := awgTierFor(mem).env
		if !slices.Contains(tier, "GOGC="+awgGOGC) {
			t.Errorf("%d KiB: tier %q does not set GOGC=%s", mem, tier, awgGOGC)
		}
		without := func(keys ...string) string {
			var out []string
			for _, kv := range tier {
				if k, _, _ := strings.Cut(kv, "="); !slices.Contains(keys, k) {
					out = append(out, kv)
				}
			}
			return strings.Join(append(out, "AWG_SOCKET_DIR="+awgSocketDir), " ")
		}
		for _, c := range []struct {
			environ []string
			want    string
		}{
			{[]string{"PATH=/usr/bin"}, without()},
			{[]string{"PATH=/usr/bin", "GOGC=80"}, without("GOGC")},
			{[]string{"GOGC=off"}, without("GOGC")},
			{[]string{"GOGC="}, without()},
			{[]string{"XGOGC=80", "GOGCX=80"}, without()},
			{nil, without()},
			{[]string{"AWG_SOCKET_DIR=/var/run/elsewhere"}, without()},
			{[]string{"GOMEMLIMIT=64MiB", "AWG_GO_BUFFERS_PER_POOL=4096", "AWG_GO_QUEUE_SIZE=", "GOMAXPROCS=2"},
				without("GOMEMLIMIT", "AWG_GO_BUFFERS_PER_POOL", "GOMAXPROCS")},
		} {
			if got := strings.Join(awgRuntimeEnv(c.environ, mem), " "); got != c.want {
				t.Errorf("awgRuntimeEnv(%q, %d) = %q, want %q", c.environ, mem, got, c.want)
			}
		}
	}
}

// The tier boundaries and the settings each tier gives amneziawg-go (docs/AWG_LOWMEM.md, development repository).
func TestAWGTierFor(t *testing.T) {
	low := "AWG_GO_BUFFERS_PER_POOL=512 AWG_GO_QUEUE_SIZE=256 GOMEMLIMIT=24MiB GOGC=25 GOMAXPROCS=1"
	small := "AWG_GO_BUFFERS_PER_POOL=512 AWG_GO_QUEUE_SIZE=256 GOGC=25"
	normal := "AWG_GO_BUFFERS_PER_POOL=1024 AWG_GO_QUEUE_SIZE=256 GOGC=25"
	for _, c := range []struct {
		kib  int64
		want string
	}{
		{0, small}, // unknown
		{-1, small},
		{59392, low}, // a 64 MB router
		{124000, low},
		{128<<10 - 1, low},
		{128 << 10, small},
		{244736, small}, // the AX3000T
		{256<<10 - 1, small},
		{256 << 10, normal},
		{16 << 20, normal},
	} {
		if got := strings.Join(awgTierFor(c.kib).env, " "); got != c.want {
			t.Errorf("awgTierFor(%d) = %q, want %q", c.kib, got, c.want)
		}
	}
}

func TestParseMemTotalKiB(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
	}{
		{"MemTotal:         244736 kB\nMemFree:           53000 kB\n", 244736},
		{"MemFree: 1 kB\nMemTotal: 59392 kB", 59392},
		{"MemTotal:\n", 0},
		{"MemTotal: lots kB\n", 0},
		{"MemTotal: -5 kB\n", 0},
		{"SwapTotal: 100 kB\n", 0},
		{"", 0},
	} {
		if got := parseMemTotalKiB(c.in); got != c.want {
			t.Errorf("parseMemTotalKiB(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	old := awgMeminfo
	defer func() { awgMeminfo = old }()
	awgMeminfo = func() ([]byte, error) { return nil, os.ErrNotExist }
	if got := awgMemTotalKiB(); got != 0 {
		t.Errorf("an unreadable meminfo gave %d KiB, want 0", got)
	}
}

// AWG_SOCKET_DIR must name the directory internal/awg dials, or the daemon finds no socket at all.
func TestAWGSocketDirIsTheClients(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "awg", "uapi.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^const uapiSocketDir = "([^"]+)"`).FindSubmatch(src)
	if m == nil || string(m[1]) != awgSocketDir {
		t.Fatalf("internal/awg dials %q, amneziawg-go is told %q", m, awgSocketDir)
	}
}

// The device MTU amneziawg-go gets: the config's, lowered only as far as the path needs.
func TestAWGUserspaceMTU(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	lines := func(kv ...string) []awg.KV {
		var out []awg.KV
		for i := 0; i+1 < len(kv); i += 2 {
			out = append(out, awg.KV{Key: kv[i], Value: kv[i+1]})
		}
		return out
	}
	withMTU := func(mtu any, v6inside bool) model.Endpoint {
		e := awgus_endpoint("t")
		if mtu != nil {
			e.Params["mtu"] = mtu
		}
		if v6inside {
			e.Params["local_address"] = []any{"10.8.0.2/32", "fd00::2/128"}
		}
		return e
	}
	for _, c := range []struct {
		name    string
		e       model.Endpoint
		lines   []awg.KV
		peer    netip.Addr
		path    int
		mtu     int
		note    []string // substrings the note must hold; none: the note is empty
		refused string
	}{
		{"no padding, no MTU in the config", withMTU(nil, false), nil, v4, 1500, 1280, nil, ""},
		{"S4 50 on 1420: lowered", withMTU(1420, false), lines("s4", "50"), v4, 1500, 1390, []string{"MTU 1420 lowered to 1390", "adds 110 bytes", "1500-byte path"}, ""},
		{"to an IPv6 server the headers are 48", withMTU(1420, false), lines("s4", "50"), v6, 1500, 1370, []string{"lowered to 1370", "IP and UDP 48"}, ""},
		{"a v4-mapped server is IPv4 on the wire", withMTU(1420, false), lines("s4", "50"), netip.MustParseAddr("::ffff:192.0.2.1"), 1500, 1390, []string{"IP and UDP 28"}, ""},
		{"PPPoE's 1492", withMTU(1420, false), lines("s4", "50"), v4, 1492, 1382, []string{"lowered to 1382"}, ""},
		{"a lower MTU in the config is kept", withMTU(1300, false), lines("s4", "50"), v4, 1500, 1300, nil, ""},
		{"exactly fitting is kept", withMTU(1390, false), lines("s4", "50"), v4, 1500, 1390, nil, ""},
		{"an unread route is taken as 1500", withMTU(1420, false), lines("s4", "50"), v4, 0, 1390, []string{"lowered to 1390", "assumed"}, ""},
		{"the default 1280 lowered by a large S4", withMTU(nil, false), lines("s4", "200"), v4, 1500, 1240, []string{"MTU 1280 lowered to 1240"}, ""},
		{"below 1280 IPv6 inside cannot pass", withMTU(nil, true), lines("s4", "200"), v4, 1500, 1240, []string{"lowered to 1240", "IPv6 inside the tunnel"}, ""},
		{"trailers bound the server's MTU too", withMTU(1280, false), lines("s4", "50", "random_trailers", "1"), v4, 1500, 1280, []string{"server's MTU must be at most 1406"}, ""},
		{"content padding does as well", withMTU(1280, false), lines("s4", "50", "content_padding_addition", "8-16"), v4, 1500, 1280, []string{"at most 1406"}, ""},
		{"trailers off say nothing", withMTU(1280, false), lines("s4", "50", "random_trailers", "0", "content_padding_addition", "0"), v4, 1500, 1280, nil, ""},
		{"a nonsense MTU falls back to 1280", withMTU("abc", false), nil, v4, 1500, 1280, nil, ""},
		{"no room left is refused", withMTU(nil, false), lines("s4", "1000"), v4, 1500, 0, nil, "S4 1000 leaves 440 bytes of a 1500-byte path"},
	} {
		mtu, note, err := awgUserspaceMTU(c.e, c.lines, c.peer, c.path)
		if c.refused != "" {
			if err == nil || !strings.Contains(err.Error(), c.refused) {
				t.Errorf("%s: err %v, want %q", c.name, err, c.refused)
			}
			continue
		}
		if err != nil || mtu != c.mtu {
			t.Errorf("%s: mtu %d err %v, want %d", c.name, mtu, err, c.mtu)
		}
		if len(c.note) == 0 && note != "" {
			t.Errorf("%s: note %q, want none", c.name, note)
		}
		for _, sub := range c.note {
			if !strings.Contains(note, sub) {
				t.Errorf("%s: note %q lacks %q", c.name, note, sub)
			}
		}
	}
}

// `ip route get` as iproute2 and busybox print it: the route's own mtu first, then the device's.
func TestRouteGetMTU(t *testing.T) {
	devs := map[string]int{"wan": 1492, "eth0": 1500}
	devMTU := func(dev string) int { return devs[dev] }
	for _, c := range []struct {
		out  string
		want int
	}{
		{"203.0.113.5 via 192.0.2.1 dev wan src 192.0.2.2 uid 0 \n    cache \n", 1492},
		{"203.0.113.5 via 192.0.2.1 dev eth0 src 192.0.2.2 uid 0 \n    cache expires 580sec mtu 1400 \n", 1400},
		{"203.0.113.5 via 192.0.2.1 dev eth0 src 192.0.2.2 \n    cache  mtu lock 1300\n", 1300},
		{"203.0.113.5 via 192.0.2.1 dev eth0  src 192.0.2.2\n", 1500},
		{"2001:db8::1 from :: via fe80::1 dev wan proto ra src 2001:db8:1::2 metric 1024 pref medium\n", 1492},
		{"203.0.113.5 dev ppp9 src 10.0.0.2\n", 0},
		{"RTNETLINK answers: Network is unreachable\n", 0},
		{"", 0},
	} {
		if got := routeGetMTU(c.out, devMTU); got != c.want {
			t.Errorf("routeGetMTU(%q) = %d, want %d", c.out, got, c.want)
		}
	}
}
