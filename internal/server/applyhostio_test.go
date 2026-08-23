package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunHostCommandBounded_Timeout(t *testing.T) {
	setApplyHostIOHelper(t)
	started := time.Now()
	_, err := runHostCommandBounded(
		context.Background(), 100*time.Millisecond, 8<<10, 100*time.Millisecond,
		os.Args[0], "-test.run=^TestApplyHostIOHelperProcess$", "--", "hang",
	)
	if !errors.Is(err, errApplyHostCommandTimeout) {
		t.Fatalf("error = %v, want fixed timeout sentinel", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v; command was not context-bounded", elapsed)
	}
}

func TestRunHostCommandBounded_OutputCap(t *testing.T) {
	setApplyHostIOHelper(t)
	_, err := runHostCommandBounded(
		context.Background(), 2*time.Second, 4<<10, 100*time.Millisecond,
		os.Args[0], "-test.run=^TestApplyHostIOHelperProcess$", "--", "flood",
	)
	if !errors.Is(err, errApplyHostCommandOutput) {
		t.Fatalf("error = %v, want fixed output-limit sentinel", err)
	}
}

func TestRunHostCommandBounded_DescendantPipeHasWaitBound(t *testing.T) {
	setApplyHostIOHelper(t)
	started := time.Now()
	_, err := runHostCommandBounded(
		context.Background(), 2*time.Second, 8<<10, 100*time.Millisecond,
		os.Args[0], "-test.run=^TestApplyHostIOHelperProcess$", "--", "descendant",
	)
	if !errors.Is(err, errApplyHostCommandPipes) {
		t.Fatalf("error = %v, want fixed inherited-pipe sentinel", err)
	}
	// A -race child has an approximately one-second exit delay of its own. Stay below the
	// command's two-second deadline while allowing that instrumentation overhead.
	if elapsed := time.Since(started); elapsed > 1800*time.Millisecond {
		t.Fatalf("inherited pipe held Wait for %v; WaitDelay was not effective", elapsed)
	}
}

func setApplyHostIOHelper(t *testing.T) {
	t.Helper()
	t.Setenv("WAYHOP_APPLYHOSTIO_HELPER", "1")
}

// TestApplyHostIOHelperProcess supplies portable child behaviors without depending on a shell. The
// descendant case exits its direct child successfully while a grandchild keeps both pipes open.
func TestApplyHostIOHelperProcess(t *testing.T) {
	if os.Getenv("WAYHOP_APPLYHOSTIO_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "hang", "sleeper":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "flood":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 256<<10)))
		os.Exit(0)
	case "descendant":
		var child *exec.Cmd
		if runtime.GOOS == "windows" {
			// A grandchild running this same *.test.exe would keep the image locked after the parent
			// test exits, and `go test` could not remove it. cmd.exe is a separate disposable image
			// while still exercising an inherited stdout/stderr pipe.
			child = exec.Command("cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul")
		} else {
			child = exec.Command(os.Args[0], "-test.run=^TestApplyHostIOHelperProcess$", "--", "sleeper")
		}
		child.Env = os.Environ()
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, "direct child exited")
		os.Exit(0)
	default:
		os.Exit(3)
	}
}

func TestReadApplyHostConntrackReader_StopsAt400Lines(t *testing.T) {
	var all strings.Builder
	for i := 0; i < 1000; i++ {
		_, _ = fmt.Fprintf(&all, "flow-%04d [HW_OFFLOAD] mark=0 use=1\n", i)
	}
	source := []byte(all.String())
	counting := &applyHostCountingReader{data: source, chunk: 113}
	sample, err := readApplyHostConntrackReader(
		context.Background(), counting, applyHostConntrackLines, applyHostConntrackBytes,
	)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	if got := strings.Count(sample, "\n"); got != 400 {
		t.Fatalf("sampled lines = %d, want 400", got)
	}
	if !strings.Contains(sample, "flow-0399") || strings.Contains(sample, "flow-0400") {
		t.Fatalf("sample did not stop at the 400-line boundary")
	}
	if counting.read >= len(source) {
		t.Fatalf("reader consumed %d of %d bytes; conntrack was read wholesale", counting.read, len(source))
	}
}

type applyHostCountingReader struct {
	data  []byte
	read  int
	chunk int
}

func (r *applyHostCountingReader) Read(p []byte) (int, error) {
	if r.read == len(r.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data)-r.read {
		n = len(r.data) - r.read
	}
	copy(p, r.data[r.read:r.read+n])
	r.read += n
	return n, nil
}

func TestProbeAutoOffloadDevicesWithIO_ParsesAndDeduplicates(t *testing.T) {
	host := inertApplyHostIO()
	host.runCommand = func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ip -o route show default":
			return "default via 192.0.2.1 dev wan src 192.0.2.2\n", nil
		case "ip -o link show type bridge":
			return "3: br-lan: <UP> mtu 1500\n5: wan: <UP> mtu 1500\n7: br0@eth0: <UP>\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}
	devices, probeErrors := probeAutoOffloadDevicesWithIO(context.Background(), host)
	if len(probeErrors) != 0 {
		t.Fatalf("probe errors = %v", probeErrors)
	}
	want := []string{"wan", "br-lan", "br0"}
	if strings.Join(devices, ",") != strings.Join(want, ",") {
		t.Fatalf("devices = %v, want %v", devices, want)
	}
}

func TestProbeAutoOffloadDevicesWithIO_UsesSysfsFallback(t *testing.T) {
	netDir := t.TempDir()
	for _, name := range []string{"eth0", "br-guest", "br-lan"} {
		if err := os.Mkdir(filepath.Join(netDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"br-guest", "br-lan"} {
		if err := os.Mkdir(filepath.Join(netDir, name, "bridge"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	host := inertApplyHostIO()
	host.sysClassNetPath = netDir
	host.readDir = os.ReadDir
	host.stat = os.Stat
	host.runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-o route show default" {
			return "default dev eth0 scope link\n", nil
		}
		return "", errors.New("ip bridge enumeration unsupported: secret host detail")
	}
	devices, probeErrors := probeAutoOffloadDevicesWithIO(context.Background(), host)
	if len(probeErrors) != 0 {
		t.Fatalf("successful sysfs fallback left probe errors: %v", probeErrors)
	}
	want := []string{"eth0", "br-guest", "br-lan"}
	if strings.Join(devices, ",") != strings.Join(want, ",") {
		t.Fatalf("devices = %v, want %v", devices, want)
	}
}

func TestProbeAutoOffloadDevicesWithIO_ReturnsOnlyFixedErrors(t *testing.T) {
	host := inertApplyHostIO()
	host.runCommand = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("secret command and path")
	}
	host.readDir = func(string) ([]os.DirEntry, error) {
		return nil, errors.New("secret sysfs path")
	}
	_, probeErrors := probeAutoOffloadDevicesWithIO(context.Background(), host)
	joined := strings.Join(probeErrors, ";")
	if strings.Contains(joined, "secret") {
		t.Fatalf("raw probe detail escaped: %q", joined)
	}
	if !strings.Contains(joined, applyHostDefaultRouteError) || !strings.Contains(joined, applyHostBridgeDevicesError) {
		t.Fatalf("probe errors = %v, want fixed route and bridge errors", probeErrors)
	}
}

func TestProbeAutoOffloadDevicesWithIO_FailsClosedWithoutDefaultRoute(t *testing.T) {
	host := inertApplyHostIO()
	host.runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-o route show default" {
			return "", nil
		}
		return "", nil
	}
	host.readDir = func(string) ([]os.DirEntry, error) { return []os.DirEntry{}, nil }

	devices, probeErrors := probeAutoOffloadDevicesWithIO(context.Background(), host)
	if len(devices) != 0 {
		t.Fatalf("devices = %v, want none without a default route", devices)
	}
	if strings.Join(probeErrors, ";") != applyHostDefaultRouteAbsent {
		t.Fatalf("probe errors = %v, want fixed absent-route verdict", probeErrors)
	}
}

func TestObserveEffectiveOffloadWithIO_UsesBoundedFreshInputs(t *testing.T) {
	dir := t.TempDir()
	paths := map[string]string{
		"firewall":  filepath.Join(dir, "firewall"),
		"ppe":       filepath.Join(dir, "ppe_enabled"),
		"fastnat":   filepath.Join(dir, "fastnat"),
		"conntrack": filepath.Join(dir, "conntrack"),
	}
	mustWriteApplyHostIOFile(t, paths["firewall"], "config defaults\n\toption flow_offloading '1'\n\toption flow_offloading_hw '1'\n")
	mustWriteApplyHostIOFile(t, paths["ppe"], "1\n")
	mustWriteApplyHostIOFile(t, paths["fastnat"], "1\n")
	var conntrack strings.Builder
	for i := 0; i < 600; i++ {
		_, _ = fmt.Fprintf(&conntrack, "ipv4 2 tcp 6 100 ESTABLISHED id=%d [HW_OFFLOAD] mark=0 use=1\n", i)
	}
	mustWriteApplyHostIOFile(t, paths["conntrack"], conntrack.String())

	host := inertApplyHostIO()
	host.openFile = func(path string) (io.ReadCloser, error) { return os.Open(path) }
	host.firewallPath = paths["firewall"]
	host.ppePath = paths["ppe"]
	host.fastNATPath = paths["fastnat"]
	host.conntrackPath = paths["conntrack"]
	host.runCommand = func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "nft list flowtables":
			return "table inet fw4 { flowtable ft { flags offload; } }\n", nil
		case "nft list table inet wayhop_pbr":
			return "table inet wayhop_pbr { chain prerouting { } }\n", nil
		default:
			return "", errors.New("unexpected command")
		}
	}
	state, probeErrors := observeEffectiveOffloadWithIO(context.Background(), "hw", "wayhop_pbr", host)
	if len(probeErrors) != 0 {
		t.Fatalf("probe errors = %v", probeErrors)
	}
	if state.Effective != "hw" || state.FlowsTotal != 400 || state.FlowsHW != 400 {
		t.Fatalf("state = %+v, want 400 sampled hardware-offloaded flows", state)
	}
	if !state.FlowtableHW || !state.PPEEnabled || !state.FastNATOn || !state.MarkedPlane {
		t.Fatalf("decision-bearing evidence missing: %+v", state)
	}
}

func TestObserveEffectiveOffloadWithIO_FailsUnknownWithSafeErrors(t *testing.T) {
	host := inertApplyHostIO()
	host.runCommand = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("secret command output")
	}
	host.openFile = func(string) (io.ReadCloser, error) {
		return nil, errors.New("secret filesystem path")
	}
	state, probeErrors := observeEffectiveOffloadWithIO(context.Background(), "hw", "wayhop_pbr", host)
	if state.Effective != "unknown" {
		t.Fatalf("effective = %q, want unknown without evidence", state.Effective)
	}
	joined := strings.Join(probeErrors, ";")
	if strings.Contains(joined, "secret") {
		t.Fatalf("raw probe detail escaped: %q", joined)
	}
	for _, want := range []string{
		applyHostFlowtableError,
		applyHostFirewallOffloadError,
		applyHostPPEError,
		applyHostFastNATError,
		applyHostConntrackError,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("probe errors = %v, missing %q", probeErrors, want)
		}
	}
}

func inertApplyHostIO() applyHostIO {
	return applyHostIO{
		runCommand: func(context.Context, string, ...string) (string, error) {
			return "", errors.New("unexpected command")
		},
		openFile: func(string) (io.ReadCloser, error) { return nil, os.ErrNotExist },
		readDir:  func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
		stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
}

func mustWriteApplyHostIOFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
