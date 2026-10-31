package tgbridge

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/plugin"
	"wayhop/internal/updater"
)

// TestTGBridgeLive runs the real tg-ws-proxy with the argv and environment the daemon builds,
// through the plugin manager's service path, and stops it. WR_TGWSPROXY names a tg-ws-proxy binary
// (upstream's static musl build). It needs no internet: it proves the binary accepts the flags,
// listens where it is told, takes the secret from its environment, and that a bridge which cannot
// bind leaves the reason where the API reads it. Run as root on Linux it also checks the uid and
// that the secret is not on the command line.
func TestTGBridgeLive(t *testing.T) {
	src := os.Getenv("WR_TGWSPROXY")
	if src == "" {
		t.Skip("WR_TGWSPROXY not set — point it at a tg-ws-proxy binary to run it for real")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	// A root-only directory, like a router's: the launcher must stage a copy the uid can execute.
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, BinName), raw, 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(filepath.Join(binDir, BinName), "--version").CombinedOutput()
	t.Logf("--version: %q", strings.TrimSpace(string(out)))
	if updater.ParseVersion(string(out)) == "" {
		t.Errorf("--version printed no version the updater can read: %q", out)
	}

	loop := netip.MustParseAddr("127.0.0.1")
	port := freePort(t)
	secret, _ := config.NewTelegramBridgeSecret()
	args, err := Args(Settings{Listen: loop, Port: port, CFDomain: "proxy.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	m := plugin.New(t.TempDir(), binDir)
	t.Cleanup(m.StopAll)
	m.RunService("telegram-bridge", &plugin.ServiceSpec{Bin: BinName, Args: args, Env: Env(secret), UID: UID, Scrub: []string{secret}})
	addr := net.JoinHostPort(loop.String(), strconv.Itoa(port))
	if !waitListening(addr) {
		st, _ := m.ServiceStatus("telegram-bridge")
		t.Fatalf("tg-ws-proxy did not listen on %s: %+v", addr, st)
	}
	if st, _ := m.ServiceStatus("telegram-bridge"); !st.Running || st.Exits != 0 {
		t.Fatalf("status = %+v", st)
	}
	t.Logf("listening on %s with %q", addr, args)
	if runtime.GOOS == "linux" {
		pid := pidWithArg(t, "--port", strconv.Itoa(port))
		cmdline, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		if strings.Contains(string(cmdline), secret) {
			t.Error("the secret is on the command line")
		}
		if os.Geteuid() == 0 {
			status, _ := os.ReadFile("/proc/" + pid + "/status")
			if !strings.Contains(string(status), "Uid:\t"+strconv.Itoa(UID)+"\t") {
				t.Errorf("not running as uid %d:\n%s", UID, status)
			}
			env, _ := os.ReadFile("/proc/" + pid + "/environ")
			if !strings.Contains(string(env), "TG_SECRET="+secret) {
				t.Error("TG_SECRET is not in its environment")
			}
		}
	}
	m.RunService("telegram-bridge", nil)
	time.Sleep(300 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Error("still listening after the service was stopped")
	}

	// A port somebody else holds: the bridge exits, and says why where the API reads it.
	held, err := net.Listen("tcp", net.JoinHostPort(loop.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	busy := held.Addr().(*net.TCPAddr).Port
	args, _ = Args(Settings{Listen: loop, Port: busy})
	m.RunService("telegram-bridge", &plugin.ServiceSpec{Bin: BinName, Args: args, Env: Env(secret), UID: UID, Scrub: []string{secret}})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m.Supervise()
		if st, _ := m.ServiceStatus("telegram-bridge"); st.Exits > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := m.ServiceStatus("telegram-bridge")
	t.Logf("on a held port: %+v", st)
	if st.Exits == 0 || !strings.Contains(st.LastOutput, strconv.Itoa(busy)) {
		t.Fatalf("a bridge that cannot bind left no reason: %+v", st)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(addr string) bool {
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// pidWithArg finds the process whose argv holds flag followed by value.
func pidWithArg(t *testing.T, flag, value string) string {
	t.Helper()
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		b, _ := os.ReadFile("/proc/" + d.Name() + "/cmdline")
		if strings.Contains(string(b), flag+"\x00"+value+"\x00") {
			return d.Name()
		}
	}
	t.Fatalf("no process with %s %s", flag, value)
	return ""
}
