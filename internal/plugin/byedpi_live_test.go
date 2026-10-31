package plugin

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
)

// TestByeDPILive starts the real ciadpi through the plugin manager and fetches a page through it,
// then stops it. WR_BYEDPI names a ciadpi binary (upstream's static build); it needs the internet.
// Run as root on Linux it also checks that ciadpi runs as the uid the TUN excludes.
func TestByeDPILive(t *testing.T) {
	src := os.Getenv("WR_BYEDPI")
	if src == "" {
		t.Skip("WR_BYEDPI not set — point it at a ciadpi binary to run it for real")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	// A root-only directory, like a router's: the launcher must stage a copy the uid can execute.
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ciadpi"), raw, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	m := New(t.TempDir(), binDir)
	spec := Spec{ID: "bye", SOCKSPort: port, Endpoint: model.Endpoint{ID: "bye", Engine: model.EngineByeDPI, Enabled: true}}
	m.Sync([]Spec{spec})
	t.Cleanup(func() { m.Sync(nil) })
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	up := false
	for i := 0; i < 50 && !up; i++ {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			up = true
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !up {
		t.Fatalf("ciadpi did not start listening on %s: %+v", addr, m.Status())
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: addr})}}
	resp, err := client.Get("https://www.example.com/")
	if err != nil {
		t.Fatalf("a request through ciadpi failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d through ciadpi", resp.StatusCode)
	}
	t.Logf("through ciadpi on %s: %s; status %+v", addr, resp.Status, m.Status())
	if uid, ok := ciadpiUID(port); ok && os.Geteuid() == 0 && uid != strconv.Itoa(model.ByeDPIUID) {
		t.Errorf("ciadpi runs as uid %s, want %d (the uid the TUN excludes)", uid, model.ByeDPIUID)
	} else if ok {
		t.Logf("ciadpi uid %s", uid)
	}

	m.Sync(nil)
	time.Sleep(300 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Error("ciadpi is still listening after the connection was removed")
	}
}

// ciadpiUID finds the ciadpi listening on port in /proc and returns its real uid (Linux only).
func ciadpiUID(port int) (string, bool) {
	dirs, _ := os.ReadDir("/proc")
	want := "-p\x00" + strconv.Itoa(port) + "\x00"
	for _, d := range dirs {
		cmd, err := os.ReadFile(filepath.Join("/proc", d.Name(), "cmdline"))
		if err != nil || !strings.Contains(string(cmd), want) || !strings.Contains(string(cmd), "ciadpi") {
			continue
		}
		st, err := os.ReadFile(filepath.Join("/proc", d.Name(), "status"))
		if err != nil {
			return "", false
		}
		for _, line := range strings.Split(string(st), "\n") {
			if f := strings.Fields(line); len(f) > 1 && f[0] == "Uid:" {
				return f[1], true
			}
		}
	}
	return "", false
}
