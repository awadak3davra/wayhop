package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/qr"
	"wayhop/internal/tgbridge"
	"wayhop/internal/updater"
)

// tgbServer is a file-backed, non-demo server on an OpenWrt-shaped host whose br-lan holds lan (CIDR)
// and whose default route leaves by the interfaces in routes. PATH is emptied so no tg-ws-proxy is
// found unless a test installs its stub.
func tgbServer(t *testing.T, lan string, routes map[string]bool) (*Server, string) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	s, path := tgServerAt(t)
	s.cfg.Demo = false
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	s.tgBridgeAddrsOf = func(name string) ([]net.Addr, error) {
		if name != "br-lan" {
			return nil, &net.OpError{Op: "route", Err: os.ErrNotExist}
		}
		ip, n, _ := net.ParseCIDR(lan)
		n.IP = ip
		return []net.Addr{n}, nil
	}
	s.tgBridgeRoutesOf = func() map[string]bool { return routes }
	t.Cleanup(s.plugins.StopAll)
	return s, path
}

func tgbView(t *testing.T, s *Server) tgBridgeView {
	t.Helper()
	w := tgDo(t, s, http.MethodGet, "/api/telegram-bridge", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q: the link carries the secret", cc)
	}
	var v tgBridgeView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func tgbFindings(s *Server) map[string]PlanFinding {
	out := map[string]PlanFinding{}
	for _, f := range s.tgBridgeFindings() {
		out[f.ID+"/"+f.Severity] = f
	}
	return out
}

// Both routes are session-protected: the GET answer holds the secret.
func TestTelegramBridgeRoutesNeedAuth(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	_ = authenticatedTestHandler(t, s) // configures auth; the requests below carry no session
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(method, "http://127.0.0.1/api/telegram-bridge", strings.NewReader(`{"enabled":true}`))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a session = %d", method, w.Code)
		}
	}
	if s.config().TelegramBridge.Enabled {
		t.Fatal("an unauthenticated PUT changed the settings")
	}
}

// Enabling makes and keeps a secret, the link names the LAN address, and the secret stays out of
// the config views and the shared export.
func TestTelegramBridgeEnableMakesSecretAndLink(t *testing.T) {
	s, path := tgbServer(t, "10.77.0.1/24", nil)
	w := tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	secret := s.config().TelegramBridge.Secret
	if !config.ValidTelegramBridgeSecret(secret) {
		t.Fatalf("secret %q", secret)
	}
	disk, err := config.Load(path)
	if err != nil || disk.TelegramBridge.Secret != secret || !disk.TelegramBridge.Enabled {
		t.Fatalf("not persisted: %+v, %v", disk.TelegramBridge, err)
	}
	v := tgbView(t, s)
	if want := "tg://proxy?server=10.77.0.1&port=1443&secret=dd" + secret; v.Link != want {
		t.Fatalf("link = %q, want %q", v.Link, want)
	}
	// The panel shows the link as a QR code too; the longest link (a 15-character address, a 5-digit
	// port) still fits the encoder's largest symbol.
	if !strings.HasPrefix(v.QRSVG, "<svg") {
		t.Fatalf("qr_svg = %.40q", v.QRSVG)
	}
	if _, err := qr.Encode(tgbridge.Link(netip.MustParseAddr("192.168.100.100"), 65535, secret)); err != nil {
		t.Fatalf("the longest link does not fit a QR code: %v", err)
	}
	if v.Listen != "10.77.0.1:1443" || v.Iface != "br-lan" || v.Running || v.Installed {
		t.Fatalf("view = %+v", v)
	}
	// The missing binary is said once, by installed: no last_error repeating it under the panel's
	// own pointer to the Components page.
	if v.LastError != "" {
		t.Fatalf("last_error = %q", v.LastError)
	}
	if _, ok := tgbFindings(s)["telegram_bridge.binary_missing/"+platform.SeverityDegraded]; !ok {
		t.Fatalf("findings = %+v", s.tgBridgeFindings())
	}
	for _, target := range []string{"/api/config", "/api/config/export"} {
		if body := tgDo(t, s, http.MethodGet, target, "").Body.String(); strings.Contains(body, secret) {
			t.Fatalf("%s returned the bridge secret", target)
		}
	}

	// Saving again keeps the secret (the link on every phone stays valid); the mask keeps it too.
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"secret":"***","port":2443}`)
	if got := s.config().TelegramBridge; got.Secret != secret || got.Port != 2443 {
		t.Fatalf("after a second save: %+v", got)
	}
	if v := tgbView(t, s); !strings.HasPrefix(v.Link, "tg://proxy?server=10.77.0.1&port=2443&") {
		t.Fatalf("link after a port change = %q", v.Link)
	}
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"regenerate_secret":true}`)
	if got := s.config().TelegramBridge.Secret; got == secret || !config.ValidTelegramBridgeSecret(got) {
		t.Fatalf("regenerate kept %q", got)
	}
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"secret":"0123456789ABCDEF0123456789ABCDEF"}`)
	if got := s.config().TelegramBridge.Secret; got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("an explicit secret was stored as %q", got)
	}
	// Turning it off keeps the secret for the next time, and reports nothing to fix.
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":false}`)
	if got := s.config().TelegramBridge; got.Enabled || got.Secret == "" {
		t.Fatalf("after disabling: %+v", got)
	}
	if v := tgbView(t, s); v.Link != "" || v.QRSVG != "" || v.LastError != "" || len(s.tgBridgeFindings()) != 0 {
		t.Fatalf("disabled view %+v, findings %+v", v, s.tgBridgeFindings())
	}
}

// The port may not be one of WayHop's own or a privileged one, and a Settings save may not move a
// WayHop port onto the running bridge's.
func TestTelegramBridgePortRules(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	for _, body := range []string{`{"enabled":true,"port":8088}`, `{"enabled":true,"port":9090}`, `{"enabled":true,"port":443}`,
		`{"enabled":true,"secret":"dd` + "0123456789abcdef0123456789abcdef" + `"}`, `{"enabled":true,"cf_domain":"https://x.example.net"}`} {
		if w := tgDo(t, s, http.MethodPut, "/api/telegram-bridge", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", body, w.Code, w.Body)
		}
	}
	if s.config().TelegramBridge.Enabled {
		t.Fatal("a refused PUT was saved")
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	cfg := s.config()
	cfg.Ports.Mixed = config.DefaultTelegramBridgePort
	cfg.TelegramBridge = config.TelegramBridge{} // the page's own copy is not what runs
	body, _ := json.Marshal(cfg)
	if w := tgDo(t, s, http.MethodPut, "/api/config", string(body)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "telegram bridge") {
		t.Fatalf("Settings PUT onto the bridge's port = %d %s", w.Code, w.Body)
	}
	if s.config().Ports.Mixed == config.DefaultTelegramBridgePort {
		t.Fatal("the refused Settings save was applied")
	}
}

// A Settings save and an import are checked against the saved bridge, never the page's copy of it,
// which was loaded whenever the page was. Here the page still holds the bridge on 7892 from before it
// was turned off; moving the mixed inbound to 7892 used to be refused for a bridge that no longer
// listened anywhere.
func TestTelegramBridgeSettingsSaveIgnoresThePagesCopy(t *testing.T) {
	s, path := tgbServer(t, "10.77.0.1/24", nil)
	for i, target := range []string{"/api/config", "/api/config/import"} {
		cfg := s.config()
		cfg.Ports.Mixed = 7892 + i
		cfg.TelegramBridge = config.TelegramBridge{Enabled: true, Port: 7892 + i, Secret: config.RedactedMark}
		body, _ := json.Marshal(cfg)
		method := http.MethodPut
		if strings.HasSuffix(target, "/import") {
			method = http.MethodPost
		}
		if w := tgDo(t, s, method, target, string(body)); w.Code != http.StatusOK {
			t.Fatalf("%s with a stale bridge copy = %d %s", target, w.Code, w.Body)
		}
		disk, err := config.Load(path)
		if err != nil || disk.Ports.Mixed != 7892+i || disk.TelegramBridge != (config.TelegramBridge{}) {
			t.Fatalf("%s saved ports %+v, bridge %+v (%v)", target, disk.Ports, disk.TelegramBridge, err)
		}
	}
}

// A reset whose default ports land on the bridge's turns the bridge off instead of saving both on
// one port. Reproduced before: mixed 7891 and the bridge on 7890, then a reset, saved mixed 7890
// beside the bridge on 7890, and an unchanged Settings round trip was refused from then on.
func TestTelegramBridgeResetOntoItsPortTurnsItOff(t *testing.T) {
	s, path := tgbServer(t, "10.77.0.1/24", nil)
	tgbStub(t, "")
	mixed := config.Default().Ports.Mixed
	cfg := s.config()
	cfg.Ports.Mixed = mixed + 1
	body, _ := json.Marshal(cfg)
	if w := tgDo(t, s, http.MethodPut, "/api/config", string(body)); w.Code != http.StatusOK {
		t.Fatalf("moving mixed = %d %s", w.Code, w.Body)
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram-bridge", fmt.Sprintf(`{"enabled":true,"port":%d}`, mixed)); w.Code != http.StatusOK {
		t.Fatalf("bridge onto the old mixed port = %d %s", w.Code, w.Body)
	}
	secret := s.config().TelegramBridge.Secret
	if st, _ := s.plugins.ServiceStatus(tgBridgeService); !st.Running {
		t.Fatal("the bridge is not running before the reset")
	}

	w := tgDo(t, s, http.MethodPost, "/api/config/reset", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"telegram_bridge_disabled":true`) {
		t.Fatalf("reset = %d %s", w.Code, w.Body)
	}
	disk, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Ports.Mixed != mixed || disk.TelegramBridge.Enabled || disk.TelegramBridge.Port != mixed || disk.TelegramBridge.Secret != secret {
		t.Fatalf("after the reset: ports %+v, bridge %+v", disk.Ports, disk.TelegramBridge)
	}
	if _, ok := s.plugins.ServiceStatus(tgBridgeService); ok {
		t.Fatal("the bridge turned off by the reset is still running")
	}

	// The Settings page's round trip saves unchanged.
	get := tgDo(t, s, http.MethodGet, "/api/config", "")
	if w := tgDo(t, s, http.MethodPut, "/api/config", get.Body.String()); w.Code != http.StatusOK {
		t.Fatalf("unchanged GET->PUT after the reset = %d %s", w.Code, w.Body)
	}

	// A reset that collides with nothing leaves the bridge alone.
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"port":2443}`)
	w = tgDo(t, s, http.MethodPost, "/api/config/reset", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "telegram_bridge_disabled") {
		t.Fatalf("second reset = %d %s", w.Code, w.Body)
	}
	if got := s.config().TelegramBridge; !got.Enabled || got.Port != 2443 {
		t.Fatalf("a reset with no clash changed the bridge: %+v", got)
	}
	// A bridge block its own endpoint would refuse (only a hand edit makes one) does not stop a reset.
	s.cfgMu.Lock()
	s.cfg.TelegramBridge.CFDomain = "https://proxy.example.net/x"
	s.cfgMu.Unlock()
	if w := tgDo(t, s, http.MethodPost, "/api/config/reset", ""); w.Code != http.StatusOK {
		t.Fatalf("reset with a hand-edited bridge = %d %s", w.Code, w.Body)
	}
}

// A bridge an earlier daemon left running is ended before anything syncs, also when the bridge is
// off now: turning it off (or regenerating the secret) must reach a leftover still serving the old
// secret. The loop's channel closes once it has stopped, which the daemon waits for before StopAll.
func TestTelegramBridgeStartReapsLeftoverFirst(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	var order []string
	s.tgBridgeReapOf = func() { order = append(order, "reap") }
	ctx, cancel := context.WithCancel(context.Background())
	done := s.StartTelegramBridge(ctx)
	// Synchronous, so it is done before the daemon serves a save that could sync.
	if !slices.Equal(order, []string{"reap"}) {
		t.Fatalf("calls before StartTelegramBridge returned: %v", order)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the bridge loop did not stop with its context")
	}
}

// After StopAll (the daemon's shutdown) a save that syncs the bridge starts nothing: a process
// started then would be tracked by nobody and outlive the daemon.
func TestTelegramBridgeNotStartedAfterShutdown(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	tgbStub(t, "")
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	if st, _ := s.plugins.ServiceStatus(tgBridgeService); !st.Running {
		t.Fatal("the bridge did not start")
	}
	s.plugins.StopAll()
	// A changed port is a new spec: before StopAll closed the manager this started a new process.
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"port":2443}`)
	if st, ok := s.plugins.ServiceStatus(tgBridgeService); ok {
		t.Fatalf("a sync after StopAll started the bridge: %+v", st)
	}
}

// A LAN bridge with a public address is refused, and the review says so.
func TestTelegramBridgeRefusesAPublicAddress(t *testing.T) {
	s, _ := tgbServer(t, "203.0.113.5/24", nil)
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	v := tgbView(t, s)
	if v.Running || v.Link != "" || !v.PublicAddress || !strings.Contains(v.LastError, "public address") {
		t.Fatalf("view = %+v", v)
	}
	if _, ok := s.plugins.ServiceStatus(tgBridgeService); ok {
		t.Fatal("a service was started for a public address")
	}
	// The binary-missing finding names the first thing to fix; with the binary there, this one shows.
	tgbStub(t, "")
	s.syncTelegramBridge()
	f, ok := tgbFindings(s)["telegram_bridge.wan_listener/"+platform.SeverityDegraded]
	if !ok || !strings.Contains(f.Detail, "203.0.113.5") || f.Blocks != platform.BlocksNothing {
		t.Fatalf("findings = %+v", s.tgBridgeFindings())
	}
}

// tgbStubSource records its argv and the secret's arrival, then blocks; with TGB_STUB_EXIT set it
// prints that and exits 1, like a bridge whose port is taken.
const tgbStubSource = `package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if out := os.Getenv("TGB_STUB_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(os.Args[1:], " ")+"\n"+os.Getenv("TG_SECRET")), 0o600)
	}
	if msg := os.Getenv("TGB_STUB_EXIT"); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	for {
		time.Sleep(time.Hour)
	}
}
`

// Resolve Go at package init: tgbServer deliberately empties PATH before tgbStub builds its binary.
var tgbGoBin = func() string {
	if home, err := os.UserHomeDir(); err == nil {
		exe := ""
		if runtime.GOOS == "windows" {
			exe = ".exe"
		}
		if c := filepath.Join(home, "go-toolchain", "go", "bin", "go"+exe); tgbFileExists(c) {
			return c
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return ""
}()

// tgbStub builds the stub as tg-ws-proxy into a directory on PATH (resolve's PATH fallback is what
// finds tg-ws-proxy.exe on Windows) and returns the file its argv is recorded in.
func tgbStub(t *testing.T, exitMsg string) string {
	t.Helper()
	goBin := tgbGoBin
	if goBin == "" {
		t.Skip("no Go toolchain to build the bridge stub")
	}
	src, bin := t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "main.go"), []byte(tgbStubSource), 0o600)
	_ = os.WriteFile(filepath.Join(src, "go.mod"), []byte("module tgbstub\n\ngo 1.22\n"), 0o600)
	name := tgbridge.BinName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	// cgo off: PATH holds only Go's directory here, and on Linux a cgo build then cannot find gcc.
	cmd := exec.Command(goBin, "build", "-o", filepath.Join(bin, name), ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on", "CGO_ENABLED=0", "PATH="+filepath.Dir(goBin))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build the bridge stub: %v\n%s", err, out)
	}
	t.Setenv("PATH", bin)
	out := filepath.Join(t.TempDir(), "argv")
	t.Setenv("TGB_STUB_OUT", out)
	t.Setenv("TGB_STUB_EXIT", exitMsg)
	return out
}

func tgbFileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// With the binary there the bridge runs on the LAN address, unprivileged, with the secret in its
// environment and not on its command line; turning it off stops it.
func TestTelegramBridgeRunsAndStops(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	argvFile := tgbStub(t, "")
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true,"cf_domain":"Proxy.Example.net"}`)
	secret := s.config().TelegramBridge.Secret
	v := tgbView(t, s)
	if !v.Running || !v.Installed || v.LastError != "" || v.CrashLoop {
		t.Fatalf("view = %+v", v)
	}
	var rec []byte
	deadline := time.Now().Add(10 * time.Second)
	for len(rec) == 0 && time.Now().Before(deadline) {
		rec, _ = os.ReadFile(argvFile)
		time.Sleep(10 * time.Millisecond)
	}
	lines := strings.SplitN(string(rec), "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("the stub recorded %q", rec)
	}
	if want := "--host 10.77.0.1 --port 1443 --quiet --cf-domain proxy.example.net"; lines[0] != want {
		t.Fatalf("argv = %q, want %q", lines[0], want)
	}
	if lines[1] != secret || strings.Contains(lines[0], secret) {
		t.Fatalf("the secret must arrive in TG_SECRET only: argv %q, env %q", lines[0], lines[1])
	}
	if len(s.tgBridgeFindings()) != 0 {
		t.Fatalf("findings for a running bridge: %+v", s.tgBridgeFindings())
	}
	// A periodic sync with nothing changed leaves the running process alone.
	s.syncTelegramBridge()
	if st, _ := s.plugins.ServiceStatus(tgBridgeService); !st.Running {
		t.Fatal("a sync with nothing changed stopped it")
	}
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":false}`)
	if _, ok := s.plugins.ServiceStatus(tgBridgeService); ok {
		t.Fatal("disabling did not stop the service")
	}
}

// A bridge that keeps exiting is a review finding carrying the reason it printed.
func TestTelegramBridgeCrashLoopFinding(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", map[string]bool{"br-lan": true})
	tgbStub(t, "failed to bind 10.77.0.1:1443: Address in use (os error 98)")
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	for i := 0; i < tgBridgeCrashExits; i++ {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if st, _ := s.plugins.ServiceStatus(tgBridgeService); !st.Running {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		s.plugins.Supervise()
	}
	got := tgbFindings(s)
	f, ok := got["telegram_bridge.crash_loop/"+platform.SeverityDegraded]
	if !ok || !strings.Contains(f.Detail, "Address in use") {
		t.Fatalf("findings = %+v", s.tgBridgeFindings())
	}
	// The LAN bridge carries the default route here: said, as a privacy note.
	if _, ok := got["telegram_bridge.wan_listener/"+platform.SeverityPrivacy]; !ok {
		t.Fatalf("no uplink finding: %+v", s.tgBridgeFindings())
	}
	if v := tgbView(t, s); v.Exits < tgBridgeCrashExits || v.LastExit == "" || !v.Uplink {
		t.Fatalf("view = %+v", v)
	}
	// The findings reach the review the operator reads.
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, f := range plan.Findings {
		ids = append(ids, f.ID)
	}
	if !slices.Contains(ids, "telegram_bridge.crash_loop") {
		t.Fatalf("review findings = %v", ids)
	}
}

// The API's crash_loop is the review finding's own rule (tgBridgeCrashLoop): set in the GET and the
// PUT answers while the finding stands, also while the process happens to be up between two restarts
// (the moment the Settings card read as a green "running"), and clear once the bridge is turned off.
func TestTelegramBridgeCrashLoopFlag(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		exits int
		ago   time.Duration
		want  bool
	}{
		{tgBridgeCrashExits - 1, time.Second, false},
		{tgBridgeCrashExits, time.Second, true},
		{tgBridgeCrashExits + 2, tgBridgeCrashWindow - time.Second, true},
		{tgBridgeCrashExits, tgBridgeCrashWindow, false},
	} {
		if got := tgBridgeCrashLoop(c.exits, now.Add(-c.ago), now); got != c.want {
			t.Errorf("%d exits, the last %s ago: crash loop %v, want %v", c.exits, c.ago, got, c.want)
		}
	}
	if tgBridgeCrashLoop(tgBridgeCrashExits, time.Time{}, now) {
		t.Error("a crash loop without a last exit")
	}

	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	tgbStub(t, "failed to bind 10.77.0.1:1443: Address in use (os error 98)")
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	if v := tgbView(t, s); v.CrashLoop {
		t.Fatalf("crash_loop before any exit: %+v", v)
	}
	deadline := time.Now().Add(20 * time.Second)
	status := func() plugin.ServiceStatus {
		t.Helper()
		if time.Now().After(deadline) {
			t.Fatal("the stub did not reach the state the test waits for")
		}
		st, _ := s.plugins.ServiceStatus(tgBridgeService)
		return st
	}
	for st := status(); st.Exits < tgBridgeCrashExits; st = status() {
		if !st.Running {
			s.plugins.Supervise()
		}
		time.Sleep(5 * time.Millisecond)
	}
	// From here the stub starts and stays up: the next start is the bridge alive between restarts.
	t.Setenv("TGB_STUB_EXIT", "")
	for {
		st := status()
		if !st.Running {
			s.plugins.Supervise()
			time.Sleep(5 * time.Millisecond)
			continue
		}
		time.Sleep(500 * time.Millisecond)
		if again := status(); again.Running && again.Exits == st.Exits {
			break
		}
	}
	v := tgbView(t, s)
	if !v.Running || !v.CrashLoop || !strings.Contains(v.LastError, "Address in use") {
		t.Fatalf("a bridge up between the restarts of a crash loop: %+v", v)
	}
	if _, ok := tgbFindings(s)["telegram_bridge.crash_loop/"+platform.SeverityDegraded]; !ok {
		t.Fatalf("crash_loop set without the finding: %+v", s.tgBridgeFindings())
	}
	// A save's answer carries it too: the same settings saved again keep the process and its count.
	w := tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	var put tgBridgeView
	if err := json.Unmarshal(w.Body.Bytes(), &put); w.Code != http.StatusOK || err != nil || !put.CrashLoop {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":false}`)
	if v := tgbView(t, s); v.CrashLoop || len(s.tgBridgeFindings()) != 0 {
		t.Fatalf("turned off: %+v, findings %+v", v, s.tgBridgeFindings())
	}
}

// The Components row names the bridge as what needs the binary, while it is enabled.
func TestTelegramBridgeComponentUsedBy(t *testing.T) {
	s, _ := tgbServer(t, "10.77.0.1/24", nil)
	usedBy := func() []string {
		w := tgDo(t, s, http.MethodGet, "/api/updater/engines", "")
		var resp struct {
			Engines []struct {
				ID     string   `json:"id"`
				UsedBy []string `json:"used_by"`
			} `json:"engines"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		for _, e := range resp.Engines {
			if e.ID == tgBridgeEngineID {
				return e.UsedBy
			}
		}
		t.Fatalf("no %s row: %s", tgBridgeEngineID, w.Body)
		return nil
	}
	s.updater = updater.New(t.TempDir(), "arm64", nil)
	s.updater.Offline = true
	if got := usedBy(); len(got) != 0 {
		t.Fatalf("used_by while off = %v", got)
	}
	tgDo(t, s, http.MethodPut, "/api/telegram-bridge", `{"enabled":true}`)
	if got := usedBy(); !slices.Equal(got, []string{"Telegram bridge"}) {
		t.Fatalf("used_by = %v", got)
	}
}
