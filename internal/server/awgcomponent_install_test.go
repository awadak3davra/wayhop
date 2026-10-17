package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/updater"
)

// awgFeedFake is the installer as a test arranges it: it records each argv and answers with the
// verdict queued for that operation.
type awgFeedFake struct {
	calls   [][]string
	verdict map[string]string // "plan" | "install" | "uninstall" -> last stdout line
	code    map[string]int
}

func (f *awgFeedFake) run(_ context.Context, argv []string) (updater.AWGOutput, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	op := "install"
	switch args := strings.Join(argv, " "); {
	case strings.Contains(args, "--dry-run"):
		op = "plan"
	case strings.Contains(args, "--uninstall"):
		op = "uninstall"
	}
	v := f.verdict[op] + "\n"
	return updater.AWGOutput{Stdout: []byte(v), Combined: []byte("install-awg.sh: working\n" + v), ExitCode: f.code[op]}, nil
}

func (f *awgFeedFake) lastArgs() string {
	if len(f.calls) == 0 {
		return ""
	}
	return strings.Join(f.calls[len(f.calls)-1][2:], " ")
}

// awgFeedServer is a server on platform p whose installer is f and whose probe answers probe.
func awgFeedServer(t *testing.T, p platform.Platform, probe awg.Probe, f *awgFeedFake) *Server {
	t.Helper()
	s := updaterinstall_serverWithUpdater(t, "arm64")
	s.updater.RunDir = t.TempDir()
	s.updater.WithAWGRunner(f.run)
	s.platformOf = func() platform.Platform { return p }
	s.awgProbeOf = func() awg.Probe { return probe }
	old := awgEntwareOpkg
	awgEntwareOpkg = filepath.Join(t.TempDir(), "no-opkg")
	t.Cleanup(func() { awgEntwareOpkg = old })
	return s
}

func awgCall(s *Server, method, id, body string) *httptest.ResponseRecorder {
	h := map[string]http.HandlerFunc{http.MethodGet: s.handleUpdaterFit, http.MethodPost: s.handleUpdaterInstall,
		http.MethodDelete: s.handleUpdaterUninstall}[method]
	req := httptest.NewRequest(method, "/api/updater/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

const (
	awgPlanKmod    = `{"result":"dry-run","path":"kmod","packages":["kmod-amneziawg","amneziawg-tools"],"generation":"3.1","reason":"the feed has a kmod for kernel 6.6.73"}`
	awgPlanUser    = `{"result":"dry-run","path":"userspace","packages":["amneziawg-go"],"generation":"3.1","profile":"lowmem","mem_total_kib":131072}`
	awgInstallKmod = `{"result":"installed","path":"kmod","packages":["kmod-amneziawg","amneziawg-tools"],"generation":"3.1"}`
)

// The plan is the installer's dry run, under the pseudo-engine "awg" on the /fit route: auto on
// OpenWrt, held to userspace on KeeneticOS, and not offered where the installer does not apply.
func TestAWGFeedPlan(t *testing.T) {
	f := &awgFeedFake{verdict: map[string]string{"plan": awgPlanKmod}}
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{Kernel: awg.Gen2, TUN: true}, f)
	w := awgCall(s, http.MethodGet, "awg", "")
	var ans awgFeedAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &ans); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %v: %s", w.Code, err, w.Body.String())
	}
	if f.lastArgs() != "--dry-run --json" || !ans.Installable || ans.Run.Path != updater.AWGPathKmod || ans.Fallback {
		t.Errorf("OpenWrt plan: args %q, answer %+v", f.lastArgs(), ans)
	}
	if !strings.Contains(ans.Summary, "kernel module AmneziaWG 3.1 for this OpenWrt release, about 0.3 MB of flash (kmod-amneziawg, amneziawg-tools): the feed has a kmod") {
		t.Errorf("summary %q", ans.Summary)
	}

	f = &awgFeedFake{verdict: map[string]string{"plan": awgPlanUser}}
	s = awgFeedServer(t, platform.Keenetic, awg.Probe{Kernel: awg.Gen2, TUN: true}, f)
	if w := awgCall(s, http.MethodGet, "awg", ""); w.Code != http.StatusOK || f.lastArgs() != "--dry-run --json --mode userspace" {
		t.Errorf("KeeneticOS plan: %d, args %q", w.Code, f.lastArgs())
	} else if _ = json.Unmarshal(w.Body.Bytes(), &ans); !strings.Contains(ans.Summary, "userspace amneziawg-go (AmneziaWG 3.1), lowmem profile for 128 MiB of RAM") {
		t.Errorf("KeeneticOS summary %q", ans.Summary)
	}

	f = &awgFeedFake{}
	s = awgFeedServer(t, platform.Unknown, awg.Probe{TUN: true}, f)
	if w := awgCall(s, http.MethodGet, "awg", ""); w.Code != http.StatusUnprocessableEntity || len(f.calls) != 0 {
		t.Errorf("a router the installer does not support: %d, %d runs", w.Code, len(f.calls))
	}
}

// A refused or failed plan offers the release asset as the way round where amneziawg-go could run.
func TestAWGFeedPlanFallback(t *testing.T) {
	f := &awgFeedFake{verdict: map[string]string{"plan": `{"result":"refused","reason":"needs the compressed store: 1 MiB free on /overlay"}`}, code: map[string]int{"plan": 2}}
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{TUN: true}, f)
	var ans awgFeedAnswer
	_ = json.Unmarshal(awgCall(s, http.MethodGet, "awg", "").Body.Bytes(), &ans)
	if ans.Installable || !ans.Fallback || ans.Summary != "needs the compressed store: 1 MiB free on /overlay" {
		t.Errorf("refused plan: %+v", ans)
	}
	s.awgProbeOf = func() awg.Probe { return awg.Probe{TUN: false} }
	ans = awgFeedAnswer{}
	_ = json.Unmarshal(awgCall(s, http.MethodGet, "awg", "").Body.Bytes(), &ans)
	if ans.Fallback {
		t.Error("the release asset was offered on a router without /dev/net/tun")
	}
}

// An install runs on the path the plan showed, refreshes the cached capabilities so the page and the
// planner see the new module at once, and reports the generation the probe reads afterwards.
func TestAWGFeedInstall(t *testing.T) {
	f := &awgFeedFake{verdict: map[string]string{"install": awgInstallKmod}}
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{Kernel: awg.Gen2, TUN: true}, f)
	s.setUpdErr("amneziawg-go", "an earlier failure")
	s.caps.set.ProbedAt = time.Unix(1, 0)
	s.awgProbeOf = func() awg.Probe {
		// What the module reads once the installer has loaded it.
		return awg.Probe{Kernel: awg.Gen31, TUN: true, GenlVersion: 3, GenlMaxAttr: 34}
	}
	w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`)
	var ans awgFeedAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &ans); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %v: %s", w.Code, err, w.Body.String())
	}
	if f.lastArgs() != "--yes --json --mode kmod" || ans.Kernel != "3.1" || !ans.Run.OK() {
		t.Errorf("args %q, answer %+v", f.lastArgs(), ans)
	}
	if !strings.Contains(ans.Summary, "AmneziaWG 3.1 kernel module installed") {
		t.Errorf("summary %q", ans.Summary)
	}
	if time.Since(s.caps.set.ProbedAt) > time.Minute {
		t.Error("the cached capability set was not refreshed after the install")
	}
	if s.updErr("amneziawg-go") != "" {
		t.Error("a successful install left the earlier failure on the row")
	}
}

func TestAWGFeedInstallRefusals(t *testing.T) {
	f := &awgFeedFake{verdict: map[string]string{"install": awgInstallKmod}}
	s := awgFeedServer(t, platform.Keenetic, awg.Probe{TUN: true}, f)
	for _, body := range []string{`{"mode":"kmod"}`, `{"mode":"auto"}`, `{}`} {
		if w := awgCall(s, http.MethodPost, "awg", body); w.Code != http.StatusBadRequest {
			t.Errorf("KeeneticOS %s: %d", body, w.Code)
		}
	}
	if w := awgCall(s, http.MethodPost, "awg", `not json`); w.Code != http.StatusBadRequest {
		t.Errorf("bad body: %d", w.Code)
	}
	if len(f.calls) != 0 {
		t.Errorf("the installer ran for a refused request: %q", f.calls)
	}

	// Another package operation holds the lock: answered at once, nothing run.
	s = awgFeedServer(t, platform.OpenWrt, awg.Probe{TUN: true}, f)
	pmMu.Lock()
	w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`)
	pmMu.Unlock()
	if w.Code != http.StatusConflict || len(f.calls) != 0 {
		t.Errorf("busy: %d, %d runs", w.Code, len(f.calls))
	}

	// The installer refuses: a conflict, not an install failure kept as the row's last error.
	f.verdict = map[string]string{"install": `{"result":"refused","reason":"needs 4 MiB on /overlay"}`}
	f.code = map[string]int{"install": 2}
	if w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "needs 4 MiB") || s.updErr("amneziawg-go") != "" {
		t.Errorf("refused: %d %s, last error %q", w.Code, w.Body.String(), s.updErr("amneziawg-go"))
	}
	// The installer fails: a gateway error with the log, and the reason stays on the row.
	f.verdict = map[string]string{"install": `{"result":"failed","reason":"modprobe amneziawg failed; rolled back"}`}
	f.code = map[string]int{"install": 1}
	w = awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`)
	var resp struct {
		Error  string        `json:"error"`
		Answer awgFeedAnswer `json:"answer"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusBadGateway || !strings.Contains(resp.Error, "rolled back") || len(resp.Answer.Run.Log) == 0 ||
		!strings.Contains(s.updErr("amneziawg-go"), "rolled back") {
		t.Errorf("failed: %d %+v, last error %q", w.Code, resp, s.updErr("amneziawg-go"))
	}
}

// Removal stops amneziawg-go's procs first, and brings them back when nothing was removed.
func TestAWGFeedUninstall(t *testing.T) {
	f := &awgFeedFake{verdict: map[string]string{"uninstall": `{"result":"removed","packages":["kmod-amneziawg","amneziawg-tools"]}`}}
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{TUN: true}, f)
	stopped, restored := "", false
	s.pmCoreHook = &pmCoreState{
		stopPlugin:    func(bin string) int { stopped = bin; return 1 },
		restorePlugin: func() { restored = true },
	}
	w := awgCall(s, http.MethodDelete, "awg", "")
	if w.Code != http.StatusOK || f.lastArgs() != "--uninstall --yes --json" || stopped != "amneziawg-go" || restored {
		t.Errorf("removed: %d %s, args %q, stopped %q, restored %v", w.Code, w.Body.String(), f.lastArgs(), stopped, restored)
	}
	f.verdict["uninstall"] = `{"result":"refused","reason":"awg0 still uses the module"}`
	f.code = map[string]int{"uninstall": 2}
	if w := awgCall(s, http.MethodDelete, "awg", ""); w.Code != http.StatusConflict || !restored {
		t.Errorf("refused removal: %d, restored %v", w.Code, restored)
	}
}

// The demo answers from its own runner and says it installed nothing.
func TestAWGFeedDemo(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")
	s.cfg.Demo = true
	s.updater.RunDir = t.TempDir()
	var ans awgFeedAnswer
	if w := awgCall(s, http.MethodGet, "awg", ""); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	} else if _ = json.Unmarshal(w.Body.Bytes(), &ans); !ans.Installable || !ans.Demo || !strings.Contains(ans.Summary, "(demo)") {
		t.Errorf("demo plan %+v", ans)
	}
	w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`)
	if _ = json.Unmarshal(w.Body.Bytes(), &ans); w.Code != http.StatusOK || !ans.Demo || !strings.HasPrefix(ans.Summary, "Demo mode, nothing was changed. On a router: AmneziaWG 3.1 kernel module installed") {
		t.Errorf("demo install %d %+v", w.Code, ans)
	}
}

// The AmneziaWG block says which paths the installer may take here.
func TestAWGComponentFeedModes(t *testing.T) {
	old := awgEntwareOpkg
	t.Cleanup(func() { awgEntwareOpkg = old })
	awgEntwareOpkg = filepath.Join(t.TempDir(), "no-opkg")
	for p, want := range map[platform.Platform]string{platform.OpenWrt: "kmod,userspace", platform.Keenetic: "userspace", platform.Unknown: ""} {
		s := awgComponentServer(p, platform.CapabilitySet{}, awg.Probe{TUN: true}, false)
		if got := strings.Join(s.awgComponent(context.Background(), model.Profile{}).FeedModes, ","); got != want {
			t.Errorf("%s: feed modes %q, want %q", p, got, want)
		}
	}
	awgEntwareOpkg = t.TempDir() // Entware on some other firmware
	s := awgComponentServer(platform.Unknown, platform.CapabilitySet{}, awg.Probe{TUN: true}, false)
	if got := strings.Join(s.awgFeedModes(), ","); got != "userspace" {
		t.Errorf("Entware elsewhere: %q", got)
	}
}

func TestAWGRunSummary(t *testing.T) {
	mem := int64(65536)
	for _, c := range []struct {
		run  updater.AWGRun
		want string
	}{
		{updater.AWGRun{AWGResult: updater.AWGResult{Result: updater.AWGDryRun, Path: updater.AWGPathKmod}},
			"kernel module AmneziaWG 3.1 for OpenWrt 24.10.8 mediatek/filogic, about 0.3 MB of flash"},
		{updater.AWGRun{AWGResult: updater.AWGResult{Result: updater.AWGDryRun, Path: updater.AWGPathUserspace, Profile: "lowmem", MemTotalKiB: &mem}},
			"userspace amneziawg-go (AmneziaWG 3.1), lowmem profile for 64 MiB of RAM"},
		{updater.AWGRun{AWGResult: updater.AWGResult{Result: updater.AWGCurrent, Generation: "3.1"}},
			"AmneziaWG 3.1 from WayHop's feed is already installed here"},
		{updater.AWGRun{AWGResult: updater.AWGResult{Result: updater.AWGRefused, Reason: "MemTotal 40 MiB is below 48 MiB"}},
			"MemTotal 40 MiB is below 48 MiB"},
		{updater.AWGRun{AWGResult: updater.AWGResult{Result: updater.AWGFailed}}, "the installer gave no reason"},
	} {
		if got := awgRunSummary(c.run, awgWhere(platform.OpenWrt, platform.OpenWrtRelease{Release: "24.10.8", Target: "mediatek/filogic"}, false)); got != c.want {
			t.Errorf("summary %q, want %q", got, c.want)
		}
	}
	if got := awgWhere(platform.Keenetic, platform.OpenWrtRelease{}, false); got != "Entware on KeeneticOS" {
		t.Errorf("KeeneticOS: %q", got)
	}
}
