package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/platform"
)

func TestParseProcStartTicks(t *testing.T) {
	// The command name may hold spaces and parentheses; the fields are counted after its last ')'.
	stat := "812 (net ifd) S 1 812 812 0 -1 4194560 371 0 0 0 4 9 0 0 20 0 1 0 2345 4153344 345 4294967295"
	if v, ok := parseProcStartTicks(stat); !ok || v != 2345 {
		t.Errorf("starttime %d %v", v, ok)
	}
	for _, bad := range []string{"", "812 netifd S 1", "812 (netifd) S 1 2 3"} {
		if _, ok := parseProcStartTicks(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseBootTime(t *testing.T) {
	if v, ok := parseBootTime("cpu  1 2 3\nbtime 1760600000\nprocesses 9\n"); !ok || v != 1760600000 {
		t.Errorf("btime %d %v", v, ok)
	}
	if _, ok := parseBootTime("cpu 1 2 3\n"); ok {
		t.Error("no btime parsed")
	}
}

// netifd is found by name under a /proc laid out like a router's, and its start is boot time plus its
// start ticks at USER_HZ 100.
func TestNetifdStartTime(t *testing.T) {
	proc := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(proc, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu 1 2 3\nbtime 1760600000\n")
	write("1/comm", "procd\n")
	write("1/stat", "1 (procd) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0 0")
	write("self/comm", "wayhop\n")
	if _, ok := netifdStartTime(proc); ok {
		t.Fatal("found a netifd that is not running")
	}
	write("812/comm", "netifd\n")
	write("812/stat", "812 (netifd) S 1 812 812 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 2345 0 0 0")
	got, ok := netifdStartTime(proc)
	if want := time.Unix(1760600000, 0).Add(23450 * time.Millisecond); !ok || !got.Equal(want) {
		t.Errorf("start %v %v, want %v", got, ok, want)
	}
}

func TestNetifdStale(t *testing.T) {
	started := time.Unix(1760600000, 0)
	for _, c := range []struct {
		changed time.Duration
		stale   bool
	}{
		{-time.Hour, false},             // installed before netifd started: it read it
		{500 * time.Millisecond, false}, // the same second: the tick rounding
		{10 * time.Minute, true},        // installed while netifd ran
	} {
		if got := netifdStale(started.Add(c.changed), started); got != c.stale {
			t.Errorf("handler changed at %v: stale=%v", c.changed, got)
		}
	}
}

func TestParseAWGNetifd(t *testing.T) {
	r := parseAWGNetifd([]byte("install-awg.sh: done\n" + `{"result":"installed","netifd_restart_needed":true,"network_restarted":false}` + "\n"))
	if r.RestartNeeded == nil || !*r.RestartNeeded || r.Restarted == nil || *r.Restarted {
		t.Errorf("report %+v", r)
	}
	for _, out := range []string{"", "no verdict\n", `{"result":"installed"}`, "{not json}\n"} {
		if r := parseAWGNetifd([]byte(out)); r.RestartNeeded != nil || r.Restarted != nil {
			t.Errorf("%q: %+v", out, r)
		}
	}
}

// The netifd state the row and the review use: measured where it can be, else what the last install said.
func TestAWGNetifdRestartPending(t *testing.T) {
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{Kernel: awg.Gen31, TUN: true}, &awgFeedFake{})
	s.netifdStaleOf = func() (bool, bool) { return false, false }
	if s.awgNetifdRestartPending() {
		t.Error("pending with nothing measured and nothing reported")
	}
	s.awgNetifdPending.Store(true)
	if !s.awgNetifdRestartPending() {
		t.Error("the install's report is not used when netifd cannot be measured")
	}
	s.netifdStaleOf = func() (bool, bool) { return false, true }
	if s.awgNetifdRestartPending() {
		t.Error("a measured netifd that read the handler is overruled by an old report")
	}
	s.netifdStaleOf = func() (bool, bool) { return true, true }
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	if s.awgNetifdRestartPending() {
		t.Error("KeeneticOS has no netifd")
	}
}

const awgInstallKmodNetifd = `{"result":"installed","path":"kmod","packages":["kmod-amneziawg","amneziawg-tools"],"generation":"3.1","netifd_restart_needed":%s,"network_restarted":%s}`

// The plan says when the install would change netifd's handler; restart_network passes
// --restart-network; an install that changed the handler without it leaves the restart to the row.
func TestAWGFeedInstallNetifdRestart(t *testing.T) {
	plan := strings.Replace(awgPlanKmod, `"generation"`, `"netifd_restart_needed":true,"network_restarted":false,"generation"`, 1)
	f := &awgFeedFake{verdict: map[string]string{"plan": plan}}
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{Kernel: awg.Gen31, TUN: true}, f)
	s.netifdStaleOf = func() (bool, bool) { return false, false }
	var ans awgFeedAnswer
	if w := awgCall(s, http.MethodGet, "awg", ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ans) != nil ||
		!ans.NetifdRestart || !strings.Contains(ans.Summary, "netifd reads only when the network service restarts") {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(f.lastArgs(), "--restart-network") {
		t.Errorf("a plan never restarts anything: %q", f.lastArgs())
	}

	for _, c := range []struct {
		name, body, needed, restarted string
		wantFlag, wantPending         bool
	}{
		{"without the flag", `{"mode":"kmod"}`, "true", "false", false, true},
		{"with restart_network", `{"mode":"kmod","restart_network":true}`, "false", "true", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f.verdict["install"] = strings.Replace(awgInstallKmodNetifd, "%s", c.needed, 1)
			f.verdict["install"] = strings.Replace(f.verdict["install"], "%s", c.restarted, 1)
			s.awgNetifdPending.Store(!c.wantPending)
			w := awgCall(s, http.MethodPost, "awg", c.body)
			var got awgFeedAnswer
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
				t.Fatalf("install: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(f.lastArgs(), "--restart-network") != c.wantFlag {
				t.Errorf("argv %q", f.lastArgs())
			}
			if got.NetifdRestart != c.wantPending || got.NetworkRestarted != c.wantFlag || s.awgNetifdPending.Load() != c.wantPending {
				t.Errorf("answer %+v, pending %v", got, s.awgNetifdPending.Load())
			}
			if c.wantPending && !strings.Contains(got.Summary, "or it happens at the next reboot") {
				t.Errorf("summary %q", got.Summary)
			}
		})
	}

	// restart_network is OpenWrt's: elsewhere there is no netifd to restart.
	k := awgFeedServer(t, platform.Keenetic, awg.Probe{TUN: true}, &awgFeedFake{verdict: map[string]string{}})
	if w := awgCall(k, http.MethodPost, "awg", `{"mode":"userspace","restart_network":true}`); w.Code != http.StatusBadRequest {
		t.Errorf("KeeneticOS restart_network: %d %s", w.Code, w.Body.String())
	}
}

func awgRestartCall(s *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/updater/awg/restart-network", nil)
	w := httptest.NewRecorder()
	s.handleAWGRestartNetwork(w, req)
	return w
}

// The restart button: started detached on OpenWrt, refused elsewhere and while a package operation
// runs, and in the demo it says what would happen and changes nothing.
func TestAWGRestartNetwork(t *testing.T) {
	s := awgFeedServer(t, platform.OpenWrt, awg.Probe{TUN: true}, &awgFeedFake{})
	started := 0
	s.networkRestartOf = func() error { started++; return nil }
	s.awgNetifdPending.Store(true)
	if w := awgRestartCall(s); w.Code != http.StatusAccepted || started != 1 || s.awgNetifdPending.Load() {
		t.Fatalf("restart: %d %s, started %d", w.Code, w.Body.String(), started)
	}

	pmMu.Lock()
	w := awgRestartCall(s)
	pmMu.Unlock()
	if w.Code != http.StatusConflict || started != 1 {
		t.Errorf("under a package operation: %d, started %d", w.Code, started)
	}

	s.networkRestartOf = func() error { return errNetworkRestartUnavailable }
	if w := awgRestartCall(s); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no init script: %d", w.Code)
	}
	s.networkRestartOf = func() error { return errors.New("fork: resource temporarily unavailable") }
	if w := awgRestartCall(s); w.Code != http.StatusInternalServerError {
		t.Errorf("start failed: %d", w.Code)
	}

	s.platformOf = func() platform.Platform { return platform.Keenetic }
	s.networkRestartOf = func() error { started++; return nil }
	if w := awgRestartCall(s); w.Code != http.StatusUnprocessableEntity || started != 1 {
		t.Errorf("KeeneticOS: %d, started %d", w.Code, started)
	}

	s.cfg.Demo = true
	s.awgNetifdPending.Store(true)
	w = awgRestartCall(s)
	var resp struct {
		Restarting bool   `json:"restarting"`
		Demo       bool   `json:"demo"`
		Summary    string `json:"summary"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Restarting || !resp.Demo ||
		!strings.HasPrefix(resp.Summary, "Demo mode, nothing was changed") || started != 1 {
		t.Errorf("demo: %d %s, started %d", w.Code, w.Body.String(), started)
	}
}

// The demo's runner predates the netifd fields; the demo still walks the whole flow and changes nothing.
func TestAWGFeedDemoNetifd(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "arm64")
	s.cfg.Demo = true
	s.updater.RunDir = t.TempDir()
	var plan awgFeedAnswer
	if w := awgCall(s, http.MethodGet, "awg", ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &plan) != nil || !plan.NetifdRestart {
		t.Fatalf("demo plan: %d %s", w.Code, w.Body.String())
	}
	var got awgFeedAnswer
	if w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod"}`); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil ||
		!got.NetifdRestart || !s.awgNetifdRestartPending() {
		t.Fatalf("demo install: %d %s", w.Code, w.Body.String())
	}
	if w := awgRestartCall(s); w.Code != 200 || s.awgNetifdRestartPending() {
		t.Errorf("demo restart: %d, still pending %v", w.Code, s.awgNetifdRestartPending())
	}
	var restarted awgFeedAnswer
	if w := awgCall(s, http.MethodPost, "awg", `{"mode":"kmod","restart_network":true}`); w.Code != 200 ||
		json.Unmarshal(w.Body.Bytes(), &restarted) != nil || restarted.NetifdRestart || !restarted.NetworkRestarted {
		t.Errorf("demo install with the restart: %d %s", w.Code, w.Body.String())
	}
}
