package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The router this whole path was written for: /overlay 20.2 MiB free, the installed sing-box
// 38.7 MiB, the build the feed offers 42.4 MiB. The upgrade fits only in the room the installed
// build is holding, so the plan removes it first — and that makes an UPGRADE an operation that takes
// the core binary away, which is the thing the acknowledgement gate exists to announce.
func tightPMServer(t *testing.T) (*Server, *pmScript) {
	t.Helper()
	s, sc := pmServer(t)
	sc.answers["apk list --available sing-box"] = "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n" +
		"sing-box-1.13.21-r1 aarch64 {sing-box} (GPL-3.0)\n"
	sc.answers["apk list --installed sing-box"] = "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n"
	sc.answers["apk query --format json --fields name,version,installed-size,file-size --all-matches sing-box"] =
		`[{"name":"sing-box","version":"1.12.17-r1","installed-size":40537528,"file-size":14485215},` +
			`{"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117}]`
	sc.answers["apk del sing-box"] = "(1/2) Purging sing-box (1.12.17-r1)\nOK: 37.9 MiB in 187 packages"
	sc.answers["apk add sing-box"] = "(1/2) Installing sing-box (1.13.21-r1)\nOK: 80.4 MiB in 189 packages"
	s.updater.WithAvail(func(string) (uint64, bool) { return 21178368, true })
	return s, sc
}

const lowSpaceBody = `{"action":"upgrade","argv":["apk","del","sing-box"],` +
	`"steps":[["apk","del","sing-box"],["apk","add","sing-box"]]%s}`

func lowSpacePlan(t *testing.T, s *Server) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/plan?action=upgrade", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMPlan(w, r)
	var plan map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatalf("plan body: %v", err)
	}
	return plan
}

// The plan is where the operator learns this. It carries both commands and the arithmetic that
// forced them, before anything runs.
func TestPMPlan_LowSpaceUpgradeShowsBothCommandsAndTheArithmetic(t *testing.T) {
	s, _ := tightPMServer(t)
	plan := lowSpacePlan(t, s)
	if plan["blocked"] != nil {
		t.Fatalf("blocked: %v", plan["blocked"])
	}
	steps, _ := json.Marshal(plan["steps"])
	if got := string(steps); got != `[["apk","del","sing-box"],["apk","add","sing-box"]]` {
		t.Fatalf("steps = %s", got)
	}
	space, ok := plan["space"].(map[string]any)
	if !ok || space["strategy"] != "replace" || space["target_version"] != "1.13.21-r1" {
		t.Fatalf("space = %+v", plan["space"])
	}
	if space["measured"] != true || space["need_bytes"].(float64) != 44466473 {
		t.Fatalf("the figures are not the feed's: %+v", space)
	}
}

// Removing the installed build takes the datapath down, whatever verb the operator pressed. The gate
// used to ask whether the ACTION was a remove — so an upgrade planned this way would have deleted a
// running core's binary with no warning at all.
func TestPMApply_LowSpaceUpgradeAsksBeforeTakingTheCoreDown(t *testing.T) {
	s, sc := tightPMServer(t)
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return true },
		stop:       func() error { t.Fatal("stopped the core without asking"); return nil },
		stopPlugin: func(string) int { return 0 },
		reload:     func() (bool, error) { return true, nil },
	}
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply",
		strings.NewReader(strings.Replace(lowSpaceBody, "%s", "", 1)))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["needs_stop"] != true {
		t.Fatalf("resp = %+v, want the acknowledgement gate", resp)
	}
	// The question has to carry why: an operator who pressed Update is not expecting to be told the
	// core is about to be removed, and "there is not enough space" is the only thing that explains it.
	msg, _ := resp["error"].(string)
	for _, want := range []string{"not enough free space", "1.13.21-r1", "42.4 MiB", "20.2 MiB"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("prompt %q does not say %q", msg, want)
		}
	}
	if sc.ran("del") || sc.ran("add") {
		t.Fatal("a command ran before the operator answered")
	}
}

// Acknowledged: stop, remove, install, and bring the core back. The last step is the one a reload
// cannot do — Reload restarts a RUNNING core and answers "nothing to reload" for the one this
// handler just stopped, which would leave the router upgraded and the datapath down.
func TestPMApply_LowSpaceUpgradeStopsRemovesInstallsAndRestartsTheCore(t *testing.T) {
	s, sc := tightPMServer(t)
	running := true
	started := 0
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return running },
		stop:       func() error { running = false; return nil },
		stopPlugin: func(string) int { return 0 },
		reload: func() (bool, error) {
			if !running {
				return false, nil // what the real one answers for a core that is not up
			}
			return true, nil
		},
		restore: func() error { running = true; started++; return nil },
	}
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply",
		strings.NewReader(strings.Replace(lowSpaceBody, "%s", `,"stop":true`, 1)))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var order []string
	for _, argv := range sc.seen {
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "--simulate") {
			continue
		}
		if len(argv) > 1 && (argv[1] == "del" || argv[1] == "add") {
			order = append(order, joined)
		}
	}
	if len(order) != 2 || order[0] != "apk del sing-box" || order[1] != "apk add sing-box" {
		t.Fatalf("ran %v", order)
	}
	if started != 1 || !running {
		t.Fatalf("the core was stopped to make room and not brought back (starts=%d, running=%v)", started, running)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["reloaded"] != true || resp["reload_error"] != nil {
		t.Fatalf("resp = %+v", resp)
	}
	// The package database is asked what is installed now. Here it still answers 1.12.17-r1 — the
	// script has no reason to change — so the handler must say so rather than report a clean success:
	// this is the exact check that would have caught `apk add` silently changing nothing.
	if resp["verify_error"] == nil {
		t.Fatal("a build that did not move must not be reported as an upgrade")
	}
}
