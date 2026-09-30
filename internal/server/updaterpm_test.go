package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/pm"
	"wayhop/internal/updater"
)

// The dev host and CI have no package manager, so every plan there blocks with "no opkg or apk on
// this system" — correct, and useless for testing the paths that matter. These tests inject a
// scripted apk so the interesting answers exist: a runnable plan, a refusal, and the mismatch between
// what was shown and what would run.
type pmScript struct {
	answers map[string]string
	errs    map[string]error
	seen    [][]string
	// flip models an external opkg/apk run BETWEEN the handler's first preflight and ExecutePM's
	// re-preflight: once a key has been served flipAt-or-more times, flip[key] replaces its answer, so
	// the first preflight sees the box as it was and the re-check sees it changed. Both zero-valued
	// (flip nil) unless a test opts in, so every existing test is unaffected; counts is per-key and
	// only accrues while flip is set, so the harness's own setup calls (made before a test wires flip)
	// are never counted.
	flip   map[string]string
	flipAt int
	counts map[string]int
}

func (s *pmScript) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	s.seen = append(s.seen, append([]string{name}, args...))
	if s.flip != nil {
		if s.counts == nil {
			s.counts = map[string]int{}
		}
		s.counts[key]++
		if v, ok := s.flip[key]; ok && s.counts[key] >= s.flipAt {
			return v, nil
		}
	}
	if e, ok := s.errs[key]; ok {
		return s.answers[key], e
	}
	if out, ok := s.answers[key]; ok {
		return out, nil
	}
	if strings.Contains(key, " --simulate ") || strings.Contains(key, " --noaction ") {
		return "OK", nil
	}
	return "", errors.New("pmScript: no answer for " + key)
}

// ran reports whether a MUTATING run happened. The dry-run forms — `apk add --simulate`,
// `opkg install --noaction` — carry the same verb and change nothing, so matching on the verb alone
// counted the planner's own preview as an execution and failed three tests that were right. Matching
// on the verb AND the absence of a dry-run flag keeps the assertion sharp: a real execution in a path
// that should only plan still fails it.
func (s *pmScript) ran(verb string) bool {
	for _, argv := range s.seen {
		if len(argv) < 2 || argv[1] != verb {
			continue
		}
		dry := false
		for _, a := range argv[2:] {
			if a == "--simulate" || a == "-s" || a == "--noaction" {
				dry = true
			}
		}
		if !dry {
			return true
		}
	}
	return false
}

// pmServer wires a Server whose updater believes apk owns the sing-box binary at the path the daemon
// would run. The who-owns answer is the real device format — name and version glued.
func pmServer(t *testing.T) (*Server, *pmScript) {
	t.Helper()
	up := updater.New("/usr/bin", "aarch64", nil)
	sc := &pmScript{answers: map[string]string{}, errs: map[string]error{}}
	up.WithPM(pm.Manager{Kind: pm.Apk, Runner: sc})
	// The path is whatever the updater itself resolves, so the script cannot describe a path shape the
	// code never produces (filepath.Join yields backslashes on the Windows dev host).
	plan := up.PlanPM(context.Background(), *updater.EngineByID("sing-box"), updater.PlanUpgrade, "")
	path := plan.Path
	sc.answers["apk info --who-owns "+path] = path + " is owned by sing-box-1.12.17-r1"
	sc.answers["apk info -L sing-box"] = "sing-box-1.12.17-r1 contains:\nusr/bin/sing-box\n"
	sc.answers["apk list --available sing-box"] = "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0) [installed]\n" +
		"sing-box-1.11.4-r2 aarch64 {sing-box} (GPL-3.0)\n"
	// Forget the setup's own probe. Resolving the path above costs one `apk info --who-owns`, and a
	// test asserting "nothing reached the package manager" would otherwise be counting this harness
	// rather than the handler — which is exactly what it did, and it went red for the wrong reason.
	sc.seen = nil
	return &Server{updater: up}, sc
}

func TestPMRefreshPlanShowsExactNonMutatingCommand(t *testing.T) {
	s, sc := pmServer(t)
	w := httptest.NewRecorder()
	s.handleUpdaterPMRefreshPlan(w, httptest.NewRequest(http.MethodGet, "/api/updater/pm/refresh/plan", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var got struct {
		Manager string   `json:"manager"`
		Argv    []string `json:"argv"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Manager != "apk" || strings.Join(got.Argv, " ") != "apk update" {
		t.Fatalf("plan = %#v", got)
	}
	if sc.ran("update") {
		t.Fatalf("refresh planning mutated the package database: %v", sc.seen)
	}
}

func TestPMRefreshApplyRequiresAndRunsReviewedCommand(t *testing.T) {
	s, sc := pmServer(t)
	sc.answers["apk update"] = "indexes refreshed"

	bad := httptest.NewRequest(http.MethodPost, "/api/updater/pm/refresh/apply",
		strings.NewReader(`{"argv":["apk","upgrade"]}`))
	badW := httptest.NewRecorder()
	s.handleUpdaterPMRefreshApply(badW, bad)
	if badW.Code != http.StatusConflict || sc.ran("upgrade") {
		t.Fatalf("substituted refresh: status=%d calls=%v", badW.Code, sc.seen)
	}

	good := httptest.NewRequest(http.MethodPost, "/api/updater/pm/refresh/apply",
		strings.NewReader(`{"argv":["apk","update"]}`))
	goodW := httptest.NewRecorder()
	s.handleUpdaterPMRefreshApply(goodW, good)
	if goodW.Code != http.StatusOK || !sc.ran("update") {
		t.Fatalf("reviewed refresh: status=%d body=%s calls=%v", goodW.Code, goodW.Body.String(), sc.seen)
	}
}

func TestPMRefreshFailureDoesNotLeakRepositoryURLs(t *testing.T) {
	s, sc := pmServer(t)
	sc.errs["apk update"] = errors.New("https://token@example.invalid/private/packages.adb failed")
	w := httptest.NewRecorder()
	s.handleUpdaterPMRefreshApply(w, httptest.NewRequest(http.MethodPost,
		"/api/updater/pm/refresh/apply", strings.NewReader(`{"argv":["apk","update"]}`)))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token@") || strings.Contains(w.Body.String(), "example.invalid") {
		t.Fatalf("package repository secret leaked in response: %s", w.Body.String())
	}
}

func TestPMRefreshOpkgPartialSuccessIsTruthfulAndSanitized(t *testing.T) {
	up := updater.New("/opt/bin", "aarch64", nil)
	sc := &pmScript{answers: map[string]string{}, errs: map[string]error{}}
	up.WithPM(pm.Manager{Kind: pm.Opkg, Runner: sc})
	s := &Server{updater: up}
	sc.answers["opkg update"] = "Downloading http://bin.entware.net/Packages.gz\n" +
		"Updated list of available packages in /opt/var/opkg-lists/entware\n" +
		"*** Failed to download the package list from https://token@example.invalid/Packages.gz\n"
	sc.errs["opkg update"] = errors.New("exit status 1")

	w := httptest.NewRecorder()
	s.handleUpdaterPMRefreshApply(w, httptest.NewRequest(http.MethodPost,
		"/api/updater/pm/refresh/apply", strings.NewReader(`{"argv":["opkg","update"]}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var got struct {
		Refreshed      bool `json:"refreshed"`
		Partial        bool `json:"partial"`
		UpdatedSources int  `json:"updated_sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Refreshed || !got.Partial || got.UpdatedSources != 1 {
		t.Fatalf("partial refresh = %+v, want refreshed partial with one source", got)
	}
	if strings.Contains(w.Body.String(), "token@") || strings.Contains(w.Body.String(), "example.invalid") ||
		strings.Contains(w.Body.String(), "bin.entware.net") {
		t.Fatalf("package repository details leaked in response: %s", w.Body.String())
	}
}

func TestPMCandidatesFailureDoesNotLeakRepositoryURLs(t *testing.T) {
	s, sc := pmServer(t)
	sc.errs["apk list --available sing-box"] = errors.New("https://token@example.invalid/private/packages.adb failed")
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/candidates", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMCandidates(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token@") || strings.Contains(w.Body.String(), "example.invalid") {
		t.Fatalf("package repository secret leaked in response: %s", w.Body.String())
	}
}

// pmPluginServer is pmServer for a NON-core engine, so the plugin half of the removal guard has a
// subject. Built from the engine's own record rather than a second hand-written fixture: an engine id
// that drifted out of updater.Engines would otherwise make every assertion below vacuous.
func pmPluginServer(t *testing.T, id string) (*Server, *pmScript) {
	t.Helper()
	e := updater.EngineByID(id)
	if e == nil {
		t.Fatalf("no engine %q — the test would be about nothing", id)
	}
	up := updater.New("/usr/bin", "aarch64", nil)
	sc := &pmScript{answers: map[string]string{}, errs: map[string]error{}}
	up.WithPM(pm.Manager{Kind: pm.Apk, Runner: sc})
	path := up.PlanPM(context.Background(), *e, updater.PlanUpgrade, "").Path
	sc.answers["apk info --who-owns "+path] = path + " is owned by " + id + "-1.0.0-r1"
	sc.answers["apk info -L "+id] = id + "-1.0.0-r1 contains:\n" + strings.TrimPrefix(path, "\\") + "\n"
	sc.answers["apk list --available "+id] = id + "-1.0.0-r1 aarch64 {" + id + "} (GPL-3.0) [installed]\n"
	sc.seen = nil
	return &Server{updater: up}, sc
}

func TestPMPlanEndpoint_ReturnsTheCommandAndRunsNothing(t *testing.T) {
	s, sc := pmServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/plan?action=rollback&version=1.11.4-r2", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMPlan(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var plan updater.PMPlan
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := strings.Join(plan.Argv, " "); got != "apk add sing-box=1.11.4-r2" {
		t.Fatalf("argv = %q", got)
	}
	if plan.Blocked != "" {
		t.Fatalf("blocked: %s", plan.Blocked)
	}
	// Planning must not touch the box.
	if sc.ran("add") || sc.ran("del") {
		t.Fatalf("the plan endpoint ran a mutating command: %v", sc.seen)
	}
}

// A blocked plan is 200 with the reasons, not an error code. The whole point of the endpoint is to
// let the page show WHY, and a 4xx would leave it with a bare string — which is what it has today.
func TestPMPlanEndpoint_BlockedPlanStillCarriesItsChecks(t *testing.T) {
	s, _ := pmServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/plan?action=rollback&version=9.9.9-r9", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMPlan(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var plan updater.PMPlan
	_ = json.Unmarshal(w.Body.Bytes(), &plan)
	if plan.Blocked == "" {
		t.Fatal("a version absent from the feed produced a runnable plan")
	}
	if len(plan.Checks) < 3 {
		t.Fatalf("only %d checks reported — the page would have nothing to explain the refusal with", len(plan.Checks))
	}
	if len(plan.Argv) != 0 {
		t.Fatalf("a blocked plan carries a command: %v", plan.Argv)
	}
}

func TestPMPlanEndpoint_RejectsAnUnknownAction(t *testing.T) {
	s, _ := pmServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/plan?action=reboot", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMPlan(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for an action outside the allow-list", w.Code)
	}
}

// The apply endpoint runs only the command it was shown. Sending back a different argv must be a
// conflict, not an execution.
func TestPMApplyEndpoint_RefusesAnArgvItDidNotPropose(t *testing.T) {
	s, sc := pmServer(t)
	body := `{"action":"remove","argv":["apk","del","busybox"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", w.Code, w.Body.String())
	}
	if sc.ran("del") {
		t.Fatalf("a substituted command was executed: %v", sc.seen)
	}
}

// And the honest case must go through, or the guard is only a way of never doing anything.
func TestPMApplyEndpoint_RunsTheCommandItProposed(t *testing.T) {
	s, sc := pmServer(t)
	sc.answers["apk del sing-box"] = "OK: 1 package removed"
	body := `{"action":"remove","argv":["apk","del","sing-box"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if !sc.ran("del") {
		t.Fatalf("nothing ran; calls were %v", sc.seen)
	}
}

// Without an argv the operator was never shown anything, so there is nothing to confirm.
func TestPMApplyEndpoint_RequiresTheApprovedArgv(t *testing.T) {
	s, sc := pmServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(`{"action":"remove"}`))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for a request with no approved command", w.Code)
	}
	if len(sc.seen) != 0 {
		t.Fatalf("a request with no approved command reached the package manager: %v", sc.seen)
	}
}

// runningCore wires the server's view of the routing core to a pair of counters, so a test can put
// it in the one state that matters — up — without starting a process.
func runningCore(s *Server, up bool) *int {
	stops := 0
	s.pmCoreHook = &pmCoreState{
		running: func() bool { return up },
		stop:    func() error { stops++; up = false; return nil },
	}
	return &stops
}

// Removing the package removes the FILE, and the panel's own uninstall path has stopped the core
// first since the day it was written: a deleted binary keeps running as an orphan holding ports and
// locks, and the watchdog — Desired() still set — respawns onto a path that no longer exists. The
// delegation reached the same deletion by a different door and had no guard on it at all.
func TestPMApplyEndpoint_RefusesToRemoveTheRunningCoreWithoutAnExplicitStop(t *testing.T) {
	s, sc := pmServer(t)
	stops := runningCore(s, true)
	sc.answers["apk del sing-box"] = "OK: 1 package removed"

	body := `{"action":"remove","argv":["apk","del","sing-box"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for removing the binary of a running core; body %s", w.Code, w.Body.String())
	}
	if sc.ran("del") {
		t.Fatalf("the running core's package was removed with no acknowledgement: %v", sc.seen)
	}
	if *stops != 0 {
		t.Fatalf("the core was stopped by a request that was refused (%d stops)", *stops)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["needs_stop"] != true {
		t.Fatalf("the refusal does not tell the client a stop is what is missing: %s", w.Body.String())
	}
}

// And the acknowledged case must go through, core first, or the guard is only a way of never
// removing anything.
func TestPMApplyEndpoint_StopsTheCoreBeforeRemovingIt(t *testing.T) {
	s, sc := pmServer(t)
	stops := runningCore(s, true)
	sc.answers["apk del sing-box"] = "OK: 1 package removed"

	body := `{"action":"remove","argv":["apk","del","sing-box"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if *stops != 1 {
		t.Fatalf("core stops = %d, want exactly one before the removal", *stops)
	}
	if !sc.ran("del") {
		t.Fatalf("the core was stopped and nothing was removed: %v", sc.seen)
	}
}

// Replacing the FILE does not replace the PROCESS. apk unlinks the old inode and writes a new one, so
// a running sing-box keeps executing the build that was there before — while the panel reads the
// version by exec'ing the new file and reports the upgrade as done. The sibling install path has
// reloaded the core here since it was written; the delegation did not, so its success was a report
// about the disk rather than about the router.
func TestPMApplyEndpoint_ReloadsTheCoreAfterReplacingItsBinary(t *testing.T) {
	s, sc := pmServer(t)
	reloads := 0
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return true },
		stop:       func() error { t.Fatal("an upgrade stopped the core"); return nil },
		stopPlugin: func(string) int { return 0 },
		reload:     func() (bool, error) { reloads++; return true, nil },
	}
	// apk's own verb. The mock used to answer `apk add sing-box` with "OK: 1 package upgraded",
	// which is a sentence the real apk never prints for that command — it keeps the installed build
	// and says "OK: 76.6 MiB in 189 packages". A fake that lies in the direction of the code is how
	// an upgrade path that could not upgrade anything passed its tests for its whole life.
	sc.answers["apk upgrade sing-box"] = "OK: 1 package upgraded"

	body := `{"action":"upgrade","argv":["apk","upgrade","sing-box"],"steps":[["apk","upgrade","sing-box"]]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if reloads != 1 {
		t.Fatalf("core reloads = %d, want exactly one — the router is still running the old build", reloads)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["reloaded"] != true {
		t.Fatalf("the response does not say the core was reloaded: %s", w.Body.String())
	}
}

// A reload that fails must not be reported as a plain success: the package changed and the router did
// not, which is the exact confusion the reload is there to prevent.
func TestPMApplyEndpoint_AFailedReloadIsReportedNotSwallowed(t *testing.T) {
	s, sc := pmServer(t)
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return true },
		stop:       func() error { return nil },
		stopPlugin: func(string) int { return 0 },
		reload:     func() (bool, error) { return false, errors.New("config rejected by the new build") },
	}
	// apk's own verb. The mock used to answer `apk add sing-box` with "OK: 1 package upgraded",
	// which is a sentence the real apk never prints for that command — it keeps the installed build
	// and says "OK: 76.6 MiB in 189 packages". A fake that lies in the direction of the code is how
	// an upgrade path that could not upgrade anything passed its tests for its whole life.
	sc.answers["apk upgrade sing-box"] = "OK: 1 package upgraded"

	body := `{"action":"upgrade","argv":["apk","upgrade","sing-box"],"steps":[["apk","upgrade","sing-box"]]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["reloaded"] == true {
		t.Fatalf("a failed reload was reported as a reload: %s", w.Body.String())
	}
	if got["reload_error"] == nil {
		t.Fatalf("the failure is not in the response at all: %s", w.Body.String())
	}
}

// The inverse, and it is load-bearing: Reload re-asserts desired=true. Calling it after a REMOVAL
// would point the watchdog at a binary that was just deleted, undoing the stop that precedes it.
func TestPMApplyEndpoint_ARemovalDoesNotReloadTheCore(t *testing.T) {
	s, sc := pmServer(t)
	reloads := 0
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return true },
		stop:       func() error { return nil },
		stopPlugin: func(string) int { return 0 },
		reload:     func() (bool, error) { reloads++; return true, nil },
	}
	sc.answers["apk del sing-box"] = "OK: 1 package removed"

	body := `{"action":"remove","argv":["apk","del","sing-box"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if reloads != 0 {
		t.Fatalf("a removal reloaded the core (%d) — the watchdog would be re-armed onto a deleted binary", reloads)
	}
}

// The core is not the only process that keeps running the file it was exec'd from. olcRTC's proc has
// the same problem, and nothing brings it back on its own: the watchdog's Supervise only relaunches
// procs that DIED, so an upgraded plugin serves the previous build until the next Apply while the
// page reports the new version — the same false success the core's reload was added for.
func TestPMApplyEndpoint_RestartsAPluginOntoItsNewBinary(t *testing.T) {
	s, sc := pmPluginServer(t, "olcrtc")
	var restarted []string
	s.pmCoreHook = &pmCoreState{
		running:       func() bool { return false },
		stop:          func() error { return nil },
		stopPlugin:    func(string) int { t.Fatal("an upgrade used the removal's stop path"); return 0 },
		reload:        func() (bool, error) { t.Fatal("a plugin upgrade reloaded the core"); return false, nil },
		restartPlugin: func(bin string) int { restarted = append(restarted, bin); return 1 },
	}
	sc.answers["apk upgrade olcrtc"] = "OK: 1 package upgraded"

	body := `{"action":"upgrade","argv":["apk","upgrade","olcrtc"],"steps":[["apk","upgrade","olcrtc"]]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/olcrtc/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if len(restarted) != 1 || restarted[0] != "olcrtc" {
		t.Fatalf("plugin restarts = %v, want one for the olcrtc binary — the tunnel is still the old build", restarted)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["restarted"] == nil {
		t.Fatalf("the response does not say the plugin was restarted: %s", w.Body.String())
	}
}

// And not after a removal: there is no binary left to restart onto, and Sync would relaunch the proc
// against a file that was just deleted.
func TestPMApplyEndpoint_ARemovalDoesNotRestartThePlugin(t *testing.T) {
	s, sc := pmPluginServer(t, "olcrtc")
	restarts := 0
	s.pmCoreHook = &pmCoreState{
		running:       func() bool { return false },
		stop:          func() error { return nil },
		stopPlugin:    func(string) int { return 1 },
		reload:        func() (bool, error) { return false, nil },
		restartPlugin: func(string) int { restarts++; return 1 },
	}
	sc.answers["apk del olcrtc"] = "OK: 1 package removed"

	body := `{"action":"remove","argv":["apk","del","olcrtc"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/olcrtc/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if restarts != 0 {
		t.Fatalf("a removal relaunched the plugin (%d) — onto a binary that was just deleted", restarts)
	}
}

// The guard added for sing-box covered half the engine list. A plugin engine's binary is deleted by
// the same `apk del`, and the panel's own uninstall path stops the plugin proc for exactly the same
// reason it stops the core — an orphan holding ports and locks. The gate is core-only by design
// (removing a plugin implies stopping it), but the STOP is not.
func TestPMApplyEndpoint_StopsARunningPluginBeforeRemovingIt(t *testing.T) {
	s, sc := pmPluginServer(t, "olcrtc")
	var stoppedBins []string
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return false }, // not the core; the core's state is irrelevant here
		stop:       func() error { t.Fatal("the core was stopped for a plugin removal"); return nil },
		stopPlugin: func(bin string) int { stoppedBins = append(stoppedBins, bin); return 1 },
	}
	sc.answers["apk del olcrtc"] = "OK: 1 package removed"

	body := `{"action":"remove","argv":["apk","del","olcrtc"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/olcrtc/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if len(stoppedBins) != 1 || stoppedBins[0] != "olcrtc" {
		t.Fatalf("plugin stops = %v, want exactly one for the olcrtc binary — its binary was deleted under the running process", stoppedBins)
	}
	if !sc.ran("del") {
		t.Fatalf("nothing was removed: %v", sc.seen)
	}
}

// And the same inversion guard as the core has: a plugin removal that will be refused must not stop
// the plugin on its way to being refused, or the tunnel is down with its binary still installed.
func TestPMApplyEndpoint_ARefusedPluginRemovalDoesNotStopIt(t *testing.T) {
	s, sc := pmPluginServer(t, "olcrtc")
	stops := 0
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return false },
		stop:       func() error { return nil },
		stopPlugin: func(string) int { stops++; return 1 },
	}

	body := `{"action":"remove","argv":["apk","del","busybox"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/olcrtc/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if stops != 0 {
		t.Fatalf("a refused removal stopped the plugin (%d stops) — the tunnel is down and its binary is still installed", stops)
	}
	if sc.ran("del") {
		t.Fatalf("a substituted command was executed: %v", sc.seen)
	}
}

// The inversion the panel's uninstall path documents, and the reason PreflightPM is a separate call:
// a command that will be REFUSED must not take the datapath down on its way to being refused. With
// the stop placed before the check, this leaves the router with no routing and nothing removed.
func TestPMApplyEndpoint_ARefusedRemovalDoesNotStopTheCore(t *testing.T) {
	s, sc := pmServer(t)
	stops := runningCore(s, true)

	// An argv the plan never proposed: refused by the same guard as always, but now reached by a
	// request that also carries the stop acknowledgement.
	body := `{"action":"remove","argv":["apk","del","busybox"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if *stops != 0 {
		t.Fatalf("a refused command stopped the routing core (%d stops) — the router would be left with no routing and nothing removed", *stops)
	}
	if sc.ran("del") {
		t.Fatalf("a substituted command was executed: %v", sc.seen)
	}
}

// restorableCore wires the core hook for the remove-then-abort window: running/stop AND the restore
// a post-stop abort must call. `up` flips false on stop and true again on a successful restore, so a
// test can assert the datapath ended back where it started. restoreErr, when non-nil, makes restore
// fail — the binary-really-gone case that must surface as its own critical result rather than a
// quiet datapath outage. Returns pointers to the stop and restore counters.
func restorableCore(s *Server, restoreErr error) (stops, restores *int) {
	st, rs := new(int), new(int)
	up := true
	s.pmCoreHook = &pmCoreState{
		running:    func() bool { return up },
		stop:       func() error { *st++; up = false; return nil },
		stopPlugin: func(string) int { return 0 },
		reload:     func() (bool, error) { return false, nil },
		restore: func() error {
			*rs++
			if restoreErr != nil {
				return restoreErr
			}
			up = true
			return nil
		},
	}
	return st, rs
}

// The window this whole path is careful about: the core is stopped between the two preflights, and
// the package manager then FAILS the removal. Before the fix the handler returned 502 with the core
// still down and nothing removed — routing dead on a box whose sing-box the remove did not even
// delete. The stop must be compensated: the binary is still there, so the core comes back.
func TestPMApplyEndpoint_ARemoveThatFailsAfterTheStopRestartsTheCore(t *testing.T) {
	s, sc := pmServer(t)
	stops, restores := restorableCore(s, nil)
	sc.errs["apk del sing-box"] = errors.New("apk: I/O error deleting package")

	body := `{"action":"remove","argv":["apk","del","sing-box"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a package-manager remove failure; body %s", w.Code, w.Body.String())
	}
	if *stops != 1 {
		t.Fatalf("core stops = %d, want exactly one before the removal", *stops)
	}
	if *restores != 1 {
		t.Fatalf("the core was stopped for a removal that FAILED and was never restarted (%d restores) — the datapath is dead with nothing removed", *restores)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["datapath_restored"] != true {
		t.Fatalf("the response does not tell the operator the datapath was restored: %s", w.Body.String())
	}
	if got["rollback_error"] != nil {
		t.Fatalf("a successful restart reported a rollback_error: %s", w.Body.String())
	}
}

// The other half of the window: an external opkg/apk run changes the package database between the two
// preflights, so ExecutePM's re-check REFUSES (409). The refusal is correct, but it arrives after the
// stop — so the core must still be brought back. stops==1 also proves the refusal happened in the
// post-stop window and not before it (a flip that triggered too early would leave stops==0 and this
// test would be measuring nothing).
func TestPMApplyEndpoint_ARemoveRefusedByTheSecondPreflightRestartsTheCore(t *testing.T) {
	s, sc := pmServer(t)
	stops, restores := restorableCore(s, nil)
	sc.answers["apk del sing-box"] = "OK: 1 package removed" // would succeed — but the re-check refuses first
	// Between the two preflights the package's file list stops containing the binary in use, so the
	// re-plan blocks at "the package installs the file in use". flipAt=2: first preflight intact,
	// ExecutePM's re-preflight changed.
	sc.flip = map[string]string{"apk info -L sing-box": "sing-box-1.12.17-r1 contains:\nusr/bin/not-the-core\n"}
	sc.flipAt = 2

	body := `{"action":"remove","argv":["apk","del","sing-box"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a re-check refusal; body %s", w.Code, w.Body.String())
	}
	if *stops != 1 {
		t.Fatalf("core stops = %d — the refusal did not happen in the post-stop window this test exists for", *stops)
	}
	if *restores != 1 {
		t.Fatalf("core stopped, the removal was refused by the re-check, and the core was never restarted (%d restores)", *restores)
	}
	if sc.ran("del") {
		t.Fatalf("a removal the re-check refused still ran apk del: %v", sc.seen)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["datapath_restored"] != true {
		t.Fatalf("the response does not say the datapath was restored after the refusal: %s", w.Body.String())
	}
}

// When the compensation itself cannot bring the core back — the removal got far enough to unlink the
// binary before failing — that is a worse state than the failure that triggered it and must be its
// own result, not folded into the package error where the operator would read "remove failed" and
// assume routing merely paused.
func TestPMApplyEndpoint_AFailedRestartIsReportedAsItsOwnCriticalResult(t *testing.T) {
	s, sc := pmServer(t)
	stops, restores := restorableCore(s, errors.New("sing-box binary is gone"))
	sc.errs["apk del sing-box"] = errors.New("apk: partial failure")

	body := `{"action":"remove","argv":["apk","del","sing-box"],"stop":true}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/sing-box/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body %s", w.Code, w.Body.String())
	}
	if *stops != 1 || *restores != 1 {
		t.Fatalf("stops=%d restores=%d, want one attempt of each", *stops, *restores)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["rollback_error"] == nil {
		t.Fatalf("the core could not be restarted and that is not in the response — the operator would read only the package error: %s", w.Body.String())
	}
	if got["datapath_restored"] == true {
		t.Fatalf("reported the datapath restored when the restart FAILED: %s", w.Body.String())
	}
}

// The plugin half of the same window: a plugin removal is stopped, the package manager fails, and the
// stopped plugin must be re-synced onto the binary still on disk — the counterpart to the core's
// restart.
func TestPMApplyEndpoint_APluginRemoveThatFailsAfterTheStopReSyncsIt(t *testing.T) {
	s, sc := pmPluginServer(t, "olcrtc")
	stopped, restored := 0, 0
	s.pmCoreHook = &pmCoreState{
		running:       func() bool { return false },
		stop:          func() error { return nil },
		stopPlugin:    func(string) int { stopped++; return 1 },
		reload:        func() (bool, error) { return false, nil },
		restartPlugin: func(string) int { return 0 },
		restorePlugin: func() { restored++ },
	}
	sc.errs["apk del olcrtc"] = errors.New("apk: I/O error deleting package")

	body := `{"action":"remove","argv":["apk","del","olcrtc"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/updater/olcrtc/pm/apply", strings.NewReader(body))
	r.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterPMApply(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body %s", w.Code, w.Body.String())
	}
	if stopped != 1 {
		t.Fatalf("plugin stops = %d, want one before the removal", stopped)
	}
	if restored != 1 {
		t.Fatalf("the plugin was stopped for a removal that FAILED and never re-synced (%d) — the tunnel is down with its binary still installed", restored)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["datapath_restored"] != true {
		t.Fatalf("the response does not say the tunnel was restored: %s", w.Body.String())
	}
}

// On a manager that cannot install a named build, the rollback flow must decline BEFORE it offers a
// choice. The panel used to list the feed's builds on an opkg router, let the operator pick one, and
// only then answer that opkg cannot install a named version — the refusal arriving after the choice.
// The Keenetic is an opkg router.
func TestPMCandidatesEndpoint_SaysUpFrontWhenTheManagerCannotPin(t *testing.T) {
	up := updater.New("/usr/bin", "aarch64", nil)
	sc := &pmScript{answers: map[string]string{}, errs: map[string]error{}}
	up.WithPM(pm.Manager{Kind: pm.Opkg, Runner: sc})
	e := updater.EngineByID("sing-box")
	path := up.PlanPM(context.Background(), *e, updater.PlanUpgrade, "").Path
	sc.answers["opkg search "+path] = "sing-box - 1.12.17-1"
	// The file list is what opkg prints — POSIX separators — while `path` is whatever filepath.Join
	// produced on this host, which is backslashes on the Windows dev box. Converting rather than
	// hand-writing keeps the fixture tied to the path the planner actually resolves.
	sc.answers["opkg files sing-box"] = "Package sing-box (1.12.17-1) is installed on root and has the following files:\n" +
		strings.ReplaceAll(path, "\\", "/") + "\n"
	sc.answers["opkg list sing-box"] = "sing-box - 1.12.17-1\nsing-box - 1.11.4-1\n"
	s := &Server{updater: up}

	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/candidates", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMCandidates(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — %s", err, w.Body.String())
	}
	if got["can_pin"] != false {
		t.Fatalf("opkg reported as able to pin a version: %s", w.Body.String())
	}
	if got["cannot_pin_reason"] == nil {
		t.Fatalf("the refusal carries no reason, so the page would have to invent one: %s", w.Body.String())
	}
	// And no menu: offering builds it cannot install is the defect itself.
	if got["candidates"] != nil {
		t.Fatalf("a manager that cannot pin still offered builds to choose from: %s", w.Body.String())
	}
}

// The apk side must keep its picker, or the fix above is just a way of never rolling anything back.
func TestPMCandidatesEndpoint_StillOffersBuildsWhereThePinWorks(t *testing.T) {
	s, _ := pmServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/candidates", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMCandidates(w, r)

	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["can_pin"] != true {
		t.Fatalf("apk reported as unable to pin: %s", w.Body.String())
	}
	if got["candidates"] == nil {
		t.Fatalf("apk lost its candidate list: %s", w.Body.String())
	}
}

func TestPMCandidatesEndpoint_ListsTheFeedNotGitHub(t *testing.T) {
	s, _ := pmServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/updater/sing-box/pm/candidates", nil)
	r.SetPathValue("id", "sing-box")
	w := httptest.NewRecorder()
	s.handleUpdaterPMCandidates(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var got struct {
		Package    string `json:"package"`
		Candidates []struct {
			Version   string `json:"Version"`
			Installed bool   `json:"Installed"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if got.Package != "sing-box" {
		t.Fatalf("package = %q, want the bare name", got.Package)
	}
	if len(got.Candidates) != 2 || got.Candidates[0].Version != "1.12.17-r1" {
		t.Fatalf("candidates = %+v", got.Candidates)
	}
}
