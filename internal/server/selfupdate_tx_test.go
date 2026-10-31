package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/pm"
	"wayhop/internal/updater"
	"wayhop/internal/updatetx"
)

// txServer is a Server whose config sits in a temp dir (where the update records go), with the
// supervisor's init and spawn replaced by a recorder.
func txServer(t *testing.T) (*Server, *[][]string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spawned [][]string
	s := &Server{cfg: cfg, updater: updater.New(dir, "amd64", nil),
		updInit:  func() string { return "/etc/init.d/wayhop" },
		updSpawn: func(etc string, args ...string) error { spawned = append(spawned, args); return nil },
		// Not the host's /tmp: a supervisor recorded there must not decide a test.
		updPIDFile: filepath.Join(dir, "update-verify.pid")}
	return s, &spawned
}

func readMarker(t *testing.T, etc string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(etc, updatetx.MarkerFile))
	if err != nil {
		t.Fatalf("no update marker: %v", err)
	}
	return string(b)
}

// The panel's self-update records the update BEFORE the swap (the hook runs right before the rename)
// and hands the restart to the supervisor, which is what judges it.
func TestSelfUpdateIsRecordedBeforeTheSwapAndJudgedOutside(t *testing.T) {
	s, spawned := txServer(t)
	etc := s.updateDir()
	exe := filepath.Join(t.TempDir(), "wayhop")
	var sawMarker bool
	s.selfSwap = func(_ context.Context, _, tag, gotExe string, before func(string) error) (string, error) {
		if err := before("wayhop 0.5.8 (293a4894bb18, 2026-10-17T11:54:07-07:00)"); err != nil {
			return "", err
		}
		sawMarker = updatetx.Pending(etc)
		return tag, nil
	}
	installed, restarting, note, err := s.selfSwapAndJudge(context.Background(), "awadak3davra/wayhop", "v0.5.8", exe, "panel")
	if err != nil || installed != "v0.5.8" || !restarting {
		t.Fatalf("selfSwapAndJudge = %q %v %q %v", installed, restarting, note, err)
	}
	if !sawMarker {
		t.Error("the update was not recorded before the swap")
	}
	m := readMarker(t, etc)
	for _, want := range []string{"bin=" + exe + "\n", "rollback=" + exe + ".bak\n", "want_commit=293a4894bb18\n", "want_version=0.5.8\n", "by=panel\n", "init=/etc/init.d/wayhop\n"} {
		if !strings.Contains(m, want) {
			t.Errorf("marker lacks %q:\n%s", want, m)
		}
	}
	if len(*spawned) != 1 || strings.Join((*spawned)[0], " ") != "restart" {
		t.Errorf("supervisor spawned with %v, want [restart]", *spawned)
	}
	if _, err := os.Stat(filepath.Join(etc, updatetx.ScriptFile)); err != nil {
		t.Error("the supervisor script was not written beside the config")
	}
	if !strings.Contains(note, "put back automatically") {
		t.Errorf("the reply does not say the update is judged: %q", note)
	}
}

// A swap that fails after the record was written must not leave a record for the init to judge at
// the next boot: there is nothing to judge.
func TestAFailedSwapLeavesNoUpdateToJudge(t *testing.T) {
	s, spawned := txServer(t)
	s.selfSwap = func(_ context.Context, _, _, _ string, before func(string) error) (string, error) {
		_ = before("wayhop 0.5.8 (293a4894bb18, x)")
		return "", errors.New("swap binary: no space left on device")
	}
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.8", "/usr/sbin/wayhop", "panel"); err == nil {
		t.Fatal("the swap error was swallowed")
	}
	if updatetx.Pending(s.updateDir()) {
		t.Error("a failed swap left the update recorded")
	}
	if len(*spawned) != 0 {
		t.Error("the supervisor was started for a swap that did not happen")
	}
}

// With no init script to restart through, nothing can judge the update: no record, and the old
// behaviour (swap, then say restart by hand).
func TestNoInitMeansNoRecord(t *testing.T) {
	s, spawned := txServer(t)
	s.updInit = func() string { return "" }
	s.selfSwap = func(_ context.Context, _, tag, _ string, before func(string) error) (string, error) {
		return tag, before("wayhop 0.5.8 (293a4894bb18, x)")
	}
	_, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.8", "/usr/sbin/wayhop", "panel")
	if err != nil {
		t.Fatal(err)
	}
	if updatetx.Pending(s.updateDir()) || len(*spawned) != 0 {
		t.Error("an update was recorded where no init can restart it")
	}
}

// apkSizes answers `apk query` with the target build's size, as apk 3 does.
type apkSizes struct{ size string }

func (r apkSizes) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "apk" && len(args) > 0 && args[0] == "query" {
		return `[{"name":"wayhop","version":"0.5.8-r1","installed-size":` + r.size + `,"file-size":5900000},{"name":"wayhop","version":"0.5.7-r1","installed-size":15175842,"file-size":5800000}]`, nil
	}
	return "", errors.New("unexpected " + name + " " + strings.Join(args, " "))
}

func pmStatus(kind pm.Kind, payload string) updater.PackageStatus {
	return updater.PackageStatus{Manager: kind, Managed: true, OwnershipKnown: true, Package: "wayhop", Path: payload,
		InstalledVersion: "0.5.7-r1", LatestVersion: "0.5.8-r1", State: updater.PackageStateBehind}
}

// Item 2: a feed-installed WayHop is updated from the panel by its package manager, run by the
// supervisor (so the package's restart cannot kill it midway). On apk the live path is not the
// package's file, so a rollback copy is kept and recorded.
func TestPackageOwnedWayHopIsUpdatedThroughTheSupervisor(t *testing.T) {
	s, spawned := txServer(t)
	root := t.TempDir()
	exe := filepath.Join(root, "sbin", "wayhop")
	payload := filepath.Join(root, "libexec", "wayhop", "wayhop")
	for _, p := range []string{exe, payload} {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("OLD"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.updater.WithPM(pm.Manager{Kind: pm.Apk, Runner: apkSizes{size: "15421783"}}).WithAvail(func(string) (uint64, bool) { return 40 << 20, true })
	code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Apk, payload))
	if code != http.StatusOK || out["restarting"] != true {
		t.Fatalf("selfInstallPM = %d %v", code, out)
	}
	if len(*spawned) != 1 || strings.Join((*spawned)[0], " ") != "pm apk" {
		t.Fatalf("supervisor spawned with %v, want [pm apk]", *spawned)
	}
	m := readMarker(t, s.updateDir())
	for _, want := range []string{"rollback=" + exe + ".bak\n", "want_version=0.5.8\n", "to=0.5.8-r1\n", "by=apk\n"} {
		if !strings.Contains(m, want) {
			t.Errorf("marker lacks %q:\n%s", want, m)
		}
	}
	if b, err := os.ReadFile(exe + ".bak"); err != nil || string(b) != "OLD" {
		t.Error("no rollback copy of the running binary was kept before apk replaces it")
	}
}

// opkg owns the live path itself: no rollback copy (it would desync the package database), and the
// record says why, so the result can say it too.
func TestOpkgOwnedWayHopIsUpdatedWithoutABinaryRollback(t *testing.T) {
	s, spawned := txServer(t)
	exe := filepath.Join(t.TempDir(), "wayhop")
	_ = os.WriteFile(exe, []byte("OLD"), 0o755)
	s.updater.WithPM(pm.Manager{Kind: pm.Opkg, Runner: apkSizes{}})
	code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Opkg, exe))
	if code != http.StatusOK {
		t.Fatalf("selfInstallPM = %d %v", code, out)
	}
	m := readMarker(t, s.updateDir())
	if !strings.Contains(m, "rollback=\n") || !strings.Contains(m, "norollback=opkg owns") {
		t.Errorf("opkg update recorded a rollback it must not do:\n%s", m)
	}
	if _, err := os.Stat(exe + ".bak"); !os.IsNotExist(err) {
		t.Error("a rollback copy was made of a binary opkg owns")
	}
	if len(*spawned) != 1 || strings.Join((*spawned)[0], " ") != "pm opkg" {
		t.Errorf("supervisor spawned with %v", *spawned)
	}
}

// The package needs room beside the running build (the panel cannot remove its own package first):
// refused with the numbers, nothing recorded, nothing started.
func TestPackageUpdateThatDoesNotFitIsRefusedUpFront(t *testing.T) {
	s, spawned := txServer(t)
	root := t.TempDir()
	exe, payload := filepath.Join(root, "wayhop"), filepath.Join(root, "payload")
	_ = os.WriteFile(exe, []byte("OLD"), 0o755)
	s.updater.WithPM(pm.Manager{Kind: pm.Apk, Runner: apkSizes{size: "15421783"}}).WithAvail(func(string) (uint64, bool) { return 10 << 20, true })
	code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Apk, payload))
	if code != http.StatusInsufficientStorage || !strings.Contains(out["error"].(string), "free at least") {
		t.Fatalf("selfInstallPM = %d %v, want a refusal naming the MiB to free", code, out)
	}
	if updatetx.Pending(s.updateDir()) || len(*spawned) != 0 {
		t.Error("a refused update was recorded or started")
	}
}

// Demo mode drives the flow and changes nothing.
func TestDemoPackageUpdateChangesNothing(t *testing.T) {
	s, spawned := txServer(t)
	s.cfg.Demo = true
	exe := filepath.Join(t.TempDir(), "wayhop")
	code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Apk, exe+"-payload"))
	if code != http.StatusOK || out["restarting"] != false || !strings.Contains(out["note"].(string), "demo") {
		t.Fatalf("demo selfInstallPM = %d %v", code, out)
	}
	if updatetx.Pending(s.updateDir()) || len(*spawned) != 0 {
		t.Error("the demo recorded or started an update")
	}
}

// The panel and the bot read the last judgement from the status.
func TestSelfStatusReportsARollback(t *testing.T) {
	s, _ := txServer(t)
	line := `{"result":"rolled_back","reason":"the new build does not stay running (it exits or crashes on start), within 90s","from":"wayhop 0.5.7 (447a04fa7422, x)","to":"v0.5.8","by":"panel","at":` +
		strconv.FormatInt(time.Now().Unix(), 10) + "}\n"
	if err := os.WriteFile(filepath.Join(s.updateDir(), updatetx.ResultFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	s.selfUpdateReport(out)
	if n, _ := out["last_update_note"].(string); !strings.Contains(n, "rolled back") || !strings.Contains(n, "crashes on start") {
		t.Errorf("last_update_note = %q", n)
	}
}
