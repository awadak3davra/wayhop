package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/pm"
	"wayhop/internal/updatetx"
)

// writeResult records a judgement as verify.sh writes it.
func writeResult(t *testing.T, etc, result, to string) {
	t.Helper()
	line := `{"result":"` + result + `","reason":"the new build does not stay running (it exits or crashes on start), within 90s","from":"wayhop 0.5.8 (447a04fa7422, x)","to":"` + to + `","by":"auto-update","at":` +
		strconv.FormatInt(time.Now().Unix(), 10) + "}\n"
	if err := os.WriteFile(filepath.Join(etc, updatetx.ResultFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// countingSwap is a release swap that records the update through the hook, as SelfUpdateWith does,
// and counts how often it ran.
func countingSwap(n *int) func(context.Context, string, string, string, func(string) error) (string, error) {
	return func(_ context.Context, _, tag, _ string, before func(string) error) (string, error) {
		*n++
		return tag, before("wayhop " + tag[1:] + " (293a4894bb18, x)")
	}
}

// A release the supervisor rolled back must not be installed again by the next auto-update tick: the
// restored daemon starts a fresh 15-minute timer, still sees the release as newer, and each round
// stops routing for 90 s and writes a whole binary to the flash. Only a newer release, or a manual
// install, may try again.
func TestAutoUpdateSkipsAReleaseTheSupervisorRolledBack(t *testing.T) {
	for _, result := range []string{"rolled_back", "failed"} {
		t.Run(result, func(t *testing.T) {
			s, spawned := txServer(t)
			etc := s.updateDir()
			var swaps int
			s.selfSwap = countingSwap(&swaps)
			writeResult(t, etc, result, "v0.5.9")
			if s.autoInstall(context.Background(), "", "v0.5.9") || swaps != 0 || len(*spawned) != 0 {
				t.Fatalf("auto-update installed v0.5.9 again after it was %s (swaps=%d)", result, swaps)
			}
			if !s.autoInstall(context.Background(), "", "v0.5.10") || swaps != 1 {
				t.Errorf("a newer release than the one %s was not installed (swaps=%d)", result, swaps)
			}
		})
	}
}

// A release that was judged good is not a reason to skip anything.
func TestAutoUpdateInstallsAfterASuccess(t *testing.T) {
	s, _ := txServer(t)
	var swaps int
	s.selfSwap = countingSwap(&swaps)
	writeResult(t, s.updateDir(), "ok", "v0.5.9")
	if !s.autoInstall(context.Background(), "", "v0.5.9") || swaps != 1 {
		t.Errorf("auto-update skipped a release after a success (swaps=%d)", swaps)
	}
}

// The installers do not record the tag. Their marker carries the bare version, which verify.sh copies
// into its result when it finishes the judgement after a boot inside the window; their own result
// carries the --version line of the build they installed. Compared with the tag as written, a release
// an installer's run rolled back was installed again by the next auto-update tick.
func TestAutoUpdateSkipsAReleaseTheInstallerRolledBack(t *testing.T) {
	for name, to := range map[string]string{
		"verify.sh on an installer's marker": "0.5.9",
		"the installer's own result":         "wayhop 0.5.9 (293a4894bb18, 2026-10-20T00:00:00Z)",
	} {
		t.Run(name, func(t *testing.T) {
			s, spawned := txServer(t)
			var swaps int
			s.selfSwap = countingSwap(&swaps)
			writeResult(t, s.updateDir(), "rolled_back", to)
			if s.autoInstall(context.Background(), "", "v0.5.9") || swaps != 0 || len(*spawned) != 0 {
				t.Fatalf("auto-update installed v0.5.9 again after the installer rolled back %q (swaps=%d)", to, swaps)
			}
			if !s.autoInstall(context.Background(), "", "v0.5.10") || swaps != 1 {
				t.Errorf("a newer release than the one rolled back was not installed (swaps=%d)", swaps)
			}
		})
	}
}

// Only the same release matches: not a longer version that shares a prefix, and not a package
// rebuild of the same version, which may be the fix for what the first build broke.
func TestSameRelease(t *testing.T) {
	cases := []struct {
		to, tag string
		same    bool
	}{
		{"v0.5.9", "v0.5.9", true},
		{"0.5.9", "v0.5.9", true},
		{" 0.5.9\n", "v0.5.9", true},
		{"wayhop 0.5.9 (293a4894bb18, 2026-10-20T00:00:00Z)", "v0.5.9", true},
		{"wayhop 0.5.9 (unknown, unknown)", "v0.5.9", true},
		{"0.5.9", "v0.5.90", false},
		{"wayhop 0.5.9 (293a4894bb18, 2026-10-20T00:00:00Z)", "v0.5.10", false},
		{"0.5.5", "v0.5.5-r2", false},
		{"", "v0.5.9", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := sameRelease(c.to, c.tag); got != c.same {
			t.Errorf("sameRelease(%q, %q) = %v, want %v", c.to, c.tag, got, c.same)
		}
	}
}

// A second self-update while the first is still being judged would make the rollback copy the build
// under judgement (linkRollback runs on whatever the binary is now): if that build then crashes on
// start, the supervisor "restores" it and the router is left without a working WayHop.
func TestASelfUpdateWhileOneIsJudgedIsRefused(t *testing.T) {
	s, spawned := txServer(t)
	var swaps int
	s.selfSwap = countingSwap(&swaps)
	exe := filepath.Join(t.TempDir(), "wayhop")
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.9", exe, "panel"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.9", exe, "auto-update"); !errors.Is(err, errUpdateInFlight) || swaps != 1 {
		t.Fatalf("a second update ran while the first was being judged (err=%v, swaps=%d)", err, swaps)
	}
	if len(*spawned) != 1 || !updatetx.Pending(s.updateDir()) {
		t.Errorf("the refusal disturbed the update being judged (spawned %v)", *spawned)
	}
}

// Two requests queued on the swap lock: the second one checked nothing before the lock that the first
// had not yet recorded, so the check has to be made once it holds the lock.
func TestQueuedSelfUpdatesCannotBothPass(t *testing.T) {
	s, _ := txServer(t)
	exe := filepath.Join(t.TempDir(), "wayhop")
	var mu sync.Mutex
	swaps := 0
	inFirst, release := make(chan struct{}), make(chan struct{})
	s.selfSwap = func(_ context.Context, _, tag, _ string, before func(string) error) (string, error) {
		mu.Lock()
		swaps++
		first := swaps == 1
		mu.Unlock()
		if first {
			close(inFirst)
			<-release // still downloading: nothing is recorded yet
		}
		return tag, before("wayhop 0.5.9 (293a4894bb18, x)")
	}
	errs := make(chan error, 2)
	update := func() {
		_, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.9", exe, "panel")
		errs <- err
	}
	go update()
	<-inFirst
	go update()
	time.Sleep(50 * time.Millisecond) // the second request reaches the lock
	close(release)
	var failed int
	for i := 0; i < 2; i++ {
		if <-errs != nil {
			failed++
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if swaps != 1 || failed != 1 {
		t.Errorf("both queued updates swapped (swaps=%d, refused=%d)", swaps, failed)
	}
}

// The package path writes a rollback copy and a marker of its own: refused the same way while an
// update is being judged.
func TestPackageUpdateWhileOneIsJudgedIsRefused(t *testing.T) {
	s, spawned := txServer(t)
	root := t.TempDir()
	exe, payload := filepath.Join(root, "wayhop"), filepath.Join(root, "payload")
	_ = os.WriteFile(exe, []byte("UNDER JUDGEMENT"), 0o755)
	_ = os.WriteFile(exe+".bak", []byte("LAST GOOD"), 0o755)
	if err := (updatetx.Marker{Bin: exe, Init: "/etc/init.d/wayhop", Rollback: exe + ".bak", To: "v0.5.9"}).Write(s.updateDir()); err != nil {
		t.Fatal(err)
	}
	s.updater.WithPM(pm.Manager{Kind: pm.Apk, Runner: apkSizes{size: "15421783"}}).WithAvail(func(string) (uint64, bool) { return 40 << 20, true })
	code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Apk, payload))
	if code != http.StatusConflict || len(*spawned) != 0 {
		t.Fatalf("selfInstallPM = %d %v (spawned %v); want a refusal", code, out, *spawned)
	}
	if b, _ := os.ReadFile(exe + ".bak"); string(b) != "LAST GOOD" {
		t.Errorf("the rollback copy was replaced: %q", b)
	}
}

// A marker nobody is finishing (an installer interrupted over SSH, a supervisor killed) is acted on
// at the next boot; until then it must not lock the panel out of updating. A supervisor killed with
// SIGKILL leaves its pid file behind (its EXIT trap never runs): a pid that is gone is no supervisor.
func TestAStaleMarkerDoesNotBlockAnUpdate(t *testing.T) {
	for name, pid := range map[string]func(*testing.T) int{
		"no pid file":            nil,
		"the supervisor's ghost": exitedPID,
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := txServer(t)
			etc := s.updateDir()
			markerAt(t, etc, time.Now().Add(-updatetx.PendingStale-time.Minute))
			if pid != nil {
				supervisorAt(t, s, pid(t))
			}
			var swaps int
			s.selfSwap = countingSwap(&swaps)
			if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.9", filepath.Join(t.TempDir(), "wayhop"), "panel"); err != nil || swaps != 1 {
				t.Errorf("a stale marker blocked the update (err=%v, swaps=%d)", err, swaps)
			}
		})
	}
}

// markerAt writes a marker recorded at at.
func markerAt(t *testing.T, etc string, at time.Time) {
	t.Helper()
	if err := (updatetx.Marker{Bin: "/usr/sbin/wayhop", Init: "/etc/init.d/wayhop", To: "v0.5.8"}).Write(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(etc, updatetx.MarkerFile), at, at); err != nil {
		t.Fatal(err)
	}
}

// supervisorAt records pid in the supervisor's pid file, as verify.sh does (echo "$$" > "$PIDF").
func supervisorAt(t *testing.T, s *Server, pid int) {
	t.Helper()
	if err := os.WriteFile(s.updPIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// exitedPID is the pid of a process that has run and been reaped.
func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// The supervisor drops the marker first and works on: rollback() then stops the service, restores the
// copy and waits up to 60 s for the old build; proven() compresses the copy, 10-40 s on a test router.
// An update let in there relinked .bak to the build now running and deleted .bak.gz, and the
// compression then moved its gzip of the first build into place and deleted .bak: the second update
// had no rollback copy, and a build that crashes on start crash-looped.
func TestAnUpdateWaitsForTheSupervisorToFinish(t *testing.T) {
	s, spawned := txServer(t)
	root := t.TempDir()
	exe := filepath.Join(root, "wayhop")
	supervisorAt(t, s, os.Getpid()) // alive, and no marker: it is rolling back or compressing
	var swaps int
	s.selfSwap = countingSwap(&swaps)
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.10", exe, "auto-update"); !errors.Is(err, errUpdateInFlight) || swaps != 0 || len(*spawned) != 0 {
		t.Fatalf("an update ran while the supervisor was still at work (err=%v, swaps=%d)", err, swaps)
	}
	_ = os.WriteFile(exe, []byte("RUNNING"), 0o755)
	_ = os.WriteFile(exe+".bak", []byte("BEING COMPRESSED"), 0o755)
	s.updater.WithPM(pm.Manager{Kind: pm.Apk, Runner: apkSizes{size: "15421783"}}).WithAvail(func(string) (uint64, bool) { return 40 << 20, true })
	if code, out := s.selfInstallPM(context.Background(), exe, pmStatus(pm.Apk, filepath.Join(root, "payload"))); code != http.StatusConflict || len(*spawned) != 0 {
		t.Fatalf("selfInstallPM = %d %v (spawned %v); want a refusal", code, out, *spawned)
	}
	if b, _ := os.ReadFile(exe + ".bak"); string(b) != "BEING COMPRESSED" {
		t.Errorf("the package path replaced the copy the supervisor is working on: %q", b)
	}
	supervisorAt(t, s, exitedPID(t)) // done
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.10", exe, "auto-update"); err != nil || swaps != 1 {
		t.Errorf("the update was still refused once the supervisor had exited (err=%v, swaps=%d)", err, swaps)
	}
}

// The boot pass stamps the marker with the clock OpenWrt restored at boot, and NTP may then move the
// clock forward by hours while the judgement runs: the marker looks stale and is not.
func TestAMarkerThatLooksStaleBlocksWhileItsSupervisorLives(t *testing.T) {
	s, _ := txServer(t)
	markerAt(t, s.updateDir(), time.Now().Add(-3*time.Hour))
	supervisorAt(t, s, os.Getpid())
	var swaps int
	s.selfSwap = countingSwap(&swaps)
	if _, _, _, err := s.selfSwapAndJudge(context.Background(), "", "v0.5.9", filepath.Join(t.TempDir(), "wayhop"), "panel"); !errors.Is(err, errUpdateInFlight) || swaps != 0 {
		t.Errorf("an update ran past a judgement in progress (err=%v, swaps=%d)", err, swaps)
	}
}

// The refusal names the time in the router's zone: Go's time.Local is UTC on Keenetic and OpenWrt, so
// a marker an operator saw recorded at 14:32 in UTC+3 was reported as recorded at 11:32.
func TestTheInFlightRefusalNamesTheRoutersTime(t *testing.T) {
	s, _ := txServer(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	markerAt(t, s.updateDir(), at)
	// Five hours off this host's own zone, so a time formatted in time.Local cannot pass.
	_, off := at.In(time.Local).Zone()
	zone := time.FixedZone("router", off+5*3600)
	s.updZone = func() *time.Location { return zone }
	err := s.updateInFlight()
	if want := "recorded at " + at.In(zone).Format("15:04:05"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("updateInFlight() = %v; want it to say %q", err, want)
	}
}
