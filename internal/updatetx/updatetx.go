// Package updatetx is the transaction around replacing WayHop's own binary: the record written
// before the swap, the supervisor that judges the new build from outside the daemon being replaced,
// and the result the panel and the bot report afterwards.
//
// The daemon cannot judge its own replacement: the restart kills the process that did the swap, and a
// build that crashes on start cannot roll itself back. So the judgement is verify.sh, a shell script
// embedded here and written next to the config before every update (installers write it too, from
// `wayhop update-verifier`). It runs in a session of its own, restarts the service through its init or
// lets the package manager do it, and restores the rollback copy when the new build does not answer
// /api/health with its own commit within a bounded window. The pending marker lives on flash, so the
// init script can finish the judgement after a reboot inside the window.
package updatetx

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/localtz"
)

//go:embed verify.sh
var script []byte

// Script is the supervisor, as the installers and the daemon write it.
func Script() []byte { return script }

const (
	MarkerFile = "update.pending"     // written before the swap; removed once the update is judged
	ResultFile = "update-result.json" // the last judgement, for the panel and the bot
	ScriptFile = "update-verify.sh"   // the supervisor, beside the config
	// LogFile is RAM on a router (/tmp): a log of the judgement and of a package manager's run.
	LogFile = "/tmp/wayhop-update.log"
	// DefaultWindow is how long a new build gets to answer. Generous for a MIPS router that starts
	// slowly; a build that has not answered in a minute and a half is not going to.
	DefaultWindow = 90
)

// Marker describes the update in flight.
type Marker struct {
	Bin         string // the binary being replaced
	Init        string // the init script that starts and stops it
	Config      string // its config, for the address it answers on
	Rollback    string // the copy to restore; "" = no rollback possible (NoRollback says why)
	NoRollback  string
	WantCommit  string // the new build's commit, as its --version prints it
	WantVersion string // the new build's version, when no commit can be compared
	From        string // the old build's --version line
	To          string // what is being installed, for the report
	By          string // panel | installer | apk | opkg
	Window      int    // seconds
}

// Write records m in etc, atomically. Every value is one line; a newline would forge another key.
func (m Marker) Write(etc string) error {
	if m.Window <= 0 {
		m.Window = DefaultWindow
	}
	kv := [][2]string{{"bin", m.Bin}, {"init", m.Init}, {"config", m.Config}, {"rollback", m.Rollback},
		{"norollback", m.NoRollback}, {"want_commit", m.WantCommit}, {"want_version", m.WantVersion},
		{"from", m.From}, {"to", m.To}, {"by", m.By}, {"window", fmt.Sprint(m.Window)}, {"boots", "0"}}
	var b strings.Builder
	for _, p := range kv {
		if strings.ContainsAny(p[1], "\r\n") {
			return fmt.Errorf("update marker: %s carries a line break", p[0])
		}
		b.WriteString(p[0] + "=" + p[1] + "\n")
	}
	return writeAtomic(filepath.Join(etc, MarkerFile), []byte(b.String()), 0o600)
}

// Pending reports whether an update is waiting to be judged.
func Pending(etc string) bool {
	_, err := os.Stat(filepath.Join(etc, MarkerFile))
	return err == nil
}

// PendingStale is how old a marker can be and still describe a judgement in progress. The longest
// one is a package manager's run plus its window; the supervisor's boot pass rewrites the marker
// when it starts. An older marker is one nobody is finishing (an installer interrupted over SSH, a
// supervisor killed): only the next boot acts on it. The age is only for a marker with no live
// supervisor (SupervisorAlive): the boot pass stamps the marker with the clock OpenWrt restored at
// boot, and NTP may then move it forward by more than this while the judgement runs.
const PendingStale = 30 * time.Minute

// PendingSince is when the update waiting to be judged was recorded; ok is false when none is.
func PendingSince(etc string) (since time.Time, ok bool) {
	fi, err := os.Stat(filepath.Join(etc, MarkerFile))
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// SupervisorPIDFile is where verify.sh records its pid for as long as it runs (PIDF there; the init
// script reads it too, to leave a running judgement alone at boot). It is in RAM, so a reboot clears it.
const SupervisorPIDFile = "/tmp/wayhop-update-verify.pid"

// SupervisorAlive reports whether pidFile names a live process, and which: the supervisor is still at
// work. The marker alone cannot say so, because the supervisor drops it first and works on after it:
// rollback() removes it before it stops the service, restores the copy and waits up to 60 s for the
// old build; proven() removes it before it compresses the rollback copy, 10-40 s on a test router. The
// liveness test is the init script's `kill -0`.
func SupervisorAlive(pidFile string) (pid int, alive bool) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, processAlive(pid)
}

// Clear drops the marker: the update it described did not happen after all.
func Clear(etc string) { _ = os.Remove(filepath.Join(etc, MarkerFile)) }

// Result is the last judgement.
type Result struct {
	Result string `json:"result"` // ok | rolled_back | failed
	Reason string `json:"reason"`
	From   string `json:"from"`
	To     string `json:"to"`
	By     string `json:"by"`
	At     int64  `json:"at"`
}

// ReadResult reads the last judgement; ok is false when there is none (or it is unreadable).
func ReadResult(etc string) (Result, bool) {
	b, err := os.ReadFile(filepath.Join(etc, ResultFile))
	if err != nil {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal(b, &r) != nil || r.Result == "" {
		return Result{}, false
	}
	return r, true
}

// Note is the sentence the panel and the bot show for a result worth showing: a rollback or a
// failure, recent enough to still be news (a week). "" for a success or an old result.
//
// The time is written in now's zone, with that zone named: a caller passes now in the router's zone
// (localtz.Location). Go's own time.Local is UTC on Keenetic and OpenWrt, so a rollback the router's
// clock put at 22:20 in UTC+3 was reported as 19:20, beside bot times that were right.
func (r Result) Note(now time.Time) string {
	if r.At == 0 || now.Sub(time.Unix(r.At, 0)) > 7*24*time.Hour {
		return ""
	}
	to := r.To
	if to == "" {
		to = "the new build"
	}
	at := time.Unix(r.At, 0).In(now.Location())
	when := at.Format("2006-01-02 15:04") + " (" + localtz.Label(at) + ")"
	switch r.Result {
	case "rolled_back":
		return fmt.Sprintf("The update to %s was rolled back at %s: %s.", to, when, r.Reason)
	case "failed":
		return fmt.Sprintf("The update to %s failed at %s: %s.", to, when, r.Reason)
	}
	return ""
}

// InstallScript writes the supervisor into etc and returns its path. Rewritten only when it differs,
// so an unchanged script costs no flash write.
func InstallScript(etc string) (string, error) {
	p := filepath.Join(etc, ScriptFile)
	if cur, err := os.ReadFile(p); err == nil && string(cur) == string(script) {
		return p, nil
	}
	return p, writeAtomic(p, script, 0o755)
}

// InitScript is the init that runs WayHop here: OpenWrt's procd script or Entware's S99. "" = none
// (a dev host, the demo), where no update can be judged.
func InitScript() string {
	for _, p := range []string{"/etc/init.d/wayhop", "/opt/etc/init.d/S99wayhop"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// LogTail is the last n lines of the update log.
func LogTail(n int) []string {
	b, err := os.ReadFile(LogFile)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ParseVersionLine splits a `wayhop --version` line ("wayhop 0.5.8 (293a4894bb18, 2026-…)") into
// its version and commit. Either is "" when the line does not carry it.
func ParseVersionLine(line string) (ver, commit string) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) >= 2 && f[0] == "wayhop" {
		ver = f[1]
	}
	if i := strings.Index(line, "("); i >= 0 {
		rest := line[i+1:]
		if j := strings.IndexAny(rest, ",)"); j > 0 {
			commit = strings.TrimSpace(rest[:j])
		}
	}
	if !hexCommit.MatchString(commit) {
		commit = "" // "unknown", or a stub's free text: nothing a health answer could match
	}
	return ver, commit
}

var hexCommit = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// ErrNoInit is Spawn's answer where nothing can run the judgement.
var ErrNoInit = errors.New("no WayHop init script here to restart through")

// writeSynced and syncDir are the durable write and the directory sync, as seams: a power cut is the
// failure they exist for, and no test can cut one, so the tests check the order instead.
var (
	writeSynced = atomicfile.WriteSynced
	syncDir     = atomicfile.SyncDir
)

// writeAtomic replaces p with b, synced before the rename and with the directory synced after it. The
// marker exists to survive a power cut inside the window; renamed into place unsynced it can reach
// the flash empty (UBIFS does not sync data on rename, and a new name on ext4 does not trigger
// auto_da_alloc), and verify.sh drops an empty marker at boot, so a broken build is never rolled back.
func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".new"
	if err := writeSynced(tmp, b, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(p))
	return nil
}
