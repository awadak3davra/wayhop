package updatetx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The marker is read by a shell script with sed: one key per line, and no value may carry a line
// break, which would let a value forge another key (a second "rollback=" pointing elsewhere).
func TestMarkerIsOneKeyPerLineAndRefusesLineBreaks(t *testing.T) {
	etc := t.TempDir()
	m := Marker{Bin: "/usr/sbin/wayhop", Init: "/etc/init.d/wayhop", Config: "/etc/wayhop/config.json",
		Rollback: "/usr/sbin/wayhop.bak", WantCommit: "293a4894bb18", WantVersion: "0.5.8",
		From: "wayhop 0.5.7 (447a04fa7422, 2026-09-29)", To: "v0.5.8", By: "panel"}
	if err := m.Write(etc); err != nil {
		t.Fatal(err)
	}
	if !Pending(etc) {
		t.Fatal("a written marker is not pending")
	}
	b, _ := os.ReadFile(filepath.Join(etc, MarkerFile))
	for _, want := range []string{"bin=/usr/sbin/wayhop\n", "rollback=/usr/sbin/wayhop.bak\n", "want_commit=293a4894bb18\n",
		"window=90\n", "boots=0\n", "from=wayhop 0.5.7 (447a04fa7422, 2026-09-29)\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("marker lacks %q:\n%s", want, b)
		}
	}
	Clear(etc)
	if Pending(etc) {
		t.Error("Clear left the marker")
	}
	bad := m
	bad.To = "v0.5.8\nrollback=/tmp/evil"
	if err := bad.Write(etc); err == nil || Pending(etc) {
		t.Errorf("a value with a line break was written (err=%v)", err)
	}
}

func TestResultNoteSaysWhatHappenedOnlyWhenItIsNews(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := now.Add(-time.Hour).Unix()
	if n := (Result{Result: "rolled_back", Reason: "the new build does not stay running", To: "v0.5.8", At: at}).Note(now); !strings.Contains(n, "rolled back") || !strings.Contains(n, "does not stay running") {
		t.Errorf("rollback note = %q", n)
	}
	if n := (Result{Result: "failed", Reason: "apk exited 1", To: "0.5.8-r1", At: at}).Note(now); !strings.Contains(n, "failed") {
		t.Errorf("failure note = %q", n)
	}
	if n := (Result{Result: "ok", At: at}).Note(now); n != "" {
		t.Errorf("a success is not news: %q", n)
	}
	if n := (Result{Result: "rolled_back", At: now.Add(-8 * 24 * time.Hour).Unix()}).Note(now); n != "" {
		t.Errorf("a week-old rollback is not news: %q", n)
	}
}

func TestReadResultReadsWhatTheSupervisorWrites(t *testing.T) {
	etc := t.TempDir()
	if _, ok := ReadResult(etc); ok {
		t.Fatal("no file, yet a result")
	}
	// The exact line verify.sh prints (result()).
	line := `{"result":"rolled_back","reason":"the new build does not answer on :8088, within 90s; the previous build (wayhop 0.5.7 (447a04fa7422, x)) runs again","from":"wayhop 0.5.7 (447a04fa7422, x)","to":"v0.5.8","by":"panel","at":1800000000}` + "\n"
	if err := os.WriteFile(filepath.Join(etc, ResultFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok := ReadResult(etc)
	if !ok || r.Result != "rolled_back" || r.By != "panel" || r.At != 1800000000 || !strings.Contains(r.Reason, "runs again") {
		t.Errorf("ReadResult = %+v %v", r, ok)
	}
}

// The script the daemon and the installers write is the one embedded here, verbatim: LF line ends
// (a CR breaks every line in busybox sh), a shebang the installers check for, and every mode.
func TestScriptIsTheSupervisorAndInstallsOnce(t *testing.T) {
	s := string(Script())
	if strings.Contains(s, "\r") {
		t.Fatal("the supervisor has CR line ends; busybox sh would fail on every line")
	}
	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatal("the supervisor does not start with the shebang the installers check for")
	}
	for _, mode := range []string{"  restart)", "  boot)", "  pm)", "rollback()", "squash_if_tight()"} {
		if !strings.Contains(s, mode) {
			t.Errorf("the supervisor has no %q", mode)
		}
	}
	etc := t.TempDir()
	p, err := InstallScript(etc)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != s {
		t.Fatal("the installed supervisor differs from the embedded one")
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(p, old, old)
	if _, err := InstallScript(etc); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); !fi.ModTime().Equal(old) {
		t.Error("an unchanged supervisor was rewritten: a flash write for nothing")
	}
}

func TestParseVersionLine(t *testing.T) {
	cases := []struct{ line, ver, commit string }{
		{"wayhop 0.5.8 (293a4894bb18, 2026-10-17T11:54:07-07:00)", "0.5.8", "293a4894bb18"},
		{"wayhop 0.5.9-dev (511c80de304d, 2026-10-17, dirty)", "0.5.9-dev", "511c80de304d"},
		{"wayhop 0.5.5 (unknown, unknown)", "0.5.5", ""},
		{"wayhop 9.9.9 (self-update test stub)", "9.9.9", ""},
		{"garbage", "", ""},
	}
	for _, c := range cases {
		v, cm := ParseVersionLine(c.line)
		if v != c.ver || cm != c.commit {
			t.Errorf("ParseVersionLine(%q) = %q %q, want %q %q", c.line, v, cm, c.ver, c.commit)
		}
	}
}
