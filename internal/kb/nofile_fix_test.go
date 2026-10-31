package kb

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// QA-132. The open-files fix told OpenWrt owners to add `limits { nofile = '16384 16384'; }` to the
// init script. procd has no such syntax, and in shell the "}" closes start_service early, so the
// script stops parsing and WayHop does not start at boot. procd's only form is
// `procd_set_param limits nofile="soft hard"` inside the instance, and the shipped OpenWrt script now
// carries it, as the shipped S99wayhop carries `ulimit -n` on Entware. These tests hold the advice to
// those lines and to the files that ship them.

var (
	procdLimitLine = regexp.MustCompile("`(procd_set_param limits [^`]+)`")
	ulimitLine     = regexp.MustCompile("`(ulimit -n [^`]+)`")
	procdNofile    = regexp.MustCompile(`^procd_set_param limits nofile="[1-9][0-9]* [1-9][0-9]*"$`)
)

func repoFile(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func nofileFix(t *testing.T) string {
	t.Helper()
	e := entryByID("gen-too-many-files")
	if e == nil {
		t.Fatal("gen-too-many-files is missing")
	}
	return e.Fix
}

// The OpenWrt line in the advice is procd's own form, and it is the line the shipped init script
// sets inside the instance, so the two cannot drift apart.
func TestNofileFix_OpenWrtLineIsTheShippedProcdLine(t *testing.T) {
	fix := nofileFix(t)
	m := procdLimitLine.FindStringSubmatch(fix)
	if m == nil {
		t.Fatalf("the fix names no procd limits line: %q", fix)
	}
	line := m[1]
	if !procdNofile.MatchString(line) {
		t.Fatalf("%q is not procd's form for a limit", line)
	}
	for _, e := range Entries() {
		if strings.Contains(e.Fix, "limits {") {
			t.Errorf("%s still gives the block form, which is not procd syntax: %q", e.ID, e.Fix)
		}
	}

	script := repoFile(t, "packaging", "openwrt", "wayhop.init")
	start := strings.Index(script, "\nstart_service() {\n")
	if start < 0 {
		t.Fatal("wayhop.init has no start_service")
	}
	body := script[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("start_service is not closed")
	}
	body = body[:end]
	open := strings.Index(body, "\n\tprocd_open_instance\n")
	set := strings.Index(body, "\n\t"+line+"\n")
	closing := strings.Index(body, "\n\tprocd_close_instance")
	if open < 0 || closing < 0 {
		t.Fatal("start_service opens or closes no instance")
	}
	if set < 0 || set < open || set > closing {
		t.Errorf("wayhop.init does not set %q between procd_open_instance and procd_close_instance", line)
	}
}

// The Entware advice names a place that exists, start() in S99wayhop, and the shipped S99wayhop runs
// that command there before it starts the daemon, so the daemon and the core inherit the limit. Were
// the line only advice, install.sh and every package upgrade would put back a script without it.
func TestNofileFix_EntwareLineIsInTheShippedS99(t *testing.T) {
	fix := nofileFix(t)
	m := ulimitLine.FindStringSubmatch(fix)
	if m == nil || !strings.Contains(fix, "start() in /opt/etc/init.d/S99wayhop") {
		t.Fatalf("the fix does not say where on Entware: %q", fix)
	}
	script := repoFile(t, "packaging", "S99wayhop")
	start := strings.Index(script, "\nstart() {\n")
	if start < 0 {
		t.Fatal("S99wayhop has no start() for the advice to point at")
	}
	body := script[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("start() is not closed")
	}
	body = body[:end]
	set := strings.Index(body, " "+m[1]+" ")
	launch := strings.Index(body, "\"$PROG\" --config")
	if launch < 0 {
		t.Fatal("start() no longer launches the daemon where this test looks for it")
	}
	if set < 0 || set > launch {
		t.Errorf("S99wayhop does not run %q in start() before it launches the daemon", m[1])
	}
}

// The line ships from this release on, but only an install or a package upgrade replaces the init
// script: an update from the panel or the bot swaps the binary alone. The advice has to say so, or an
// owner updated from the panel reads "this release sets it" and keeps the old limit.
func TestNofileFix_SaysAPanelUpdateKeepsTheOldScript(t *testing.T) {
	fix := nofileFix(t)
	for _, want := range []string{"install.sh", "update from the panel or the bot replaces only the binary", "add the line by hand"} {
		if !strings.Contains(fix, want) {
			t.Errorf("the fix does not say %q: %q", want, fix)
		}
	}
}

// What the advice tells an owner to write must leave each script parsable: the shipped init as it
// is, an older init that gains the procd line by hand, and S99wayhop with the ulimit line added at
// the top of start(), as an owner of an older copy would.
func TestNofileFix_EditedScriptsStillParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to parse the init scripts with")
	}
	fix := nofileFix(t)
	procd := procdLimitLine.FindStringSubmatch(fix)
	ulimit := ulimitLine.FindStringSubmatch(fix)
	if procd == nil || ulimit == nil {
		t.Fatalf("the fix names no line to add: %q", fix)
	}
	parses := func(name, src string) {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v %s", name, err, strings.TrimSpace(string(out)))
		}
	}
	script := repoFile(t, "packaging", "openwrt", "wayhop.init")
	parses("wayhop.init", script)

	older := strings.Replace(script, "\t"+procd[1]+"\n", "", 1)
	const anchor = "\tprocd_set_param respawn 60 5 10\n"
	if older == script || !strings.Contains(older, anchor) {
		t.Fatal("cannot rebuild the older init the hand edit applies to")
	}
	parses("older.init", strings.Replace(older, anchor, anchor+"\t"+procd[1]+"\n", 1))

	s99 := repoFile(t, "packaging", "S99wayhop")
	parses("S99wayhop", strings.Replace(s99, "\nstart() {\n", "\nstart() {\n\t"+ulimit[1]+"\n", 1))
}
