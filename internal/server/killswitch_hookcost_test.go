package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// reRuleAdd is one final `ip [-6] rule add <spec> priority <p>` call as the shim logged it.
var reRuleAdd = regexp.MustCompile(`^ip (-6 )?rule add (.*) priority (\d+)$`)

// iprouteDump prints a rule the way `ip rule show` does: %#x marks, fwmark before iif, "lookup".
func iprouteDump(spec string, pref int) string {
	f := strings.Fields(spec)
	var to, mark, iif, action string
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "blackhole":
			action = "blackhole"
		case "to":
			to, i = " to "+f[i+1], i+1
		case "iif":
			iif, i = " iif "+f[i+1], i+1
		case "table", "lookup":
			action, i = "lookup "+f[i+1], i+1
		case "fwmark":
			v, m, ok := strings.Cut(f[i+1], "/")
			a, _ := strconv.ParseUint(v, 0, 32)
			mark = fmt.Sprintf(" fwmark %#x", a)
			if ok {
				b, _ := strconv.ParseUint(m, 0, 32)
				mark += fmt.Sprintf("/%#x", b)
			}
			i++
		}
	}
	return fmt.Sprintf("%d:\tfrom all%s%s%s %s\n", pref, to, mark, iif, action)
}

// A hook run on a router whose rules are all in place (every NDM rebuild) forked up to
// six `ip` calls per rule before the marking chain. Now the rule list is read once per family and a
// rule present in it is not touched.
func TestKeeneticHookSkipsRulesInPlace(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the hook with")
	}
	tools, dir := keeneticHookShims(t, sh)
	// The BusyBox shim answers `ip rule show` from a file, as the kernel would.
	shim := "#!/bin/sh\necho \"$*\" >> \"$QA_LOG\"\ncase \"$*\" in \"ip rule show\") cat \"$QA_DIR/rules4\" 2>/dev/null; exit 0 ;; \"ip -6 rule show\") cat \"$QA_DIR/rules6\" 2>/dev/null; exit 0 ;; esac\ncase \" $* \" in *\" rule del \"*) exit 1 ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir.native, "busybox"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QA_DIR", dir.sh)
	plan := ksPlan(t, nil)
	io := keeneticPBROptions("eth3")
	io.LANIfaces = []string{"br0", "br1", "nwg0"}
	io.BootRestore, io.BackstopReady = "", ""
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, tools)
	if err != nil {
		t.Fatal(err)
	}
	hook, err := renderKeeneticPBRHook(art.Script)
	if err != nil {
		t.Fatal(err)
	}
	first := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables")
	dumps := map[bool]*strings.Builder{false: {}, true: {}}
	adds := 0
	for _, c := range first {
		m := reRuleAdd.FindStringSubmatch(strings.TrimSuffix(c, " 2>/dev/null || true"))
		if m == nil {
			continue
		}
		p, _ := strconv.Atoi(m[3])
		dumps[m[1] != ""].WriteString(iprouteDump(m[2], p))
		adds++
	}
	if adds < 12 {
		t.Fatalf("the first run added %d rules:\n%q", adds, first)
	}
	_ = os.WriteFile(filepath.Join(dir.native, "rules4"), []byte(dumps[false].String()), 0o644)
	_ = os.WriteFile(filepath.Join(dir.native, "rules6"), []byte(dumps[true].String()), 0o644)
	again := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables")
	if n := countCalls(again, "rule add") + countCalls(again, "rule del"); n != 0 {
		t.Fatalf("%d rule writes with every rule in place:\n%q", n, again)
	}
	if n := countCalls(again, "rule show"); n == 0 || n > 2 {
		t.Fatalf("rule list read %d times", n)
	}
}
