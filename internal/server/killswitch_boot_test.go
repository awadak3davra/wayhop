package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The boot hold, run as NDM runs it after a reboot: no kernel sets, no daemon yet. The hook restores the
// sets from the restore file before the chain names them, and holds the backstop table closed until
// the daemon's stamp exists.
func TestKeeneticPBRHook_BootRestoresSetsAndHolds(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the hook with")
	}
	tools, dir := keeneticHookShims(t, sh)
	plan := ksPlan(t, nil)
	io := keeneticPBROptions("eth3")
	io.LANIfaces = []string{"br0"}
	io.BootRestore, io.BackstopReady = dir.sh+"/policy.ipset", dir.sh+"/ready"
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, tools)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.native, "policy.ipset"), keeneticBootRestoreFile(*art), 0o644); err != nil {
		t.Fatal(err)
	}
	hook, err := renderKeeneticPBRHook(art.Script)
	if err != nil {
		t.Fatal(err)
	}
	calls := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables")
	at := func(parts ...string) int {
		return slices.IndexFunc(calls, func(c string) bool {
			for _, p := range parts {
				if !strings.Contains(c, p) {
					return false
				}
			}
			return true
		})
	}
	list, restore, chain := at("list -n"), at("restore -!"), at("iptables-restore")
	hold := at("route replace blackhole default table 407")
	rule := at("rule add iif br0 fwmark", "table 407 priority")
	if list < 0 || restore < list || chain < restore || hold < 0 || hold > rule || rule > chain {
		t.Fatalf("boot order: list@%d restore@%d hold@%d backstop rule@%d chain@%d\n%q", list, restore, hold, rule, chain, calls)
	}
	// Once the daemon has filled the table and written its stamp, a rebuild holds nothing.
	if err := os.WriteFile(filepath.Join(dir.native, "ready"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if calls := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables"); countCalls(calls, "blackhole default table 407") != 0 {
		t.Fatalf("held with the stamp present: %q", calls)
	}
}

// The restore file is on flash: identical content is not written again.
func TestReplaceFileIfChangedSkipsIdentical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.ipset")
	if _, err := replaceFileIfChanged(path, []byte("create a hash:net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	undo, err := replaceFileIfChanged(path, []byte("create a hash:net\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Fatal("identical content rewritten")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceFileIfChanged(path, []byte("create b hash:net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "create b hash:net\n" {
		t.Fatalf("changed content not written: %q", b)
	}
}
