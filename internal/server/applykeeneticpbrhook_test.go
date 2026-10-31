package server

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// pbrhook_identity names the file a path resolves to right now. It is taken from an open handle so
// the identity is captured immediately (a Stat result on Windows resolves it lazily, at comparison
// time, which would compare the new file with itself).
func pbrhook_identity(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

// NDM runs every file in netfilter.d after a firewall rebuild, and nativePrepare triggers rebuilds
// while the hook is being replaced. Rewriting the live file in place (O_TRUNC, then write) let sh
// read the first chunk of the old script and the rest from the new bytes, and a power cut between the
// truncate and the fsync left a zero-length or half-written hook. The new bytes must arrive as a
// different file renamed over the old one, in the write and in the rollback alike.
func TestReplaceFilePreservingPrevious_SwapsInANewFileInsteadOfRewritingTheLiveOne(t *testing.T) {
	root := t.TempDir()
	hookDir := filepath.Join(root, "ndm", "netfilter.d")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hookDir, "50-wayhop-policy.sh")
	old := []byte("#!/opt/bin/sh\niptables -t mangle -A OLD\nexit 0\n")
	next := []byte("#!/opt/bin/sh\niptables -t mangle -A NEW\nexit 0\n")
	if err := os.WriteFile(path, old, 0o755); err != nil {
		t.Fatal(err)
	}

	before := pbrhook_identity(t, path)
	restore, err := replaceFilePreservingPrevious(path, next, keeneticPBRHookPerm)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	written := pbrhook_identity(t, path)
	if os.SameFile(before, written) {
		t.Fatal("the hook was rewritten in place: NDM can execute a truncated or half-old, half-new script")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, next) {
		t.Fatalf("hook = %q, want %q", got, next)
	}
	// NDM runs only executables; Windows reports a synthetic mode, the contract is Unix.
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != keeneticPBRHookPerm {
		t.Fatalf("hook mode = %v, want %v", fi.Mode().Perm(), keeneticPBRHookPerm)
	}

	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if os.SameFile(written, pbrhook_identity(t, path)) {
		t.Fatal("the rollback rewrote the hook in place")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, old) {
		t.Fatalf("restored hook = %q, want %q", got, old)
	}

	// Nothing may be left behind in the directory NDM executes, nor where the temp was staged.
	for _, dir := range []string{hookDir, filepath.Dir(hookDir)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "50-wayhop-policy.sh" && e.Name() != "netfilter.d" {
				t.Errorf("leftover %s in %s", e.Name(), dir)
			}
		}
	}

	// A first Apply had no hook: the rollback puts back "nothing".
	fresh := filepath.Join(hookDir, "60-first.sh")
	restoreFresh, err := replaceFilePreservingPrevious(fresh, next, keeneticPBRHookPerm)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := restoreFresh(); err != nil {
		t.Fatalf("restore of a first write: %v", err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback of a first write must remove the file: %v", err)
	}
}

// A daemon killed while the hook was staged leaves the temp behind. The next write sweeps it, so a
// crash cannot leave a second copy of the policy (with the plane's marks) on the router for good.
func TestReplaceFilePreservingPrevious_SweepsATempACrashLeftBehind(t *testing.T) {
	root := t.TempDir()
	confDir := filepath.Join(root, "dnsmasq.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(confDir, "wayhop-policy.conf")
	orphan := filepath.Join(root, ".wayhop-policy.conf.123456.tmp")
	if err := os.WriteFile(orphan, []byte("ipset=/exa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceFilePreservingPrevious(path, []byte("ipset=/example.net/wh4\n"), keeneticPBRConfPerm); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temp an interrupted write left behind survived: %v", err)
	}
}
