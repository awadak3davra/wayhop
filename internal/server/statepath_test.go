package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// realStateHits collects every test that resolved apply-state.json or fastest-journal.json inside
// the installed daemon's directory (config.Default's, /opt/etc/wayhop; S:\opt\etc\wayhop on Windows)
// rather than a temporary one. Such a test would read what an earlier run or the real
// daemon left there and could overwrite it, so the path is moved into this run's own directory.
// A fastest-journal hit fails the run: the failover and election fixtures keep their state in
// t.TempDir(). Older fixtures built on config.Default reach apply-state.json; that is moved aside,
// not failed.
var realStateHits struct {
	sync.Mutex
	journal map[string]string // test -> path
}

func TestMain(m *testing.M) {
	realDir := filepath.Clean(filepath.Dir(config.Default().SingBox.Config))
	aside, err := os.MkdirTemp("", "wayhop-server-state-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "state directory for tests: %v\n", err)
		os.Exit(1)
	}
	statePathTest = func(path string) string {
		if filepath.Clean(filepath.Dir(path)) != realDir {
			return path
		}
		realStateHits.Lock()
		defer realStateHits.Unlock()
		if filepath.Base(path) == fastestJournalFile {
			if realStateHits.journal == nil {
				realStateHits.journal = map[string]string{}
			}
			realStateHits.journal[callingTest()] = path
		}
		return filepath.Join(aside, filepath.Base(path))
	}
	fastRemoteAutoFetch = false
	fastDNSResolverProblem = func(context.Context) string { return "" }
	fastDNSUpstream = func(context.Context) error { return nil }
	fastDNSIsRAM = func(string) bool { return true }
	fastDNSRunDir = aside
	code := m.Run()
	_ = os.RemoveAll(aside)
	if len(realStateHits.journal) > 0 {
		names := make([]string, 0, len(realStateHits.journal))
		for name, path := range realStateHits.journal {
			names = append(names, name+": "+path)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "FAIL: tests resolved the installed daemon's fastest journal instead of t.TempDir():\n  %s\n",
			strings.Join(names, "\n  "))
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// callingTest names the Test function on the stack, or the innermost caller outside this file.
func callingTest() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	var trail []string
	for {
		f, more := frames.Next()
		if i := strings.LastIndex(f.Function, ".Test"); i >= 0 && !strings.Contains(f.Function, ".TestMain") {
			return f.Function[i+1:]
		}
		if !strings.Contains(f.Function, "TestMain") && !strings.HasPrefix(f.Function, "runtime.") && len(trail) < 4 {
			trail = append(trail, f.Function[strings.LastIndex(f.Function, "/")+1:])
		}
		if !more {
			return "(goroutine) " + strings.Join(trail, " < ")
		}
	}
}

// The fixtures of the failover tests keep apply-state.json and the fastest journal in their own
// temporary directory; the production paths come from the server's configuration.
func TestStatePathsFollowTheConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.SingBox.Config = filepath.Join(dir, "singbox.json")
	s := &Server{cfg: cfg}
	if got := s.applyStateFile(); got != filepath.Join(dir, applyStateFileName) {
		t.Fatalf("apply state %q", got)
	}
	if got := s.fastestJournalPath(); got != filepath.Join(dir, fastestJournalFile) {
		t.Fatalf("journal %q", got)
	}
	other := t.TempDir()
	s.applyStateDir = other
	if s.applyStateFile() != filepath.Join(other, applyStateFileName) || s.fastestJournalPath() != filepath.Join(other, fastestJournalFile) {
		t.Fatal("StartApply's directory is not preferred")
	}
	s.applyStateDir, cfg.Demo = "", true
	if got := s.fastestJournalPath(); got != "" {
		t.Fatalf("demo journal %q", got)
	}

	f, _ := appliedFailoverServer(t, model.Profile{}, model.Profile{}, &fakeTables{})
	if strings.HasPrefix(f.applyStateFile(), filepath.Dir(config.Default().SingBox.Config)) {
		t.Fatalf("the failover fixture keeps its state in the installed daemon's directory: %s", f.applyStateFile())
	}
}
