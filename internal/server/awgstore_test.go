package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/binstore"
	"wayhop/internal/platform"
	"wayhop/internal/pm"
)

// opkgOwnsAWG answers opkg as a router where the feed's amneziawg-go package owns the binary, or, with
// fail, as one whose package database is locked.
type opkgOwnsAWG struct{ fail bool }

func (o opkgOwnsAWG) Run(_ context.Context, _ string, args ...string) (string, error) {
	if o.fail {
		return "", errors.New("opkg: could not lock /var/lock/opkg.lock")
	}
	switch {
	case len(args) > 0 && args[0] == "search":
		return "amneziawg-go - 3.1.20260828-1\n", nil
	case len(args) > 0 && args[0] == "status":
		return "Package: amneziawg-go\nVersion: 3.1.20260828-1\nStatus: install user installed\n", nil
	}
	return "", nil
}

// awgStoreServer is a server whose bin directory holds the package's amneziawg-go next to the copy
// WayHop kept compressed from a release asset, and the copy unpacked from it in the run directory.
func awgStoreServer(t *testing.T, runner pm.Runner, demo bool) (*Server, map[string]string) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	s := updaterinstall_serverWithUpdater(t, "arm64")
	s.cfg.Demo = demo
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	s.updater.RunDir = t.TempDir()
	s.updater.WithPM(pm.Manager{Kind: pm.Opkg, Runner: runner})
	dir, run := s.updater.BinDir, s.updater.RunDir
	paths := map[string]string{
		"binary":   filepath.Join(dir, "amneziawg-go"),
		"gzip":     binstore.Stored(dir, "amneziawg-go", true),
		"record":   filepath.Join(dir, ".amneziawg-go.version"),
		"unpacked": filepath.Join(run, "amneziawg-go"),
		"marker":   filepath.Join(run, "amneziawg-go.src"),
	}
	for name, body := range map[string]string{"gzip": "wayhop gzip", "unpacked": "wayhop build", "marker": "sum\n"} {
		if err := os.WriteFile(paths[name], []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := binstore.Write(dir, "amneziawg-go", "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["binary"], []byte("package build"), 0o755); err != nil {
		t.Fatal(err)
	}
	return s, paths
}

// The engine list is where the panel learns that a package owns amneziawg-go; from then on the copy
// WayHop kept is gone and the package's binary is what runs. An answer the package manager could not
// give, and the demo, leave everything in place.
func TestUpdaterEnginesDropTheStaleAWGStore(t *testing.T) {
	for _, c := range []struct {
		name   string
		runner pm.Runner
		demo   bool
		gone   bool
	}{
		{"a package owns amneziawg-go", opkgOwnsAWG{}, false, true},
		{"ownership unknown", opkgOwnsAWG{fail: true}, false, false},
		{"demo", opkgOwnsAWG{}, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, paths := awgStoreServer(t, c.runner, c.demo)
			if w := updaterinstall_get(s.handleUpdaterEngines); w.Code != 200 {
				t.Fatalf("engines: %d %s", w.Code, w.Body.String())
			}
			if _, err := os.Stat(paths["binary"]); err != nil {
				t.Fatalf("the package's binary was touched: %v", err)
			}
			for _, name := range []string{"gzip", "record", "unpacked", "marker"} {
				_, err := os.Stat(paths[name])
				if gone := os.IsNotExist(err); gone != c.gone {
					t.Errorf("%s: removed=%v, want %v", name, gone, c.gone)
				}
			}
		})
	}
}

// After an install that may have handed amneziawg-go to a package, the daemon asks the package manager
// itself rather than waiting for the page.
func TestAWGDropStaleStoreNowAsksThePackageManager(t *testing.T) {
	s, paths := awgStoreServer(t, opkgOwnsAWG{}, false)
	s.awgDropStaleStoreNow(context.Background())
	if _, err := os.Stat(paths["gzip"]); !os.IsNotExist(err) {
		t.Errorf("the stale gzip survived: %v", err)
	}
	if _, err := os.Stat(paths["binary"]); err != nil {
		t.Errorf("the package's binary was touched: %v", err)
	}
}
