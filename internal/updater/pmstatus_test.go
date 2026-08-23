package updater

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/pm"
)

type overlapPMStatusRunner struct {
	path    string
	active  atomic.Int32
	overlap atomic.Bool
}

func (r *overlapPMStatusRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if r.active.Add(1) != 1 {
		r.overlap.Store(true)
	}
	defer r.active.Add(-1)
	// Make an overlap deterministic without coupling the test to goroutine scheduling.
	time.Sleep(2 * time.Millisecond)
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(cmd, "info --who-owns"):
		return r.path + " is owned by sing-box-1.12.17-r1\n", nil
	case cmd == "apk info -L sing-box":
		return "sing-box-1.12.17-r1 contains:\n" + strings.TrimPrefix(r.path, "/") + "\n", nil
	case cmd == "apk list --installed sing-box":
		return "sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", nil
	case cmd == "apk list sing-box":
		return "sing-box-1.12.17-r1 aarch64 {sing-box}\n", nil
	default:
		return "", fmt.Errorf("unexpected command %q", cmd)
	}
}

func TestPackageStatusSerializesConcurrentPackageDatabaseReads(t *testing.T) {
	bin := "/usr/bin/sing-box"
	runner := &overlapPMStatusRunner{path: bin}
	u := New("/usr/bin", "arm64", nil).WithPM(pm.Manager{Kind: pm.Apk, Runner: runner})

	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status := u.packageStatusForPath(context.Background(), bin)
			if status.State != PackageStateCurrent || !status.Managed || !status.OwnershipKnown {
				errCh <- fmt.Sprintf("%#v", status)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for got := range errCh {
		t.Errorf("status = %s", got)
	}
	if runner.overlap.Load() {
		t.Fatal("package-manager reads overlapped")
	}
}

func TestEnginePackageStatusUsesNativeCatalog(t *testing.T) {
	bin := "/usr/bin/sing-box"
	runner := &pathPMStatusRunner{path: bin, catalog: "sing-box-1.12.18-r0 aarch64 {sing-box}\n" +
		"sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n"}
	u := New("/usr/bin", "arm64", nil).WithPM(pm.Manager{Kind: pm.Apk, Runner: runner})
	status := u.packageStatusForPath(context.Background(), bin)
	if status.State != PackageStateBehind || status.Package != "sing-box" ||
		status.InstalledVersion != "1.12.17-r1" || status.LatestVersion != "1.12.18-r0" {
		t.Fatalf("status = %#v", status)
	}
}

type pathPMStatusRunner struct {
	path       string
	catalog    string
	catalogErr error
}

func (r *pathPMStatusRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(cmd, "info --who-owns"):
		return r.path + " is owned by sing-box-1.12.17-r1\n", nil
	case cmd == "apk info -L sing-box":
		return "sing-box-1.12.17-r1 contains:\n" + strings.TrimPrefix(r.path, "/") + "\n", nil
	case cmd == "apk list --installed sing-box":
		return "sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", nil
	case cmd == "apk list sing-box":
		return r.catalog, r.catalogErr
	default:
		return "", fmt.Errorf("unexpected command %q", cmd)
	}
}

func TestPackageStatusDoesNotExposeRepositoryOutput(t *testing.T) {
	bin := "/usr/bin/sing-box"
	runner := &pathPMStatusRunner{path: bin,
		catalog:    "https://token@example.invalid/private/packages.adb failed",
		catalogErr: fmt.Errorf("exit status 1")}
	u := New("/usr/bin", "arm64", nil).WithPM(pm.Manager{Kind: pm.Apk, Runner: runner})
	status := u.packageStatusForPath(context.Background(), bin)
	if status.State != PackageStateCatalogError || !strings.Contains(status.Error, "refresh package lists") {
		t.Fatalf("status = %#v", status)
	}
	if strings.Contains(status.Error, "token@") || strings.Contains(status.Error, "example.invalid") {
		t.Fatalf("repository output leaked through status: %q", status.Error)
	}
}

func TestPackageStatusDistinguishesMissingCatalogAndMissingChannel(t *testing.T) {
	bin := "/usr/bin/sing-box"
	for _, tc := range []struct {
		name    string
		catalog string
		state   string
	}{
		{"indexes missing", "WARNING: opening from cache https://feed.invalid/packages.adb: No such file or directory\n" +
			"sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", PackageStateCatalogError},
		{"installed local package only", "sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", PackageStateChannelMissing},
		{"same build in repository", "sing-box-1.12.17-r1 aarch64 {sing-box}\n" +
			"sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", PackageStateCurrent},
		{"installed newer than repository", "sing-box-1.12.16-r0 aarch64 {sing-box}\n" +
			"sing-box-1.12.17-r1 aarch64 {sing-box} [installed]\n", PackageStateAhead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &pathPMStatusRunner{path: bin, catalog: tc.catalog}
			u := New("/usr/bin", "arm64", nil).WithPM(pm.Manager{Kind: pm.Apk, Runner: runner})
			if got := u.packageStatusForPath(context.Background(), bin); got.State != tc.state {
				t.Fatalf("state = %q, want %q (%#v)", got.State, tc.state, got)
			}
		})
	}
}
