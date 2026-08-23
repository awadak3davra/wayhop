package server

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The strict transaction adapter is the only Keenetic mutation authority. A second stateful
// profile-to-device backend would bypass the authenticated execution artifact, ledger journal,
// ownership checks, and exact postconditions even if no caller happened to construct it today.
func TestKeeneticStrictAdapterIsTheSoleNativeApplyImplementation(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	for _, rel := range []string{
		"internal/keenetic/adapter.go",
		"internal/keenetic/apply.go",
		"internal/keenetic/failsafe_apply.go",
		"internal/keenetic/singbox_apply.go",
		"internal/keenetic/kpbr.go",
		"internal/keenetic/kpbr_build.go",
		"internal/keenetic/kpbr_cutover.go",
		"internal/keenetic/migrate.go",
		"internal/keenetic/prepare.go",
		"internal/keenetic/cutover_run.go",
		"internal/platform/backend.go",
		"zzgen/main.go",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			t.Errorf("legacy Keenetic mutation path still exists: %s", rel)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("inspect %s: %v", rel, err)
		}
	}

	for _, check := range []struct {
		path      string
		forbidden string
	}{
		{"cmd/wayhop/main.go", "platform.RoutingBackend"},
		{"internal/platform/capability.go", "imported only by a generator"},
	} {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.path)))
		if err != nil {
			t.Fatalf("read %s: %v", check.path, err)
		}
		if strings.Contains(string(body), check.forbidden) {
			t.Errorf("%s still advertises retired architecture %q", check.path, check.forbidden)
		}
	}
}
