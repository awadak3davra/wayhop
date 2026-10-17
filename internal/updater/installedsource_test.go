package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/binstore"
	"wayhop/internal/pm"
)

// --- package ownership: amneziawg-go as a package -----------------------------------------------

// opkgOwns answers opkg as a router where the feed's amneziawg-go package owns the binary.
type opkgOwns struct{ pkg, version string }

func (o opkgOwns) Run(_ context.Context, name string, args ...string) (string, error) {
	switch {
	case len(args) > 0 && args[0] == "search":
		return o.pkg + " - " + o.version + "\n", nil
	case len(args) > 0 && args[0] == "status":
		if args[len(args)-1] != o.pkg {
			return "", nil
		}
		return "Package: " + o.pkg + "\nVersion: " + o.version + "\nStatus: install user installed\n", nil
	}
	return "", nil
}

// The panel never writes over, nor deletes, an amneziawg-go a package owns - not even the gzip it
// kept itself from an earlier install - and it does not go to the network to find that out.
func TestCompanionOwnedByAPackageIsNeverTouched(t *testing.T) {
	binDir := t.TempDir()
	e := *EngineByID("amneziawg-go")
	bin := filepath.Join(binDir, e.BinName)
	if err := os.WriteFile(bin, []byte("packaged"), 0o755); err != nil {
		t.Fatal(err)
	}
	gz := binstore.Stored(binDir, e.BinName, true)
	if err := os.WriteFile(gz, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	u := New(binDir, "arm64", []string{"http://127.0.0.1:1/"}).WithPM(pm.Manager{Kind: pm.Opkg, Runner: opkgOwns{"amneziawg-go", "3.1.20260828-1"}})
	var nm *NativeManagedError
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); !errors.As(err, &nm) {
		t.Errorf("Install over the package's binary: %v", err)
	}
	if err := u.Uninstall(e); !errors.As(err, &nm) {
		t.Errorf("Uninstall of the package's binary: %v", err)
	}
	for _, p := range []string{bin, gz} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(bin); string(b) != "packaged" {
		t.Errorf("the package's binary was overwritten: %q", b)
	}
}

// Where amneziawg-go comes from, and at which version: the package database for a package (its own
// --version is upstream's stale constant), the panel's record for a release asset, nothing for a
// binary put there some other way.
func TestInstalledForReportsTheSource(t *testing.T) {
	binDir := t.TempDir()
	e := *EngineByID("amneziawg-go")
	u := New(binDir, "arm64", nil).WithPM(pm.Manager{Kind: pm.None})
	if got := u.InstalledFor(e, PackageStatus{}); got.Present || got.Source != "" {
		t.Errorf("absent: %+v", got)
	}
	gz := binstore.Stored(binDir, e.BinName, true)
	if err := os.WriteFile(gz, []byte("gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := u.InstalledFor(e, PackageStatus{}); got.Source != SourceOther || got.Version != "" {
		t.Errorf("unrecorded gzip: %+v", got)
	}
	if err := binstore.Write(binDir, e.BinName, "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	if got := u.InstalledFor(e, PackageStatus{}); got.Source != SourceRelease || got.Version != "v3.1.20260828" || got.Path != gz {
		t.Errorf("release asset: %+v", got)
	}
	pkg := PackageStatus{Managed: true, OwnershipKnown: true, Package: "amneziawg-go", Path: "/usr/bin/amneziawg-go", InstalledVersion: "3.1.20260828-r1"}
	if got := u.InstalledFor(e, pkg); got.Source != SourcePackage || got.Version != "3.1.20260828-r1" || got.Path != "/usr/bin/amneziawg-go" || !got.Present {
		t.Errorf("package: %+v", got)
	}
	// A non-companion keeps the version its binary reports; the package only names the source.
	core := Engine{ID: "x", BinName: "x-not-on-path"}
	if got := u.InstalledFor(core, PackageStatus{Managed: true, InstalledVersion: "1.0-r1"}); got.Source != SourcePackage || got.Version != "1.0-r1" {
		t.Errorf("a package-owned engine with no version of its own: %+v", got)
	}
}
