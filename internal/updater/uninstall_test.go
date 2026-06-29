package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUninstall(t *testing.T) {
	dir := t.TempDir()
	u := &Updater{BinDir: dir}
	e := Engine{ID: "sing-box", BinName: "sing-box"}
	bin := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Removes the installed binary from BinDir.
	if err := u.Uninstall(e); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(bin); !os.IsNotExist(err) {
		t.Errorf("binary still present after Uninstall: %v", err)
	}
	// Already-absent is a no-op success (idempotent).
	if err := u.Uninstall(e); err != nil {
		t.Errorf("Uninstall of an absent binary should succeed, got %v", err)
	}
	// SourceOnly engines have no panel-installed binary -> refused (don't pretend to remove one).
	if err := u.Uninstall(Engine{ID: "amneziawg-go", BinName: "amneziawg-go", SourceOnly: true}); err == nil {
		t.Error("Uninstall of a SourceOnly engine should be refused")
	}
	// A blank BinName is refused rather than removing the BinDir itself.
	if err := u.Uninstall(Engine{ID: "x"}); err == nil {
		t.Error("Uninstall with no BinName should be refused")
	}
}
