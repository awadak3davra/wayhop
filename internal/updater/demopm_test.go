package updater

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoPMOwnsOnlyTheSingBoxFixture(t *testing.T) {
	m := DemoPM()
	singbox := filepath.Join(t.TempDir(), "sing-box")
	if pkg, owned, err := m.Owner(context.Background(), singbox); err != nil || !owned || pkg != "sing-box-1.12.17-r1" {
		t.Fatalf("sing-box owner = %q,%v,%v", pkg, owned, err)
	}
	wayhop := filepath.Join(t.TempDir(), "wayhop.exe")
	if pkg, owned, err := m.Owner(context.Background(), wayhop); err != nil || owned || pkg != "" {
		t.Fatalf("WayHop must not inherit the sing-box fixture owner: %q,%v,%v", pkg, owned, err)
	}
}

func TestDemoPMRefreshIsInert(t *testing.T) {
	m := DemoPM()
	out, err := m.Refresh(context.Background())
	if err != nil || !strings.Contains(out, "not changed") {
		t.Fatalf("Refresh = %q,%v", out, err)
	}
}
