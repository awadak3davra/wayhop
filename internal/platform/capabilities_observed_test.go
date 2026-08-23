package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectCapabilitiesObservedUnknownHostIsExplicitlyUnverified(t *testing.T) {
	if Detect() != Unknown {
		t.Skip("test host is a recognized router platform")
	}
	caps, probeErrors := DetectCapabilitiesObserved()
	if caps.Platform != string(Unknown) {
		t.Fatalf("platform = %q, want unknown", caps.Platform)
	}
	if len(probeErrors) == 0 {
		t.Fatal("unknown host was returned without a probe error")
	}
}

func TestListProtoHandlersOKDistinguishesEmptyFromUnreadable(t *testing.T) {
	dir := t.TempDir()
	if names, ok := listProtoHandlersOK(dir); !ok || names == nil || len(names) != 0 {
		t.Fatalf("empty readable directory = names:%#v ok:%v", names, ok)
	}
	if err := os.WriteFile(filepath.Join(dir, "wireguard.sh"), []byte("# fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, ok := listProtoHandlersOK(dir)
	if !ok || len(names) != 1 || names[0] != "wireguard.sh" {
		t.Fatalf("readable proto directory = names:%#v ok:%v", names, ok)
	}
	if names, ok := listProtoHandlersOK(filepath.Join(dir, "missing")); ok || names != nil {
		t.Fatalf("unreadable proto directory = names:%#v ok:%v", names, ok)
	}
}
