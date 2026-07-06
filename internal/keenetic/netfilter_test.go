package keenetic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetfilterHookScript(t *testing.T) {
	s := wrNetfilterHookScript("wr-tun")
	for _, want := range []string{
		"#!/opt/bin/sh",
		"IF=wr-tun",
		`ip link show "$IF"`, // gated on the TUN existing
		`iptables -C FORWARD -i br0 -o "$IF" -j ACCEPT 2>/dev/null || iptables -I FORWARD -i br0 -o "$IF" -j ACCEPT`,
		`iptables -C FORWARD -i "$IF" -o br0 -j ACCEPT`,
		`iptables -t nat -C POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IF" -j MASQUERADE`,
		`[ "$table" = "filter" ]`,
		`[ "$table" = "nat" ]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("hook script missing %q\n--- script ---\n%s", want, s)
		}
	}
}

func TestInstallRemoveNetfilterHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "40-wayhop.sh")
	opt := NetfilterHookOptions{Path: path, TunIface: "wr-tun"}

	if err := InstallNetfilterHook(opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("hook not written: %v", err)
	}
	// (The 0755 exec bit is requested via atomicfile.Write and honored on the Linux device;
	// the Windows test filesystem doesn't preserve it, so it isn't asserted here.)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "MASQUERADE") {
		t.Error("installed hook missing the masquerade rule")
	}

	// Idempotent re-install.
	if err := InstallNetfilterHook(opt); err != nil {
		t.Fatalf("re-install must succeed: %v", err)
	}

	// Remove, then a second remove is a no-op (not an error).
	if err := RemoveNetfilterHook(opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("hook must be gone after remove")
	}
	if err := RemoveNetfilterHook(opt); err != nil {
		t.Errorf("removing a missing hook must be a no-op, got %v", err)
	}
}
