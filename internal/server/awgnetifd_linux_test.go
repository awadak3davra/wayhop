//go:build linux

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The restart outlives the request that asked for it: its own session, a plain exec.Command with no
// request context, and a second's wait so the answer reaches the browser before the links drop. A
// stand-in init script proves that shape on any Linux host, not only on an OpenWrt one.
func TestNetworkRestartCommandIsDetached(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "network")
	if networkRestartCommandFor(missing) != nil {
		t.Fatal("a restart command on a host with no OpenWrt network service")
	}
	script := filepath.Join(t.TempDir(), "network")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := networkRestartCommandFor(script)
	if cmd == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("not detached: %+v", cmd)
	}
	if got := strings.Join(cmd.Args, " "); got != "/bin/sh -c sleep 1; exec "+script+" restart" {
		t.Errorf("argv %q", got)
	}
	if isFile("/etc/init.d/network") != (networkRestartCommand() != nil) {
		t.Error("the real command does not follow whether this host has OpenWrt's network service")
	}
}
