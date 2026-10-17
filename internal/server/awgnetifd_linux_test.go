//go:build linux

package server

import (
	"strings"
	"testing"
)

// The restart outlives the request that asked for it: its own session, a plain exec.Command with no
// request context, and a second's wait so the answer reaches the browser before the links drop.
func TestNetworkRestartCommandIsDetached(t *testing.T) {
	if !isFile("/etc/init.d/network") {
		if networkRestartCommand() != nil {
			t.Fatal("a restart command on a host with no OpenWrt network service")
		}
		t.Skip("not OpenWrt: no /etc/init.d/network")
	}
	cmd := networkRestartCommand()
	if cmd == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("not detached: %+v", cmd)
	}
	if got := strings.Join(cmd.Args, " "); got != "/bin/sh -c sleep 1; exec /etc/init.d/network restart" {
		t.Errorf("argv %q", got)
	}
}
