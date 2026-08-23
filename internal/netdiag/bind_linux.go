//go:build linux

package netdiag

import (
	"syscall"
)

// bindToDevice ties a socket to one interface with SO_BINDTODEVICE, which is what makes an
// "is this reachable THROUGH that exit" probe mean anything: without it the kernel picks the route
// itself and every exit answers the same question about the default path.
//
// Root-only, which the daemon is. An interface that does not exist fails here rather than silently
// probing the default route — a false "reachable" is the worst answer this file can give.
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return opErr
	}
}
