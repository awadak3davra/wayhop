package netdiag

import "syscall"

// BindToDevice is the exported form of the per-platform bindToDevice: a net.Dialer Control hook that
// pins a socket to one interface.
//
// Exported because a second caller needs exactly this and must not grow its own copy — the component
// downloader, which binds its socket so a release can be fetched through a tunnel when the router's
// ordinary path to GitHub is blocked. One definition means one answer to "what does binding mean
// here", including the off-Linux build where it means "cannot bind" rather than "bound".
func BindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return bindToDevice(iface)
}
