//go:build !linux

package awg

// ProbeHost off Linux (the Windows/macOS demo build) has no generic netlink and no /dev/net/tun, so
// nothing is available; Err says why instead of the result reading as a router without a module.
func ProbeHost() Probe {
	return Probe{Err: "AmneziaWG can only be probed on Linux"}
}
