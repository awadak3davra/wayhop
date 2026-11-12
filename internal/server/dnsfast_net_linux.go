//go:build linux

package server

import (
	"syscall"

	"wayhop/internal/dnscheck"
)

// Fast measurements follow exactly the DNS check's binding and engine-bypass rule, so choosing a tunnel
// cannot silently measure the provider instead.
func newDNSFastNet() dnscheck.FastNet {
	return dnscheck.NewFastNet(func(iface string) func(network, address string, c syscall.RawConn) error {
		return egressControl(iface, engineBypassMark, false)
	})
}
