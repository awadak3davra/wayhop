//go:build linux

package server

import (
	"syscall"

	"wayhop/internal/dnscheck"
)

// newDNSCheckNet binds every engine probe to the path it names and exempts it from the engine's own
// transparent redirect. A failed bind fails the probe rather than measuring the default route.
func newDNSCheckNet() dnscheck.Net {
	return dnscheck.NewNet(func(iface string) func(network, address string, c syscall.RawConn) error {
		return egressControl(iface, engineBypassMark, false)
	})
}

func dnsCheckQuery(name string) []byte {
	q, err := dnscheck.BuildQuery(name, 1, 1, false) // A, IN, without DNSSEC records
	if err != nil {
		return nil // the generated canary name is valid; an empty query fails the local probe only
	}
	return q
}
