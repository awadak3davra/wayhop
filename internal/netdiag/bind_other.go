//go:build !linux

package netdiag

import "syscall"

// bindToDevice has no equivalent off Linux. Returning nil means "no binding", and the caller reports
// that honestly rather than probing the default route and calling the answer an exit's.
func bindToDevice(string) func(network, address string, c syscall.RawConn) error { return nil }
