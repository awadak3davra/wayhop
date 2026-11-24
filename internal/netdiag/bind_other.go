//go:build !linux

package netdiag

import (
	"errors"
	"syscall"
)

// bindToDevice has no equivalent off Linux. Returning nil means "no binding", and the caller reports
// that honestly rather than probing the default route and calling the answer an exit's.
func bindToDevice(string) func(network, address string, c syscall.RawConn) error { return nil }

// setSocketMark has no equivalent off Linux: a probe that needs a mark is not measured.
func setSocketMark(syscall.RawConn, int) error { return errors.New("no fwmark on this platform") }
