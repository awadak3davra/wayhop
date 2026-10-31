//go:build windows

package updatetx

import "syscall"

// stillActive is STILL_ACTIVE, the exit code Windows reports for a process that has not exited.
const stillActive = 259

// processAlive answers what `kill -0` answers on the router, so the tests that run here exercise the
// same decision. A process that has exited can still be opened while anything holds a handle to it,
// so its exit code is what tells.
func processAlive(pid int) bool {
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var code uint32
	return syscall.GetExitCodeProcess(h, &code) == nil && code == stillActive
}
