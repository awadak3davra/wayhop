//go:build !linux

package ramdir

// isRAMFSImpl: no router runs this build; a development machine's temp directory is disk.
func isRAMFSImpl(string) (bool, error) { return false, nil }
