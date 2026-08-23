//go:build !linux

package util

// RestrictNewFiles is a no-op off Linux: Windows has no umask, and the file it exists to protect
// (sing-box's cache.db on a router) is not created there. Returning applied=false keeps a caller
// from reporting a restriction that did not happen.
func RestrictNewFiles() (previous int, applied bool) { return 0, false }
