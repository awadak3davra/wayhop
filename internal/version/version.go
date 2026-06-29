// Package version carries build-stamped identifiers for velinx.
package version

// These defaults are overridden at build time via -ldflags
// (see the Makefile's LDFLAGS).
var (
	Version = "0.4.0"
	Commit  = "unknown"
	Date    = "unknown"
)
