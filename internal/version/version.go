// Package version carries build-stamped identifiers for wakeroute.
package version

// These defaults are overridden at build time via -ldflags
// (see the Makefile's LDFLAGS).
var (
	Version = "0.3.7"
	Commit  = "unknown"
	Date    = "unknown"
)
