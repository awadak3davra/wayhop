// Package version carries build-stamped identifiers for wayhop.
package version

// These defaults are overridden at build time via -ldflags
// (see the Makefile's LDFLAGS).
var (
	Version = "0.5.1"
	Commit  = "unknown"
	Date    = "unknown"
)
