//go:build !unix

package binstore

import "os"

// runDirProblem has no owner or mode to check on Windows, where WayHop runs only as the demo.
func runDirProblem(os.FileInfo) string { return "" }
