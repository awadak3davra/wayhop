//go:build unix

package binstore

import (
	"os"
	"syscall"
)

// runDirProblem refuses a run directory another user owns, or one others can write to: either could
// already hold a file, or a symlink, waiting for root to write or run it.
func runDirProblem(fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return "belongs to another user"
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "can be written by other users"
	}
	return ""
}
