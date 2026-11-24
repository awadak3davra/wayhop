package binstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureRunDir creates dir (DefaultRunDir in production) or accepts the one already there only when
// it is a real directory this process owns that nobody else can write to. Root unpacks binaries into
// it and runs them, writes the AmneziaWG installer there and runs it, and amneziawg-go serves its
// configuration sockets, private keys included, under it. /tmp is world-writable, so a local process
// that created the directory first would own every one of those files between write and exec;
// a symlink would put them wherever it points.
func EnsureRunDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; WayHop runs binaries from it as root, so it must be a directory of its own (remove it and retry)", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (remove it and retry)", dir)
	}
	if p := runDirProblem(fi); p != "" {
		return fmt.Errorf("%s %s; WayHop runs binaries from it as root, so it refuses it (remove it and retry)", dir, p)
	}
	return nil
}
