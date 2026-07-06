// Package atomicfile writes a file atomically and durably: temp file in the same
// directory, fsync the contents, rename over the target, then fsync the directory
// so the rename survives a power loss. This matters on a router, which can lose
// power mid-write — without the fsyncs a crash can leave a zero-length or torn
// config that bricks the panel (sing-box won't start, the daemon panics at boot).
package atomicfile

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// Write atomically and durably replaces path with data (mode perm). It is the
// single audited write path shared by every JSON store in the daemon.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// UNIQUE temp name (not a fixed path+".tmp"): two goroutines writing the SAME target concurrently
	// (e.g. a manual "refresh now" racing the scheduled refresh of one IPTV list) must not share one
	// temp file — a shared O_TRUNC temp would interleave their bytes into a torn file before rename.
	tf, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	_ = tf.Close() // WriteSynced re-opens it (O_TRUNC) and fsyncs the contents
	if err := WriteSynced(tmp, data, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	SyncDir(dir) // make the rename itself durable
	return nil
}

// WriteSynced writes data to path and fsyncs the file contents to stable storage
// (it does NOT rename). Use it when the caller must validate the temp file before
// committing it with a rename (see server.handleApply, which runs `sing-box check`
// on the temp config first).
func WriteSynced(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// SyncDir fsyncs a directory so a prior rename into it is durable. Directory
// fsync is a no-op / unsupported on some platforms (e.g. Windows); best-effort.
func SyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		// A durability failure is invisible if swallowed; log so a missing
		// directory fsync (e.g. permission/IO error) shows up in the router log.
		log.Printf("atomicfile: open dir %q for fsync: %v", dir, err)
		return
	}
	if err := d.Sync(); err != nil && runtime.GOOS != "windows" {
		// Directory fsync is unsupported on Windows (Sync on a dir handle returns
		// "Access is denied") — that's expected, not an error, so don't scare a
		// Windows dev running the demo. On the real (Linux) router it's meaningful.
		log.Printf("atomicfile: fsync dir %q: %v", dir, err)
	}
	_ = d.Close()
}
