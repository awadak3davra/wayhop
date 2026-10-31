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
	"strings"
)

// Write atomically and durably replaces path with data (mode perm). It is the
// single audited write path shared by every JSON store in the daemon.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	// Which directory levels does MkdirAll have to CREATE? Compute before creating them, so after the
	// write we can make each new level durable: a new directory's entry lives in its PARENT, and only
	// SyncDir(dir) below (the leaf) is otherwise fsync'd — a power loss right after a first write into a
	// freshly-created tree could then lose the new directories (and the 'durably'-written file in them).
	created := dirsMissing(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := replace(dir, filepath.Base(path)+".*.tmp", path, data, perm); err != nil {
		return err
	}
	// Make each newly-CREATED directory durable by fsyncing the parent that now holds its entry (walking
	// up the chain MkdirAll built). Empty for the common case where the directory already existed.
	for _, d := range created {
		SyncDir(filepath.Dir(d))
	}
	return nil
}

// WriteOutsideDir is Write for a file in a directory that another program consumes entry by entry:
// NDM executes every file in /opt/etc/ndm/netfilter.d after a firewall rebuild, and dnsmasq loads
// every file in its conf-dir. Write's sibling temp would sit in that directory for the whole write,
// and a crash would leave it there for good — a half-written script NDM runs, or a second copy of the
// directives dnsmasq reads. So the temp is staged in the PARENT directory under a dot name (the same
// filesystem, so the rename stays atomic) and renamed in. The target directory is not created: it
// belongs to the program that reads it, and creating it would make a file look installed for a
// program that is not there.
func WriteOutsideDir(path string, data []byte, perm os.FileMode) error {
	stage := filepath.Dir(filepath.Dir(path))
	if err := replace(stage, "."+filepath.Base(path)+".*.tmp", path, data, perm); err != nil {
		return err
	}
	SyncDir(stage) // the temp's name left the parent too; unsynced, a power loss could bring it back
	return nil
}

// beforeRename, when set by a test, observes the staged temp just before it is renamed over the target.
var beforeRename func(tmp string)

// replace stages data in a unique temp in stageDir, fsyncs it, renames it over path and fsyncs path's
// directory. The temp is removed on every in-process failure; one a crash leaves is RemoveStale's.
func replace(stageDir, pattern, path string, data []byte, perm os.FileMode) error {
	// UNIQUE temp name (not a fixed path+".tmp"): two goroutines writing the SAME target concurrently
	// (e.g. a manual "refresh now" racing the scheduled refresh of one IPTV list) must not share one
	// temp file — a shared O_TRUNC temp would interleave their bytes into a torn file before rename.
	tf, err := os.CreateTemp(stageDir, pattern)
	if err != nil {
		return err
	}
	tmp := tf.Name()
	_ = tf.Close() // WriteSynced re-opens it (O_TRUNC) and fsyncs the contents
	if err := WriteSynced(tmp, data, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if beforeRename != nil {
		beforeRename(tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	SyncDir(filepath.Dir(path)) // make the file's entry in the leaf directory durable
	return nil
}

// RemoveStale deletes the temps that a Write or WriteOutsideDir of path left behind when the process
// died between creating the temp and renaming it (an OOM kill, a power cut during the fsync). Nothing
// else ever removes them: each is a full copy of the file — endpoint keys, panel credentials — that
// survives the operator rotating them, and repeated crashes keep adding more until the overlay is full
// and every write fails with ENOSPC.
//
// It must run before any writer of path starts — in a store's Open, or from the only goroutine that
// writes the file — since a temp in flight looks exactly like an orphan.
func RemoveStale(path string) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	removeStale(dir, func(name string) bool { return isTempOf(name, base+".") })
	removeStale(filepath.Dir(dir), func(name string) bool { return isTempOf(name, "."+base+".") }) // WriteOutsideDir's
}

// RemoveStaleMatching is RemoveStale for temps that are not named after one fixed target: a family of
// targets (timestamped backups) or a staging file with its own prefix. pattern is a filepath.Match
// pattern for names in dir. The same rule applies: no writer may be in flight.
func RemoveStaleMatching(dir, pattern string) {
	removeStale(dir, func(name string) bool {
		ok, _ := filepath.Match(pattern, name)
		return ok
	})
}

// isTempOf reports whether name is prefix + CreateTemp's decimal random part + ".tmp". Matching the
// name literally rather than as a glob keeps a target whose name holds glob characters from matching,
// and so deleting, some other file's temps.
func isTempOf(name, prefix string) bool {
	if len(name) <= len(prefix)+len(".tmp") || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") {
		return false
	}
	for _, c := range name[len(prefix) : len(name)-len(".tmp")] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func removeStale(dir string, stale func(name string) bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // no directory, nothing to sweep; a real I/O problem surfaces on the next write
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !stale(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Remove(p); err != nil {
			log.Printf("atomicfile: remove stale temp %q: %v", p, err)
			continue
		}
		log.Printf("atomicfile: removed %q, left by a write that was interrupted", p)
	}
}

// dirsMissing returns the ancestor directories of (and including) dir that do NOT currently exist,
// leaf-first — the levels MkdirAll will create and that must be made durable afterward. Any Stat error
// (including permission) is treated conservatively as "missing" so the parent is fsynced anyway (an
// fsync of an already-durable directory is harmless); it stops at the first existing ancestor and at
// the filesystem root.
func dirsMissing(dir string) []string {
	var missing []string
	for d := dir; ; {
		if _, err := os.Stat(d); err == nil {
			break // this ancestor exists — so do all further ancestors
		}
		missing = append(missing, d)
		parent := filepath.Dir(d)
		if parent == d {
			break // reached the root
		}
		d = parent
	}
	return missing
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
	// OpenFile's perm is IGNORED when the file already EXISTS — and atomicfile.Write re-opens a
	// CreateTemp file that is already 0600 — so set the mode explicitly. Without this, a caller
	// asking for an executable 0755 (e.g. a Keenetic firewall hook) silently gets 0600 and the
	// hook never runs. (On Windows only the writable bit is honored; Chmod still succeeds.)
	if err := f.Chmod(perm); err != nil {
		f.Close()
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
