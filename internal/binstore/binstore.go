// Package binstore keeps a binary the updater installed either as itself or, where the flash cannot
// hold it, gzip-compressed beside a record - and unpacks the compressed form into RAM to run it.
//
// Why: amneziawg-go is 3.3-3.8 MB unpacked and 1.35-1.48 MB as the gzip WayHop ships, and a router's
// overlay can be too full for the first while its tmpfs (half the RAM) has room. Keeping the gzip on
// flash and unpacking it on start costs about 40% of the flash, and the unpacked size in RAM for as
// long as the binary runs - the trade the updater makes only when the unpacked binary does not fit.
//
// The record also carries the version, because a companion binary cannot say which version it is:
// amneziawg-go reports upstream's stale 0.0.20250522. It describes one stored file by size and
// modification time, so a file replaced by any other means reads as unrecorded rather than as the
// version installed before it.
package binstore

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultRunDir is where a compressed binary is unpacked to run: /tmp is tmpfs on OpenWrt and on
// KeeneticOS, and not mounted noexec (measured on the AX3000T: tmpfs rw,nosuid,nodev,noatime).
const DefaultRunDir = "/tmp/wayhop"

// maxUnpacked bounds what one gzip may inflate to. amneziawg-go is under 4 MB; the cap only stops a
// corrupted store from filling the tmpfs, which is the router's RAM.
const maxUnpacked = 64 << 20

// ErrNotStored means name has no compressed copy on record - the answer for every binary that is
// stored as itself, and not a failure.
var ErrNotStored = errors.New("no compressed copy on record")

// Record is what was stored for one binary.
type Record struct {
	Version    string // the release's version - never the binary's own claim
	Compressed bool   // stored as <name>.gz, unpacked to run
	Size       int64  // of the stored file
	ModTime    int64  // of the stored file, UnixNano
	SHA256     string // of the stored file when compressed: checked before every unpack
}

func recordPath(dir, name string) string { return filepath.Join(dir, "."+name+".version") }

// Stored is the file a record describes: the binary itself, or its gzip.
func Stored(dir, name string, compressed bool) string {
	if compressed {
		return filepath.Join(dir, name+".gz")
	}
	return filepath.Join(dir, name)
}

// Write records the file now stored for name - the binary, or its gzip when compressed.
func Write(dir, name, version string, compressed bool) error {
	p := Stored(dir, name, compressed)
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	sum := "-"
	if compressed {
		if sum, err = fileSHA256(p); err != nil {
			return err
		}
	}
	c := 0
	if compressed {
		c = 1
	}
	rec := fmt.Sprintf("%s %d %d %d %s\n", version, c, fi.Size(), fi.ModTime().UnixNano(), sum)
	tmp := recordPath(dir, name) + ".new"
	if err := os.WriteFile(tmp, []byte(rec), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, recordPath(dir, name))
}

// Read returns name's record when it still describes the stored file.
func Read(dir, name string) (Record, bool) {
	b, err := os.ReadFile(recordPath(dir, name))
	if err != nil {
		return Record{}, false
	}
	f := strings.Fields(string(b))
	if len(f) != 5 || (f[1] != "0" && f[1] != "1") {
		return Record{}, false
	}
	r := Record{Version: f[0], Compressed: f[1] == "1", SHA256: f[4]}
	var e1, e2 error
	r.Size, e1 = strconv.ParseInt(f[2], 10, 64)
	r.ModTime, e2 = strconv.ParseInt(f[3], 10, 64)
	if e1 != nil || e2 != nil {
		return Record{}, false
	}
	fi, err := os.Stat(Stored(dir, name, r.Compressed))
	if err != nil || fi.Size() != r.Size || fi.ModTime().UnixNano() != r.ModTime {
		return Record{}, false
	}
	return r, true
}

// Remove deletes everything stored for name: the binary, its gzip, the record, and an unpacked copy
// in runDir.
func Remove(dir, name, runDir string) {
	_ = os.Remove(Stored(dir, name, false))
	_ = os.Remove(Stored(dir, name, true))
	_ = os.Remove(recordPath(dir, name))
	if runDir != "" {
		_ = os.Remove(filepath.Join(runDir, name))
		_ = os.Remove(filepath.Join(runDir, name) + ".src")
	}
}

// RemoveStaleCompressed deletes the compressed copy of name the updater kept in dir - the gzip, its
// record, and the copy unpacked from it into runDir - for when a package (opkg, apk, Entware) has taken
// name over. The copy is then stale twice over: it costs flash and tmpfs for a binary the router
// already has, and the plugin, which looks in dir before PATH, would keep starting WayHop's older build
// instead of the package's.
//
// It never removes the binary itself (Stored(dir, name, false)): a package that installs into dir owns
// that file. A record describing such a binary is removed only when it no longer matches the file - the
// package wrote over it - and one that still matches is left with its binary. An unpacked copy in runDir
// is removed only beside the marker Unpack writes, which proves Unpack made it. It returns the paths it
// removed; a path that is already gone is not an error.
func RemoveStaleCompressed(dir, name, runDir string) ([]string, error) {
	var removed []string
	var errs []error
	drop := func(p string) {
		switch err := os.Remove(p); {
		case err == nil:
			removed = append(removed, p)
		case !errors.Is(err, os.ErrNotExist):
			errs = append(errs, err)
		}
	}
	if gz := Stored(dir, name, true); isRegular(gz) {
		drop(gz)
	}
	if b, err := os.ReadFile(recordPath(dir, name)); err == nil {
		f := strings.Fields(string(b))
		raw := len(f) == 5 && f[1] == "0"
		if _, current := Read(dir, name); !raw || !current {
			drop(recordPath(dir, name))
		}
	}
	if runDir != "" {
		target := filepath.Join(runDir, name)
		if filepath.Clean(target) != filepath.Clean(Stored(dir, name, false)) && isRegular(target+".src") {
			drop(target)
			drop(target + ".src")
		}
	}
	return removed, errors.Join(errs...)
}

func isRegular(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Unpack makes the compressed copy of name runnable and returns its path: the gzip's digest checked
// against the record first - flash does wear, and a binary that runs as root is not unpacked on
// trust - then inflated into runDir. A copy already unpacked from the same stored file is reused, so
// a crash-relaunch does not rewrite megabytes of RAM each time.
func Unpack(dir, name, runDir string) (string, error) {
	rec, ok := Read(dir, name)
	if !ok || !rec.Compressed {
		return "", ErrNotStored
	}
	target := filepath.Join(runDir, name)
	marker := target + ".src"
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == rec.SHA256 {
		if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
			return target, nil
		}
	}
	gz := Stored(dir, name, true)
	sum, err := fileSHA256(gz)
	if err != nil {
		return "", err
	}
	if sum != rec.SHA256 {
		return "", fmt.Errorf("the compressed %s on flash does not match its record (sha256 %s, recorded %s); reinstall it", name, sum, rec.SHA256)
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", err
	}
	if err := Gunzip(gz, target); err != nil {
		return "", err
	}
	if err := os.WriteFile(marker, []byte(rec.SHA256+"\n"), 0o644); err != nil {
		return "", err
	}
	return target, nil
}

// Gunzip inflates src into dst as an executable, through dst.new and a rename, so a reader never sees
// half a binary.
func Gunzip(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("%s: %v", filepath.Base(src), err)
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(zr, maxUnpacked+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxUnpacked {
		err = fmt.Errorf("%s inflates past %d MiB; it is not the binary it claims to be", filepath.Base(src), maxUnpacked>>20)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
