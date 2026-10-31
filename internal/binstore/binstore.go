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

	"wayhop/internal/atomicfile"
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

// nextPath is the record StoreCompressed writes for a gzip before the gzip takes its name, and the
// one Read falls back to. Not Write's staging name (.new): the installers sweep that one as an
// unfinished install, and this one can be the only record of the stored gzip.
func nextPath(dir, name string) string { return recordPath(dir, name) + ".next" }

// writeSynced and syncDir are the durable write and the directory sync, as seams: a power cut is the
// failure they exist for, and no test can cut one, so the tests check the order instead.
var (
	writeSynced = atomicfile.WriteSynced
	syncDir     = atomicfile.SyncDir
)

// Stored is the file a record describes: the binary itself, or its gzip.
func Stored(dir, name string, compressed bool) string {
	if compressed {
		return filepath.Join(dir, name+".gz")
	}
	return filepath.Join(dir, name)
}

// Write records the file now stored for name - the binary, or its gzip when compressed. The record is
// synced before it takes its name, and the directory after: renamed into place unsynced, it can reach
// the flash empty after a power cut (UBIFS does not sync data on rename), and an empty record leaves a
// compressed binary unrunnable until it is reinstalled.
func Write(dir, name, version string, compressed bool) error {
	rec, err := describe(Stored(dir, name, compressed), version, compressed)
	if err != nil {
		return err
	}
	tmp := recordPath(dir, name) + ".new"
	if err := writeSynced(tmp, []byte(rec), 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, recordPath(dir, name)); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// describe is the record of the file at p, stored as version.
func describe(p, version string, compressed bool) (string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	sum := "-"
	if compressed {
		if sum, err = fileSHA256(p); err != nil {
			return "", err
		}
	}
	c := 0
	if compressed {
		c = 1
	}
	return fmt.Sprintf("%s %d %d %d %s\n", version, c, fi.Size(), fi.ModTime().UnixNano(), sum), nil
}

// StoreCompressed makes src, a verified gzip in dir, the stored copy of name, and records it as
// version. The order leaves a record that matches a runnable copy wherever a kill or a power cut
// lands: the record for src is written and synced first, under the name Read falls back to; then src
// takes the gzip's name and the unpacked binary goes; only then does the record take its own name.
// Done the other way round (gzip, unpacked binary removed, record last), a cut in between left a
// record naming a file that was gone (raw to gzip) or no longer matched (gzip to gzip): Unpack said
// ErrNotStored, the plugin found nothing, and the binary did not run again until reinstalled.
func StoreCompressed(dir, name, version, src string) error {
	rec, err := describe(src, version, true)
	if err != nil {
		return fmt.Errorf("record %s: %w (nothing was replaced)", filepath.Base(src), err)
	}
	settle(dir, name)
	pending := nextPath(dir, name)
	if err := writeSynced(pending, []byte(rec), 0o644); err != nil {
		_ = os.Remove(pending)
		return fmt.Errorf("record %s: %w (nothing was replaced)", filepath.Base(src), err)
	}
	syncDir(dir)
	// The rename keeps src's size and modification time, so the record written for src describes it
	// under its new name.
	if err := os.Rename(src, Stored(dir, name, true)); err != nil {
		_ = os.Remove(pending)
		return fmt.Errorf("store %s: %w (nothing was replaced)", filepath.Base(src), err)
	}
	// An unpacked binary left from an earlier install is no longer the copy that runs, and its space is
	// what the compressed form exists to save.
	_ = os.Remove(Stored(dir, name, false))
	if err := os.Rename(pending, recordPath(dir, name)); err != nil {
		return fmt.Errorf("%s is stored, but its record could not take its name (%w); it is read from %s until the next install", name, err, filepath.Base(pending))
	}
	syncDir(dir)
	return nil
}

// settle gives a record a kill left at nextPath its own name: that name is about to be rewritten, and
// until then the record there is the only one that describes the stored gzip.
func settle(dir, name string) {
	if _, ok := readRecord(dir, name, recordPath(dir, name)); ok {
		return
	}
	if _, ok := readRecord(dir, name, nextPath(dir, name)); ok && os.Rename(nextPath(dir, name), recordPath(dir, name)) == nil {
		syncDir(dir)
	}
}

// Read returns name's record when it still describes the stored file: the record itself, or the one
// StoreCompressed wrote for a gzip that took its name before the record could take its own.
func Read(dir, name string) (Record, bool) {
	if r, ok := readRecord(dir, name, recordPath(dir, name)); ok {
		return r, true
	}
	return readRecord(dir, name, nextPath(dir, name))
}

// readRecord reads the record at p, when it describes the file stored for name.
func readRecord(dir, name, p string) (Record, bool) {
	b, err := os.ReadFile(p)
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
	_ = os.Remove(nextPath(dir, name))
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
	// A record StoreCompressed left pending describes only a gzip, and the gzip is gone.
	if isRegular(nextPath(dir, name)) {
		drop(nextPath(dir, name))
	}
	if b, err := os.ReadFile(recordPath(dir, name)); err == nil {
		f := strings.Fields(string(b))
		raw := len(f) == 5 && f[1] == "0"
		if _, current := Read(dir, name); !raw || !current {
			drop(recordPath(dir, name))
		}
	}
	ur, uerr := RemoveUnpacked(dir, name, runDir)
	removed = append(removed, ur...)
	if uerr != nil {
		errs = append(errs, uerr)
	}
	return removed, errors.Join(errs...)
}

// RemoveUnpacked deletes the copy Unpack made of name in runDir, and its marker, for when that copy is
// no longer what runs: a package took name over, or name is now stored as the binary itself, which
// the plugin prefers. Left there, it holds the unpacked size in tmpfs - the router's RAM - until a
// reboot. Only beside the marker, which proves Unpack made it, and never the stored binary itself. It
// returns the paths it removed; a path that is already gone is not an error.
func RemoveUnpacked(dir, name, runDir string) ([]string, error) {
	if runDir == "" {
		return nil, nil
	}
	target := filepath.Join(runDir, name)
	if filepath.Clean(target) == filepath.Clean(Stored(dir, name, false)) || !isRegular(target+".src") {
		return nil, nil
	}
	var removed []string
	var errs []error
	for _, p := range []string{target, target + ".src"} {
		switch err := os.Remove(p); {
		case err == nil:
			removed = append(removed, p)
		case !errors.Is(err, os.ErrNotExist):
			errs = append(errs, err)
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
	// The marker goes before the copy it vouches for is replaced. Killed after the rename below (a
	// SIGKILL or an OOM kill: the tmpfs survives both), a marker naming the previous build would vouch
	// for this one once the store holds that build again - a downgrade - and this copy would run.
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := gunzip(gz, target); err != nil {
		return "", err
	}
	if err := os.WriteFile(marker, []byte(rec.SHA256+"\n"), 0o644); err != nil {
		return "", err
	}
	return target, nil
}

// gunzip is Gunzip, as a seam: a test stands in for the daemon killed right after its rename.
var gunzip = Gunzip

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
