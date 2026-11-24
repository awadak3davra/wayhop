// Package ramdir resolves the directory WayHop keeps runtime-only state in: data that is derived,
// re-fetchable or only meaningful for the running process (feed caches between their rare flash
// snapshots). Routers run Entware's /opt or OpenWrt's overlay on flash or a USB stick, and every
// write there wears the medium; /tmp is tmpfs on both KeeneticOS and OpenWrt.
//
// A directory that is NOT RAM is refused rather than used: writing "RAM" state to flash would wear
// it exactly as much as the flash copy this layer exists to spare. Callers then keep that state in
// memory only and fall back to their coalesced flash policy.
package ramdir

import (
	"fmt"
	"log"
	"path/filepath"

	"wayhop/internal/binstore"
)

// Default is used when the config does not name one: beside binstore's run directory, under the
// same ownership rules (root writes and later reads it, and /tmp is world-writable).
const Default = binstore.DefaultRunDir + "/state"

// isRAMFS reports whether dir is on a RAM-backed filesystem; a variable so tests can stand in for
// statfs.
var isRAMFS = isRAMFSImpl

// Resolve returns the RAM directory to use (configured, or Default when empty) after creating it
// with the run directory's safety checks, or "" with the reason when there is none to use.
func Resolve(configured string) (string, error) {
	dir := configured
	if dir == "" {
		dir = Default
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("runtime dir %q is not an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	// Both levels: a parent that someone else created could be swapped for a symlink under us.
	if parent := filepath.Dir(dir); parent != "/" && parent != filepath.Dir(parent) && filepath.Base(parent) != "tmp" {
		if err := binstore.EnsureRunDir(parent); err != nil {
			return "", err
		}
	}
	if err := binstore.EnsureRunDir(dir); err != nil {
		return "", err
	}
	ram, err := isRAMFS(dir)
	if err != nil {
		return "", fmt.Errorf("runtime dir %s: %w", dir, err)
	}
	if !ram {
		return "", fmt.Errorf("runtime dir %s is not on tmpfs/ramfs; runtime-only state stays in memory", dir)
	}
	return dir, nil
}

// MustResolveOrLog is Resolve that logs the fallback and returns "" instead of an error.
func MustResolveOrLog(configured string) string {
	dir, err := Resolve(configured)
	if err != nil {
		log.Printf("ramdir: %v", err)
		return ""
	}
	return dir
}
