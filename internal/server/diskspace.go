package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"velinx/internal/updater"
)

// diskVerdict maps free bytes on Velinx's filesystem to a battery status. The router overlay is
// tiny (~60 MB) and fills with logs; once it's nearly full, config applies (which write a temp
// config), log writes, and binary updates all fail — so this is a real, confusing failure to
// surface early. Pure for unit-testing.
func diskVerdict(avail uint64, ok bool) (status, summary, fix string) {
	if !ok {
		return "warn", "couldn't read free space (non-Linux?)", ""
	}
	switch {
	case avail < 3<<20:
		return "fail", "router storage critically low", "free space now (clear logs / remove unused packages) — config applies and updates will fail"
	case avail < 10<<20:
		return "warn", "router storage low", "free space soon — a binary update or large config may not fit"
	default:
		return "pass", "enough free space", ""
	}
}

// diskSpaceCheck is a Diagnostics-battery probe: it reports the free space on the filesystem
// holding the Velinx binary (where the binary swaps and, on most installs, the config lives)
// and warns/fails when it's low. Read-only.
func (s *Server) diskSpaceCheck(_ context.Context) healthRow {
	row := healthRow{ID: "disk-space", Label: "Router storage has room"}
	dir := "/"
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	avail, ok := updater.AvailBytes(dir)
	row.Status, row.Summary, row.Fix = diskVerdict(avail, ok)
	if ok {
		row.Detail = fmt.Sprintf("%d MiB free on the filesystem holding %s", avail>>20, dir)
	}
	return row
}
