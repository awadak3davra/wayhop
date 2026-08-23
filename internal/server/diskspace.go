package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"wayhop/internal/updater"
)

// diskVerdict maps free bytes on WayHop's filesystem to a battery status. The router overlay is
// tiny (~60 MB) and fills with logs; once it's nearly full, config applies (which write a temp
// config), log writes, and binary updates all fail — so this is a real, confusing failure to
// surface early. Pure for unit-testing.
//
// The "enough" threshold is what an UPDATE actually needs, not a round number. It was a fixed
// 10 MiB, and on a live AX3000T that produced two answers to one question on one panel:
// Diagnostics said "enough free space" over 12.6 MB while the Components page, which knows what an
// install costs, said "Little room on internal flash" about the same filesystem. Components was
// right — WayHop's own binary is ~13 MB, so that router cannot replace it, and nothing but the
// number changes between the two pages. selfSize is the running binary's size: swapping it needs
// room for the new one beside the old, which is the smallest concrete requirement this router has
// and the one it fails first.
//
// installFloor is the OTHER question the panel asks about the same disk — can a component be
// installed here at all — and it is passed in rather than assumed so both surfaces move together.
// Above the swap need but below that floor the verdict stays a pass and says which of the two it
// checked, because the bare "enough free space" in that band is what read as a contradiction of the
// Components page.
func diskVerdict(avail uint64, ok bool, selfSize uint64, installFloor uint64) (status, summary, fix string) {
	if !ok {
		return "na", "free space could not be read on this host", ""
	}
	// A margin over the bare binary size: the swap stages beside the old file and the config write
	// needs somewhere to land too. Falls back to the old 10 MiB when the size cannot be read, so a
	// failed stat degrades to the previous behaviour rather than to "everything is fine".
	needed := uint64(10 << 20)
	if selfSize > 0 {
		needed = selfSize + selfSize/10 + (1 << 20)
	}
	switch {
	case avail < 3<<20:
		return "fail", "router storage critically low", "free space now (clear logs / remove unused packages) — config applies and updates will fail"
	case avail < needed:
		return "warn", fmt.Sprintf("%d MiB free — not enough to replace WayHop itself (%d MiB)", avail>>20, needed>>20),
			"free space before updating: the new binary is staged beside the old one, so a swap needs about twice the binary. Installing a component needs more still — the Components page states what each one costs."
	case installFloor > 0 && avail < installFloor:
		// A pass, because a router that can update itself is not unhealthy for being unable to take
		// an optional engine. But the sentence has to say which question was answered: "enough free
		// space", unqualified, is what let this page contradict the Components page on one disk.
		return "pass", fmt.Sprintf("%d MiB free — enough to update WayHop, too little to install a component (needs %d MiB)", avail>>20, installFloor>>20), ""
	default:
		return "pass", "enough free space", ""
	}
}

// diskSpaceCheck is a Diagnostics-battery probe: it reports the free space on the filesystem
// holding the WayHop binary (where the binary swaps and, on most installs, the config lives)
// and warns/fails when it's low. Read-only.
func (s *Server) diskSpaceCheck(_ context.Context) healthRow {
	row := healthRow{ID: "disk-space", Label: "Router storage has room"}
	dir := "/"
	var selfSize uint64
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
		if fi, statErr := os.Stat(exe); statErr == nil && fi.Size() > 0 {
			selfSize = uint64(fi.Size())
		}
	}
	avail, ok := updater.AvailBytes(dir)
	row.Status, row.Summary, row.Fix = diskVerdict(avail, ok, selfSize, componentInstallFloor)
	if ok {
		row.Detail = fmt.Sprintf("%d MiB free on the filesystem holding %s", avail>>20, dir)
		if selfSize > 0 {
			row.Detail += fmt.Sprintf("; WayHop itself is %d MiB", selfSize>>20)
		}
	}
	return row
}
