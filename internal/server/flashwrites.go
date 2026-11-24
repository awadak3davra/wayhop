package server

import (
	"net/http"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/ramdir"
)

// handleFlashWrites (GET /api/diagnostics/flash) reports what the daemon has written since it
// started, per file class: writes and bytes asked of the filesystem, and the identical rewrites it
// skipped. Classes under the RAM directory are marked ram. It is how an operator sees flash wear
// without block-device counters; sing-box's own cache.db is not included (sing-box writes it).
func (s *Server) handleFlashWrites(w http.ResponseWriter, _ *http.Request) {
	classes, since := atomicfile.Stats()
	var flashWrites, flashBytes, skipped, skippedBytes uint64
	for _, c := range classes {
		if c.RAM {
			continue
		}
		flashWrites += c.Writes
		flashBytes += c.Bytes
		skipped += c.Skipped
		skippedBytes += c.SkippedBytes
	}
	used, peak, budget := ramdir.Shared.Usage()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"since":          since.Unix(),
		"uptime_seconds": int64(time.Since(since).Seconds()),
		"flash_writes":   flashWrites,
		"flash_bytes":    flashBytes,
		"skipped_writes": skipped,
		"skipped_bytes":  skippedBytes,
		"classes":        classes,
		"ram_budget":     map[string]int64{"used": used, "peak": peak, "cap": budget},
	})
}
