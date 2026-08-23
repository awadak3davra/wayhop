package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/config"
)

// autoBackupDefaultKeep is the retention when Config.Backup.KeepN is unset (<=0).
const autoBackupDefaultKeep = 14

// backupDir resolves the auto-backup directory: Config.Backup.Dir, or <DataDir>/backups.
func (s *Server) backupDir(c config.Config) string {
	if d := strings.TrimSpace(c.Backup.Dir); d != "" {
		return d
	}
	return filepath.Join(c.DataDir, "backups")
}

func backupKeepN(c config.Config) int {
	if c.Backup.KeepN > 0 {
		return c.Backup.KeepN
	}
	return autoBackupDefaultKeep
}

// writeAutoBackup writes a timestamped whole-setup backup into the backup dir (atomically)
// and prunes to the newest KeepN. Returns the written path. `now` is injectable for tests.
// The bundle is byte-identical to GET /api/backup, so a scheduled file restores the same way.
func (s *Server) writeAutoBackup(now time.Time) (string, error) {
	c := s.config()
	dir := s.backupDir(c)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	data, err := json.MarshalIndent(s.buildBackupBundle(), "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	// Sortable UTC name (human-friendly, chronological while the clock runs forward).
	path := filepath.Join(dir, "wayhop-backup-"+now.UTC().Format("20060102T150405Z")+".json")
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	pruneBackups(dir, backupKeepN(c), path)
	return path, nil
}

// pruneBackups keeps the newest `keep` auto-backup files (by modtime) and removes the
// rest. keepPath — the just-written backup — is NEVER pruned, so a backward wall-clock
// step (an NTP correction on an RTC-less router, which also boots at 1970 before sync)
// cannot delete the freshest snapshot even if its timestamp NAME sorts as the oldest.
// Best-effort. Ordering by modtime rather than by filename means a name whose timestamp
// is out of order after a clock step doesn't misrank the file either.
// backupFile is one candidate for pruning: its path and, as a fallback ordering key, its mtime.
type backupFile struct {
	path string
	mod  time.Time
}

// backupSortKey returns the ordering key for one backup: the UTC stamp encoded in its filename
// when present, else a stamp derived from mtime so an unrecognised name still sorts sanely rather
// than sinking to the bottom and being pruned first.
func backupSortKey(f backupFile) string {
	base := filepath.Base(f.path)
	if m := backupNameStamp.FindStringSubmatch(base); m != nil {
		return m[1]
	}
	return f.mod.UTC().Format("20060102T150405Z")
}

// backupNameStamp matches the timestamp written by the backup writer.
var backupNameStamp = regexp.MustCompile(`wayhop-backup-(\d{8}T\d{6}Z)\.json$`)

func pruneBackups(dir string, keep int, keepPath string) {
	if keep <= 0 {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "wayhop-backup-*.json"))
	if len(matches) <= keep {
		return
	}
	files := make([]backupFile, 0, len(matches))
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		files = append(files, backupFile{m, fi.ModTime()})
	}
	// Order by the timestamp in the FILENAME, not by mtime.
	//
	// mtime is the wrong key twice over. Its granularity on a router's jffs2/overlayfs is a second,
	// so two backups written in the same second compare equal — and sort.Slice is not stable, so
	// which one counted as "newest" was arbitrary and prune could delete the newer file. And mtime
	// tracks the last WRITE, not the backup's content: restoring, copying or touching an old file
	// makes it look newest, so a genuinely recent backup gets pruned instead.
	//
	// The name already carries an exact, lexicographically-ordered UTC stamp
	// (wayhop-backup-20260102T030405Z.json), which is both correct and free. Paths break ties so
	// the order is total and the outcome can never depend on scheduling.
	sort.Slice(files, func(i, j int) bool {
		ki, kj := backupSortKey(files[i]), backupSortKey(files[j])
		if ki != kj {
			return ki > kj // newest first
		}
		return files[i].path > files[j].path
	})
	for i, f := range files {
		if i < keep || f.path == keepPath {
			continue // among the newest `keep`, or the file we just wrote — always keep
		}
		_ = os.Remove(f.path)
	}
}

// BackupLoop writes a scheduled local backup every Config.Backup.AutoHours hours. Opt-in:
// disabled while AutoHours<=0 (the default). A base 30-min tick gates on AutoHours + the
// last write, so enabling it at runtime (config save) takes effect without a restart and no
// ticker is rebuilt. Off by default; only writes files, never touches routing. Stops on ctx.
func (s *Server) BackupLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c := s.config()
			if c.Backup.AutoHours <= 0 {
				continue // disabled (default), or turned off at runtime
			}
			if !last.IsZero() && now.Sub(last) < time.Duration(c.Backup.AutoHours)*time.Hour {
				continue // not due yet
			}
			if path, err := s.writeAutoBackup(now); err != nil {
				log.Printf("auto-backup: %v", err)
			} else {
				last = now
				log.Printf("auto-backup: wrote %s", path)
			}
		}
	}
}
