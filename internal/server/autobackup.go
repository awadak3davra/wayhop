package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	// Sortable UTC name so a plain lexicographic sort is chronological (used by pruneBackups).
	path := filepath.Join(dir, "wayhop-backup-"+now.UTC().Format("20060102T150405Z")+".json")
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	pruneBackups(dir, backupKeepN(c))
	return path, nil
}

// pruneBackups keeps the newest `keep` auto-backup files and removes the rest. Best-effort.
func pruneBackups(dir string, keep int) {
	if keep <= 0 {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "wayhop-backup-*.json"))
	if len(matches) <= keep {
		return
	}
	sort.Strings(matches) // sortable timestamp names → chronological order
	for _, old := range matches[:len(matches)-keep] {
		_ = os.Remove(old)
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
