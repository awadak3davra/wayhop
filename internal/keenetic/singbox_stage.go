package keenetic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"velinx/internal/atomicfile"
)

// singbox_stage.go atomically swaps the sing-box config for the cutover, with a snapshot for
// rollback. The device's S99sing-box runs `sing-box run -C /opt/etc/sing-box` — DIRECTORY
// mode, which merges EVERY *.json in the dir (the red-team's hole). So Velinx overwrites
// the single config.json, snapshots the original bytes (to a non-*.json sidecar so sing-box
// won't merge it), and refuses to stage if a stray *.json would also load.

// SingboxStageOptions configure the staged swap.
type SingboxStageOptions struct {
	ConfigPath   string // default /opt/etc/sing-box/config.json
	SnapshotPath string // default <ConfigPath>.wr-orig (NOT *.json → sing-box ignores it)
}

func (o *SingboxStageOptions) defaults() {
	if o.ConfigPath == "" {
		o.ConfigPath = "/opt/etc/sing-box/config.json"
	}
	if o.SnapshotPath == "" {
		o.SnapshotPath = o.ConfigPath + ".wr-orig"
	}
}

// strayJSON returns the *.json files in dir other than `keep` — any of these would be merged
// by sing-box's directory mode and silently corrupt the cutover config.
func strayJSON(dir, keep string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var stray []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".json") && n != keep {
			stray = append(stray, n)
		}
	}
	return stray, nil
}

// StageSingboxConfig snapshots the original config.json (once) and atomically writes the new
// one. It does NOT restart sing-box — the orchestrator does that after the rest of the plane
// is staged. Re-staging keeps the FIRST snapshot (the true pre-Velinx config). ⚠️
// DEVICE-WRITING; cutover only.
func StageSingboxConfig(cfg map[string]any, opt SingboxStageOptions) error {
	opt.defaults()
	dir := filepath.Dir(opt.ConfigPath)

	if stray, err := strayJSON(dir, filepath.Base(opt.ConfigPath)); err != nil {
		return fmt.Errorf("scan %s: %w", dir, err)
	} else if len(stray) > 0 {
		return fmt.Errorf("refusing to stage: stray *.json in %s would also load in directory mode: %v", dir, stray)
	}

	// Snapshot the ORIGINAL only once (never snapshot a Velinx config as "original").
	if _, err := os.Stat(opt.SnapshotPath); os.IsNotExist(err) {
		if orig, rerr := os.ReadFile(opt.ConfigPath); rerr == nil {
			if err := atomicfile.Write(opt.SnapshotPath, orig, 0o600); err != nil {
				return fmt.Errorf("snapshot original config: %w", err)
			}
		} // no config.json yet → nothing to snapshot; Restore becomes a no-op
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sing-box config: %w", err)
	}
	if err := atomicfile.Write(opt.ConfigPath, b, 0o644); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}
	return nil
}

// RestoreSingboxConfig restores the snapshot over config.json and removes the snapshot (the
// cutover rollback for the sing-box plane). No snapshot → no-op. ⚠️ DEVICE-WRITING.
func RestoreSingboxConfig(opt SingboxStageOptions) error {
	opt.defaults()
	orig, err := os.ReadFile(opt.SnapshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read snapshot: %w", err)
	}
	if err := atomicfile.Write(opt.ConfigPath, orig, 0o644); err != nil {
		return fmt.Errorf("restore sing-box config: %w", err)
	}
	_ = os.Remove(opt.SnapshotPath)
	return nil
}
