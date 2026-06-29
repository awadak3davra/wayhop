package keenetic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStageRestoreSingboxConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	opt := SingboxStageOptions{ConfigPath: cfgPath}

	// Seed an "original" config (mama's Hy2/VLESS-only config).
	orig := []byte(`{"inbounds":[],"outbounds":[{"type":"hysteria2","tag":"orig"}]}`)
	if err := os.WriteFile(cfgPath, orig, 0o644); err != nil {
		t.Fatal(err)
	}

	newCfg := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "wr-tun"}}, "outbounds": []any{}}
	if err := StageSingboxConfig(newCfg, opt); err != nil {
		t.Fatal(err)
	}
	// config.json is now the new one; the snapshot holds the original bytes.
	got, _ := os.ReadFile(cfgPath)
	var m map[string]any
	if json.Unmarshal(got, &m); m["inbounds"] == nil {
		t.Errorf("config.json not replaced: %s", got)
	}
	snap, err := os.ReadFile(cfgPath + ".wr-orig")
	if err != nil || string(snap) != string(orig) {
		t.Errorf("snapshot must hold the ORIGINAL bytes, got %q err %v", snap, err)
	}
	// Snapshot is NOT a *.json (sing-box directory mode would otherwise merge it).
	if filepath.Ext(cfgPath+".wr-orig") == ".json" {
		t.Error("snapshot must not end in .json")
	}

	// Re-stage keeps the FIRST snapshot (never snapshots a Velinx config as "original").
	if err := StageSingboxConfig(map[string]any{"x": 1}, opt); err != nil {
		t.Fatal(err)
	}
	if snap2, _ := os.ReadFile(cfgPath + ".wr-orig"); string(snap2) != string(orig) {
		t.Errorf("re-stage must keep the original snapshot, got %q", snap2)
	}

	// Restore brings back the original and removes the snapshot.
	if err := RestoreSingboxConfig(opt); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(cfgPath); string(back) != string(orig) {
		t.Errorf("restore did not bring back the original: %q", back)
	}
	if _, err := os.Stat(cfgPath + ".wr-orig"); !os.IsNotExist(err) {
		t.Error("snapshot must be removed after restore")
	}
	// Restore again is a no-op (no snapshot).
	if err := RestoreSingboxConfig(opt); err != nil {
		t.Errorf("restore with no snapshot must be a no-op, got %v", err)
	}
}

func TestStageSingbox_RefusesStrayJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, []byte(`{}`), 0o644)
	// A stray *.json that directory-mode would merge.
	_ = os.WriteFile(filepath.Join(dir, "leftover.json"), []byte(`{}`), 0o644)

	err := StageSingboxConfig(map[string]any{"x": 1}, SingboxStageOptions{ConfigPath: cfgPath})
	if err == nil {
		t.Fatal("must refuse to stage when a stray *.json is present")
	}
	// A non-.json sidecar (like mama's config.json.bak.pre-vless) must NOT trip it.
	_ = os.Remove(filepath.Join(dir, "leftover.json"))
	_ = os.WriteFile(filepath.Join(dir, "config.json.bak.pre-vless"), []byte(`{}`), 0o644)
	if err := StageSingboxConfig(map[string]any{"x": 1}, SingboxStageOptions{ConfigPath: cfgPath}); err != nil {
		t.Errorf("a non-.json sidecar must not block staging, got %v", err)
	}
}
