package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func nfqwsEndpoint(params map[string]any) model.Endpoint {
	return model.Endpoint{ID: "desync1", Engine: model.EngineNfqws, Params: params}
}

func TestNfqwsArgs_DefaultsAndStrategy(t *testing.T) {
	got := strings.Join(nfqwsArgs(nfqwsEndpoint(map[string]any{
		"dpi_desync":         "fake,split2",
		"dpi_desync_fooling": "md5sig,badseq",
		"dpi_desync_ttl":     6,
	})), " ")
	for _, want := range []string{"--qnum=200", "--dpi-desync=fake,split2", "--dpi-desync-fooling=md5sig,badseq", "--dpi-desync-ttl=6"} {
		if !strings.Contains(got, want) {
			t.Errorf("nfqwsArgs missing %q in: %s", want, got)
		}
	}
}

func TestNfqwsArgs_CustomQueue(t *testing.T) {
	// qnum as a JSON number (float64) and as a string both work.
	if got := strings.Join(nfqwsArgs(nfqwsEndpoint(map[string]any{"qnum": float64(8080)})), " "); !strings.Contains(got, "--qnum=8080") {
		t.Errorf("float qnum not honored: %s", got)
	}
	if got := strings.Join(nfqwsArgs(nfqwsEndpoint(map[string]any{"qnum": "311"})), " "); !strings.Contains(got, "--qnum=311") {
		t.Errorf("string qnum not honored: %s", got)
	}
}

func TestNfqwsArgs_DropsMalformed(t *testing.T) {
	args := strings.Join(nfqwsArgs(nfqwsEndpoint(map[string]any{
		"dpi_desync":     "fake; rm -rf /", // spaces + shell metachars → rejected
		"dpi_desync_ttl": 9999,             // out of range → dropped
		"qnum":           70000,            // out of range → default
	})), " ")
	if strings.Contains(args, "rm") || strings.Contains(args, "--dpi-desync=") {
		t.Errorf("malformed dpi_desync must be dropped, got: %s", args)
	}
	if strings.Contains(args, "--dpi-desync-ttl=") {
		t.Errorf("out-of-range ttl must be dropped, got: %s", args)
	}
	if !strings.Contains(args, "--qnum=200") {
		t.Errorf("out-of-range qnum must fall back to the default 200, got: %s", args)
	}
}

func TestNativeConfig_Nfqws(t *testing.T) {
	cfg, fname, err := NativeConfig(nfqwsEndpoint(map[string]any{"dpi_desync": "disorder2"}), 0)
	if err != nil {
		t.Fatal(err)
	}
	if fname != "desync1.nfqws" {
		t.Errorf("filename = %q, want desync1.nfqws", fname)
	}
	if !strings.Contains(cfg, "--qnum=200") || !strings.Contains(cfg, "--dpi-desync=disorder2") {
		t.Errorf("NativeConfig nfqws args wrong: %q", cfg)
	}
}

// TestNfqws_SyncNeedsBinaryWritesConfig: Sync of a nfqws2 spec on a host with no nfqws2 binary
// writes the .nfqws args file, reports needs_binary / not-running, and surfaces the engine — the
// same graceful degradation as olcRTC/awg.
func TestNfqws_SyncNeedsBinaryWritesConfig(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // hermetic: no nfqws2 on PATH
	cfgDir, binDir := t.TempDir(), t.TempDir()
	m := New(cfgDir, binDir)
	ep := nfqwsEndpoint(map[string]any{"dpi_desync": "fake,split2"})
	m.Sync([]Spec{{ID: ep.ID, Endpoint: ep}})

	b, err := os.ReadFile(filepath.Join(cfgDir, ep.ID+".nfqws")) // NativeConfig names the file from the endpoint ID
	if err != nil {
		t.Fatalf("nfqws args file not written: %v", err)
	}
	if !strings.Contains(string(b), "--dpi-desync=fake,split2") {
		t.Errorf("nfqws args file content: %s", b)
	}
	st := m.Status()
	if len(st) != 1 || st[0].Engine != string(model.EngineNfqws) {
		t.Fatalf("status: %+v", st)
	}
	if !st[0].NeedsBinary || st[0].Running {
		t.Errorf("nfqws with no binary: NeedsBinary=%v Running=%v, want true/false", st[0].NeedsBinary, st[0].Running)
	}
}

// TestNfqws_RelaunchResolvesBinName: a managed nfqws2 proc whose binary has vanished (cooldown
// elapsed) must be relaunched via its binName, fail to resolve, and degrade to needs_binary —
// proving Supervise's generalized relaunch uses the per-proc binName, not a hardcoded "olcrtc".
func TestNfqws_RelaunchResolvesBinName(t *testing.T) {
	t.Setenv("PATH", t.TempDir())      // hermetic
	m := New(t.TempDir(), t.TempDir()) // empty binDir → nfqws2 unresolvable
	p := &proc{engine: model.EngineNfqws, binName: "nfqws2", runArgs: []string{"--qnum=200"}, managed: true, running: false, cooldown: 0}
	m.mu.Lock()
	m.procs["d1"] = p
	m.mu.Unlock()

	m.Supervise()

	m.mu.Lock()
	defer m.mu.Unlock()
	if !p.needsBin {
		t.Error("a managed nfqws2 proc with no resolvable binary must degrade to needs_binary on relaunch")
	}
	if p.managed {
		t.Error("a needs_binary proc must drop out of supervision (managed=false)")
	}
}
