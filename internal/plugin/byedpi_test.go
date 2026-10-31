package plugin

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// ciadpi listens on loopback at the port sing-box's SOCKS outbound uses, then takes the strategy.
func TestByeDPIArgs(t *testing.T) {
	e := model.Endpoint{ID: "bye", Engine: model.EngineByeDPI, Params: map[string]any{"strategy": "--fake -1 --ttl 8"}}
	args, err := byedpiArgs(e, 17900)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "-i 127.0.0.1 -p 17900 --fake -1 --ttl 8" {
		t.Errorf("argv = %q", got)
	}
	if _, err := byedpiArgs(e, 0); err == nil {
		t.Error("no port, no start")
	}
	e.Params["strategy"] = "--ip 0.0.0.0"
	if _, err := byedpiArgs(e, 17900); err == nil {
		t.Error("a strategy moving the listener must not reach the argv")
	}
	cfg, name, err := NativeConfig(model.Endpoint{ID: "bye", Engine: model.EngineByeDPI}, 17901)
	if err != nil || name != "bye.byedpi" || !strings.HasPrefix(cfg, "-i 127.0.0.1 -p 17901 ") {
		t.Errorf("NativeConfig = %q %q %v", cfg, name, err)
	}
}

// A ByeDPI connection applied before ciadpi was installed waits for it by name: installing the
// component looks the waiting procs up by binary (StopByBin) and re-syncs them. Unnamed, it was never
// found, and the connection stayed down while Components showed ciadpi installed.
func TestByeDPIWaitingForItsBinaryIsFoundByName(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m := New(t.TempDir(), t.TempDir())
	ep := model.Endpoint{ID: "bye", Engine: model.EngineByeDPI, Protocol: model.ProtoSOCKS, Enabled: true}
	m.Sync([]Spec{{ID: ep.ID, Endpoint: ep, SOCKSPort: 17900}})
	if st := m.Status(); len(st) != 1 || !st[0].NeedsBinary {
		t.Fatalf("status = %+v, want one proc waiting for its binary", st)
	}
	if n := m.StopByBin("ciadpi"); n != 1 {
		t.Fatalf("StopByBin(ciadpi) = %d, want the waiting proc", n)
	}
	m.Sync(m.Specs())
	if st := m.Status(); len(st) != 1 || !st[0].NeedsBinary {
		t.Errorf("after the re-sync = %+v, want it re-created (still waiting: no binary here)", st)
	}
}
