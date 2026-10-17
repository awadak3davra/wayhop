package server

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/binstore"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/updater"
)

func openWrtAWGCapabilities() platform.CapabilitySet {
	return platform.Evaluate(platform.Capabilities{
		Platform: string(platform.OpenWrt), Native: map[string]bool{"amneziawg": true},
		NetifdProtos: map[string]bool{"amneziawg": true}, Installable: map[string]string{},
	}, platform.RuntimeFacts{})
}

func awgComponentServer(p platform.Platform, capset platform.CapabilitySet, probe awg.Probe, demo bool) *Server {
	cfg := *config.Default()
	cfg.Demo = demo
	s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return p },
		awgProbeOf: func() awg.Probe { return probe }}
	s.caps.set = capset
	s.caps.set.ProbedAt = time.Now()
	return s
}

func awgRuns(st awgComponentStatus) map[string]string {
	out := map[string]string{}
	for _, c := range st.Connections {
		out[c.ID] = c.Path
	}
	return out
}

// Each connection's path is the one the daemon acts on: the router's own AmneziaWG where the native
// planner keeps it, and otherwise the plugin's own choice between the kernel module and amneziawg-go.
func TestAWGComponentPaths(t *testing.T) {
	gen2 := awg.Probe{Kernel: awg.Gen2, TUN: true, GenlVersion: 2, GenlMaxAttr: 25}
	adopted := awg3Endpoint("adopted")
	adopted.Owner = model.OwnerExternal
	disabled := awg3Endpoint("off")
	disabled.Enabled = false
	prof := model.Profile{Endpoints: []model.Endpoint{executionAWGEndpoint("g1"), awg3Endpoint("g3"), adopted, disabled}}

	for _, c := range []struct {
		name   string
		p      platform.Platform
		capset platform.CapabilitySet
		probe  awg.Probe
		demo   bool
		kernel string
		runs   map[string]string
		needed bool
	}{
		{"OpenWrt with its own AmneziaWG 2", platform.OpenWrt, openWrtAWGCapabilities(), gen2, false, "2",
			map[string]string{"g1": "native", "g3": "userspace"}, true},
		{"OpenWrt without native AmneziaWG (generic path)", platform.OpenWrt, platform.CapabilitySet{}, gen2, false, "2",
			map[string]string{"g1": "kernel", "g3": "userspace"}, true},
		{"KeeneticOS with NDM AmneziaWG", platform.Keenetic, keeneticAWGCapabilities(), gen2, false, "2",
			map[string]string{"g1": "native", "g3": "userspace"}, true},
		{"the demo", platform.Keenetic, keeneticAWGCapabilities(), gen2, true, "none",
			map[string]string{"g1": "userspace", "g3": "userspace"}, true},
		{"a probe that failed, generic path", platform.Unknown, platform.CapabilitySet{}, awg.Probe{Err: "no netlink"}, false, "unknown",
			map[string]string{"g1": "kernel", "g3": "kernel"}, false},
	} {
		st := awgComponentServer(c.p, c.capset, c.probe, c.demo).awgComponent(context.Background(), prof)
		if st.Kernel != c.kernel || st.Needed != c.needed || len(st.Connections) != 2 {
			t.Errorf("%s: kernel %q needed %v connections %+v", c.name, st.Kernel, st.Needed, st.Connections)
			continue
		}
		for id, want := range c.runs {
			if got := awgRuns(st)[id]; got != want {
				t.Errorf("%s: %s runs %q, want %q", c.name, id, got, want)
			}
		}
	}

	keenetic := awgComponentServer(platform.Keenetic, keeneticAWGCapabilities(), gen2, false).awgComponent(context.Background(), prof)
	if !keenetic.FirmwareOwned {
		t.Error("KeeneticOS's module was not reported as the firmware's")
	}
	for _, conn := range keenetic.Connections {
		if conn.ID == "g3" && (!strings.Contains(conn.Reason, "KeeneticOS's own AmneziaWG cannot carry") || conn.Need != "3.0") {
			t.Errorf("the userspace connection's reason and need: %+v", conn)
		}
	}
	unconfirmed := platform.Evaluate(platform.Capabilities{Platform: string(platform.Keenetic),
		Native: map[string]bool{"amneziawg": true}, Installable: map[string]string{}},
		platform.RuntimeFacts{NativeOperations: keeneticProductionNativeOperations(), ProbeError: "ndm did not answer"})
	st := awgComponentServer(platform.Keenetic, unconfirmed, gen2, false).awgComponent(context.Background(), prof)
	if awgRuns(st)["g1"] != "unavailable" {
		t.Errorf("a connection the planner would refuse is shown as %q", awgRuns(st)["g1"])
	}
}

// The footprint is the stored form, what it costs on flash, and - for the compressed form - the copy
// it runs from in RAM.
func TestAWGFootprint(t *testing.T) {
	dir, runDir := t.TempDir(), t.TempDir()
	cfg := *config.Default()
	cfg.SingBox.Bin = filepath.Join(dir, "sing-box")
	s := &Server{cfg: &cfg, updater: &updater.Updater{RunDir: runDir}}
	if f := s.awgFootprint(); f != nil {
		t.Fatalf("a footprint for nothing installed: %+v", f)
	}
	if err := os.WriteFile(filepath.Join(dir, "amneziawg-go"), make([]byte, 3000), 0o755); err != nil {
		t.Fatal(err)
	}
	if f := s.awgFootprint(); f == nil || f.Form != "binary" || f.FlashBytes != 3000 || f.RAMBytes != 0 {
		t.Fatalf("an unrecorded binary: %+v", f)
	}
	_ = os.Remove(filepath.Join(dir, "amneziawg-go"))
	if err := os.WriteFile(binstore.Stored(dir, "amneziawg-go", true), make([]byte, 1200), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := binstore.Write(dir, "amneziawg-go", "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	if f := s.awgFootprint(); f == nil || f.Form != "compressed" || f.FlashBytes != 1200 || f.RAMBytes != 0 {
		t.Fatalf("a compressed store not yet unpacked: %+v", f)
	}
	if err := os.WriteFile(filepath.Join(runDir, "amneziawg-go"), make([]byte, 3400), 0o755); err != nil {
		t.Fatal(err)
	}
	if f := s.awgFootprint(); f == nil || f.RAMBytes != 3400 {
		t.Fatalf("the unpacked copy in RAM: %+v", f)
	}
}

func TestParseVmRSS(t *testing.T) {
	status := "Name:\tamneziawg-go\nVmPeak:\t  900000 kB\nVmRSS:\t   12345 kB\nThreads:\t8\n"
	if got := parseVmRSS(bufio.NewScanner(strings.NewReader(status))); got != 12345<<10 {
		t.Errorf("VmRSS = %d", got)
	}
	if got := parseVmRSS(bufio.NewScanner(strings.NewReader("Name:\tx\n"))); got != 0 {
		t.Errorf("no VmRSS = %d", got)
	}
}

// "The kernel carries it" holds only while no connection runs on amneziawg-go and the router's own
// AmneziaWG is already the newest generation: a generation-2 module cannot carry 3.x settings.
func TestAWGCarriedByKernel(t *testing.T) {
	newest := awgComponentStatus{Builtin: "3.1", Newest: "3.1"}
	if !awgCarriedByKernel(true, newest) {
		t.Error("a 3.1 kernel carrying every connection was not reported")
	}
	if awgCarriedByKernel(true, awgComponentStatus{Builtin: "2", Newest: "3.1"}) {
		t.Error("a generation-2 module was reported as carrying AmneziaWG with nothing to install")
	}
	needed := newest
	needed.Needed = true
	if awgCarriedByKernel(true, needed) {
		t.Error("a kernel next to a connection on amneziawg-go was reported as carrying it")
	}
	if awgCarriedByKernel(false, newest) {
		t.Error("a router without the module was reported as carrying it")
	}
}

// The engine list carries the block on the AmneziaWG row and nowhere else, built from the saved
// profile: an AmneziaWG 3 connection the kernel module cannot carry makes the component needed.
func TestUpdaterEnginesCarryTheAWGBlock(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s := updaterinstall_serverWithUpdater(t, "amd64")
	s.platformOf = func() platform.Platform { return platform.Unknown }
	s.awgProbeOf = func() awg.Probe { return awg.Probe{Kernel: awg.Gen2, TUN: true} }
	if err := s.store.UpsertEndpoint(awg3Endpoint("g3")); err != nil {
		t.Fatal(err)
	}
	w := updaterinstall_get(s.handleUpdaterEngines)
	var resp struct {
		Engines []struct {
			ID       string              `json:"id"`
			Provides string              `json:"provides"`
			Carried  bool                `json:"carried_by_kernel"`
			AWG      *awgComponentStatus `json:"awg"`
		} `json:"engines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	seen := false
	for _, e := range resp.Engines {
		if e.Provides != "amneziawg" {
			if e.AWG != nil {
				t.Errorf("%s carries an AmneziaWG block", e.ID)
			}
			continue
		}
		seen = true
		if e.AWG == nil || !e.AWG.Needed || e.Carried || len(e.AWG.Connections) != 1 || e.AWG.Connections[0].Path != "userspace" {
			t.Errorf("the AmneziaWG row: carried %v, block %+v", e.Carried, e.AWG)
		}
	}
	if !seen {
		t.Fatal("no AmneziaWG engine in the list")
	}
}
