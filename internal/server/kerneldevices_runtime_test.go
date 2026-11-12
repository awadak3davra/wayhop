package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// keeneticDevicesTarget is an applied KeeneticOS native plan with one decision of every path: a tunnel
// NDM created (Wireguard10, kernel device nwg10), one WayHop's engine runs, an adopted router tunnel and
// a compatibility endpoint.
func keeneticDevicesTarget() *nativeplan.Plan {
	return &nativeplan.Plan{Platform: platform.Keenetic, Decisions: []nativeplan.EndpointDecision{
		{EndpointID: "ndm", Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathNativeCreate, Interface: "Wireguard10"},
		{EndpointID: "engine", Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathEnginePlugin, Interface: util.AWGIface("engine")},
		{EndpointID: "adopted", Protocol: model.ProtoWireGuard, Path: nativeplan.PathNativeAdopt, Interface: "nwg3"},
		{EndpointID: "proxy", Protocol: model.ProtoVLESS, Path: nativeplan.PathCompatibility, Interface: "wrtun0"},
	}}
}

// withAppliedNativeTarget records a committed Apply whose native plan is target.
func withAppliedNativeTarget(s *Server, target *nativeplan.Plan) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r1", At: 1,
		Materialization: executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1,
			Native: &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
				SchemaVersion: executionNativeDeltaSchemaV1,
				Reconcile:     nativeplan.Reconciliation{Target: target},
			}},
		},
	}}
	s.applyState.loaded = true
}

// Only the tunnels NDM creates get a device of NDM's naming; the engine's and the adopted ones are
// already what pbr derives, and nothing on OpenWrt is renamed.
func TestKeeneticKernelDevicesNamesWhatNDMCreated(t *testing.T) {
	got, err := keeneticKernelDevices(keeneticDevicesTarget())
	if err != nil || !reflect.DeepEqual(got, map[string]string{"ndm": "nwg10"}) {
		t.Fatalf("devices = %v (%v), want only ndm on nwg10", got, err)
	}
	if got, err := keeneticKernelDevices(nil); got != nil || err != nil {
		t.Errorf("no plan: %v %v", got, err)
	}
	openwrt := &nativeplan.Plan{Platform: platform.OpenWrt, Decisions: []nativeplan.EndpointDecision{
		{EndpointID: "ndm", Path: nativeplan.PathNativeCreate, Interface: util.AWGIface("ndm")},
	}}
	if got, err := keeneticKernelDevices(openwrt); got != nil || err != nil {
		t.Errorf("OpenWrt names its interfaces wr_* on purpose, yet got %v %v", got, err)
	}
	// An NDM interface the plane cannot name is refused rather than left to the derived device, which
	// is the empty table this exists to prevent.
	for _, name := range []string{"", "nwg10", "Wireguard", "Wireguard1a", "Proxy0"} {
		bad := keeneticDevicesTarget()
		bad.Decisions[0].Interface = name
		if got, err := keeneticKernelDevices(bad); err == nil {
			t.Errorf("NDM interface %q gave %v", name, got)
		}
	}
}

// The runtime answer comes from the plan the router runs: the committed one, or none.
func TestAppliedKernelDevicesFollowTheAppliedPlan(t *testing.T) {
	s := bindTestServer(t, model.Profile{}, "")
	s.applyState.loaded = true // nothing applied, and no record on disk to read
	if got := s.appliedKernelDevices(); got != nil {
		t.Fatalf("nothing applied, yet %v", got)
	}
	withAppliedNativeTarget(s, keeneticDevicesTarget())
	if got := s.appliedKernelDevices(); !reflect.DeepEqual(got, map[string]string{"ndm": "nwg10"}) {
		t.Errorf("applied Keenetic plan: %v", got)
	}
	damaged := keeneticDevicesTarget()
	damaged.Decisions[0].Interface = "Proxy0"
	withAppliedNativeTarget(s, damaged)
	if got := s.appliedKernelDevices(); got != nil {
		t.Errorf("a damaged record named %v", got)
	}
}

// fakeClash answers every delay probe with a measurement, so the monitor records the probed member
// alive through its own probe path.
func fakeClash(t *testing.T) *clash.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/delay") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"delay": 25}`))
	}))
	t.Cleanup(srv.Close)
	cl, err := clash.New(strings.TrimPrefix(srv.URL, "http://"), "")
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// The list failover loop repoints a group's table with `ip route replace default dev <device> table
// N`. For a member NDM created the device is nwg10; the derived wr_* name is a device that does not
// exist on KeeneticOS, and the kernel refuses the write.
func TestListFailoverElectsTheDeviceNDMCreated(t *testing.T) {
	profile := model.Profile{
		Endpoints: []model.Endpoint{executionAWGEndpoint("ndm"), adopted("adopted", "nwg3", true)},
		Groups: []model.Group{{ID: "grp", Name: "Main", Type: model.GroupFallback,
			Members: []string{"ndm", "adopted"}}},
		RoutingLists: []model.RoutingList{{ID: "l", Name: "L", Outbound: "grp", Enabled: true,
			Manual: []string{"203.0.113.0/24"}}},
	}
	s := bindTestServer(t, profile, "")
	s.applyState.loaded = true
	monitor := health.NewMonitor(fakeClash(t), s.store, nil, false)
	// Probed through the controller rather than `ping -I`, which a test host cannot run: the election
	// reads health, and health is what this sets.
	monitor.SetNativeInterfaceResolver(func() (map[string]string, bool) { return map[string]string{}, true })
	monitor.ProbeOne(context.Background(), "ndm")
	s.monitor = monitor

	// The loop elects over the applied kernel plan (supervisedKernelPlan); compiled here from the same
	// profile, with the derived devices, so only the member election is under test.
	plan, _, err := pbr.Compile(&profile, s.pbrCompileOptions(s.config()))
	if err != nil || plan == nil {
		t.Fatalf("kernel plan: %v", err)
	}
	elected := func() string {
		t.Helper()
		targets := s.listFailoverTargetsFrom(plan, &profile, map[int]string{})
		if len(targets) != 1 || targets[0].Group != "grp" {
			t.Fatalf("targets = %+v, want the group's table", targets)
		}
		return targets[0].Elected
	}
	// No native plan applied: the device is the derived one, as before (and as on OpenWrt).
	if got := elected(); got != util.AWGIface("ndm") {
		t.Fatalf("with no applied plan elected %q, want the derived %s", got, util.AWGIface("ndm"))
	}
	withAppliedNativeTarget(s, keeneticDevicesTarget())
	if got := elected(); got != "nwg10" {
		t.Errorf("elected %q, want nwg10, the device NDM created", got)
	}
}

// The component downloader binds its socket through the same answer: the chosen tunnel, or the group's
// healthy member, is NDM's device.
func TestUpdaterDownloadBindsTheDeviceNDMCreated(t *testing.T) {
	profile := model.Profile{Endpoints: []model.Endpoint{executionAWGEndpoint("ndm"), adopted("adopted", "nwg3", true)}}
	s := bindTestServer(t, profile, "ndm")
	s.applyState.loaded = true
	withAppliedNativeTarget(s, keeneticDevicesTarget())
	if got := s.updaterDownloadIface(); got != "nwg10" {
		t.Errorf("download bound to %q, want nwg10", got)
	}
	byID := map[string]downloadPath{}
	for _, p := range s.downloadPathChoices() {
		byID[p.ID] = p
	}
	if byID["ndm"].Iface != "nwg10" || byID["adopted"].Iface != "nwg3" {
		t.Errorf("download paths: %+v", byID)
	}

	grouped := profile
	grouped.Groups = []model.Group{{ID: "grp", Name: "Main", Type: model.GroupFallback, Members: []string{"ndm", "adopted"}}}
	g := bindTestServer(t, grouped, "grp")
	g.applyState.loaded = true
	withAppliedNativeTarget(g, keeneticDevicesTarget())
	monitor := health.NewMonitor(fakeClash(t), g.store, nil, false)
	monitor.SetNativeInterfaceResolver(func() (map[string]string, bool) { return map[string]string{}, true })
	monitor.ProbeOne(context.Background(), "ndm")
	g.monitor = monitor
	if got := g.updaterDownloadIface(); got != "nwg10" {
		t.Errorf("download through the group bound to %q, want nwg10", got)
	}
}

// Every production caller of kernelIfaceByEndpoint asks with the applied plan's devices. A caller
// passing nil compiles, runs, and on KeeneticOS names a device that does not exist - the lan-prefix
// filter has no behavioural seam to catch that, so the calls are pinned at the source. The profile
// argument is spelled per caller (a value or a pointer named profile or prof); the devices never are.
func TestKernelIfaceByEndpointCallersPassTheAppliedDevices(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`kernelIfaceByEndpoint\(&?(profile|prof), s\.appliedKernelDevices\(\)\)`)
	calls := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "func kernelIfaceByEndpoint(") ||
				!strings.Contains(line, "kernelIfaceByEndpoint(") {
				continue
			}
			calls++
			if !call.MatchString(line) {
				t.Errorf("%s: %s", file, trimmed)
			}
		}
	}
	// list failover x2 and its health card, downloader x2, lan prefixes, the DNS page, the DNS check x5,
	// the encrypted-DNS quick list and the Telegram bot's groups.
	if calls < 14 {
		t.Errorf("found %d production calls, want the fourteen known", calls)
	}
}
