package server

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// The health monitor probes a native tunnel with `ping -I <device>` and reads its traffic from
// /sys/class/net/<device>, so the binding it is given must be a kernel device. NDM's WireguardN is
// not one: a tunnel NDM created could never probe alive, and list failover never elected it.
func TestCurrentNativeInterfaceBindingsNameTheKernelDevice(t *testing.T) {
	s := bindTestServer(t, model.Profile{}, "")
	s.applyState.loaded = true
	withAppliedNativeTarget(s, keeneticDevicesTarget())
	bindings, known := s.currentNativeInterfaceBindings()
	want := map[string]string{"ndm": "nwg10", "engine": util.AWGIface("engine"), "adopted": "nwg3", "proxy": "wrtun0"}
	if !known || !reflect.DeepEqual(bindings, want) {
		t.Fatalf("bindings = %v (known %v), want %v", bindings, known, want)
	}
	// A record that cannot name a device is no authority: the monitor keeps its own fallback rather
	// than probing through NDM's name.
	damaged := keeneticDevicesTarget()
	damaged.Decisions[0].Interface = "Proxy0"
	withAppliedNativeTarget(s, damaged)
	if bindings, known := s.currentNativeInterfaceBindings(); known {
		t.Errorf("a damaged record was authoritative: %v", bindings)
	}
}

// In compatibility routing sing-box carries the whole policy and reaches each native tunnel with a
// direct outbound bound to it. bind_interface takes the kernel's name: bound to NDM's WireguardN the
// outbound has no device to leave through.
func TestKeeneticCompatibilityCoreBindsTheDeviceNDMCreated(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	desired.Profile.Rules = []model.Rule{{ID: "all", Default: true, Outbound: "gen3"}}
	m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	target := m.Native.Delta.Reconcile.Target
	if !target.Keenetic.CompatibilityRouting || m.Core.Action != ExecutionEnsurePresent {
		t.Fatalf("compatibility routing %v, core %v", target.Keenetic.CompatibilityRouting, m.Core.Action)
	}
	created := nativeDecision(t, target, "native")
	device := keeneticKernelName(created.Interface)
	if created.Path != nativeplan.PathNativeCreate || device == "" {
		t.Fatalf("fixture: the NDM endpoint is %+v", created)
	}
	config := string(m.Core.Config)
	if !strings.Contains(config, `"bind_interface": "`+device+`"`) {
		t.Errorf("the core does not reach the NDM tunnel through %s:\n%s", device, config)
	}
	if strings.Contains(config, `"bind_interface": "`+created.Interface+`"`) {
		t.Errorf("the core binds NDM's name %s, which is no device:\n%s", created.Interface, config)
	}
}

// The binding rewrites a natively created endpoint as an external interface for the core. Its
// interface is the device: NDM's tunnel is nwgN, OpenWrt's is the wr_* name it was created under, and
// an NDM name with no kernel device is refused rather than bound as written.
func TestApplyNativeConnectionBindingsUseTheKernelDevice(t *testing.T) {
	bind := func(p platform.Platform, iface string) (model.Endpoint, error) {
		profile := model.Profile{Endpoints: []model.Endpoint{executionAWGEndpoint("ndm")}}
		plan := &nativeplan.Plan{Platform: p, Decisions: []nativeplan.EndpointDecision{
			{EndpointID: "ndm", Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathNativeCreate, Interface: iface},
		}}
		err := applyNativeConnectionBindings(&profile, plan)
		return profile.Endpoints[0], err
	}
	if e, err := bind(platform.Keenetic, "Wireguard10"); err != nil || e.Engine != model.EngineExternal ||
		e.Params["interface"] != "nwg10" {
		t.Errorf("Keenetic: %+v (%v), want an external endpoint on nwg10", e, err)
	}
	if e, err := bind(platform.OpenWrt, util.AWGIface("ndm")); err != nil || e.Params["interface"] != util.AWGIface("ndm") {
		t.Errorf("OpenWrt: %+v (%v), want its own %s", e, err, util.AWGIface("ndm"))
	}
	if e, err := bind(platform.Keenetic, "Proxy0"); err == nil {
		t.Errorf("an NDM name with no kernel device was bound: %+v", e)
	}
}
