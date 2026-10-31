package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// QA-128. The hunt's repro, through the production fold: OpenWrt in fast mode with offload auto and no
// device list, and the IPv4 WAN down while Apply captures the host, so `ip -o -4 route show default`
// prints nothing. The offload-device probe failure used to join ProbeErrors, every native operation
// became unknown, and materialize silently moved the reviewed native plan to the generic path, the
// previous native interface left in UCI under the name the plugin then took.
func TestQA128OffloadDeviceProbeStaysWithOffload(t *testing.T) {
	desired0, _, capture := executionNativeTestTuple(t)
	cfg := desired0.Config
	cfg.RoutingMode = "fast"
	cfg.Offload = "auto"
	cfg.OffloadDevices = nil
	profile := desired0.Profile
	profile.RoutingLists = []model.RoutingList{{ID: "l1", Name: "L", Manual: []string{"203.0.113.0/24"}, Outbound: "ep-native", Enabled: true}}
	desired, err := newDesiredSnapshot(cfg, profile, 8)
	if err != nil {
		t.Fatal(err)
	}
	kp, _, err := pbr.Compile(&desired.Profile, pbr.Options{})
	if err != nil || kp == nil {
		t.Fatalf("setup: kernel plan: %v", err)
	}
	base := hostTestProbe(desired)
	base.RawCapabilities.Native["amneziawg"] = true
	delete(base.RawCapabilities.Installable, "amneziawg")
	base.RawCapabilities.NetifdProtos["amneziawg"] = true
	hostOK, err := newHostSnapshot(desired, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	nft, ip := executionTestKernelTools()
	prev, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: hostOK, KernelNFT: nft, KernelIP: ip},
		native: &capture, kernelPlan: kp})
	if err != nil || prev.Native == nil {
		t.Fatalf("setup: previous native materialize: err=%v native=%v", err, prev.Native != nil)
	}

	// WAN down: `ip -o -4 route show default` prints nothing.
	io := inertApplyHostIO()
	io.runCommand = func(context.Context, string, ...string) (string, error) { return "", nil }
	io.readDir = func(string) ([]os.DirEntry, error) { return []os.DirEntry{}, nil }
	_, deviceProbeErrors := probeAutoOffloadDevicesWithIO(context.Background(), io)
	if len(deviceProbeErrors) == 0 {
		t.Fatal("setup: device probe reported no error")
	}
	wanDown := cloneHostTestProbe(base)
	wanDown.OffloadDevices = nil
	wanDown = foldOffloadDeviceProbe(wanDown, deviceProbeErrors) // as probeHostSnapshot does
	hostDown, err := newHostSnapshot(desired, wanDown, nil)
	if err != nil {
		t.Fatal(err)
	}

	if hostDown.ProbeError != "" {
		t.Errorf("an offload-device observation poisons the capability set: probe_error=%q", hostDown.ProbeError)
	}
	for _, op := range []platform.NativeOperation{platform.NativeCreate, platform.NativeUpdate, platform.NativeRemove} {
		id := platform.NativeOperationCapabilityID(string(model.ProtoAmneziaWG), op)
		if got, want := hostDown.CapabilitySet.Get(id).State, hostOK.CapabilitySet.Get(id).State; got != want {
			t.Errorf("%s: %s with the WAN down, %s with it up", id, got, want)
		}
	}
	// Offload answers for it: off for this Apply, with the reason, and no flowtable.
	if hostDown.ResolvedOffload != "off" || len(hostDown.OffloadDevices) != 0 ||
		!strings.Contains(hostDown.OffloadReason, applyHostDefaultRouteAbsent) {
		t.Errorf("offload = %q devices %v reason %q, want off with the device probe named",
			hostDown.ResolvedOffload, hostDown.OffloadDevices, hostDown.OffloadReason)
	}
	if !strings.Contains(strings.Join(hostDown.OffloadState.Reasons, "\n"), applyHostDefaultRouteAbsent) {
		t.Errorf("offload_state reasons %q do not name the device probe", hostDown.OffloadState.Reasons)
	}
	opts, warning := kernelOffloadForHost(pbr.Options{Offload: "hw", OffloadDevices: []string{"br-lan"}}, hostDown)
	if opts.Offload != "" || opts.OffloadDevices != nil || warning == "" {
		t.Errorf("kernel options %+v warning %q, want no flowtable and a warning", opts, warning)
	}
	if opts, warning := kernelOffloadForHost(pbr.Options{Offload: "hw", OffloadDevices: []string{"br-lan"}}, hostOK); opts.Offload != "hw" || warning != "" {
		t.Errorf("a capture that resolved hw changed the kernel options: %+v %q", opts, warning)
	}

	m, warnings, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: hostDown, KernelNFT: nft, KernelIP: ip},
		native: &capture, previous: &prev, kernelPlan: kp})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if m.Native == nil || strings.Contains(strings.Join(warnings, "\n"), "router-native tunnels are not used") {
		t.Fatalf("the reviewed native plan was dropped with the WAN down: native=%v warnings=%q", m.Native != nil, warnings)
	}
	for _, p := range m.Plugins {
		if p.ID == "ep-native" {
			t.Fatalf("ep-native moved to the plugin on %q", pbr.KernelIface(&p.Endpoint))
		}
	}
}

// A canceled capture is no offload fact: it still poisons the set.
func TestQA128CanceledDeviceProbeStillPoisons(t *testing.T) {
	desired, _, _ := executionNativeTestTuple(t)
	probe := foldOffloadDeviceProbe(hostTestProbe(desired), []string{applyHostProbeCanceledError})
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(host.ProbeError, applyHostProbeCanceledError) || host.ResolvedOffload != "off" {
		t.Fatalf("probe_error %q offload %q, want the cancel kept and offload off", host.ProbeError, host.ResolvedOffload)
	}
}

// A device probe that answered leaves the probe as it was.
func TestQA128AnsweredDeviceProbeUnchanged(t *testing.T) {
	desired, _, _ := executionNativeTestTuple(t)
	before := hostTestProbe(desired)
	after := foldOffloadDeviceProbe(cloneHostTestProbe(before), nil)
	if after.ResolvedOffload != before.ResolvedOffload || after.OffloadReason != before.OffloadReason ||
		strings.Join(after.OffloadDevices, ",") != strings.Join(before.OffloadDevices, ",") || len(after.ProbeErrors) != 0 {
		t.Fatalf("fold changed an answered probe: %+v", after)
	}
}
