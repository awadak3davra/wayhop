package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

// keeneticKernelListTuple is a KeeneticOS fast-mode fixture with the ipset plane wired: one AmneziaWG
// endpoint NDM creates (interface WireguardN, kernel device nwgN), one AmneziaWG 3 endpoint WayHop's
// userspace engine runs (device wr_*), and an IP routing list to each.
func keeneticKernelListTuple(t *testing.T) (DesiredSnapshot, ExecutionHostFactsV1, executionNativeCaptureV1) {
	t.Helper()
	desired, _, capture := keeneticUserspaceTuple(t)
	cfg := desired.Config
	cfg.RoutingMode = "fast"
	profile := desired.Profile
	profile.RoutingLists = []model.RoutingList{
		{ID: "to-native", Name: "to-native", Enabled: true, Outbound: "native", Manual: []string{"203.0.113.0/24"}},
		{ID: "to-gen3", Name: "to-gen3", Enabled: true, Outbound: "gen3", Manual: []string{"192.0.2.0/24"}},
	}
	desired, err := newDesiredSnapshot(cfg, profile, 10)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Native = map[string]bool{"amneziawg": true, "wireguard": true}
	probe.RawCapabilities.NetifdProtos = nil
	probe.NativeOperations = keeneticProductionNativeOperations()
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := keeneticPBRTestTools()
	facts := ExecutionHostFactsV1{
		Host:        host,
		KernelIpset: tools.IpsetTool, KernelIptables: tools.IptablesTool, KernelIp6tables: tools.IP6Tool,
		KernelIP: tools.IPTool, KernelDnsmasq: tools.DnsmasqTool, KernelShell: tools.ShellTool,
		KernelWANIface: "eth3",
	}
	capture.ListsViaIpset = true
	return desired, facts, capture
}

// materializeKeeneticKernel runs the Apply's kernel step the way runApply does, with the options
// pbrCompileOptions gives KeeneticOS.
func materializeKeeneticKernel(t *testing.T, desired DesiredSnapshot, facts ExecutionHostFactsV1, capture executionNativeCaptureV1) executionMaterializationV1 {
	t.Helper()
	m, _, err := materialize(materializeInput{desired: desired, host: facts, native: &capture,
		kernelOptions: &pbr.Options{CollectDomainZones: true}})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return m
}

func nativeDecision(t *testing.T, plan *nativeplan.Plan, endpointID string) nativeplan.EndpointDecision {
	t.Helper()
	for _, decision := range plan.Decisions {
		if decision.EndpointID == endpointID {
			return decision
		}
	}
	t.Fatalf("no decision for %q in %+v", endpointID, plan.Decisions)
	return nativeplan.EndpointDecision{}
}

func kernelEgress(t *testing.T, plan *pbr.Plan, tag string) pbr.Egress {
	t.Helper()
	for _, egress := range plan.Egresses {
		if egress.Tag == tag {
			return egress
		}
	}
	t.Fatalf("no egress %q in %+v", tag, plan.Egresses)
	return pbr.Egress{}
}

// runApply hands materialize the kernel options in the modes that have a kernel plane; the plan is
// compiled there, after the native plan. Without them fast mode cannot even generate its core config.
func TestRunApplyHandsTheKernelOptionsToMaterialize(t *testing.T) {
	s, _ := applytest_server(t)
	s.cfg.RoutingMode = "fast"
	apply_seedVLESS(t, s)
	res, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if !res.Applied || s.committedRevision() == nil {
		t.Fatalf("result = %+v", res)
	}
}

// The ipset plane steers a marked list into its table, and the table's route names a DEVICE. For an
// endpoint NDM creates that device is NDM's nwgN, not the wr_* name WayHop derives for the devices it
// creates itself: `ip route add default dev wr_… table N 2>/dev/null || true` fails without a word, the
// table stays empty, and the marked traffic falls through to the main table - the provider - or into
// the blackhole under a kill switch. The userspace engine's device is wr_* and stays so.
func TestMaterializeKeeneticKernelPlaneRoutesThroughTheDeviceNDMCreated(t *testing.T) {
	desired, facts, capture := keeneticKernelListTuple(t)
	m := materializeKeeneticKernel(t, desired, facts, capture)
	if m.Native == nil || m.Kernel.Action != ExecutionEnsurePresent || m.Kernel.Ipset == nil || m.Kernel.Plan == nil {
		t.Fatalf("native %v, kernel %v, ipset %v", m.Native != nil, m.Kernel.Action, m.Kernel.Ipset != nil)
	}
	target := m.Native.Delta.Reconcile.Target
	created := nativeDecision(t, target, "native")
	device := keeneticKernelName(created.Interface)
	if created.Path != nativeplan.PathNativeCreate || device == "" {
		t.Fatalf("fixture: the NDM endpoint is %+v", created)
	}
	if got := kernelEgress(t, m.Kernel.Plan, "native").Iface; got != device {
		t.Errorf("list to the NDM-created endpoint egresses %q, want %q (NDM %s)", got, device, created.Interface)
	}
	script := string(m.Kernel.Ipset.Script)
	if !strings.Contains(script, "ip route add default dev "+device+" table ") {
		t.Errorf("the plane never seeds a route through %s:\n%s", device, script)
	}
	if strings.Contains(script, util.AWGIface("native")) {
		t.Errorf("the plane names %s, a device nothing creates on KeeneticOS:\n%s", util.AWGIface("native"), script)
	}
	if plugin := nativeDecision(t, target, "gen3"); plugin.Path != nativeplan.PathEnginePlugin ||
		kernelEgress(t, m.Kernel.Plan, "gen3").Iface != util.AWGIface("gen3") {
		t.Errorf("the userspace endpoint lost its wr_ device: decision %+v, egress %+v", plugin, kernelEgress(t, m.Kernel.Plan, "gen3"))
	}
}
