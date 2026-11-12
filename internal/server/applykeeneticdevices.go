package server

import (
	"fmt"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// keeneticKernelDevices maps each endpoint a KeeneticOS native plan has NDM create to the kernel device
// that carries it. NDM names the interface WireguardN and the kernel calls it nwgN; the wr_* name pbr
// derives from the endpoint id is a device only WayHop's own AmneziaWG engine creates. Everything
// that names the tunnel to the kernel needs the device: the kernel policy plane routes by it (`ip
// route add default dev <device> table N`; seeded with the derived name its table stays empty and
// the marked list falls through to the main table), the health monitor pings through it and reads
// its counters, and the compatibility core binds its outbound to it.
//
// Only NDM-created endpoints are listed. An adopted endpoint already carries its captured kernel link
// in params["interface"], and an engine-plugin endpoint runs on exactly the wr_* device pbr derives, so
// for both pbr's own answer is the device. Any other plan yields nil: OpenWrt names its native
// interfaces wr_* on purpose, the same name pbr derives.
//
// Read from the native plan, never from the router: Apply compiles that plan from the captured facts
// it authenticates, so the device cannot drift from what was reviewed, and boot replays the same one.
func keeneticKernelDevices(plan *nativeplan.Plan) (map[string]string, error) {
	if plan == nil || plan.Platform != platform.Keenetic {
		return nil, nil
	}
	var devices map[string]string
	for _, decision := range plan.Decisions {
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
		default:
			continue
		}
		device := keeneticKernelName(decision.Interface)
		if device == "" {
			return nil, fmt.Errorf("endpoint %q: NDM interface %q has no kernel device name", decision.EndpointID, decision.Interface)
		}
		if devices == nil {
			devices = make(map[string]string)
		}
		devices[decision.EndpointID] = device
	}
	return devices, nil
}

// appliedKernelDevices is keeneticKernelDevices for the native plan the router runs now: the open Test
// window's, else the committed one. nil when no native plan is applied and on OpenWrt, which leaves
// every device as pbr derives it. A recorded plan that cannot name a device names none: Apply refuses
// to materialize such a plan, so only a damaged record can hold one.
func (s *Server) appliedKernelDevices() map[string]string {
	base := s.appliedBaseline()
	if base == nil {
		return nil
	}
	devices, err := keeneticKernelDevices(base.Materialization.nativeTarget())
	if err != nil {
		return nil
	}
	return devices
}

// kernelDeviceOf is the device a single endpoint's traffic leaves through on this router now: the
// same answer kernelIfaceByEndpoint gives for it.
func (s *Server) kernelDeviceOf(e *model.Endpoint) string {
	return pbr.KernelDevice(e, s.appliedKernelDevices())
}
