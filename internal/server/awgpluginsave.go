package server

import (
	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
)

// awgpluginsave.go is the save check's half of WayHop's AmneziaWG engine (QA-133). Where the router's
// own AmneziaWG cannot create a connection - KeeneticOS before 4.2 has no `wireguard asc` (QA-127) -
// the planner runs it on the engine plugin, and a save asking only for the native operations refused
// a connection the next Apply would have run. Each answer here is one the rest of the daemon acts on:
// the lane is nativeplan's (what Compile decides), and the engine's path is plugin.AWGDecision (what the
// plugin runs).

// enginePluginLane is nativeplan.UserspaceLane for e on this router: whether Compile runs it on WayHop's
// AmneziaWG engine, and why, asked with the kernel module generation the Apply compiles with (as the
// review asks it). Only a connection of WayHop's own AmneziaWG can be in the lane, so no other asks the
// host for that generation. The demo never takes the native plan, so nothing there is in the lane.
func (s *Server) enginePluginLane(e model.Endpoint, set platform.CapabilitySet) (nativeplan.UserspaceEndpoint, bool) {
	if s.config().Demo || e.Engine != model.EngineAmneziaWG {
		return nativeplan.UserspaceEndpoint{}, false
	}
	return nativeplan.UserspaceLane(e, s.detectedPlatform(), set, s.awgKernelGeneration())
}

// awgPluginCannotRun says why WayHop's AmneziaWG engine could not run e on this router, or "" when it
// can: the path the plugin would take (plugin.AWGDecision - amneziawg-go needs /dev/net/tun, and
// KeeneticOS's module is the firmware's). amneziawg-go not yet installed is no refusal: the Apply review
// asks for it (endpoint.engine.amneziawg_go), and the Components page installs it.
func (s *Server) awgPluginCannotRun(e model.Endpoint) string {
	firmwareOwned := s.detectedPlatform() == platform.Keenetic && !s.config().Demo
	if decision := plugin.AWGDecision(s.awgHostProbe(), firmwareOwned, e); decision.Path == awg.PathUnavailable {
		return decision.Reason
	}
	return ""
}

// enginePluginOffer is the save check's answer for a new connection of one protocol that the router's
// own cannot create but the planner hands to WayHop's AmneziaWG engine - what the connection form says
// under its protocol selector.
type enginePluginOffer struct {
	// Carried: a save of it switched on is accepted, and the engine runs it.
	Carried bool `json:"carried"`
	// Reason is why the router's own does not run it, and Remedy what would let it (the lane's words).
	Reason string `json:"reason"`
	Remedy string `json:"remedy,omitempty"`
	// Installed: amneziawg-go is on the router now. Carried without it, the Components page installs it.
	Installed bool `json:"installed"`
	// Blocked is why the engine cannot run it here either, when Carried is false.
	Blocked string `json:"blocked,omitempty"`
}

// enginePluginOffers answers, against set, for a new AmneziaWG connection with the engine on
// Automatic - what the form creates and a pasted config is. Empty where the router's own takes it or
// the planner keeps no lane (the demo). Asked only on KeeneticOS: /api/native/capabilities asks on
// every request, and on OpenWrt the answer is always empty - with no settings beyond the module and
// the engine on Automatic, OpenWrtUserspaceFor keeps such a connection on the router's own, and without
// a native AmneziaWG out of the lane - while the lane would probe the kernel module (which may load it).
func (s *Server) enginePluginOffers(set platform.CapabilitySet) map[string]enginePluginOffer {
	if s.detectedPlatform() != platform.Keenetic || s.config().Demo {
		return nil
	}
	e := model.Endpoint{ID: "new-amneziawg", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Enabled: true}
	lane, onPlugin := s.enginePluginLane(e, set)
	if !onPlugin {
		return nil
	}
	requirements, err := endpointCapabilityRequirements(e)
	if err != nil {
		return nil
	}
	code, _ := s.gateCapabilities(e, requirements, set)
	offer := enginePluginOffer{Carried: code == 0, Reason: lane.Reason, Remedy: lane.Remedy,
		Installed: s.awgUserspaceInstalled()}
	if !offer.Carried {
		offer.Blocked = s.awgPluginCannotRun(e)
	}
	return map[string]enginePluginOffer{string(model.ProtoAmneziaWG): offer}
}
