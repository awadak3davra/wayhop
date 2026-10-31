package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// keeneticServicesTuple is a KeeneticOS router with the given connections and one group over members.
func keeneticServicesTuple(t *testing.T, endpoints []model.Endpoint, members []string) (DesiredSnapshot, HostSnapshotV1, executionNativeCaptureV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "mixed"
	cfg.Offload = "auto"
	cfg.Clash.Secret = "clash-secret"
	desired, err := newDesiredSnapshot(cfg, model.Profile{
		Endpoints: endpoints,
		Groups:    []model.Group{{ID: "auto", Name: "Auto", Type: model.GroupFallback, Members: members}},
	}, 9)
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
	return desired, host, executionNativeCaptureV1{
		OccupiedInterfaces: map[string]bool{},
		GlobalPriorities:   map[string]int{"ISP": 1000},
		KeeneticConfigRev:  strings.Repeat("a", 64),
	}
}

// keeneticVLESS is a connection only the core can run on KeeneticOS.
func keeneticVLESS(id string) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.40", Port: 443, Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}}
}

// probeRuleOrder is the outbound of each leading route rule that serves the probe inbound, in order.
func probeRuleOrder(t *testing.T, core []byte) []string {
	t.Helper()
	var cfg struct {
		Route struct {
			Rules []struct {
				Inbound  []string `json:"inbound"`
				AuthUser []string `json:"auth_user"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(core, &cfg); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range cfg.Route.Rules {
		if len(r.Inbound) != 1 || r.Inbound[0] != generator.ProbeInboundTag {
			break
		}
		if len(r.AuthUser) != 1 || r.AuthUser[0] != generator.ProbeUser(r.Outbound) {
			t.Errorf("probe rule %+v does not send its user to its own exit", r)
		}
		out = append(out, r.Outbound)
	}
	return out
}

// Both cores a KeeneticOS Apply can start carry the probe inbound, read back the way the check reads
// it. Neither did: every sing-box exit there read "Apply once" forever, and Apply changed nothing.
func TestKeeneticCoresCarryTheProbeInbound(t *testing.T) {
	for name, tc := range map[string]struct {
		members []string
		compat  bool
		exits   []string // probe users the core must have
	}{
		// NDM routes, the group included; the fallback core carries only what NDM cannot run.
		"fallback": {members: []string{"native"}, exits: []string{model.OutboundDirect, "nl"}},
		// A group over a core-only member moves the whole policy into the compatibility core, which
		// binds the native connection into itself and runs the group.
		"compatibility": {members: []string{"nl", "native"}, compat: true,
			exits: []string{model.OutboundDirect, "nl", "native", "auto"}},
	} {
		t.Run(name, func(t *testing.T) {
			desired, host, capture := keeneticServicesTuple(t,
				[]model.Endpoint{executionAWGEndpoint("native"), keeneticVLESS("nl")}, tc.members)
			m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
			if err != nil {
				t.Fatalf("materialize: %v", err)
			}
			target := m.Native.Delta.Reconcile.Target
			if target.Keenetic.CompatibilityRouting != tc.compat || m.Core.Action != ExecutionEnsurePresent {
				t.Fatalf("compatibility routing %v, core %v", target.Keenetic.CompatibilityRouting, m.Core.Action)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, m.Core.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			probe, ok := runningProbeInbound(path)
			if !ok || probe.port != desired.Config.Ports.Probe() {
				t.Fatalf("probe inbound read back = %+v %v, want port %d", probe, ok, desired.Config.Ports.Probe())
			}
			pw := generator.ProbePassword(desired.Config.Clash.Secret)
			for _, tag := range tc.exits {
				if probe.users[generator.ProbeUser(tag)] != pw {
					t.Errorf("no probe user for %s with the Clash-derived password: %v", tag, probe.users)
				}
			}
			// The probe rules lead, so no sniff, list or catch-all rule sees a probe first.
			if got := probeRuleOrder(t, m.Core.Config); len(got) != len(probe.users) {
				t.Errorf("leading probe rules %v, want one per user %v", got, probe.users)
			}
			if tc.compat && !strings.Contains(string(m.Core.Config), `"interface_name": "wrtun0"`) {
				t.Error("the compatibility TUN lost its wrtun0 binding")
			}
		})
	}
}

// Routing natively, KeeneticOS runs a tunnel as nwgN under the NDM name WireguardN and a group as
// routes to one member. The check read the first as "interface missing" (it looked for the derived
// wr_* name), an NDM WireGuard with no core as "Apply once", and the group as either.
func TestNetDiagServicesOnKeeneticNativeRouting(t *testing.T) {
	wg := model.Endpoint{ID: "wg", Name: "WG", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "198.51.100.41", Port: 51820, Params: executionAWGEndpoint("wg").Params}
	for name, tc := range map[string]struct {
		endpoints []model.Endpoint
		core      ExecutionActionV1
	}{
		"with the fallback core": {[]model.Endpoint{executionAWGEndpoint("native"), wg, keeneticVLESS("nl")}, ExecutionEnsurePresent},
		"native only, no core":   {[]model.Endpoint{executionAWGEndpoint("native"), wg}, ExecutionEnsureAbsent},
	} {
		t.Run(name, func(t *testing.T) {
			desired, host, capture := keeneticServicesTuple(t, tc.endpoints, []string{"native", "wg"})
			m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
			if err != nil {
				t.Fatalf("materialize: %v", err)
			}
			target := m.Native.Delta.Reconcile.Target
			if target.Keenetic.CompatibilityRouting || m.Core.Action != tc.core || target.Keenetic.GroupMember["auto"] != "native" {
				t.Fatalf("compatibility %v, core %v, group on %q", target.Keenetic.CompatibilityRouting, m.Core.Action, target.Keenetic.GroupMember["auto"])
			}
			links := map[string]string{}
			for _, d := range target.Decisions {
				if k := keeneticKernelName(d.Interface); k != "" {
					links[d.EndpointID] = k
				}
			}
			if links["native"] == "" || links["wg"] == "" {
				t.Fatalf("NDM interfaces %+v", target.Decisions)
			}

			s := &Server{cfg: config.Default()}
			st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
			if err != nil {
				t.Fatal(err)
			}
			s.store = st
			if err := s.store.Replace(desired.Profile); err != nil {
				t.Fatal(err)
			}
			s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r1", Materialization: m}}
			s.applyState.loaded = true
			origUp := ifaceUp
			t.Cleanup(func() { ifaceUp = origUp })
			ifaceUp = func(name string) bool { return name == links["native"] || name == links["wg"] }

			probe, haveProbe := probeInbound{}, false
			if len(m.Core.Config) != 0 {
				path := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(path, m.Core.Config, 0o600); err != nil {
					t.Fatal(err)
				}
				probe, haveProbe = runningProbeInbound(path)
			}
			ctx := context.Background()
			for tag, want := range map[string]string{"native": links["native"], "wg": links["wg"], "auto": links["native"]} {
				if c, via, iface, why := s.serviceClient(ctx, tag, probe, haveProbe, haveProbe); c == nil || via != "interface" || iface != want || why != "" {
					t.Errorf("%s = %v %q %q %q, want bound to %s", tag, c != nil, via, iface, why, want)
				}
			}
			if !haveProbe {
				return
			}
			c, via, _, why := s.serviceClient(ctx, "nl", probe, true, true)
			if c == nil || via != "core" || why != "" {
				t.Fatalf("fallback exit = %v %q %q, want the core's probe user", c != nil, via, why)
			}
			if proxy, _ := c.Transport.(*http.Transport).Proxy(&http.Request{}); proxy.User.Username() != generator.ProbeUser("nl") {
				t.Errorf("fallback exit asked as %q", proxy.User.Username())
			}
		})
	}
}

// A native-only Apply after a compatibility-core one stops the core but leaves its config, probe
// inbound and all, on disk. Asking through those users read "core not running" for the exits the
// router carries itself; with no core in the applied plan the check goes by their devices.
func TestNetDiagServicesIgnoresAStoppedCoresProbe(t *testing.T) {
	d1, h1, c1 := keeneticServicesTuple(t, []model.Endpoint{executionAWGEndpoint("native"), keeneticVLESS("nl")}, []string{"nl", "native"})
	m1, _, err := materialize(materializeInput{desired: d1, host: ExecutionHostFactsV1{Host: h1}, native: &c1})
	if err != nil {
		t.Fatal(err)
	}
	if !m1.Native.Delta.Reconcile.Target.Keenetic.CompatibilityRouting {
		t.Fatal("test setup: the first Apply must run the compatibility core")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, m1.Core.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	d2, h2, c2 := keeneticServicesTuple(t, []model.Endpoint{executionAWGEndpoint("native")}, []string{"native"})
	m2, _, err := materialize(materializeInput{desired: d2, host: ExecutionHostFactsV1{Host: h2}, native: &c2})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Core.Action != ExecutionEnsureAbsent {
		t.Fatalf("test setup: the second Apply must run no core, got %v", m2.Core.Action)
	}
	s := &Server{cfg: config.Default()}
	s.cfg.SingBox.Config = path // the stale file from the first Apply
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.store = st
	if err := s.store.Replace(d2.Profile); err != nil {
		t.Fatal(err)
	}
	s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r2", Materialization: m2}}
	s.applyState.loaded = true
	orig := ifaceUp
	t.Cleanup(func() { ifaceUp = orig })
	ifaceUp = func(string) bool { return true }

	probe, have := s.servicesProbe()
	if have {
		t.Errorf("a stopped core's probe inbound is still offered: %+v", probe)
	}
	for _, tag := range []string{"native", "auto"} {
		if c, via, iface, why := s.serviceClient(context.Background(), tag, probe, have, false); c == nil || via != "interface" {
			t.Errorf("%s = via %q iface %q why %q, want its own device", tag, via, iface, why)
		}
	}
}
