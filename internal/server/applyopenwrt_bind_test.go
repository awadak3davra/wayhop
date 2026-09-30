package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

// firewallSim is a uci firewall with a staging buffer: add_list/del_list stage, show reflects the
// buffer, commit keeps it, revert drops it - the property netvpn's plans rest on.
type firewallSim struct {
	names   []string
	devices map[int][]string
	staged  []string
	calls   []string
}

func newFirewallSim(names ...string) *firewallSim {
	return &firewallSim{names: names, devices: map[int][]string{}}
}

func (f *firewallSim) apply(ops []string) map[int][]string {
	out := map[int][]string{}
	for i, d := range f.devices {
		out[i] = append([]string(nil), d...)
	}
	for _, op := range ops {
		var add bool
		var rest string
		switch {
		case strings.HasPrefix(op, "uci add_list firewall.@zone["):
			add, rest = true, strings.TrimPrefix(op, "uci add_list firewall.@zone[")
		case strings.HasPrefix(op, "uci del_list firewall.@zone["):
			rest = strings.TrimPrefix(op, "uci del_list firewall.@zone[")
		default:
			continue
		}
		var zone int
		var dev string
		if _, err := fmt.Sscanf(rest, "%d].device=", &zone); err != nil {
			continue
		}
		dev = strings.Trim(rest[strings.Index(rest, "=")+1:], "'")
		if add {
			out[zone] = append(out[zone], dev)
			continue
		}
		kept := out[zone][:0]
		for _, d := range out[zone] {
			if d != dev {
				kept = append(kept, d)
			}
		}
		out[zone] = kept
	}
	return out
}

func (f *firewallSim) show() string {
	var b strings.Builder
	devices := f.apply(f.staged)
	for i, name := range f.names {
		fmt.Fprintf(&b, "firewall.@zone[%d]=zone\nfirewall.@zone[%d].name='%s'\n", i, i, name)
		if len(devices[i]) != 0 {
			fmt.Fprintf(&b, "firewall.@zone[%d].device='%s'\n", i, strings.Join(devices[i], "' '"))
		}
	}
	return b.String()
}

func (f *firewallSim) Run(_ context.Context, _ string, _ string, args ...string) (string, error) {
	cmd := args[len(args)-1]
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "uci changes firewall":
		return strings.Join(f.staged, "\n"), nil
	case cmd == "uci show firewall":
		return f.show(), nil
	case strings.HasPrefix(cmd, "uci add_list firewall."), strings.HasPrefix(cmd, "uci del_list firewall."):
		f.staged = append(f.staged, cmd)
	case cmd == "uci commit firewall":
		f.devices, f.staged = f.apply(f.staged), nil
	case cmd == "uci revert firewall":
		f.staged = nil
	}
	return "", nil
}

func (f *firewallSim) count(cmd string) int {
	n := 0
	for _, c := range f.calls {
		if c == cmd {
			n++
		}
	}
	return n
}

func enginePluginTarget(t *testing.T, fw *firewallSim, device string) nativeplan.Plan {
	t.Helper()
	binding, err := netvpn.BuildDeviceBinding(device, "vpn", fw.show())
	if err != nil {
		t.Fatal(err)
	}
	return nativeplan.Plan{
		Platform: platform.OpenWrt,
		Decisions: []nativeplan.EndpointDecision{{
			EndpointID: "e", Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathEnginePlugin, Interface: device,
		}},
		OpenWrtBindings: []netvpn.DeviceBinding{binding},
	}
}

// Prepare puts the engine's device into the reviewed zone and commits the firewall; a replay of the
// same plan writes nothing; the commit of a later Apply without the endpoint takes it back out.
func TestExactOpenWrtAdapterBindsAndUnbindsEngineDevices(t *testing.T) {
	fw := newFirewallSim("lan", "wan", "vpn")
	adapter, err := newExactOpenWrtNativeAdapter(fw)
	if err != nil {
		t.Fatal(err)
	}
	target := enginePluginTarget(t, fw, "wr_e")
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if got := fw.devices[2]; len(got) != 1 || got[0] != "wr_e" || fw.count("/etc/init.d/firewall reload") != 1 {
		t.Fatalf("vpn zone devices %v, reloads %d", got, fw.count("/etc/init.d/firewall reload"))
	}
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if got := fw.devices[2]; len(got) != 1 || fw.count("uci add_list firewall.@zone[2].device='wr_e'") != 1 {
		t.Fatalf("replay listed the device again: %v", got)
	}

	empty := nativeplan.Plan{Platform: platform.OpenWrt}
	reconcile := nativeplan.Reconciliation{Platform: platform.OpenWrt, Target: &empty,
		OpenWrtUnbindings: []netvpn.DeviceUnbinding{netvpn.BuildDeviceUnbinding("wr_e", fw.show())}}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := fw.devices[2]; len(got) != 0 {
		t.Fatalf("the retired device is still in the zone: %v", got)
	}

	forged := reconcile
	forged.OpenWrtUnbindings = []netvpn.DeviceUnbinding{{Device: "wr_e", Zones: []netvpn.Zone{{Ref: "@zone[2]", Name: "vpn"}},
		Commands: []string{"uci -q delete network.wr_e"}, Commit: []string{"uci commit firewall"}}}
	if err := adapter.commit(context.Background(), forged); err == nil {
		t.Error("an unbinding that touches /etc/config/network was executed")
	}
}

// Every engine-plugin decision has exactly the binding of its device, and a binding is firewall-only.
func TestValidateExactOpenWrtTargetHoldsEnginePluginsToBindings(t *testing.T) {
	fw := newFirewallSim("lan", "wan", "vpn")
	valid := enginePluginTarget(t, fw, "wr_e")
	if err := validateExactOpenWrtTarget(valid); err != nil {
		t.Fatalf("a valid engine-plugin target was refused: %v", err)
	}
	cases := map[string]func(p *nativeplan.Plan){
		"a decision without its binding": func(p *nativeplan.Plan) { p.OpenWrtBindings = nil },
		"a binding without its decision": func(p *nativeplan.Plan) { p.Decisions = nil },
		"the binding of another device":  func(p *nativeplan.Plan) { p.Decisions[0].Interface = "wr_other" },
		"a binding that writes network": func(p *nativeplan.Plan) {
			p.OpenWrtBindings[0].Commands = []string{"uci set network.wr_e=interface"}
		},
		"a binding without the firewall commit": func(p *nativeplan.Plan) { p.OpenWrtBindings[0].Commit = nil },
	}
	for name, mutate := range cases {
		p := enginePluginTarget(t, fw, "wr_e")
		mutate(&p)
		if err := validateExactOpenWrtTarget(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
