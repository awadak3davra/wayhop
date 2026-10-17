package nativeplan

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

var testHPK = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

// gen30AWG is an AmneziaWG 3.0 connection whose values the module would take: a real header
// protection key and paddings that hold its nonce.
func gen30AWG() model.Endpoint {
	e := managedAWG()
	for _, s := range []string{"s1", "s2", "s3", "s4"} {
		e.Params[s] = 16
	}
	e.Params["header_protection_key"] = testHPK
	e.Params["rekey_timeout"] = "5-10"
	return e
}

// gen31AWG adds a 3.1 switch that is on.
func gen31AWG() model.Endpoint {
	e := gen30AWG()
	e.Params["random_trailers"] = true
	return e
}

func gen2AWG() model.Endpoint {
	e := managedAWG()
	e.Params["s3"] = 20
	e.Params["h1"] = "100-200"
	e.Params["random_trailers"] = false
	return e
}

// Where each connection runs on OpenWrt, per kernel module generation: on the router's own interface
// when the module carries every setting it has (as awg.Decide judges the module), on WayHop's engine
// when it does not - and on the engine whatever the module when the operator chose amneziawg-go. The
// lane set the review explains by and the plan the planner compiles agree on every row.
func TestOpenWrtLanePerKernelGeneration(t *testing.T) {
	chosen31 := gen31AWG()
	chosen31.AWGUserspace = true
	endpoints := map[string]model.Endpoint{"1": managedAWG(), "2": gen2AWG(), "3.0": gen30AWG(), "3.1": gen31AWG(), "chosen": chosen31}
	native, engine := PathNativeCreate, PathEnginePlugin
	for _, row := range []struct {
		kernel awg.Generation
		want   map[string]Path
	}{
		{awg.GenNone, map[string]Path{"1": native, "2": native, "3.0": engine, "3.1": engine, "chosen": engine}},
		{awg.Gen1, map[string]Path{"1": native, "2": native, "3.0": engine, "3.1": engine, "chosen": engine}},
		{awg.Gen2, map[string]Path{"1": native, "2": native, "3.0": engine, "3.1": engine, "chosen": engine}},
		{awg.Gen30, map[string]Path{"1": native, "2": native, "3.0": native, "3.1": engine, "chosen": engine}},
		{awg.Gen31, map[string]Path{"1": native, "2": native, "3.0": native, "3.1": native, "chosen": engine}},
	} {
		for name, endpoint := range endpoints {
			facts := openWrtFacts(endpoint)
			facts.AWGKernel = row.kernel
			profile := &model.Profile{Endpoints: []model.Endpoint{endpoint}}
			plan, err := Compile(profile, facts)
			if err != nil {
				t.Errorf("module %v, connection %s: %v", row.kernel, name, err)
				continue
			}
			if got := plan.Decisions[0].Path; got != row.want[name] {
				t.Errorf("module %v, connection %s: %s, want %s", row.kernel, name, got, row.want[name])
			}
			_, inLane := UserspaceFor(profile, platform.OpenWrt, facts.Capabilities, row.kernel)[endpoint.ID]
			if inLane != (row.want[name] == engine) {
				t.Errorf("module %v, connection %s: the review's lane says %v, the plan %s", row.kernel, name, inLane, row.want[name])
			}
			// The kernel module decides as the plugin's own path choice does, for an automatic connection.
			if !endpoint.AWGUserspace && row.kernel >= awg.Gen30 {
				kernelPath := awg.Decide(row.kernel, true, awg.Need(endpoint.Params)).Path == awg.PathKernel
				if kernelPath != (row.want[name] == native) {
					t.Errorf("module %v, connection %s: awg.Decide says kernel=%v, the plan %s", row.kernel, name, kernelPath, row.want[name])
				}
			}
		}
	}
}

// KeeneticOS stays at generation 2 whatever the module: NDM's writer has no 3.x option.
func TestKeeneticIgnoresTheKernelGeneration(t *testing.T) {
	endpoint := gen31AWG()
	facts := keeneticFacts(endpoint)
	facts.AWGKernel = awg.Gen31
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Decisions[0].Path != PathEnginePlugin {
		t.Errorf("KeeneticOS took a 3.1 connection natively: %+v", plan.Decisions[0])
	}
	if _, ok := UserspaceFor(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, platform.Keenetic, facts.Capabilities, awg.Gen31)[endpoint.ID]; !ok {
		t.Error("the KeeneticOS lane let a 3.1 connection go native")
	}
	if NativeAWGGenerationFor(platform.Keenetic, awg.Gen31) != keenetic.AWGGeneration {
		t.Error("the KeeneticOS writer's generation followed the module")
	}
}

func TestNativeAWGGenerationFor(t *testing.T) {
	for _, kernel := range []awg.Generation{awg.GenNone, awg.Gen1, awg.Gen2, awg.Gen30, awg.Gen31} {
		if got := NativeAWGGenerationFor(platform.OpenWrt, kernel); got != netvpn.AWGWriterGeneration(kernel) {
			t.Errorf("OpenWrt with module %v: %v", kernel, got)
		}
		if got := NativeAWGGenerationFor(platform.Platform("linux"), kernel); got != awg.GenNone {
			t.Errorf("a platform with no writer reports %v", got)
		}
	}
	if NativeAWGGeneration(platform.OpenWrt) != awg.Gen2 || !reflect.DeepEqual(BeyondNative(gen31AWG(), platform.OpenWrt),
		BeyondNativeFor(gen31AWG(), platform.OpenWrt, awg.GenNone)) {
		t.Error("the kernel-less forms are not the baseline")
	}
}

// With a 3.1 module the plan writes the 3.x options; the same profile with no module known keeps the
// generation-2 writer and the engine.
func TestCompileOpenWrtWritesAWG31Natively(t *testing.T) {
	endpoint := gen31AWG()
	facts := openWrtFacts(endpoint)
	facts.AWGKernel = awg.Gen31
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.OpenWrt) != 1 || len(plan.OpenWrtBindings) != 0 {
		t.Fatalf("UCI plans %d, bindings %d", len(plan.OpenWrt), len(plan.OpenWrtBindings))
	}
	cmds := strings.Join(plan.OpenWrt[0].Commands, "\n")
	iface := util.AWGIface(endpoint.ID)
	for _, want := range []string{
		"uci set network." + iface + ".awg_header_protection_key='" + testHPK + "'",
		"uci set network." + iface + ".awg_rekey_timeout='5-10'",
		"uci set network." + iface + ".awg_random_trailers='1'",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("plan is missing %s:\n%s", want, cmds)
		}
	}
	if strings.Contains(cmds, "disable_cookies") {
		t.Errorf("a switch the connection does not set was written:\n%s", cmds)
	}
}

// A generation-2 connection compiles to the same native plan with any module: the upgrade changes
// nothing that runs.
func TestCompileGeneration2IsUnchangedByTheModule(t *testing.T) {
	endpoint := gen2AWG()
	var base *Plan
	for _, kernel := range []awg.Generation{awg.GenNone, awg.Gen2, awg.Gen30, awg.Gen31} {
		facts := openWrtFacts(endpoint)
		facts.AWGKernel = kernel
		plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
		if err != nil {
			t.Fatalf("module %v: %v", kernel, err)
		}
		if base == nil {
			base = plan
		} else if !reflect.DeepEqual(plan, base) {
			t.Errorf("module %v changed the plan:\n%+v\nwas\n%+v", kernel, plan.OpenWrt, base.OpenWrt)
		}
	}
}

// The module upgrade under a running 3.1 connection. The last Apply ran it on WayHop's engine (the
// module was generation 2); the upgraded module carries it, so the planner would move it to the
// router's own interface - on the same device name, which one Apply cannot do. The refusal names the
// upgrade and the way round it, and the way round it works: an Apply without the connection unbinds
// the engine's device, and the next one creates the native interface with every 3.1 option.
func TestOpenWrtModuleUpgradeMovesAConnectionInTwoApplies(t *testing.T) {
	endpoint := gen31AWG()
	profile := &model.Profile{Endpoints: []model.Endpoint{endpoint}}
	device := util.AWGIface(endpoint.ID)

	before := openWrtFacts(endpoint)
	before.AWGKernel = awg.Gen2
	previous, err := Compile(profile, before)
	if err != nil || previous.Decisions[0].Path != PathEnginePlugin {
		t.Fatalf("on generation 2: %+v, %v", previous, err)
	}
	pluginDevices := func(p *Plan) map[string]string {
		out := map[string]string{}
		for _, d := range p.Decisions {
			if d.Path == PathEnginePlugin {
				out[d.EndpointID] = d.Interface
			}
		}
		return out
	}

	upgraded := openWrtFacts(endpoint)
	upgraded.AWGKernel = awg.Gen31
	upgraded.PluginDevices = pluginDevices(previous)
	_, err = Compile(profile, upgraded)
	var move *MoveError
	if !errors.As(err, &move) || !move.ToNative || move.Device != device {
		t.Fatalf("the upgrade moved a running connection in one Apply: %v", err)
	}
	for _, want := range []string{
		"from WayHop's userspace AmneziaWG to OpenWrt's own AmneziaWG",
		"kernel module is generation 3.1, so OpenWrt's own AmneziaWG now carries its AmneziaWG 3.1 settings",
		"switch the connection off and apply, then switch it on and apply again",
	} {
		if !strings.Contains(move.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, move)
		}
	}
	// The review would see the same move: the lane no longer holds the connection.
	if _, inLane := UserspaceFor(profile, platform.OpenWrt, upgraded.Capabilities, awg.Gen31)[endpoint.ID]; inLane {
		t.Error("the review's lane still holds a connection the planner moves")
	}

	// First Apply: the connection switched off. Nothing native is created; the engine's device leaves
	// the zone it was bound into.
	off := endpoint
	off.Enabled = false
	offProfile := &model.Profile{Endpoints: []model.Endpoint{off}}
	target, err := Compile(offProfile, upgraded)
	if err != nil {
		t.Fatalf("switched off: %v", err)
	}
	listed := upgraded.FirewallUCI + "firewall.@zone[0].device='" + device + "'\n"
	rec, err := Reconcile(previous, target, upgraded.Capabilities, upgraded.NetworkUCI, listed)
	if err != nil || len(rec.OpenWrtUnbindings) != 1 || rec.OpenWrtUnbindings[0].Device != device {
		t.Fatalf("switched off: reconcile %+v, %v", rec, err)
	}

	// Second Apply: switched on again, with no engine device left behind - native, with the 3.1 options.
	again := openWrtFacts(endpoint)
	again.AWGKernel = awg.Gen31
	again.PluginDevices = pluginDevices(target)
	final, err := Compile(profile, again)
	if err != nil || final.Decisions[0].Path != PathNativeCreate || len(final.OpenWrt) != 1 {
		t.Fatalf("switched on: %+v, %v", final, err)
	}
	if !strings.Contains(strings.Join(final.OpenWrt[0].Commands, "\n"), ".awg_random_trailers='1'") {
		t.Errorf("the native interface lost a 3.1 option:\n%s", strings.Join(final.OpenWrt[0].Commands, "\n"))
	}
	if _, err := Reconcile(target, final, again.Capabilities, again.NetworkUCI, again.FirewallUCI); err != nil {
		t.Errorf("switched on: reconcile %v", err)
	}
}

// The other way: a module that falls back below what a native 3.1 interface needs (a reinstall, a
// sysupgrade that left the old kmod) moves the connection to the engine, refused within one Apply.
func TestOpenWrtModuleDowngradeMovesAConnectionInTwoApplies(t *testing.T) {
	endpoint := gen31AWG()
	device := util.AWGIface(endpoint.ID)
	facts := openWrtFacts(endpoint)
	facts.AWGKernel = awg.Gen2
	facts.NetworkUCI = "network." + device + "=interface\nnetwork." + device + ".proto='amneziawg'\n"
	facts.OwnedInterfaces = map[string]string{endpoint.ID: device}
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	var move *MoveError
	if !errors.As(err, &move) || move.ToNative || move.Why != "" {
		t.Errorf("downgrade: %v", err)
	}
}

// OpenWrtMoveReason names the module only when the module is what moves the connection.
func TestOpenWrtMoveReason(t *testing.T) {
	chosen := gen31AWG()
	chosen.AWGUserspace = true
	wireguard := gen31AWG()
	wireguard.Protocol = model.ProtoWireGuard
	for _, c := range []struct {
		name     string
		endpoint model.Endpoint
		kernel   awg.Generation
		want     string
	}{
		{"3.1 on a 3.1 module", gen31AWG(), awg.Gen31, "generation 3.1, so OpenWrt's own AmneziaWG now carries its AmneziaWG 3.1 settings"},
		{"3.0 on a 3.1 module", gen30AWG(), awg.Gen31, "generation 3.1, so OpenWrt's own AmneziaWG now carries its AmneziaWG 3.0 settings"},
		{"3.1 on a 3.0 module", gen31AWG(), awg.Gen30, ""},
		{"generation 2 (set back to Automatic)", gen2AWG(), awg.Gen31, ""},
		{"chosen amneziawg-go", chosen, awg.Gen31, ""},
		{"WireGuard", wireguard, awg.Gen31, ""},
	} {
		got := OpenWrtMoveReason(c.endpoint, c.kernel)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The lane's words for a module too old say which module, which settings, and what to install - and
// that moving the connection over afterwards takes two Applies.
func TestOpenWrtLaneSaysWhatTheModuleLacks(t *testing.T) {
	profile := &model.Profile{Endpoints: []model.Endpoint{gen31AWG()}}
	caps := openWrtFacts(gen31AWG()).Capabilities
	u := OpenWrtUserspaceFor(profile, caps, awg.Gen2)[gen31AWG().ID]
	if !strings.Contains(u.Reason, "OpenWrt's own AmneziaWG cannot carry") ||
		!strings.Contains(u.Reason, "(header_protection_key, random_trailers, rekey_timeout)") ||
		!strings.Contains(u.Reason, "kernel module is generation 2") || u.Code != platform.ReasonMissingKernelModule ||
		!strings.Contains(u.Remedy, "Install AmneziaWG 3.1 or newer for OpenWrt (kmod-amneziawg with amneziawg-tools)") ||
		!strings.Contains(u.Remedy, "two Applies") {
		t.Errorf("generation-2 module: %+v", u)
	}
	u = OpenWrtUserspaceFor(profile, caps, awg.Gen30)[gen31AWG().ID]
	if !strings.Contains(u.Reason, "(random_trailers)") || !strings.Contains(u.Reason, "generation 3.0") {
		t.Errorf("3.0 module: %+v", u)
	}
	if u := OpenWrtUserspace(profile, caps)[gen31AWG().ID]; !strings.Contains(u.Reason, "no AmneziaWG kernel module of generation 3.0 or newer is known") {
		t.Errorf("no module known: %+v", u)
	}

	chosen := gen31AWG()
	chosen.AWGUserspace = true
	chosenProfile := &model.Profile{Endpoints: []model.Endpoint{chosen}}
	if u := OpenWrtUserspaceFor(chosenProfile, caps, awg.Gen31)[chosen.ID]; !strings.Contains(u.Reason, "which is generation 3.1 too") ||
		strings.Contains(u.Reason, "the newest") {
		t.Errorf("chosen over a 3.1 module: %+v", u)
	}
	if u := OpenWrtUserspaceFor(chosenProfile, caps, awg.Gen2)[chosen.ID]; !strings.Contains(u.Reason, "the newest AmneziaWG") {
		t.Errorf("chosen over a generation-2 module: %+v", u)
	}
}

// A value the module would refuse fails the native plan by name rather than being written for netifd
// to fail on. On OpenWrt an automatic AmneziaWG connection's refusal hands the profile to the generic
// path, as every other native refusal does.
func TestCompileOpenWrtRefusesAnAWG3ValueTheModuleWouldRefuse(t *testing.T) {
	endpoint := gen30AWG()
	endpoint.Params["s4"] = 8
	facts := openWrtFacts(endpoint)
	facts.AWGKernel = awg.Gen31
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	var move *MoveError
	if err == nil || errors.As(err, &move) || !strings.Contains(err.Error(), "S4 is 8") {
		t.Errorf("error = %v, want the padding named", err)
	}
}
