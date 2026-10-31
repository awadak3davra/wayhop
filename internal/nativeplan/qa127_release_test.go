package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// QA-127. The capability set a KeeneticOS release produces decides where an AmneziaWG endpoint runs.
// Release strings are invented; only their shape is the firmware's.
func keeneticReleaseSet(release string) platform.CapabilitySet {
	caps := platform.Capabilities{Platform: string(platform.Keenetic), FirmwareRelease: release,
		Native: map[string]bool{"wireguard": true, "amneziawg": true}, Installable: map[string]string{}}
	ops := map[string]bool{}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, op := range []platform.NativeOperation{platform.NativeAdopt, platform.NativeCreate, platform.NativeRemove} {
			ops[platform.NativeOperationCapabilityID(protocol, op)] = true
		}
	}
	return platform.Evaluate(caps, platform.RuntimeFacts{NativeOperations: ops})
}

func awg1Endpoint() model.Endpoint {
	ep := managedAWG()
	for k, v := range map[string]any{"jc": 4, "jmin": 10, "jmax": 50, "s1": 20, "s2": 30, "h1": 1, "h2": 2, "h3": 3, "h4": 4} {
		ep.Params[k] = v
	}
	return ep
}

func compileKeeneticFor(t *testing.T, ep model.Endpoint, set platform.CapabilitySet) *Plan {
	t.Helper()
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{ep}}, HostFacts{
		Platform: platform.Keenetic, Capabilities: set, OccupiedInterfaces: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func ascLines(plan *Plan) []string {
	var out []string
	for _, block := range plan.Keenetic.Interfaces {
		for _, line := range block {
			if strings.HasPrefix(line, "wireguard asc ") {
				out = append(out, line)
			}
		}
	}
	return out
}

// The hunt's repro, with the release the platform now reads: an AmneziaWG 1 endpoint on KeeneticOS
// 4.1 was planned as an NDM create with a `wireguard asc` line, which that firmware has no command for.
func TestQA127Keenetic41AWGRunsOnTheEngine(t *testing.T) {
	plan := compileKeeneticFor(t, awg1Endpoint(), keeneticReleaseSet("4.01.C.7.0-0"))
	if got := plan.Decisions[0].Path; got != PathEnginePlugin {
		t.Fatalf("path = %s, want %s", got, PathEnginePlugin)
	}
	if lines := ascLines(plan); len(lines) != 0 {
		t.Fatalf("KeeneticOS 4.1 plan writes %q", lines)
	}
	lane := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{awg1Endpoint()}}, keeneticReleaseSet("4.01.C.7.0-0"))
	u := lane["ep-awg"]
	if u.Code != platform.ReasonPlatformUnsupported || !strings.Contains(u.Reason, "4.2") || !strings.Contains(u.Remedy, "4.2") {
		t.Fatalf("lane = %+v, want the firmware named with its remedy", u)
	}
}

// One generation up: KeeneticOS 4.2 to 5.0 takes the nine AmneziaWG 1 arguments and not the
// AmneziaWG 2 ones, which keenetic.WireguardCommands writes as the 16-argument form.
func TestQA127KeeneticBefore51CapsAWG2(t *testing.T) {
	ep := awg1Endpoint()
	ep.Params["s3"], ep.Params["s4"] = 15, 25
	ep.Params["i1"] = "<r 12>"

	plan := compileKeeneticFor(t, ep, keeneticReleaseSet("5.00.C.6.0-0"))
	if got := plan.Decisions[0].Path; got != PathEnginePlugin || len(ascLines(plan)) != 0 {
		t.Fatalf("AmneziaWG 2 endpoint on KeeneticOS 5.0: path %s, asc %q; want the engine and no asc", got, ascLines(plan))
	}
	u := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{ep}}, keeneticReleaseSet("5.00.C.6.0-0"))["ep-awg"]
	if u.Code != platform.ReasonPlatformUnsupported || !strings.Contains(u.Remedy, "5.1") {
		t.Fatalf("lane = %+v, want the 5.1 remedy", u)
	}
	// An AmneziaWG 1 endpoint on the same release stays on NDM with the nine arguments.
	plan = compileKeeneticFor(t, awg1Endpoint(), keeneticReleaseSet("5.00.C.6.0-0"))
	if got := plan.Decisions[0].Path; got != PathNativeCreate {
		t.Fatalf("AmneziaWG 1 endpoint on KeeneticOS 5.0: path %s, want %s", got, PathNativeCreate)
	}
	if lines := ascLines(plan); len(lines) != 1 || len(strings.Fields(lines[0])) != 2+9 {
		t.Fatalf("asc = %q, want the nine-argument form", lines)
	}
}

// Routers that never hit the trigger keep the plan they had: a release from 5.1 on, or one the
// probe could not read, writes the 16-argument form on NDM as before.
func TestQA127KeeneticNewOrUnknownReleaseUnchanged(t *testing.T) {
	ep := awg1Endpoint()
	ep.Params["s3"], ep.Params["s4"] = 15, 25
	for _, release := range []string{"5.03.C.0.0-0", ""} {
		plan := compileKeeneticFor(t, ep, keeneticReleaseSet(release))
		if got := plan.Decisions[0].Path; got != PathNativeCreate {
			t.Fatalf("release %q: path %s, want %s", release, got, PathNativeCreate)
		}
		if lines := ascLines(plan); len(lines) != 1 || !strings.Contains(lines[0], " 15 25") {
			t.Fatalf("release %q: asc = %q, want S3/S4 written", release, lines)
		}
	}
}

// A connection set to run on amneziawg-go by hand, on a release where Automatic would put it there
// as well: the way back to Automatic is no way to the router's own AmneziaWG, so the lane gives
// Automatic's reason and remedy - the firmware update - with the choice undone after it. Where
// Automatic would keep it native, the lane keeps the operator's-choice words.
func TestQA127ChosenEngineWhereAutomaticMovesToo(t *testing.T) {
	awg2 := awg1Endpoint()
	awg2.Params["s3"], awg2.Params["s4"] = 15, 25
	for _, c := range []struct {
		name, release, firmware string
		ep                      model.Endpoint
	}{
		{"AmneziaWG 1 before 4.2", "4.01.C.7.0-0", "4.2", awg1Endpoint()},
		{"AmneziaWG 2 on 5.0", "5.00.C.6.0-0", "5.1", awg2},
	} {
		chosen := c.ep
		chosen.AWGUserspace = true
		set := keeneticReleaseSet(c.release)
		u, ok := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{chosen}}, set)["ep-awg"]
		if !ok || u.Code != platform.ReasonOperatorChoice ||
			!strings.Contains(u.Reason, "set to run on amneziawg-go") || !strings.Contains(u.Reason, "Automatic would run it too") ||
			!strings.Contains(u.Reason, c.firmware) {
			t.Errorf("%s: lane = %+v (in lane: %v), want the choice with Automatic's reason", c.name, u, ok)
		}
		if !strings.HasPrefix(u.Remedy, "Update KeeneticOS to "+c.firmware) || !strings.HasSuffix(u.Remedy, "set the connection's engine back to Automatic.") ||
			strings.Contains(u.Remedy, "KeeneticOS's own AmneziaWG") {
			t.Errorf("%s: remedy = %q, want the firmware update and then Automatic", c.name, u.Remedy)
		}
		if got := compileKeeneticFor(t, chosen, set).Decisions[0].Path; got != PathEnginePlugin {
			t.Errorf("%s: path = %s, want %s", c.name, got, PathEnginePlugin)
		}
	}

	// AmneziaWG 1 on 5.0: Automatic keeps it on NDM, so going back to Automatic is the remedy.
	chosen := awg1Endpoint()
	chosen.AWGUserspace = true
	u := KeeneticUserspace(&model.Profile{Endpoints: []model.Endpoint{chosen}}, keeneticReleaseSet("5.00.C.6.0-0"))["ep-awg"]
	if u.Code != platform.ReasonOperatorChoice || strings.Contains(u.Reason, "Automatic would") ||
		u.Remedy != "Set the connection's engine back to Automatic to run it on KeeneticOS's own AmneziaWG." {
		t.Errorf("AmneziaWG 1 on 5.0: lane = %+v, want the operator's choice and Automatic as the way back", u)
	}
}
