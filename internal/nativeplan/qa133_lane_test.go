package nativeplan

import (
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// QA-133: the save check asks UserspaceLane of one endpoint, and it must be Compile's own answer - the
// lane Compile turns into PathEnginePlugin, on every release, and nothing where NDM creates it.
func TestQA133UserspaceLaneIsCompilesDecision(t *testing.T) {
	awg2 := awg1Endpoint()
	awg2.Params["s3"], awg2.Params["s4"] = 15, 25
	for _, release := range []string{"4.01.C.7.0-0", "5.00.C.6.0-0", "5.01.A.2.0-0"} {
		set := keeneticReleaseSet(release)
		for _, ep := range []model.Endpoint{awg1Endpoint(), awg2} {
			_, inLane := UserspaceLane(ep, platform.Keenetic, set, awg.GenNone)
			onPlugin := compileKeeneticFor(t, ep, set).Decisions[0].Path == PathEnginePlugin
			if inLane != onPlugin {
				t.Errorf("%s %v: lane %v, Compile on the plugin %v", release, ep.Params["s3"], inLane, onPlugin)
			}
		}
	}
	if _, inLane := UserspaceLane(awg1Endpoint(), platform.Keenetic, keeneticReleaseSet("4.01.C.7.0-0"), awg.GenNone); !inLane {
		t.Fatal("KeeneticOS 4.1: an AmneziaWG endpoint is not in the lane")
	}
	if _, inLane := UserspaceLane(awg1Endpoint(), platform.Keenetic, keeneticReleaseSet("5.01.A.2.0-0"), awg.GenNone); inLane {
		t.Fatal("KeeneticOS 5.1: an AmneziaWG 1 endpoint is in the lane")
	}
}
