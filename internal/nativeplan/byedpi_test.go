package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func byedpiEndpoint(protocol model.Protocol) model.Endpoint {
	return model.Endpoint{ID: "bye", Name: "ByeDPI", Enabled: true, Engine: model.EngineByeDPI, Protocol: protocol}
}

// withCapabilities is facts with ids added to its usable capabilities.
func withCapabilities(facts HostFacts, ids ...string) HostFacts {
	items := make(map[string]platform.Capability, len(facts.Capabilities.Items)+len(ids))
	for id, c := range facts.Capabilities.Items {
		items[id] = c
	}
	for id, c := range usableCapabilities(ids...).Items {
		items[id] = c
	}
	facts.Capabilities = platform.CapabilitySet{Items: items}
	return facts
}

// QA-043: a ByeDPI connection made the OpenWrt planner refuse the whole profile ("not a supported
// addon"), so every native tunnel went to the generic path. It is core-carried - a SOCKS outbound to
// the ciadpi the plugin manager runs - and the native tunnel beside it stays the router's own. Its
// stored protocol means nothing to it, so a native-family value does not send it to the writer.
func TestCompileOpenWrtCarriesByeDPIOnTheCore(t *testing.T) {
	for _, protocol := range []model.Protocol{model.ProtoSOCKS, "", model.ProtoWireGuard} {
		awgEndpoint := managedAWG()
		facts := withCapabilities(openWrtFacts(awgEndpoint),
			platform.CapEngineSingbox, platform.CapProtocolPrefix+string(model.ProtoSOCKS))
		plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{awgEndpoint, byedpiEndpoint(protocol)}}, facts)
		if err != nil {
			t.Fatalf("protocol %q: %v", protocol, err)
		}
		decisions := map[string]EndpointDecision{}
		for _, d := range plan.Decisions {
			decisions[d.EndpointID] = d
		}
		bye := decisions["bye"]
		if bye.Path != PathCompatibility || bye.Interface != "" || bye.Protocol != protocol ||
			bye.Capability != platform.CapProtocolPrefix+string(model.ProtoSOCKS) {
			t.Errorf("protocol %q: ByeDPI decision %+v", protocol, bye)
		}
		if decisions[awgEndpoint.ID].Path != PathNativeCreate || len(plan.OpenWrt) != 1 {
			t.Errorf("protocol %q: the AmneziaWG tunnel left the native writer: %+v", protocol, plan.Decisions)
		}
	}
}

// What the save gate asks of a ByeDPI connection is what the planner asks: the core and its SOCKS client.
func TestCompileOpenWrtByeDPINeedsTheCoreAndItsSOCKSClient(t *testing.T) {
	for name, ids := range map[string][]string{
		"no core":         {platform.CapProtocolPrefix + string(model.ProtoSOCKS)},
		"no SOCKS client": {platform.CapEngineSingbox},
	} {
		facts := withCapabilities(openWrtFacts(managedAWG()), ids...)
		_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{byedpiEndpoint(model.ProtoSOCKS)}}, facts)
		if err == nil || !strings.Contains(err.Error(), `"bye"`) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

// KeeneticOS runs no ciadpi and its core has no route to one, so the planner refuses a ByeDPI
// connection by name, saying so, rather than as an unsupported add-on.
func TestCompileKeeneticRefusesByeDPIByName(t *testing.T) {
	awgEndpoint := managedAWG()
	facts := withCapabilities(keeneticFacts(awgEndpoint),
		platform.CapEngineSingbox, platform.CapProtocolPrefix+string(model.ProtoSOCKS))
	for _, protocol := range []model.Protocol{model.ProtoSOCKS, model.ProtoWireGuard} {
		plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{awgEndpoint, byedpiEndpoint(protocol)}}, facts)
		if err == nil || !strings.Contains(err.Error(), ByeDPIOnKeenetic) || !strings.Contains(err.Error(), `"bye"`) ||
			strings.Contains(err.Error(), "supported addon") {
			t.Errorf("protocol %q: plan %+v, err %v", protocol, plan, err)
		}
	}
	disabled := byedpiEndpoint(model.ProtoSOCKS)
	disabled.Enabled = false
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{awgEndpoint, disabled}}, facts); err != nil {
		t.Errorf("a disabled ByeDPI connection is not the planner's: %v", err)
	}
}
