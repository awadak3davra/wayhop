package netvpn

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

func nativeModelEndpoint() model.Endpoint {
	return model.Endpoint{
		ID: "ep-native-model", Name: "native", Enabled: true,
		Protocol: model.ProtoAmneziaWG, Engine: model.EngineAmneziaWG,
		Server: "198.51.100.7", Port: 51820, PersistentKeepalive: 25,
		Params: map[string]any{
			"private_key": "private", "peer_public_key": "public",
			"local_address": []string{"10.7.0.2/32"},
			"allowed_ips":   []string{"0.0.0.0/0", "::/0"},
			"jc":            5, "h1": "1-2", "i1": "0x01010101",
		},
	}
}

func TestInterfaceFromEndpointSurvivesStoredJSONShape(t *testing.T) {
	fresh := nativeModelEndpoint()
	var stored model.Endpoint
	data, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	name := InterfaceName(fresh)
	want, err := InterfaceFromEndpoint(fresh, name, ProtoAmneziaWG)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InterfaceFromEndpoint(stored, name, ProtoAmneziaWG)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored conversion drifted\n got: %#v\nwant: %#v", got, want)
	}
	if got.Peers[0].EndpointHost != fresh.Server || got.Peers[0].EndpointPort != fresh.Port {
		t.Fatalf("flat peer endpoint was lost: %#v", got.Peers[0])
	}
}

func TestInterfaceFromEndpointFailsClosedOnNonNativeExtension(t *testing.T) {
	endpoint := nativeModelEndpoint()
	endpoint.Params["reserved"] = []any{1.0, 2.0, 3.0}
	if _, err := InterfaceFromEndpoint(endpoint, InterfaceName(endpoint), ProtoWireGuard); err == nil {
		t.Fatal("WARP client extension was silently written as native WireGuard")
	}
}

func TestProtoForModelIsNativeWireGuardFamilyOnly(t *testing.T) {
	for _, test := range []struct {
		protocol model.Protocol
		want     Proto
		ok       bool
	}{
		{model.ProtoWireGuard, ProtoWireGuard, true},
		{model.ProtoAmneziaWG, ProtoAmneziaWG, true},
		{model.ProtoVLESS, "", false},
		{model.ProtoAnyTLS, "", false},
	} {
		got, ok := ProtoForModel(test.protocol)
		if got != test.want || ok != test.ok {
			t.Errorf("ProtoForModel(%q) = %q,%v; want %q,%v", test.protocol, got, ok, test.want, test.ok)
		}
	}
}

// AWGGeneration is what the UCI writer writes, not a label: every setting of that generation or older
// reaches the interface, and every newer one is refused by name rather than left out.
func TestAWGGenerationIsWhatTheWriterWrites(t *testing.T) {
	for _, key := range awg.Settings() {
		value := any("7")
		if key == "random_trailers" || key == "disable_cookies" {
			value = "on"
		}
		e := nativeModelEndpoint()
		e.Params[key] = value
		got, err := InterfaceFromEndpoint(e, InterfaceName(e), ProtoAmneziaWG)
		need := awg.Need(map[string]any{key: value})
		if need <= AWGGeneration {
			if err != nil {
				t.Errorf("%s (generation %v) was refused: %v", key, need, err)
			} else if got.Obfuscation[key] != "7" {
				t.Errorf("%s (generation %v) was not written: %v", key, need, got.Obfuscation)
			}
		} else if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s (generation %v) was not refused by name: %v", key, need, err)
		}
	}
}
