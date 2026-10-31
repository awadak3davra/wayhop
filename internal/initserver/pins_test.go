package initserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// Invented pins: the hashes of two made-up byte strings, in the forms the installer prints.
var (
	pinTestCert = func() string { s := sha256.Sum256([]byte("invented certificate")); return hex.EncodeToString(s[:]) }()
	pinTestKey  = func() string {
		s := sha256.Sum256([]byte("invented public key"))
		return base64.StdEncoding.EncodeToString(s[:])
	}()
)

// pinnedLinks are the five links as the TLS fragments print them with both pins computed.
func pinnedLinks(cert string) map[string]string {
	vm := `{"v":"2","ps":"wayhop-vmess","add":"203.0.113.9","port":"8443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","type":"none","host":"wayhop.local","path":"/wayhop","tls":"tls","sni":"wayhop.local","allowInsecure":"1","pcs":"` + cert + `"}`
	return map[string]string{
		ProtoVMess:     "vmess://" + base64.StdEncoding.EncodeToString([]byte(vm)),
		ProtoTrojan:    "trojan://Pa%2Bss%2Fword%3D@203.0.113.9:8444?security=tls&sni=wayhop.local&insecure=1&pcs=" + cert + "&type=tcp#wayhop-trojan",
		ProtoHysteria2: "hysteria2://Pa%2Bss%2Fword%3D@203.0.113.9:8445?sni=wayhop.local&insecure=1&pinSHA256=" + cert + "&obfs=salamander&obfs-password=ob%2Bfs#wayhop-hy2",
		ProtoTUIC:      "tuic://11111111-2222-3333-4444-555555555555:Pa%2Bss%2Fword%3D@203.0.113.9:8446?sni=wayhop.local&insecure=1&pcs=" + cert + "&congestion_control=bbr&alpn=h3#wayhop-tuic",
		ProtoAnyTLS:    "anytls://Pa%2Bss%2Fword%3D@203.0.113.9:8447?sni=wayhop.local&insecure=1&pcs=" + cert + "#wayhop-anytls",
	}
}

// Every TLS fragment's output, both pins present, several configs in one transcript: each config
// keeps its link byte for byte and gets the public-key pin printed in its own section, and the
// imported connection ends up pinned by both, insecure kept for other clients, no may-be-a-CA mark.
func TestExtractTaggedAttachesPins(t *testing.T) {
	links := pinnedLinks(pinTestCert)
	order := []string{ProtoReality, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS}
	var b strings.Builder
	b.WriteString("[wayhop-init] public ip: 203.0.113.9\n")
	for _, id := range order {
		b.WriteString("WR_PROTO=" + id + "\n")
		link, tls := links[id]
		if !tls {
			link = sampleLink(id)
			if id == ProtoReality {
				link = "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=abcd&type=tcp#r"
			}
		} else {
			b.WriteString("  " + PubKeyPinMarker + pinTestKey + "  \n") // whitespace as a transcript may carry it
		}
		b.WriteString("WR_CLIENT_CONFIG=" + link + "\n")
	}
	tagged := ExtractTagged(b.String())
	if len(tagged) != len(order) {
		t.Fatalf("ExtractTagged returned %d configs, want %d", len(tagged), len(order))
	}
	for i, id := range order {
		tc := tagged[i]
		link, tls := links[id]
		if tc.Proto != id || len(tc.Dropped) != 0 {
			t.Errorf("%s: proto %q, dropped %v", id, tc.Proto, tc.Dropped)
		}
		if !tls {
			if tc.PubKeyPin != "" {
				t.Errorf("%s: got the public-key pin of another section: %q", id, tc.PubKeyPin)
			}
			continue
		}
		if tc.Config != link || tc.PubKeyPin != pinTestKey {
			t.Errorf("%s: config %q pin %q", id, tc.Config, tc.PubKeyPin)
		}
		ep, err := importer.Parse(tc.Config)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		notes := tc.ApplyPins(ep)
		if !reflect.DeepEqual(ep.TLS.PinCertSHA256, []string{pinTestCert}) || !reflect.DeepEqual(ep.TLS.PinPubKeySHA256, []string{pinTestKey}) {
			t.Errorf("%s: pins cert %v key %v", id, ep.TLS.PinCertSHA256, ep.TLS.PinPubKeySHA256)
		}
		if !ep.TLS.Insecure || ep.TLS.PinCertMayBeCA || len(ep.TLS.PinCertMayBeCAOf) != 0 {
			t.Errorf("%s: insecure %v, may-be-CA %v %v", id, ep.TLS.Insecure, ep.TLS.PinCertMayBeCA, ep.TLS.PinCertMayBeCAOf)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "public key from sing-box 1.13, the whole certificate from 1.15") {
			t.Errorf("%s: notes %q", id, notes)
		}
		if err := (&model.Profile{Endpoints: []model.Endpoint{*ep}}).Validate(); err != nil && strings.Contains(err.Error(), "pin") {
			t.Errorf("%s: the stored pins do not validate: %v", id, err)
		}
	}
}

// Output from an installer that printed no pins (an older WayHop, or an openssl that could not
// compute them) imports as before: the link unchanged, no pins, insecure on, and the console says so.
func TestExtractTaggedWithoutPins(t *testing.T) {
	for _, id := range []string{ProtoVMess, ProtoTrojan, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS} {
		link := sampleLink(id)
		tagged := ExtractTagged("WR_PROTO=" + id + "\nWR_CLIENT_CONFIG=" + link + "\n")
		if len(tagged) != 1 || tagged[0].Config != link || tagged[0].PubKeyPin != "" || tagged[0].Dropped != nil {
			t.Fatalf("%s: %+v", id, tagged)
		}
		ep, err := importer.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		notes := tagged[0].ApplyPins(ep)
		if model.HasPinIntent(ep) || !ep.TLS.Insecure {
			t.Errorf("%s: pins %v %v insecure %v", id, ep.TLS.PinCertSHA256, ep.TLS.PinPubKeySHA256, ep.TLS.Insecure)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "accepts any certificate") {
			t.Errorf("%s: notes %q", id, notes)
		}
	}
}

// A pin that is not a SHA-256 hash is left out, with a line saying so, and the setup goes on: the link
// still imports (the importer would refuse it whole), every other parameter as it came.
func TestExtractTaggedDropsMalformedPins(t *testing.T) {
	bad63 := pinTestCert[:63]
	for id, link := range pinnedLinks(bad63) {
		tagged := ExtractTagged("WR_PROTO=" + id + "\n" + PubKeyPinMarker + "not*base64!\nWR_CLIENT_CONFIG=" + link + "\n")
		if len(tagged) != 1 {
			t.Fatalf("%s: %d configs", id, len(tagged))
		}
		tc := tagged[0]
		if _, err := importer.Parse(link); err == nil {
			t.Fatalf("%s: the importer took a 63-digit pin; this test proves nothing", id)
		}
		if strings.Contains(tc.Config, bad63) || tc.PubKeyPin != "" || len(tc.Dropped) != 2 {
			t.Fatalf("%s: config %q pin %q dropped %q", id, tc.Config, tc.PubKeyPin, tc.Dropped)
		}
		ep, err := importer.Parse(tc.Config)
		if err != nil {
			t.Fatalf("%s: the link without its pin does not import: %v", id, err)
		}
		if model.HasPinIntent(ep) || !ep.TLS.Insecure || ep.Server != "203.0.113.9" {
			t.Errorf("%s: %+v", id, ep.TLS)
		}
		notes := tc.ApplyPins(ep)
		if len(notes) != 3 || !strings.Contains(notes[0], "certificate pin") || !strings.Contains(notes[1], "public-key pin") {
			t.Errorf("%s: notes %q", id, notes)
		}
		if id != ProtoVMess {
			if want := strings.Replace(link, map[bool]string{true: "&pinSHA256=", false: "&pcs="}[id == ProtoHysteria2]+bad63, "", 1); tc.Config != want {
				t.Errorf("%s: rewritten link\n got %q\nwant %q", id, tc.Config, want)
			}
		}
	}

	// VMess: the JSON loses "pcs" and keeps every other key and value.
	link := pinnedLinks("zz")[ProtoVMess]
	tc := ExtractTagged("WR_CLIENT_CONFIG=" + link)[0]
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tc.Config, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	_ = json.Unmarshal(raw, &got)
	orig, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	_ = json.Unmarshal(orig, &want)
	delete(want, "pcs")
	if tc.Proto != ProtoVMess || !reflect.DeepEqual(got, want) || len(tc.Dropped) != 1 {
		t.Errorf("vmess: proto %q json %v dropped %q", tc.Proto, got, tc.Dropped)
	}

	// The hash of empty input parses as a pin but names no certificate: left out of both places.
	for id, link := range pinnedLinks(emptySHA256Hex) {
		tc := ExtractTagged("WR_PROTO=" + id + "\n" + PubKeyPinMarker + emptySHA256B64 + "\nWR_CLIENT_CONFIG=" + link + "\n")[0]
		ep, err := importer.Parse(tc.Config)
		if err != nil || tc.PubKeyPin != "" || len(tc.Dropped) != 2 || !strings.Contains(tc.Dropped[1], "empty input") {
			t.Fatalf("%s: empty-input pins: err %v pin %q dropped %q", id, err, tc.PubKeyPin, tc.Dropped)
		}
		if tc.ApplyPins(ep); model.HasPinIntent(ep) {
			t.Errorf("%s: an empty-input pin reached the connection: %+v", id, ep.TLS)
		}
	}

	// A pin in hex is a SHA-256 hash too: stored in the public-key pin's form.
	tc = ExtractTagged("WR_PROTO=trojan\n" + PubKeyPinMarker + pinTestCert + "\nWR_CLIENT_CONFIG=" + sampleLink(ProtoTrojan))[0]
	if b, _ := hex.DecodeString(pinTestCert); tc.PubKeyPin != base64.StdEncoding.EncodeToString(b) || tc.Dropped != nil {
		t.Errorf("hex public-key pin: %q %q", tc.PubKeyPin, tc.Dropped)
	}
}

// The public-key pin belongs to the config after it in the same section: a WR_PROTO marker, or a
// config line that could not be read, discards one no config took, so it can never pin another
// protocol's server.
func TestExtractTaggedPubKeyPinStaysInItsSection(t *testing.T) {
	out := "WR_PROTO=trojan\n" + PubKeyPinMarker + pinTestKey + "\n" + // the trojan config never printed
		"WR_PROTO=hysteria2\nWR_CLIENT_CONFIG=" + sampleLink(ProtoHysteria2) + "\n" +
		PubKeyPinMarker + pinTestKey + "\nWR_CLIENT_CONFIG_B64=%%%\n" + // unreadable config
		"WR_CLIENT_CONFIG=" + sampleLink(ProtoTUIC) + "\n" +
		"WR_PROTO=anytls\n" + PubKeyPinMarker + pinTestKey + "\nWR_CLIENT_CONFIG=" + sampleLink(ProtoAnyTLS) + "\n" +
		"WR_CLIENT_CONFIG=" + sampleLink(ProtoTrojan) + "\n" // consumed: the next config takes nothing
	tagged := ExtractTagged(out)
	want := []struct{ proto, pin string }{{ProtoHysteria2, ""}, {ProtoTUIC, ""}, {ProtoAnyTLS, pinTestKey}, {ProtoTrojan, ""}}
	if len(tagged) != len(want) {
		t.Fatalf("got %d configs: %+v", len(tagged), tagged)
	}
	for i, w := range want {
		if tagged[i].Proto != w.proto || tagged[i].PubKeyPin != w.pin {
			t.Errorf("[%d] = %s %q, want %s %q", i, tagged[i].Proto, tagged[i].PubKeyPin, w.proto, w.pin)
		}
	}
}

// A public-key pin beside a config without TLS (or with Reality) has nothing to check; it is left
// out and said so, and the connection is untouched.
func TestApplyPinsNeedsTLS(t *testing.T) {
	for _, link := range []string{sampleLink(ProtoShadowsocks),
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab#r"} {
		ep, err := importer.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		notes := TaggedConfig{Config: link, PubKeyPin: pinTestKey}.ApplyPins(ep)
		if model.HasPinIntent(ep) || len(notes) != 1 || !strings.Contains(notes[0], "no TLS certificate") {
			t.Errorf("%s: notes %q tls %+v", link[:8], notes, ep.TLS)
		}
	}
	if notes := (TaggedConfig{Dropped: []string{"x"}}).ApplyPins(nil); len(notes) != 1 {
		t.Errorf("nil endpoint: %q", notes)
	}
}
