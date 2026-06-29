package importer

import (
	"encoding/base64"
	"testing"

	"velinx/internal/model"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#Reality"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoVLESS || e.Engine != model.EngineSingBox {
		t.Fatalf("proto/engine = %s/%s", e.Protocol, e.Engine)
	}
	if e.Server != "203.0.113.10" || e.Port != 443 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Name != "Reality" {
		t.Fatalf("name = %q", e.Name)
	}
	if e.Params["uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("uuid = %v", e.Params["uuid"])
	}
	if e.Params["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow = %v", e.Params["flow"])
	}
	if e.TLS == nil || e.TLS.Type != "reality" || e.TLS.PublicKey != "PUBKEY" || e.TLS.ShortID != "ab12" {
		t.Fatalf("tls = %+v", e.TLS)
	}
	if e.TLS.SNI != "www.microsoft.com" || e.TLS.Fingerprint != "chrome" {
		t.Fatalf("tls sni/fp = %s/%s", e.TLS.SNI, e.TLS.Fingerprint)
	}
}

// TestParseGRPCServiceNameSpellings: a grpc link's service name is the gRPC path
// segment; dropping it yields an empty service_name → the stream hits the wrong
// path and never connects (passes `sing-box check`, fails at runtime, verified
// live). Clients spell the key serviceName / service_name / servicename, so all
// three must be accepted (mirrors the packetEncoding camel+snake handling).
func TestParseGRPCServiceNameSpellings(t *testing.T) {
	for _, key := range []string{"serviceName", "service_name", "servicename"} {
		link := "vless://u@62.0.0.1:443?type=grpc&" + key + "=mysvc&security=none#G"
		e, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: parse: %v", key, err)
		}
		if e.Transport == nil || e.Transport.Type != "grpc" || e.Transport.ServiceName != "mysvc" {
			t.Fatalf("%s: serviceName not captured: %+v", key, e.Transport)
		}
	}
}

func TestParseTrojanWS(t *testing.T) {
	link := "trojan://secretpass@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#T1"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoTrojan || e.Params["password"] != "secretpass" {
		t.Fatalf("trojan = %+v", e)
	}
	if e.Transport == nil || e.Transport.Type != "ws" || e.Transport.Path != "/ws" {
		t.Fatalf("transport = %+v", e.Transport)
	}
	if e.TLS == nil || !e.TLS.Enabled || e.TLS.SNI != "cdn.example.com" {
		t.Fatalf("tls = %+v", e.TLS)
	}
}

// TestTLSSNIFallsBackToHost: a CDN-fronted ws+tls link points `server` at an IP and
// carries the real domain only in the ws `host`. With `sni` omitted, the TLS SNI must
// fall back to that host (not the IP) or an SNI-routed frontend rejects the handshake
// ("tls: unrecognized name", verified live). vless and trojan both go through
// tlsFromQuery; vmess already did this, so this closes the inconsistency.
func TestTLSSNIFallsBackToHost(t *testing.T) {
	for _, scheme := range []string{
		"vless://u@62.0.0.1:443?security=tls&type=ws&host=real.example.com#V",
		"trojan://p@62.0.0.1:443?type=ws&host=real.example.com#T", // trojan defaults to tls
	} {
		e, err := Parse(scheme)
		if err != nil {
			t.Fatalf("parse %q: %v", scheme, err)
		}
		if e.TLS == nil || e.TLS.SNI != "real.example.com" {
			t.Fatalf("%q: SNI = %q, want host fallback real.example.com", scheme, tlsSNI(e))
		}
	}
	// An explicit sni still wins over the host (domain-fronting stays possible).
	e, _ := Parse("vless://u@62.0.0.1:443?security=tls&type=ws&host=real.example.com&sni=front.example.com#V")
	if e.TLS == nil || e.TLS.SNI != "front.example.com" {
		t.Fatalf("explicit sni must win: got %q", tlsSNI(e))
	}
	// No host and no sni → fall back to the server, as before.
	e2, _ := Parse("vless://u@server.example.com:443?security=tls#V")
	if e2.TLS == nil || e2.TLS.SNI != "server.example.com" {
		t.Fatalf("no host/sni must fall back to server: got %q", tlsSNI(e2))
	}
}

func tlsSNI(e *model.Endpoint) string {
	if e == nil || e.TLS == nil {
		return ""
	}
	return e.TLS.SNI
}

func TestParseHysteria2(t *testing.T) {
	link := "hysteria2://mypassword@1.2.3.4:8443?sni=bing.com&obfs=salamander&obfs-password=xyz&insecure=1#HY2"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoHysteria2 || e.Params["password"] != "mypassword" {
		t.Fatalf("hy2 = %+v", e)
	}
	if e.Params["obfs"] != "salamander" || e.Params["obfs_password"] != "xyz" {
		t.Fatalf("obfs = %v/%v", e.Params["obfs"], e.Params["obfs_password"])
	}
	if e.TLS == nil || !e.TLS.Insecure || e.TLS.SNI != "bing.com" {
		t.Fatalf("tls = %+v", e.TLS)
	}
}

func TestParseTUIC(t *testing.T) {
	link := "tuic://uuid-aaa:passbbb@5.6.7.8:443?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example#TU"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Params["uuid"] != "uuid-aaa" || e.Params["password"] != "passbbb" {
		t.Fatalf("tuic creds = %+v", e.Params)
	}
	if e.Params["congestion_control"] != "bbr" {
		t.Fatalf("cc = %v", e.Params["congestion_control"])
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	// userinfo = base64url(method:password)
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:supersecret"))
	link := "ss://" + userinfo + "@9.9.9.9:8388#SS1"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoShadowsocks {
		t.Fatalf("proto = %s", e.Protocol)
	}
	if e.Params["method"] != "aes-256-gcm" || e.Params["password"] != "supersecret" {
		t.Fatalf("ss creds = %+v", e.Params)
	}
	if e.Server != "9.9.9.9" || e.Port != 8388 {
		t.Fatalf("ss server = %s:%d", e.Server, e.Port)
	}
}

func TestParseVMess(t *testing.T) {
	js := `{"v":"2","ps":"VM1","add":"vm.example.com","port":"443","id":"uuid-vmess","aid":"0","net":"ws","path":"/p","host":"vm.example.com","tls":"tls","scy":"auto"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoVMess || e.Server != "vm.example.com" || e.Port != 443 {
		t.Fatalf("vmess = %+v", e)
	}
	if e.Params["uuid"] != "uuid-vmess" {
		t.Fatalf("uuid = %v", e.Params["uuid"])
	}
	if e.Transport == nil || e.Transport.Type != "ws" || e.Transport.Path != "/p" {
		t.Fatalf("transport = %+v", e.Transport)
	}
	if e.TLS == nil || !e.TLS.Enabled {
		t.Fatalf("tls = %+v", e.TLS)
	}
}

// VMess "net":"h2" is the HTTP/2 transport; it must map to the sing-box "http"
// transport (as the VLESS path does) rather than being dropped to plain TCP.
func TestParseVMessH2(t *testing.T) {
	js := `{"v":"2","ps":"VMh2","add":"vm.example.com","port":"443","id":"uuid-h2","aid":"0","net":"h2","path":"/h2","host":"vm.example.com","tls":"tls"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Transport == nil || e.Transport.Type != "http" || e.Transport.Path != "/h2" {
		t.Fatalf("h2 transport must map to http, got %+v", e.Transport)
	}
}

func TestParseAmneziaWGConf(t *testing.T) {
	conf := `[Interface]
PrivateKey = aPrivateKeyBase64==
Address = 10.8.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = aPeerPublicKey==
PresharedKey = aPresharedKey==
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0`
	e, err := Parse(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoAmneziaWG || e.Engine != model.EngineAmneziaWG {
		t.Fatalf("expected amneziawg, got %s/%s", e.Protocol, e.Engine)
	}
	if e.Server != "203.0.113.10" || e.Port != 51820 {
		t.Fatalf("server = %s:%d", e.Server, e.Port)
	}
	// Jc is a small int; H1-H4 are kept as strings (can exceed 2^31 -> atoi overflows on 32-bit).
	if e.Params["jc"] != 4 || e.Params["h4"] != "4" {
		t.Fatalf("awg params = %+v", e.Params)
	}
	if e.Params["peer_public_key"] != "aPeerPublicKey==" {
		t.Fatalf("pubkey = %v", e.Params["peer_public_key"])
	}
}

// --- Bug [19]: VMess JSON edge cases -----------------------------------------

// TestParseVMessMalformedJSON asserts that parseVMess returns an error (not a
// zero Endpoint) when the base64 body decodes to truncated or otherwise invalid
// JSON. Before the [19] audit this was already handled correctly; this test
// pins the behavior so a future refactor cannot regress it silently.
func TestParseVMessMalformedJSON(t *testing.T) {
	for _, body := range []string{
		`{"v":"2","ps":"VM`, // truncated JSON
		`not-json-at-all`,   // plaintext garbage
		`{"v":2`,            // missing closing brace
		``,                  // empty (decodes fine but unmarshal fails)
	} {
		link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(body))
		_, err := Parse(link)
		if err == nil {
			t.Errorf("body %q: expected error for malformed JSON, got nil", body)
		}
	}
}

// TestParseVMessPortAsInt asserts that parseVMess correctly parses "port" when
// it is a JSON integer (common in many client exports) rather than the string
// form used in the existing TestParseVMess fixture. asInt handles both; this
// test guards against a future strongly-typed struct unmarshal that would silently
// zero-out a numeric port when the field type is `string`.
func TestParseVMessPortAsInt(t *testing.T) {
	js := `{"v":"2","ps":"VMi","add":"vm.example.com","port":8443,"id":"uuid-int","aid":0,"net":"tcp"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Port != 8443 {
		t.Fatalf("port (integer JSON) = %d, want 8443", e.Port)
	}
}

// TestParseVMessPortAsString confirms that "port" as a JSON string (common in
// older v2rayN exports and the existing test fixture) is also parsed correctly.
func TestParseVMessPortAsString(t *testing.T) {
	js := `{"v":"2","ps":"VMs","add":"vm.example.com","port":"9090","id":"uuid-str","aid":"0","net":"tcp"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Port != 9090 {
		t.Fatalf("port (string JSON) = %d, want 9090", e.Port)
	}
}

// TestParseVMessAidAsInt confirms that "aid" (alter_id) as a JSON integer is
// parsed correctly (matching the string form tested in TestParseVMess).
func TestParseVMessAidAsInt(t *testing.T) {
	js := `{"v":"2","ps":"VMaid","add":"vm.example.com","port":443,"id":"uuid-aid","aid":7,"net":"tcp"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Params["alter_id"] != 7 {
		t.Fatalf("alter_id (integer JSON) = %v, want 7", e.Params["alter_id"])
	}
}

func TestPlainWireGuardConfDetectedAsWG(t *testing.T) {
	conf := `[Interface]
PrivateKey = key==
Address = 10.0.0.2/32

[Peer]
PublicKey = pub==
Endpoint = host.example:51820
AllowedIPs = 0.0.0.0/0`
	e, err := Parse(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoWireGuard || e.Engine != model.EngineSingBox {
		t.Fatalf("expected plain wireguard/singbox, got %s/%s", e.Protocol, e.Engine)
	}
}
