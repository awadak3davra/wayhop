package exporter

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/importer"
	"velinx/internal/model"
)

// exporter_mustExport runs Export and fails if ok is not as expected.
func exporter_mustExport(t *testing.T, e model.Endpoint) Result {
	t.Helper()
	r, ok := Export(e)
	if !ok {
		t.Fatalf("Export(%s) returned ok=false, want true", e.Protocol)
	}
	return r
}

// exporter_reparse exports an endpoint to a share link and parses it back.
func exporter_reparse(t *testing.T, e model.Endpoint) *model.Endpoint {
	t.Helper()
	r := exporter_mustExport(t, e)
	if r.Kind != "link" {
		t.Fatalf("Export(%s): kind=%q, want %q", e.Protocol, r.Kind, "link")
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse(%q): %v", r.Text, err)
	}
	return got
}

// exporter_writeAndReparse writes a conf result to a temp file, reads it back,
// and parses it (exercising the full Export->file->import path).
func exporter_writeAndReparse(t *testing.T, e model.Endpoint) (*model.Endpoint, Result) {
	t.Helper()
	r := exporter_mustExport(t, e)
	if r.Kind != "conf" {
		t.Fatalf("Export(%s): kind=%q, want %q", e.Protocol, r.Kind, "conf")
	}
	if r.Filename == "" {
		t.Fatalf("Export(%s): empty Filename", e.Protocol)
	}
	path := filepath.Join(t.TempDir(), r.Filename)
	if err := os.WriteFile(path, []byte(r.Text), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}
	got, err := importer.Parse(string(b))
	if err != nil {
		t.Fatalf("Parse(conf): %v", err)
	}
	return got, r
}

func exporter_str(p map[string]any, k string) string {
	if v, ok := p[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ---- VMess round-trip ----

func TestExporter_VMessRoundTripPlain(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoVMess,
		Engine:   model.EngineSingBox,
		Name:     "vm node",
		Server:   "vm.example.com",
		Port:     8443,
		Params: map[string]any{
			"uuid":     "11111111-1111-1111-1111-111111111111",
			"alter_id": 0,
			"security": "aes-128-gcm",
		},
	}
	got := exporter_reparse(t, e)

	if got.Protocol != model.ProtoVMess {
		t.Errorf("protocol = %q, want vmess", got.Protocol)
	}
	if got.Server != e.Server {
		t.Errorf("server = %q, want %q", got.Server, e.Server)
	}
	if got.Port != e.Port {
		t.Errorf("port = %d, want %d", got.Port, e.Port)
	}
	if got.Name != e.Name {
		t.Errorf("name = %q, want %q", got.Name, e.Name)
	}
	if u := exporter_str(got.Params, "uuid"); u != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("uuid = %q, want round-tripped uuid", u)
	}
	if sec := exporter_str(got.Params, "security"); sec != "aes-128-gcm" {
		t.Errorf("security = %q, want aes-128-gcm", sec)
	}
	// alter_id is round-tripped through string and re-parsed to int 0.
	if aid, ok := got.Params["alter_id"].(int); !ok || aid != 0 {
		t.Errorf("alter_id = %#v, want int 0", got.Params["alter_id"])
	}
	// No transport, no TLS in source: importer leaves them nil.
	if got.Transport != nil {
		t.Errorf("transport = %#v, want nil (tcp)", got.Transport)
	}
	if got.TLS != nil {
		t.Errorf("tls = %#v, want nil", got.TLS)
	}
}

func TestExporter_VMessRoundTripWSAndTLS(t *testing.T) {
	e := model.Endpoint{
		Protocol:  model.ProtoVMess,
		Engine:    model.EngineSingBox,
		Name:      "vm ws",
		Server:    "ws.example.com",
		Port:      443,
		Params:    map[string]any{"uuid": "abc", "alter_id": 3, "security": "auto"},
		Transport: &model.Transport{Type: "ws", Path: "/ray", Host: "cdn.example.com"},
		TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "sni.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}},
	}
	got := exporter_reparse(t, e)

	if got.Transport == nil || got.Transport.Type != "ws" {
		t.Fatalf("transport = %#v, want ws", got.Transport)
	}
	if got.Transport.Path != "/ray" {
		t.Errorf("ws path = %q, want /ray", got.Transport.Path)
	}
	if got.Transport.Host != "cdn.example.com" {
		t.Errorf("ws host = %q, want cdn.example.com", got.Transport.Host)
	}
	if got.TLS == nil || !got.TLS.Enabled || got.TLS.Type != "tls" {
		t.Fatalf("tls = %#v, want enabled tls", got.TLS)
	}
	if got.TLS.SNI != "sni.example.com" {
		t.Errorf("sni = %q, want sni.example.com", got.TLS.SNI)
	}
	if got.TLS.Fingerprint != "chrome" {
		t.Errorf("fingerprint = %q, want chrome (vmess export must carry fp)", got.TLS.Fingerprint)
	}
	if strings.Join(got.TLS.ALPN, ",") != "h2,http/1.1" {
		t.Errorf("alpn = %v, want [h2 http/1.1]", got.TLS.ALPN)
	}
	if aid, ok := got.Params["alter_id"].(int); !ok || aid != 3 {
		t.Errorf("alter_id = %#v, want int 3", got.Params["alter_id"])
	}
}

// TestExporter_VMessHTTP2Net: the model/sing-box call the HTTP/2 transport "http",
// but VMess JSON names it "h2". The exporter must emit net:"h2" (a standard vmess
// client won't recognise net:"http"), and the round-trip back through the importer
// (which maps h2 -> http) must restore Type:"http".
func TestExporter_VMessHTTP2Net(t *testing.T) {
	e := model.Endpoint{
		Protocol:  model.ProtoVMess,
		Engine:    model.EngineSingBox,
		Name:      "vm h2",
		Server:    "h2.example.com",
		Port:      443,
		Params:    map[string]any{"uuid": "h2-uuid", "alter_id": 0, "security": "auto"},
		Transport: &model.Transport{Type: "http", Path: "/h2", Host: "a.example.com"},
		TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "h2.example.com"},
	}
	link, ok := ShareLink(e)
	if !ok {
		t.Fatal("ShareLink returned !ok for vmess")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatalf("decode vmess link: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal vmess json: %v", err)
	}
	if m["net"] != "h2" {
		t.Fatalf("vmess net = %v, want h2 (HTTP/2 must export as h2, not http)", m["net"])
	}
	got := exporter_reparse(t, e)
	if got.Transport == nil || got.Transport.Type != "http" {
		t.Fatalf("round-tripped transport = %#v, want http (h2 maps back to http)", got.Transport)
	}
}

func TestExporter_VMessRoundTripGRPC(t *testing.T) {
	e := model.Endpoint{
		Protocol:  model.ProtoVMess,
		Engine:    model.EngineSingBox,
		Name:      "vm grpc",
		Server:    "grpc.example.com",
		Port:      2096,
		Params:    map[string]any{"uuid": "g-uuid", "alter_id": 0, "security": "auto"},
		Transport: &model.Transport{Type: "grpc", ServiceName: "GunService"},
		TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "grpc.example.com"},
	}
	got := exporter_reparse(t, e)

	if got.Transport == nil || got.Transport.Type != "grpc" {
		t.Fatalf("transport = %#v, want grpc", got.Transport)
	}
	// vmess encodes grpc service name into path; importer reads it back into ServiceName.
	if got.Transport.ServiceName != "GunService" {
		t.Errorf("grpc serviceName = %q, want GunService", got.Transport.ServiceName)
	}
}

func TestExporter_VMessNameWithSpacesAndUnicode(t *testing.T) {
	name := "Узел 日本 #1 (test)"
	e := model.Endpoint{
		Protocol: model.ProtoVMess,
		Engine:   model.EngineSingBox,
		Name:     name,
		Server:   "u.example.com",
		Port:     443,
		Params:   map[string]any{"uuid": "u", "alter_id": 0, "security": "auto"},
	}
	got := exporter_reparse(t, e)
	// vmess carries ps raw inside the base64 JSON blob, so the name round-trips verbatim.
	if got.Name != name {
		t.Errorf("name = %q, want %q", got.Name, name)
	}
}

// ---- TUIC round-trip ----

func TestExporter_TUICRoundTrip(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoTUIC,
		Engine:   model.EngineSingBox,
		Name:     "tuic node",
		Server:   "tuic.example.com",
		Port:     443,
		Params: map[string]any{
			"uuid":               "tuic-uuid",
			"password":           "tuic-pass",
			"congestion_control": "bbr",
			"udp_relay_mode":     "native",
		},
		TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "tuic.example.com", ALPN: []string{"h3"}},
	}
	got := exporter_reparse(t, e)

	if got.Protocol != model.ProtoTUIC {
		t.Errorf("protocol = %q, want tuic", got.Protocol)
	}
	if u := exporter_str(got.Params, "uuid"); u != "tuic-uuid" {
		t.Errorf("uuid = %q, want tuic-uuid", u)
	}
	if pw := exporter_str(got.Params, "password"); pw != "tuic-pass" {
		t.Errorf("password = %q, want tuic-pass", pw)
	}
	if cc := exporter_str(got.Params, "congestion_control"); cc != "bbr" {
		t.Errorf("congestion_control = %q, want bbr", cc)
	}
	if m := exporter_str(got.Params, "udp_relay_mode"); m != "native" {
		t.Errorf("udp_relay_mode = %q, want native", m)
	}
	if got.TLS == nil || got.TLS.SNI != "tuic.example.com" {
		t.Fatalf("tls = %#v, want sni tuic.example.com", got.TLS)
	}
	if strings.Join(got.TLS.ALPN, ",") != "h3" {
		t.Errorf("alpn = %v, want [h3]", got.TLS.ALPN)
	}
	// Not insecure: source Insecure=false, so importer must not flag it.
	if got.TLS.Insecure {
		t.Errorf("insecure = true, want false")
	}
}

func TestExporter_TUICInsecureFlag(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoTUIC,
		Engine:   model.EngineSingBox,
		Name:     "tuic insecure",
		Server:   "tuic2.example.com",
		Port:     443,
		Params:   map[string]any{"uuid": "id2", "password": "pw2"},
		TLS:      &model.TLS{Enabled: true, Type: "tls", SNI: "tuic2.example.com", Insecure: true},
	}
	r := exporter_mustExport(t, e)
	// TUIC encodes insecure as allow_insecure=1.
	if !strings.Contains(r.Text, "allow_insecure=1") {
		t.Errorf("tuic link %q missing allow_insecure=1", r.Text)
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.TLS == nil || !got.TLS.Insecure {
		t.Errorf("insecure not round-tripped: tls = %#v", got.TLS)
	}
}

func TestExporter_TUICEmptyOptionalParams(t *testing.T) {
	// No congestion_control / udp_relay_mode / ALPN: those keys must be absent.
	e := model.Endpoint{
		Protocol: model.ProtoTUIC,
		Engine:   model.EngineSingBox,
		Server:   "tuic3.example.com",
		Port:     443,
		Params:   map[string]any{"uuid": "id3", "password": "pw3"},
		TLS:      &model.TLS{Enabled: true, Type: "tls", SNI: "tuic3.example.com"},
	}
	r := exporter_mustExport(t, e)
	if strings.Contains(r.Text, "congestion_control=") {
		t.Errorf("link unexpectedly contains congestion_control: %q", r.Text)
	}
	if strings.Contains(r.Text, "udp_relay_mode=") {
		t.Errorf("link unexpectedly contains udp_relay_mode: %q", r.Text)
	}
	if strings.Contains(r.Text, "alpn=") {
		t.Errorf("link unexpectedly contains alpn: %q", r.Text)
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := got.Params["congestion_control"]; ok {
		t.Errorf("congestion_control should be absent, got %#v", got.Params["congestion_control"])
	}
	if _, ok := got.Params["udp_relay_mode"]; ok {
		t.Errorf("udp_relay_mode should be absent, got %#v", got.Params["udp_relay_mode"])
	}
	if len(got.TLS.ALPN) != 0 {
		t.Errorf("alpn should be empty, got %v", got.TLS.ALPN)
	}
	// Name was empty; importer synthesizes a default.
	if got.Name == "" {
		t.Errorf("name should be defaulted by importer, got empty")
	}
}

// ---- plain WireGuard round-trip ----

func TestExporter_WireGuardRoundTrip(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoWireGuard,
		Engine:   model.EngineSingBox,
		Name:     "wg home",
		Server:   "wg.example.com",
		Port:     51820,
		Params: map[string]any{
			"private_key":          "PRIVKEYbase64==",
			"peer_public_key":      "PUBKEYbase64==",
			"pre_shared_key":       "PSKbase64==",
			"local_address":        []string{"10.0.0.2/32", "fd00::2/128"},
			"persistent_keepalive": 25,
		},
	}
	got, r := exporter_writeAndReparse(t, e)

	if !strings.HasSuffix(r.Filename, ".conf") {
		t.Errorf("filename = %q, want .conf suffix", r.Filename)
	}
	if !strings.Contains(r.Text, "[Interface]") || !strings.Contains(r.Text, "[Peer]") {
		t.Errorf("conf missing INI sections:\n%s", r.Text)
	}
	if got.Protocol != model.ProtoWireGuard {
		t.Errorf("protocol = %q, want wireguard", got.Protocol)
	}
	if got.Engine != model.EngineSingBox {
		t.Errorf("engine = %q, want singbox", got.Engine)
	}
	if got.Server != "wg.example.com" || got.Port != 51820 {
		t.Errorf("server:port = %s:%d, want wg.example.com:51820", got.Server, got.Port)
	}
	if pk := exporter_str(got.Params, "private_key"); pk != "PRIVKEYbase64==" {
		t.Errorf("private_key = %q, want round-tripped", pk)
	}
	if pub := exporter_str(got.Params, "peer_public_key"); pub != "PUBKEYbase64==" {
		t.Errorf("peer_public_key = %q, want round-tripped", pub)
	}
	if psk := exporter_str(got.Params, "pre_shared_key"); psk != "PSKbase64==" {
		t.Errorf("pre_shared_key = %q, want round-tripped", psk)
	}
	if ka := got.Params["persistent_keepalive"]; ka != 25 {
		t.Errorf("persistent_keepalive = %#v, want int 25 (WG conf export must carry it)", ka)
	}
	addr, ok := got.Params["local_address"].([]string)
	if !ok {
		t.Fatalf("local_address type = %T, want []string", got.Params["local_address"])
	}
	if strings.Join(addr, ",") != "10.0.0.2/32,fd00::2/128" {
		t.Errorf("local_address = %v, want [10.0.0.2/32 fd00::2/128]", addr)
	}
}

func TestExporter_WireGuardNoPSKOrAddress(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoWireGuard,
		Engine:   model.EngineSingBox,
		Server:   "wg2.example.com",
		Port:     0, // importer defaults missing port to 51820
		Params: map[string]any{
			"private_key":     "pk",
			"peer_public_key": "pub",
		},
	}
	r := exporter_mustExport(t, e)
	if strings.Contains(r.Text, "PresharedKey") {
		t.Errorf("conf should omit PresharedKey when empty:\n%s", r.Text)
	}
	if strings.Contains(r.Text, "Address =") {
		t.Errorf("conf should omit Address when no local_address:\n%s", r.Text)
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Port != 51820 {
		t.Errorf("port = %d, want defaulted 51820", got.Port)
	}
	if _, ok := got.Params["pre_shared_key"]; ok {
		t.Errorf("pre_shared_key should be absent")
	}
	if _, ok := got.Params["local_address"]; ok {
		t.Errorf("local_address should be absent")
	}
}

// TestExporter_WireGuardReserved: the WARP "reserved" bytes must survive a
// model -> .conf -> model round-trip (exported as a Reserved line, re-parsed by
// parseConf), since the WARP server needs them.
func TestExporter_WireGuardReserved(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoWireGuard,
		Engine:   model.EngineSingBox,
		Server:   "engage.cloudflareclient.com",
		Port:     2408,
		Params: map[string]any{
			"private_key":     "pk",
			"peer_public_key": "pub",
			"reserved":        []int{12, 34, 56},
			"mtu":             1280,
		},
	}
	r := exporter_mustExport(t, e)
	if !strings.Contains(r.Text, "Reserved = 12,34,56") {
		t.Fatalf("conf should carry Reserved = 12,34,56:\n%s", r.Text)
	}
	if !strings.Contains(r.Text, "MTU = 1280") {
		t.Fatalf("conf should carry MTU = 1280:\n%s", r.Text)
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res, ok := got.Params["reserved"].([]int)
	if !ok || len(res) != 3 || res[0] != 12 || res[1] != 34 || res[2] != 56 {
		t.Fatalf("round-tripped reserved = %#v, want []int{12,34,56}", got.Params["reserved"])
	}
	if got.Params["mtu"] != 1280 {
		t.Fatalf("round-tripped mtu = %#v, want 1280", got.Params["mtu"])
	}
}

// ---- AmneziaWG export ----

func TestExporter_AmneziaWGGivesConf(t *testing.T) {
	e := model.Endpoint{
		ID:       "awg-1",
		Protocol: model.ProtoAmneziaWG,
		Engine:   model.EngineAmneziaWG,
		Name:     "My AWG Tunnel",
		Server:   "awg.example.com",
		Port:     51820,
		Params: map[string]any{
			"private_key":     "privkey",
			"peer_public_key": "pubkey",
			"jc":              4,
			"jmin":            40,
			"jmax":            70,
			"s1":              50,
			"s2":              50,
			"h1":              1,
			"h2":              2,
			"h3":              3,
			"h4":              4,
		},
	}
	r, ok := Export(e)
	if !ok {
		t.Fatalf("Export(amneziawg) ok=false, want true")
	}
	if r.Kind != "conf" {
		t.Errorf("kind = %q, want conf", r.Kind)
	}
	// Filename derives from slug(Name): "My AWG Tunnel" -> "my-awg-tunnel".
	if r.Filename != "my-awg-tunnel.conf" {
		t.Errorf("filename = %q, want my-awg-tunnel.conf", r.Filename)
	}
	if !strings.Contains(r.Text, "[Interface]") || !strings.Contains(r.Text, "[Peer]") {
		t.Errorf("awg conf missing sections:\n%s", r.Text)
	}
	// AmneziaWG junk params must be present in the rendered conf.
	if !strings.Contains(r.Text, "Jc = 4") {
		t.Errorf("awg conf missing Jc:\n%s", r.Text)
	}
	if !strings.Contains(r.Text, "Endpoint = awg.example.com:51820") {
		t.Errorf("awg conf missing Endpoint:\n%s", r.Text)
	}

	// Round-trips back to AmneziaWG (junk keys flip the engine).
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("Parse(awg conf): %v", err)
	}
	if got.Protocol != model.ProtoAmneziaWG {
		t.Errorf("protocol = %q, want amneziawg", got.Protocol)
	}
	if got.Engine != model.EngineAmneziaWG {
		t.Errorf("engine = %q, want amneziawg", got.Engine)
	}
}

func TestExporter_AmneziaWGFilenameFallsBackToID(t *testing.T) {
	// Empty Name: slug(firstNonEmpty(Name, ID)) uses the ID.
	e := model.Endpoint{
		ID:       "awg-fallback-id",
		Protocol: model.ProtoAmneziaWG,
		Engine:   model.EngineAmneziaWG,
		Server:   "awg2.example.com",
		Port:     51820,
		Params: map[string]any{
			"private_key":     "pk",
			"peer_public_key": "pub",
			"jc":              1,
		},
	}
	r, ok := Export(e)
	if !ok {
		t.Fatalf("Export ok=false")
	}
	if r.Filename != "awg-fallback-id.conf" {
		t.Errorf("filename = %q, want awg-fallback-id.conf", r.Filename)
	}
}

// An IPv6 server must be bracketed in the exported URI ("[2001:db8::1]:443"):
// a bare "2001:db8::1:443" is ambiguous and won't parse. Must also round-trip.
func TestExporter_IPv6ServerBracketed(t *testing.T) {
	e := model.Endpoint{
		ID: "v6", Name: "v6", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "2001:db8::1", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"},
	}
	r := exporter_mustExport(t, e)
	if !strings.Contains(r.Text, "[2001:db8::1]:443") {
		t.Fatalf("IPv6 host not bracketed in exported link: %s", r.Text)
	}
	back := exporter_reparse(t, e)
	if back.Server != "2001:db8::1" || back.Port != 443 {
		t.Errorf("IPv6 round-trip = %q:%d, want 2001:db8::1:443", back.Server, back.Port)
	}
}

// ---- ShareLink negative cases ----

func TestExporter_ShareLinkUnsupportedProtocols(t *testing.T) {
	for _, proto := range []model.Protocol{model.ProtoSOCKS, model.ProtoHTTP, model.ProtoOlcRTC} {
		e := model.Endpoint{
			Protocol: proto,
			Server:   "x.example.com",
			Port:     1080,
			Params:   map[string]any{},
		}
		if link, ok := ShareLink(e); ok {
			t.Errorf("ShareLink(%s) ok=true (link=%q), want ok=false", proto, link)
		}
		if _, ok := Export(e); ok {
			t.Errorf("Export(%s) ok=true, want ok=false", proto)
		}
	}
}

// A conf result is not a share link even though Export succeeds.
func TestExporter_ShareLinkFalseForConf(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoWireGuard,
		Engine:   model.EngineSingBox,
		Server:   "wg.example.com",
		Port:     51820,
		Params:   map[string]any{"private_key": "pk", "peer_public_key": "pub"},
	}
	if _, ok := Export(e); !ok {
		t.Fatalf("Export(wireguard) ok=false, want true")
	}
	if link, ok := ShareLink(e); ok {
		t.Errorf("ShareLink(wireguard) ok=true (link=%q), want false (conf is not a link)", link)
	}
}
