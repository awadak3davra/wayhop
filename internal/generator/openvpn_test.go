package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// openvpnTestPEM makes a throwaway self-signed certificate and its key, so no fixture carries one.
func openvpnTestPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "server.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

// openvpnTestStaticKey makes a throwaway 2048-bit OpenVPN static key in its file format.
func openvpnTestStaticKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	var s strings.Builder
	s.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(b); i += 16 {
		s.WriteString(hex.EncodeToString(b[i:i+16]) + "\n")
	}
	s.WriteString("-----END OpenVPN Static key V1-----\n")
	return s.String()
}

// openvpnTestProfile imports three real-shaped profiles through the importer - user/pass with
// tls-crypt and two remotes, certificate with tls-auth over TCP, and static key - and routes to them.
func openvpnTestProfile(t *testing.T) *model.Profile {
	t.Helper()
	ca, key := openvpnTestPEM(t)
	wrap := openvpnTestStaticKey(t)
	parse := func(profile string) model.Endpoint {
		e, err := importer.Parse(profile)
		if err != nil {
			t.Fatalf("import: %v\n%s", err, profile)
		}
		return *e
	}
	userpass := parse("client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote 192.0.2.10 443 tcp-client\n" +
		"remote-random\nauth-user-pass\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\nauth SHA256\n" +
		"verify-x509-name server.example.com name\nremote-cert-tls server\ntun-mtu 1400\n" +
		"<ca>\n" + ca + "</ca>\n<tls-crypt>\n" + wrap + "</tls-crypt>\n")
	userpass.ID, userpass.Params["username"], userpass.Params["password"] = "ovpn-up", "user", "pass"
	certauth := parse("client\ndev tun\nproto tcp-client\nremote 198.51.100.7 8443\nkey-direction 1\ncipher AES-256-CBC\n" +
		"<ca>\n" + ca + "</ca>\n<cert>\n" + ca + "</cert>\n<key>\n" + key + "</key>\n<tls-auth>\n" + wrap + "</tls-auth>\n")
	certauth.ID = "ovpn-cert"
	static := parse("dev tun\nremote 203.0.113.5 1194\nifconfig 10.8.0.2 10.8.0.1\ncipher AES-256-CBC\n" +
		"<secret>\n" + wrap + "</secret>\nkey-direction 1\n")
	static.ID = "ovpn-static"
	for _, e := range []*model.Endpoint{&userpass, &certauth, &static} {
		e.Name, e.Enabled = e.ID, true
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{userpass, certauth, static},
		Rules: []model.Rule{
			{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "ovpn-cert"},
			{ID: "b", DomainSuffix: []string{"b.example.com"}, Outbound: "ovpn-static"},
			{ID: "def", Default: true, Outbound: "ovpn-up"},
		},
	}
}

func openvpnEndpointsOf(t *testing.T, cfg map[string]any) map[string]map[string]any {
	t.Helper()
	eps, _ := cfg["endpoints"].([]map[string]any)
	out := map[string]map[string]any{}
	for _, ep := range eps {
		if ep["type"] == "openvpn-client" {
			out[ep["tag"].(string)] = ep
		}
	}
	return out
}

// TestOpenVPNSingBoxCheck renders imported OpenVPN profiles as sing-box openvpn-client endpoints.
// The structure is always asserted. With WR_SINGBOX set, a 1.14+ core must pass `sing-box check`
// with no deprecation warning, and an older one (the 1.12/1.13 CI legs) must be refused by the
// generator by name rather than handed a config the core rejects.
func TestOpenVPNSingBoxCheck(t *testing.T) {
	p := openvpnTestProfile(t)
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.13.21"}); err == nil ||
		!strings.Contains(err.Error(), "OpenVPN needs sing-box 1.14") {
		t.Fatalf("a 1.13 core: err = %v, want the 1.14 refusal", err)
	}
	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4", CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for 1.14.4: %v", err)
	}
	eps := openvpnEndpointsOf(t, res.Config)
	up, cert, static := eps["ovpn-up"], eps["ovpn-cert"], eps["ovpn-static"]
	if up == nil || cert == nil || static == nil {
		t.Fatalf("openvpn-client endpoints = %v", eps)
	}
	if servers, _ := up["servers"].([]map[string]any); len(servers) != 2 || servers[1]["network"] != "tcp" ||
		up["remote_random"] != true || up["username"] != "user" || up["mtu"] != 1400 {
		t.Errorf("user/pass endpoint = %v", up)
	}
	if tls, _ := up["tls"].(map[string]any); tls["server_name"] != "server.example.com" ||
		tls["control_wrap"].(map[string]any)["type"] != "tls_crypt" {
		t.Errorf("user/pass tls = %v", up["tls"])
	}
	if tls, _ := cert["tls"].(map[string]any); cert["network"] != "tcp" || cert["server_port"] != 8443 ||
		tls["client_key"] == nil || tls["control_wrap"].(map[string]any)["direction"] != "client" ||
		cert["data_ciphers_fallback"] != "AES-256-CBC" || cert["cipher"] != nil {
		t.Errorf("certificate endpoint = %v", cert)
	}
	if static["mode"] != "static_key" || static["peer_address"] != "10.8.0.1" || static["cipher"] != "AES-256-CBC" ||
		static["key_direction"] != "client" {
		t.Errorf("static-key endpoint = %v", static)
	}
	if addr, _ := static["address"].([]string); len(addr) != 1 || addr[0] != "10.8.0.2/32" {
		t.Errorf("static-key address = %v", static["address"])
	}
	// A profile that signs in with a password and has none still renders - the review reports that one
	// exit (endpoint.credential) - so the config every other connection shares keeps loading.
	p.Endpoints[0].Params["password"] = ""
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"}); err != nil {
		t.Fatalf("no password must not fail the whole config: %v", err)
	}
	p.Endpoints[0].Params["password"] = "pass"

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	ver := singboxVersionOf(t, bin)
	res, err = Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if coreMinor(ver) < openvpnMinMinor {
		if err == nil {
			t.Fatalf("sing-box %s has no openvpn-client, but the generator rendered one", strings.SplitN(ver, "\n", 2)[0])
		}
		return
	}
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "openvpn.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the OpenVPN config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
}
