package importer

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Placeholder PEM bodies: the importer carries blocks verbatim and never parses them.
const (
	ovpnTestCA   = "-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----"
	ovpnTestCert = "-----BEGIN CERTIFICATE-----\nTESTCLIENT\n-----END CERTIFICATE-----"
	ovpnTestKey  = "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----"
	ovpnTestWrap = "-----BEGIN OpenVPN Static key V1-----\nTESTWRAP\n-----END OpenVPN Static key V1-----"
)

// A typical provider profile: user/pass, inline CA, tls-crypt, two remotes on different
// transports, CRLF line endings, and routing directives WayHop ignores because it owns routing.
func TestParseOpenVPN_ProviderProfile(t *testing.T) {
	profile := strings.Join([]string{
		"# exported by a provider", "client", "dev tun", "proto udp",
		"remote vpn.example.com 1194", "remote 192.0.2.10 443 tcp-client", "remote-random",
		"resolv-retry infinite", "nobind", "persist-key", "persist-tun",
		"auth-user-pass", "data-ciphers AES-256-GCM:CHACHA20-POLY1305", "auth SHA256",
		"verify-x509-name server.example.com name", "remote-cert-tls server", "tun-mtu 1400",
		"comp-lzo no", "redirect-gateway def1", "block-outside-dns", "verb 3",
		"<ca>", ovpnTestCA, "</ca>", "<tls-crypt>", ovpnTestWrap, "</tls-crypt>",
	}, "\r\n")
	e, err := Parse(profile)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Protocol != model.ProtoOpenVPN || e.Engine != model.EngineSingBox || e.Server != "vpn.example.com" || e.Port != 1194 {
		t.Fatalf("endpoint = %s/%s %s:%d", e.Protocol, e.Engine, e.Server, e.Port)
	}
	p := e.Params
	want := map[string]any{
		"mode": "tls", "network": "udp", "remote_random": true, "auth_user_pass": true,
		"data_ciphers": []any{"AES-256-GCM", "CHACHA20-POLY1305"}, "auth": "SHA256",
		"server_name": "server.example.com", "server_name_type": "name", "remote_cert_tls": "server",
		"mtu": 1400, "compression_lzo": "no", "control_wrap": "tls_crypt",
		"ca": ovpnTestCA + "\n", "control_key": ovpnTestWrap + "\n",
		"servers": []any{
			map[string]any{"server": "vpn.example.com", "port": 1194, "network": "udp"},
			map[string]any{"server": "192.0.2.10", "port": 443, "network": "tcp"},
		},
	}
	for k, v := range want {
		if !reflect.DeepEqual(p[k], v) {
			t.Errorf("param %s = %#v, want %#v", k, p[k], v)
		}
	}
	for _, k := range []string{"cert", "key", "redirect_gateway", "username", "password"} {
		if _, ok := p[k]; ok {
			t.Errorf("param %s set, want absent", k)
		}
	}
}

// Certificate authentication with tls-auth: key-direction 1 is the client side.
func TestParseOpenVPN_CertificateAndTLSAuth(t *testing.T) {
	profile := "client\ndev tun\nproto tcp\nremote 198.51.100.7\nport 8443\nkey-direction 1\ncipher AES-256-CBC\n" +
		"<ca>\n" + ovpnTestCA + "\n</ca>\n<cert>\n" + ovpnTestCert + "\n</cert>\n<key>\n" + ovpnTestKey +
		"\n</key>\n<tls-auth>\n" + ovpnTestWrap + "\n</tls-auth>\n"
	e, err := Parse(profile)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p := e.Params
	if e.Port != 8443 || p["network"] != "tcp" || p["control_wrap"] != "tls_auth" || p["control_direction"] != "client" ||
		p["cert"] != ovpnTestCert+"\n" || p["key"] != ovpnTestKey+"\n" || p["cipher"] != "AES-256-CBC" || p["servers"] != nil {
		t.Fatalf("endpoint %s:%d params %#v", e.Server, e.Port, p)
	}
}

func TestParseOpenVPN_StaticKey(t *testing.T) {
	profile := "dev tun\nremote 203.0.113.5 1194\nmode p2p\nifconfig 10.8.0.2 10.8.0.1\n" +
		"<secret>\n" + ovpnTestWrap + "\n</secret>\nkey-direction 1\n"
	e, err := Parse(profile)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p := e.Params
	if p["mode"] != "static_key" || p["static_key"] != ovpnTestWrap+"\n" || p["address"] != "10.8.0.2" ||
		p["peer_address"] != "10.8.0.1" || p["key_direction"] != "client" {
		t.Fatalf("params %#v", p)
	}
}

// What the endpoint cannot carry is refused with the reason, never stored half-understood.
func TestParseOpenVPN_Refusals(t *testing.T) {
	inline := "<ca>\n" + ovpnTestCA + "\n</ca>\n"
	for name, tc := range map[string]struct{ profile, want string }{
		"ca file":            {"client\nremote vpn.example.com\nauth-user-pass\nca ca.crt\n", `references the file "ca.crt"`},
		"tls-auth file":      {"client\nremote vpn.example.com\nauth-user-pass\ntls-auth ta.key 1\n" + inline, `references the file "ta.key"`},
		"tap":                {"client\ndev tap\nremote vpn.example.com\nauth-user-pass\n" + inline, "dev tap"},
		"pkcs12":             {"client\nremote vpn.example.com\n<pkcs12>\nAAAA\n</pkcs12>\n", "PKCS#12"},
		"http proxy":         {"client\nremote vpn.example.com\nhttp-proxy 192.0.2.1 3128\nauth-user-pass\n" + inline, "HTTP proxy"},
		"server profile":     {"dev tun\nremote vpn.example.com\nmode server\n" + inline, "server profile"},
		"no ca":              {"client\nremote vpn.example.com\nauth-user-pass\n", "no CA certificate"},
		"cert without key":   {"client\nremote vpn.example.com\n" + inline + "<cert>\n" + ovpnTestCert + "\n</cert>\n", "needs its key"},
		"no auth":            {"client\nremote vpn.example.com\n" + inline, "cannot authenticate"},
		"unclosed":           {"client\nremote vpn.example.com\nauth-user-pass\n<ca>\n" + ovpnTestCA + "\n", "never closed"},
		"server proto":       {"client\nproto tcp-server\nremote vpn.example.com\nauth-user-pass\n" + inline, "not a client transport"},
		"static no ifconfig": {"dev tun\nremote vpn.example.com\n<secret>\n" + ovpnTestWrap + "\n</secret>\n", "ifconfig"},
	} {
		e, err := Parse(tc.profile)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Parse = %+v, %v; want an error containing %q", name, e, err, tc.want)
		}
	}
}

// The sniff never steals a share link: a URI scheme wins, even with OpenVPN words in its name.
func TestParseOpenVPN_ShareLinkWithOpenVPNWordsStaysAShareLink(t *testing.T) {
	e, err := Parse("trojan://secretpass@example.com:443?security=tls&sni=example.com#client%0Aremote%20x%20<ca>")
	if err != nil || e.Protocol != model.ProtoTrojan {
		t.Fatalf("got %+v, %v; want the trojan link", e, err)
	}
}
