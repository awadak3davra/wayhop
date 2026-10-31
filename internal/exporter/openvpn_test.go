package exporter

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

const (
	ovpnExpCA   = "-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----"
	ovpnExpCert = "-----BEGIN CERTIFICATE-----\nTESTCLIENT\n-----END CERTIFICATE-----"
	ovpnExpKey  = "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----"
	ovpnExpWrap = "-----BEGIN OpenVPN Static key V1-----\nTESTWRAP\n-----END OpenVPN Static key V1-----"
)

// An OpenVPN connection exports as the .ovpn it imports from: import -> export -> import gives the
// same endpoint, for a provider profile (two remotes, user/pass, tls-crypt), a certificate profile
// (tls-auth with a key direction) and a static-key one. Credentials never reach the file.
func TestExport_OpenVPNRoundTrips(t *testing.T) {
	for name, profile := range map[string]string{
		"provider": strings.Join([]string{"client", "dev tun", "proto udp", "remote vpn.example.com 1194",
			"remote 192.0.2.10 443 tcp-client", "remote-random", "auth-user-pass",
			"data-ciphers AES-256-GCM:CHACHA20-POLY1305", "auth SHA256", "verify-x509-name server.example.com name",
			"remote-cert-tls server", "tun-mtu 1400", "comp-lzo no", "<ca>", ovpnExpCA, "</ca>",
			"<tls-crypt>", ovpnExpWrap, "</tls-crypt>"}, "\n"),
		"certificate": "client\ndev tun\nproto tcp\nremote 198.51.100.7 8443\nkey-direction 1\ncipher AES-256-CBC\n" +
			"<ca>\n" + ovpnExpCA + "\n</ca>\n<cert>\n" + ovpnExpCert + "\n</cert>\n<key>\n" + ovpnExpKey +
			"\n</key>\n<tls-auth>\n" + ovpnExpWrap + "\n</tls-auth>\n",
		"static": "dev tun\nremote 203.0.113.5 1194\nifconfig 10.8.0.2 10.8.0.1\ncipher AES-256-CBC\n" +
			"<secret>\n" + ovpnExpWrap + "\n</secret>\nkey-direction 1\n",
	} {
		first, err := importer.Parse(profile)
		if err != nil {
			t.Fatalf("%s: import: %v", name, err)
		}
		// The form's credentials, on the profile that signs in with them; given to a certificate-only
		// profile they would rightly add auth-user-pass to the export.
		if first.Params["auth_user_pass"] == true {
			first.Params["username"], first.Params["password"] = "alice", "s3cret"
		}
		res, ok := Export(*first)
		if !ok || res.Kind != "conf" || !strings.HasSuffix(res.Filename, ".ovpn") {
			t.Fatalf("%s: Export = %+v, %v", name, res, ok)
		}
		if strings.Contains(res.Text, "alice") || strings.Contains(res.Text, "s3cret") {
			t.Errorf("%s: the exported profile carries the credentials:\n%s", name, res.Text)
		}
		second, err := importer.Parse(res.Text)
		if err != nil {
			t.Fatalf("%s: re-import of the export: %v\n%s", name, err, res.Text)
		}
		delete(first.Params, "username")
		delete(first.Params, "password")
		if second.Server != first.Server || second.Port != first.Port || !reflect.DeepEqual(second.Params, first.Params) {
			t.Errorf("%s: round-trip changed the endpoint\nfirst  %s:%d %#v\nsecond %s:%d %#v\n%s", name,
				first.Server, first.Port, first.Params, second.Server, second.Port, second.Params, res.Text)
		}
	}
	if _, ok := Export(model.Endpoint{Protocol: model.ProtoOpenVPN}); ok {
		t.Error("an OpenVPN endpoint with no server must not export")
	}
}
