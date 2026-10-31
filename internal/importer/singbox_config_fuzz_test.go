package importer

import "testing"

// FuzzParseSingbox hammers the sing-box config.json importer with arbitrary input.
// ParseSingbox runs on UNTRUSTED pasted configs: json.Unmarshal is panic-safe, but the
// structural map traversal afterwards (per-type field reads, nested transport/tls maps,
// the wireguard endpoints[] + peer[] array indexing) is where a type/shape surprise could
// panic. The fuzz contract is simply: looksLikeSingbox + ParseSingbox (and the
// ParseSubscription dispatch) NEVER panic or hang on any input. (Correctness of valid
// configs is covered by singbox_config_test.go incl. the generator round-trip.)
func FuzzParseSingbox(f *testing.F) {
	seeds := []string{
		`{"outbounds":[{"type":"vless","tag":"a","server":"1.2.3.4","server_port":443,"uuid":"u","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"s","reality":{"enabled":true,"public_key":"pbk","short_id":"ab"}}}]}`,
		`{"outbounds":[{"type":"vmess","tag":"v","server":"1.2.3.4","server_port":443,"uuid":"u","alter_id":0,"transport":{"type":"ws","path":"/x","headers":{"Host":"h"}},"tls":{"enabled":true}}]}`,
		`{"outbounds":[{"type":"shadowsocks","tag":"s","server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"p"}]}`,
		`{"outbounds":[{"type":"hysteria2","server":"a","server_port":443,"password":"p","obfs":{"type":"salamander","password":"o"},"server_ports":"443:8443"}]}`,
		`{"outbounds":[{"type":"tuic","server":"a","server_port":8446,"uuid":"u","password":"p","congestion_control":"bbr"}],"endpoints":[{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"k","mtu":1280,"peers":[{"address":"1.2.3.4","port":51820,"public_key":"P","persistent_keepalive_interval":25}]}]}`,
		`{"outbounds":[{"type":"direct"},{"type":"block"},{"type":"selector","outbounds":["a"]},{"type":"urltest"}],"route":{"rules":[]}}`,
		// the sing-box 1.14 types read back since QA-019, well-formed and with wrong shapes
		`{"outbounds":[{"type":"snell","server":"a","server_port":1,"version":6,"psk":"abcdefghijkl","mode":"unshaped"},{"type":"hysteria2","server":"b","server_port":2,"password":"p","obfs":{"type":"gecko","password":"o","min_packet_size":600},"hop_interval":"10s","hop_interval_max":"30s","disable_chrome_parrot":true}],"endpoints":[{"type":"openvpn-client","server":"c","server_port":1194,"tls":{"certificate":["A","B"],"control_wrap":{"type":"tls_crypt","key":"K"}},"servers":[{"server":"c","server_port":1},{"server":"d"}]},{"type":"openconnect","server":"https://e:8443","token":{"mode":"totp","secret":"S"},"tls":{"peer_fingerprint":["x"]}}]}`,
		`{"endpoints":[{"type":"openvpn-client","mode":"static_key","address":"not-an-ip","servers":[null,7,{"server":5}]},{"type":"openconnect","server":"://"},{"type":"openconnect","token":"notamap","tls":{"peer_fingerprint":[3]}}],"outbounds":[{"type":"snell","version":"x"}]}`,
		// multiplex, well-formed and with wrong shapes
		`{"outbounds":[{"type":"trojan","server":"a","server_port":1,"password":"p","multiplex":{"enabled":true,"protocol":"smux","max_connections":4,"max_streams":-1,"brutal":{"enabled":true,"up_mbps":1e30,"down_mbps":"x"}}},{"type":"tuic","server":"b","server_port":2,"uuid":"u","multiplex":{"enabled":true}}]}`,
		`{"outbounds":[{"type":"vless","server":"a","server_port":1,"multiplex":"on"},{"type":"shadowsocks","server":"b","server_port":2,"method":"m","password":"p","multiplex":{"brutal":[1]}}]}`,
		// adversarial shapes: wrong types where a map/array is expected
		`{"outbounds":[{"type":"vmess","transport":"notamap","tls":42}]}`,
		`{"outbounds":[{"type":"wireguard","peers":"notanarray"}]}`,
		`{"endpoints":[{"type":"wireguard","peers":[]}]}`,
		`{"outbounds":"notanarray"}`,
		`{"outbounds":[null, 42, "str", {"type":123}]}`,
		`{"outbounds":[]}`,
		`not json`,
		`{}`,
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_ = looksLikeSingbox(data)
		eps, errs := ParseSingbox(data)
		_ = errs
		for i := range eps {
			_ = eps[i].ID
			_ = eps[i].Engine
			_ = eps[i].Protocol
		}
		// The real entry point dispatches through here; must also be panic-free.
		_, _ = ParseSubscription(data)
	})
}
