package exporter

import (
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// ovpnConf renders an OpenVPN connection back into the .ovpn client profile it was imported from
// (internal/importer/openvpn.go reads exactly these directives), with every certificate and key
// inline. A user name and password are never written: a profile that signs in with them carries
// auth-user-pass and the client asks, as an exported provider profile does.
func ovpnConf(e model.Endpoint) (string, bool) {
	p := e.Params
	str := func(k string) string { s, _ := p[k].(string); return s }
	if e.Server == "" || e.Port == 0 {
		return "", false
	}
	var b strings.Builder
	line := func(parts ...string) { b.WriteString(strings.Join(parts, " ") + "\n") }
	block := func(tag, body string) {
		if body = strings.TrimSpace(body); body != "" {
			b.WriteString("<" + tag + ">\n" + body + "\n</" + tag + ">\n")
		}
	}
	proto := func(network string) string {
		if network == "tcp" {
			return "tcp-client"
		}
		return "udp"
	}
	static := str("mode") == "static_key"
	if !static {
		line("client")
	}
	line("dev", "tun")
	line("proto", proto(str("network")))
	servers, _ := p["servers"].([]any)
	if len(servers) > 1 {
		for _, s := range servers {
			m, _ := s.(map[string]any)
			host, _ := m["server"].(string)
			network, _ := m["network"].(string)
			line("remote", host, strconv.Itoa(ovpnInt(m["port"])), proto(network))
		}
		if b, _ := p["remote_random"].(bool); b {
			line("remote-random")
		}
	} else {
		line("remote", e.Server, strconv.Itoa(e.Port))
	}
	if static {
		line("ifconfig", str("address"), str("peer_address"))
	} else if b, _ := p["auth_user_pass"].(bool); b || str("username") != "" {
		line("auth-user-pass")
	}
	if list, ok := p["data_ciphers"].([]any); ok && len(list) > 0 {
		var names []string
		for _, c := range list {
			if s, ok := c.(string); ok {
				names = append(names, s)
			}
		}
		line("data-ciphers", strings.Join(names, ":"))
	}
	for _, d := range [][2]string{{"data_ciphers_fallback", "data-ciphers-fallback"}, {"cipher", "cipher"},
		{"auth", "auth"}, {"remote_cert_tls", "remote-cert-tls"}, {"tls_version_min", "tls-version-min"},
		{"compression_lzo", "comp-lzo"}, {"allow_compression", "allow-compression"}} {
		if v := str(d[0]); v != "" {
			line(d[1], v)
		}
	}
	if v := str("compression"); v != "" {
		line("compress", v)
	}
	if n := str("server_name"); n != "" {
		if t := str("server_name_type"); t != "" {
			line("verify-x509-name", n, t)
		} else {
			line("verify-x509-name", n)
		}
	}
	if m := ovpnInt(p["mtu"]); m > 0 {
		line("tun-mtu", strconv.Itoa(m))
	}
	if b, _ := p["route_no_pull"].(bool); b {
		line("route-nopull")
	}
	if static {
		switch str("key_direction") {
		case "server":
			line("key-direction", "0")
		case "client":
			line("key-direction", "1")
		}
		block("secret", str("static_key"))
		return b.String(), true
	}
	switch str("control_direction") {
	case "server":
		line("key-direction", "0")
	case "client":
		line("key-direction", "1")
	}
	block("ca", str("ca"))
	block("cert", str("cert"))
	block("key", str("key"))
	switch str("control_wrap") {
	case "tls_auth":
		block("tls-auth", str("control_key"))
	case "tls_crypt":
		block("tls-crypt", str("control_key"))
	case "tls_crypt_v2":
		block("tls-crypt-v2", str("control_key"))
	}
	return b.String(), true
}

func ovpnInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}
