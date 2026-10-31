package importer

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// The sing-box 1.14 protocols WayHop generates, read back from a sing-box config: the snell
// outbound and the openvpn-client and openconnect endpoints. Each maps to the params the generator
// reads (internal/generator/snell.go, openvpn.go, openconnect.go), so Generate -> ParseSingbox
// round-trips, and a pasted sing-box config carrying them imports. A field naming a file on the
// machine the config came from is refused: the router cannot read it.

// sbText reads a sing-box "listable" string: one string, or an array of lines joined back.
func sbText(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case []any:
		var lines []string
		for _, l := range v {
			if s, ok := l.(string); ok {
				lines = append(lines, s)
			}
		}
		if len(lines) == 0 {
			return ""
		}
		return strings.Join(lines, "\n") + "\n"
	}
	return ""
}

// sbRefuseFiles reports the first of keys that names a file.
func sbRefuseFiles(m map[string]any, keys ...string) error {
	for _, k := range keys {
		if p := sbStr(m, k); p != "" {
			return fmt.Errorf("%s names the file %q; put its content in the config instead", k, p)
		}
	}
	return nil
}

func fillSnellFromSingbox(e *model.Endpoint, ob map[string]any) error {
	e.Protocol = model.ProtoSnell
	v := sbInt(ob, "version")
	if v != 4 && v != 6 {
		return fmt.Errorf("snell version %d: sing-box carries v4 and v6", v)
	}
	e.Params["version"] = v
	e.Params["psk"] = sbStr(ob, "psk")
	for _, k := range []string{"userkey", "network", "obfs_mode", "obfs_host", "mode"} {
		if s := sbStr(ob, k); s != "" {
			e.Params[k] = s
		}
	}
	if sbBool(ob, "reuse") {
		e.Params["reuse"] = true
	}
	return nil
}

func singboxOpenVPNEndpoint(ep map[string]any) (*model.Endpoint, error) {
	if err := sbRefuseFiles(ep, "static_key_path"); err != nil {
		return nil, err
	}
	e := &model.Endpoint{Engine: model.EngineSingBox, Protocol: model.ProtoOpenVPN, Name: sbStr(ep, "tag"),
		Server: sbStr(ep, "server"), Port: sbInt(ep, "server_port"), Params: map[string]any{"mode": "tls"}}
	p := e.Params
	p["network"] = "udp"
	if sbStr(ep, "network") == "tcp" {
		p["network"] = "tcp"
	}
	if list, ok := ep["servers"].([]any); ok && len(list) > 0 {
		var servers []any
		for _, s := range list {
			m, _ := s.(map[string]any)
			n := sbStr(m, "network")
			if n == "" {
				n = p["network"].(string)
			}
			servers = append(servers, map[string]any{"server": sbStr(m, "server"), "port": sbInt(m, "server_port"), "network": n})
		}
		first := servers[0].(map[string]any)
		e.Server, e.Port, p["network"] = first["server"].(string), first["port"].(int), first["network"]
		if len(servers) > 1 {
			p["servers"] = servers
		}
	}
	if sbBool(ep, "remote_random") {
		p["remote_random"] = true
	}
	if sbStr(ep, "mode") == "static_key" {
		p["mode"] = "static_key"
		p["static_key"] = sbText(ep, "static_key")
		addrs, _ := ep["address"].([]any)
		if len(addrs) > 0 {
			a, _ := addrs[0].(string)
			if host, _, err := net.ParseCIDR(a); err == nil {
				a = host.String()
			}
			p["address"] = a
		} else if a := sbStr(ep, "address"); a != "" {
			if host, _, err := net.ParseCIDR(a); err == nil {
				a = host.String()
			}
			p["address"] = a
		}
		p["peer_address"] = sbStr(ep, "peer_address")
		if p["peer_address"] == "" {
			p["peer_address"] = sbStr(ep, "peer_address_ipv6")
		}
		for _, k := range []string{"key_direction", "cipher"} {
			if s := sbStr(ep, k); s != "" {
				p[k] = s
			}
		}
	} else {
		tls, _ := ep["tls"].(map[string]any)
		if err := sbRefuseFiles(tls, "certificate_path", "client_certificate_path", "client_key_path"); err != nil {
			return nil, err
		}
		p["ca"] = sbText(tls, "certificate")
		if c := sbText(tls, "client_certificate"); c != "" {
			p["cert"], p["key"] = c, sbText(tls, "client_key")
		}
		for param, field := range map[string]string{"server_name": "server_name", "server_name_type": "server_name_type",
			"remote_cert_tls": "remote_certificate_tls", "tls_version_min": "version_min"} {
			if s := sbStr(tls, field); s != "" {
				p[param] = s
			}
		}
		if w, ok := tls["control_wrap"].(map[string]any); ok && sbStr(w, "type") != "" {
			if err := sbRefuseFiles(w, "key_path"); err != nil {
				return nil, err
			}
			p["control_wrap"], p["control_key"] = sbStr(w, "type"), sbText(w, "key")
			if d := sbStr(w, "direction"); d != "" {
				p["control_direction"] = d
			}
		}
		if u := sbStr(ep, "username"); u != "" {
			p["username"], p["password"], p["auth_user_pass"] = u, sbStr(ep, "password"), true
		}
		if list, ok := ep["data_ciphers"].([]any); ok && len(list) > 0 {
			p["data_ciphers"] = list
		}
		if f := sbStr(ep, "data_ciphers_fallback"); f != "" {
			p["data_ciphers_fallback"] = f
		}
	}
	for _, k := range []string{"auth", "compression", "compression_lzo", "allow_compression"} {
		if s := sbStr(ep, k); s != "" {
			p[k] = s
		}
	}
	if m := sbInt(ep, "mtu"); m > 0 {
		p["mtu"] = m
	}
	if sbBool(ep, "route_no_pull") {
		p["route_no_pull"] = true
	}
	return e, nil
}

func singboxOpenConnectEndpoint(ep map[string]any) (*model.Endpoint, error) {
	raw := sbStr(ep, "server")
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("openconnect server %q is not a URL", sbStr(ep, "server"))
	}
	port := 443
	if s := u.Port(); s != "" {
		if port, err = strconv.Atoi(s); err != nil {
			return nil, fmt.Errorf("openconnect server %q has port %q", sbStr(ep, "server"), s)
		}
	}
	if u.Path != "" && u.Path != "/" {
		// sing-box accepts a path (a group URL); the form has no place for it, so keep the group
		// selection explicit instead of dropping it silently.
		return nil, fmt.Errorf("openconnect server %q carries a path; set the group with auth_group instead", sbStr(ep, "server"))
	}
	e := &model.Endpoint{Engine: model.EngineSingBox, Protocol: model.ProtoOpenConnect, Name: sbStr(ep, "tag"),
		Server: u.Hostname(), Port: port, Params: map[string]any{}}
	p := e.Params
	for _, k := range []string{"flavor", "username", "password", "auth_group"} {
		if s := sbStr(ep, k); s != "" {
			p[k] = s
		}
	}
	if tok, ok := ep["token"].(map[string]any); ok {
		if sbStr(tok, "mode") != "totp" {
			return nil, fmt.Errorf("openconnect token mode %q: WayHop carries TOTP only", sbStr(tok, "mode"))
		}
		if err := sbRefuseFiles(tok, "secret_path"); err != nil {
			return nil, err
		}
		p["totp_secret"] = sbStr(tok, "secret")
	}
	if tls, ok := ep["tls"].(map[string]any); ok {
		switch v := tls["peer_fingerprint"].(type) {
		case string:
			p["server_cert"] = v
		case []any:
			if len(v) > 0 {
				p["server_cert"], _ = v[0].(string)
			}
		}
	}
	if sbBool(ep, "no_udp") {
		p["no_udp"] = true
	}
	return e, nil
}
