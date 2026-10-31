package importer

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// A pasted OpenVPN client profile (.ovpn) becomes an endpoint for sing-box's openvpn-client
// endpoint (1.14+). Only what that endpoint can carry is taken; a profile that depends on something
// it cannot - a certificate kept in a separate file, layer-2 TAP, a PKCS#12 bundle, reaching the
// server through a proxy - is refused with the reason rather than stored as a connection that fails
// at start. Routing directives (redirect-gateway, route, dhcp-option, block-outside-dns) and process
// housekeeping (persist-*, verb, nobind, resolv-retry, scripts) are ignored: WayHop owns routing and
// sing-box owns the process.
//
// Params written (read by the generator): network, servers ([]{server, port, network}) when the
// profile names more than one remote, remote_random, mode ("tls" | "static_key"), ca, cert, key,
// control_wrap ("tls_auth" | "tls_crypt" | "tls_crypt_v2"), control_key, control_direction
// ("server" | "client"), static_key, key_direction, cipher, data_ciphers ([]string),
// data_ciphers_fallback, auth, server_name, server_name_type, remote_cert_tls, tls_version_min,
// mtu, compression, compression_lzo, allow_compression, route_no_pull, auth_user_pass, and for a
// static-key profile address / peer_address (from ifconfig). Username and
// password are never in a profile; the connection form collects them.

// ovpnInline are the inline blocks a profile may carry and the param each lands in.
var ovpnInline = map[string]string{
	"ca": "ca", "cert": "cert", "key": "key",
	"tls-auth": "control_key", "tls-crypt": "control_key", "tls-crypt-v2": "control_key",
	"secret": "static_key",
}

// ovpnFileDirectives name a file when given an argument other than [inline]; the router cannot
// read the operator's files, so the profile must carry them inline.
var ovpnFileDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"secret": true,
}

// ovpnRefused are directives whose meaning the endpoint cannot honour, with what to do instead.
var ovpnRefused = map[string]string{
	"pkcs12":      "a PKCS#12 bundle is not supported; export the profile with inline PEM <ca>, <cert> and <key>",
	"http-proxy":  "reaching the server through an HTTP proxy is not supported; remove http-proxy",
	"socks-proxy": "reaching the server through a SOCKS proxy is not supported; remove socks-proxy",
	"tls-server":  "this is a server profile; import the client profile",
	"server":      "this is a server profile; import the client profile",
}

// looksLikeOpenVPN detects a pasted .ovpn profile: a `remote` directive plus a client marker or an
// inline certificate. Parse calls it only for input without a URI scheme.
func looksLikeOpenVPN(s string) bool {
	low := strings.ToLower(s)
	hasRemote := false
	for _, ln := range strings.Split(low, "\n") {
		if f := strings.Fields(ln); len(f) > 1 && f[0] == "remote" {
			hasRemote = true
			break
		}
	}
	return hasRemote && (strings.Contains(low, "\nclient") || strings.HasPrefix(low, "client") ||
		strings.Contains(low, "<ca>") || strings.Contains(low, "dev tun"))
}

type ovpnRemote struct {
	host    string
	port    int
	network string
}

// ovpnNetwork maps an OpenVPN proto to the endpoint's network, or "" when it is not a client one.
func ovpnNetwork(proto string) string {
	switch strings.ToLower(proto) {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client":
		return "tcp"
	}
	return ""
}

// What a .ovpn profile can express (sourceFields): the params parseOpenVPN writes, and the inline
// blocks (ovpnInline). The sign-in (username, password) is never in a profile; the form keeps it.
var openvpnFields = sourceFields{params: append([]string{"network", "servers", "remote_random", "mode", "address",
	"peer_address", "key_direction", "cipher", "data_ciphers", "data_ciphers_fallback", "auth", "auth_user_pass",
	"compression", "compression_lzo", "allow_compression", "control_wrap", "control_direction", "mtu",
	"remote_cert_tls", "route_no_pull", "server_name", "server_name_type", "tls_version_min"}, ovpnInlineParams()...)}

func ovpnInlineParams() []string {
	var out []string
	for _, p := range ovpnInline {
		if !containsPin(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func parseOpenVPN(text string) (*model.Endpoint, error) {
	text = strings.ReplaceAll(strings.TrimPrefix(text, "\ufeff"), "\r\n", "\n")
	p := map[string]any{"mode": "tls"}
	var remotes []ovpnRemote
	network, port := "udp", 1194
	wrap, keyDirection, inlineTag := "", "", ""
	var block strings.Builder
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if inlineTag != "" {
			if strings.EqualFold(line, "</"+inlineTag+">") {
				p[ovpnInline[inlineTag]] = strings.TrimSpace(block.String()) + "\n"
				switch inlineTag {
				case "tls-auth":
					wrap = "tls_auth"
				case "tls-crypt":
					wrap = "tls_crypt"
				case "tls-crypt-v2":
					wrap = "tls_crypt_v2"
				case "secret":
					p["mode"] = "static_key"
				}
				inlineTag = ""
				continue
			}
			block.WriteString(line + "\n")
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			tag := strings.ToLower(strings.Trim(line, "<>"))
			if tag == "pkcs12" {
				return nil, errors.New("openvpn: " + ovpnRefused["pkcs12"])
			}
			if _, ok := ovpnInline[tag]; !ok {
				return nil, fmt.Errorf("openvpn: line %d: inline <%s> is not supported", n+1, tag)
			}
			inlineTag = tag
			block.Reset()
			continue
		}
		f := strings.Fields(line)
		d, args := strings.ToLower(f[0]), f[1:]
		arg := func(i int) string {
			if i < len(args) {
				return strings.Trim(args[i], `"'`)
			}
			return ""
		}
		if why, ok := ovpnRefused[d]; ok {
			return nil, errors.New("openvpn: " + why)
		}
		if d == "mode" && strings.EqualFold(arg(0), "server") {
			return nil, errors.New("openvpn: this is a server profile (mode server); import the client profile")
		}
		if ovpnFileDirectives[d] && arg(0) != "" && !strings.EqualFold(arg(0), "[inline]") {
			return nil, fmt.Errorf("openvpn: %s references the file %q; export the profile with it inline (<%s>...</%s>)", d, arg(0), d, d)
		}
		switch d {
		case "dev":
			if strings.HasPrefix(strings.ToLower(arg(0)), "tap") {
				return nil, errors.New("openvpn: dev tap (layer 2) is not supported; only dev tun profiles import")
			}
		case "proto":
			if network = ovpnNetwork(arg(0)); network == "" {
				return nil, fmt.Errorf("openvpn: proto %q is not a client transport (use udp or tcp-client)", arg(0))
			}
		case "port", "rport":
			n, err := strconv.Atoi(arg(0))
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("openvpn: %s %q is not a port", d, arg(0))
			}
			port = n
		case "remote":
			r := ovpnRemote{host: strings.Trim(arg(0), "[]")}
			if s := arg(1); s != "" {
				n, err := strconv.Atoi(s)
				if err != nil || n < 1 || n > 65535 {
					return nil, fmt.Errorf("openvpn: remote %s has port %q", r.host, s)
				}
				r.port = n
			}
			if s := arg(2); s != "" {
				if r.network = ovpnNetwork(s); r.network == "" {
					return nil, fmt.Errorf("openvpn: remote %s has proto %q, not a client transport", r.host, s)
				}
			}
			remotes = append(remotes, r)
		case "remote-random":
			p["remote_random"] = true
		case "tls-auth":
			wrap = "tls_auth"
			if s := arg(1); s != "" {
				keyDirection = s
			}
		case "tls-crypt":
			wrap = "tls_crypt"
		case "tls-crypt-v2":
			wrap = "tls_crypt_v2"
		case "key-direction":
			keyDirection = arg(0)
		case "cipher":
			p["cipher"] = arg(0)
		case "data-ciphers", "ncp-ciphers":
			var list []any
			for _, c := range strings.Split(arg(0), ":") {
				if c = strings.TrimSpace(c); c != "" {
					list = append(list, c)
				}
			}
			p["data_ciphers"] = list
		case "data-ciphers-fallback":
			p["data_ciphers_fallback"] = arg(0)
		case "auth":
			p["auth"] = arg(0)
		case "verify-x509-name":
			p["server_name"] = arg(0)
			if t := strings.ToLower(arg(1)); t != "" {
				p["server_name_type"] = t
			}
		case "remote-cert-tls":
			p["remote_cert_tls"] = strings.ToLower(arg(0))
		case "tls-version-min":
			p["tls_version_min"] = arg(0)
		case "tun-mtu":
			n, err := strconv.Atoi(arg(0))
			if err != nil || n < 576 || n > 65535 {
				return nil, fmt.Errorf("openvpn: tun-mtu %q is not an MTU", arg(0))
			}
			p["mtu"] = n
		case "comp-lzo":
			mode := strings.ToLower(arg(0))
			if mode == "" {
				mode = "adaptive"
			}
			p["compression_lzo"] = mode
		case "compress":
			mode := strings.ToLower(arg(0))
			if mode == "" {
				mode = "stub"
			}
			p["compression"] = mode
		case "allow-compression":
			p["allow_compression"] = strings.ToLower(arg(0))
		case "ifconfig":
			// Static-key profiles name both tunnel ends: the local address and the peer's.
			p["address"] = arg(0)
			p["peer_address"] = arg(1)
		case "route-nopull":
			p["route_no_pull"] = true
		case "auth-user-pass":
			p["auth_user_pass"] = true
		}
	}
	if inlineTag != "" {
		return nil, fmt.Errorf("openvpn: <%s> is never closed", inlineTag)
	}
	if len(remotes) == 0 {
		return nil, errors.New("openvpn: the profile has no remote")
	}
	for i := range remotes {
		if remotes[i].port == 0 {
			remotes[i].port = port
		}
		if remotes[i].network == "" {
			remotes[i].network = network
		}
	}
	if p["mode"] == "static_key" {
		if _, ok := p["static_key"]; !ok {
			return nil, errors.New("openvpn: a static-key profile needs its key inline (<secret>)")
		}
		if p["address"] == nil || p["address"] == "" || p["peer_address"] == "" {
			return nil, errors.New("openvpn: a static-key profile needs ifconfig <local> <peer>, the two tunnel addresses")
		}
		switch keyDirection {
		case "0":
			p["key_direction"] = "server"
		case "1":
			p["key_direction"] = "client"
		}
	} else {
		if _, ok := p["ca"]; !ok {
			return nil, errors.New("openvpn: the profile has no CA certificate (<ca>), so the server cannot be verified")
		}
		if (p["cert"] == nil) != (p["key"] == nil) {
			return nil, errors.New("openvpn: a client certificate needs its key, and a key its certificate (<cert> and <key>)")
		}
		if p["cert"] == nil && p["auth_user_pass"] == nil {
			return nil, errors.New("openvpn: the profile has neither a client certificate nor auth-user-pass, so the client cannot authenticate")
		}
		if wrap != "" {
			if _, ok := p["control_key"]; !ok {
				return nil, fmt.Errorf("openvpn: %s needs its key inline", strings.ReplaceAll(wrap, "_", "-"))
			}
			p["control_wrap"] = wrap
			if wrap == "tls_auth" {
				switch keyDirection {
				case "0":
					p["control_direction"] = "server"
				case "1":
					p["control_direction"] = "client"
				}
			}
		}
	}
	first := remotes[0]
	p["network"] = first.network
	if len(remotes) > 1 {
		servers := make([]any, 0, len(remotes))
		for _, r := range remotes {
			servers = append(servers, map[string]any{"server": r.host, "port": r.port, "network": r.network})
		}
		p["servers"] = servers
	}
	return &model.Endpoint{
		Name:     first.host,
		Protocol: model.ProtoOpenVPN,
		Engine:   model.EngineSingBox,
		Server:   first.host,
		Port:     first.port,
		Params:   p,
	}, nil
}
