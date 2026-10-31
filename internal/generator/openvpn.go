package generator

import (
	"fmt"
	"net/netip"
	"strings"

	"wayhop/internal/model"
)

// openvpnMinMinor is the first sing-box 1.x minor with the openvpn-client endpoint.
const openvpnMinMinor = 14

// openvpnEndpointFor renders an OpenVPN connection (see the param schema at the top of
// internal/importer/openvpn.go) as sing-box's top-level openvpn-client endpoint.
//
// coreVersion is the core the config is for. A known core older than 1.14 has no such endpoint and
// would refuse the whole config, so the connection is refused here by name instead; an unknown
// version ("") renders, because the capability gate has already required a 1.14+ core before the
// connection could be enabled.
func openvpnEndpointFor(e *model.Endpoint, coreVersion string) (map[string]any, error) {
	if coreVersion != "" && coreMinor(coreVersion) < openvpnMinMinor {
		return nil, fmt.Errorf("OpenVPN needs sing-box 1.%d or newer; this core is %s", openvpnMinMinor,
			strings.TrimSpace(strings.SplitN(coreVersion, "\n", 2)[0]))
	}
	p := e.Params
	ep := map[string]any{"type": "openvpn-client", "tag": e.ID}
	network := str(p, "network")
	if network != "tcp" {
		network = "udp"
	}
	ep["network"] = network
	if servers, ok := p["servers"].([]any); ok && len(servers) > 1 {
		var list []map[string]any
		for _, s := range servers {
			m, _ := s.(map[string]any)
			host := str(m, "server")
			port := intp(m, "port")
			if host == "" || port < 1 || port > 65535 {
				return nil, fmt.Errorf("server list entry %v is not host:port", s)
			}
			entry := map[string]any{"server": host, "server_port": port}
			if n := str(m, "network"); n == "tcp" || n == "udp" {
				entry["network"] = n
			}
			list = append(list, entry)
		}
		ep["servers"] = list
		if boolp(p, "remote_random") {
			ep["remote_random"] = true
		}
	} else {
		ep["server"], ep["server_port"] = e.Server, e.Port
	}

	if str(p, "mode") == "static_key" {
		ep["mode"] = "static_key"
		ep["static_key"] = str(p, "static_key")
		if d := str(p, "key_direction"); d == "server" || d == "client" {
			ep["key_direction"] = d
		}
		local, err := openvpnPrefix(str(p, "address"))
		if err != nil {
			return nil, fmt.Errorf("static-key address: %w", err)
		}
		ep["address"] = []string{local}
		peer := str(p, "peer_address")
		if a, err := netip.ParseAddr(peer); err != nil {
			return nil, fmt.Errorf("static-key peer address %q is not an IP address", peer)
		} else if a.Is4() {
			ep["peer_address"] = peer
		} else {
			ep["peer_address_ipv6"] = peer
		}
		if c := str(p, "cipher"); c != "" {
			ep["cipher"] = c
		}
	} else {
		// A profile that signs in with credentials and has none is rendered anyway: this exit is
		// refused by its server, and the review says so (endpoint.credential). Failing here would
		// fail the config every other connection shares.
		if u := str(p, "username"); u != "" {
			ep["username"], ep["password"] = u, str(p, "password")
		}
		tls := map[string]any{"certificate": str(p, "ca")}
		if c := str(p, "cert"); c != "" {
			tls["client_certificate"], tls["client_key"] = c, str(p, "key")
		}
		if n := str(p, "server_name"); n != "" {
			tls["server_name"] = n
			if t := str(p, "server_name_type"); t == "subject" || t == "name" || t == "name-prefix" {
				tls["server_name_type"] = t
			}
		}
		if r := str(p, "remote_cert_tls"); r == "server" || r == "client" || r == "none" {
			tls["remote_certificate_tls"] = r
		}
		if v := str(p, "tls_version_min"); v == "1.0" || v == "1.1" || v == "1.2" || v == "1.3" {
			tls["version_min"] = v
		}
		if w := str(p, "control_wrap"); w == "tls_auth" || w == "tls_crypt" || w == "tls_crypt_v2" {
			wrap := map[string]any{"type": w, "key": str(p, "control_key")}
			if d := str(p, "control_direction"); w == "tls_auth" && (d == "server" || d == "client") {
				wrap["direction"] = d
			}
			tls["control_wrap"] = wrap
		}
		ep["tls"] = tls
		if list, ok := p["data_ciphers"].([]any); ok && len(list) > 0 {
			var ciphers []string
			for _, c := range list {
				if s, ok := c.(string); ok && s != "" {
					ciphers = append(ciphers, s)
				}
			}
			ep["data_ciphers"] = ciphers
		}
		// In TLS mode a profile's `cipher` is what OpenVPN falls back to with a server that cannot
		// negotiate; sing-box's own `cipher` field exists only for static-key mode.
		if f := str(p, "data_ciphers_fallback"); f != "" {
			ep["data_ciphers_fallback"] = f
		} else if c := str(p, "cipher"); c != "" {
			ep["data_ciphers_fallback"] = c
		}
	}
	if a := str(p, "auth"); a != "" {
		ep["auth"] = a
	}
	if m := intp(p, "mtu"); m > 0 {
		ep["mtu"] = m
	}
	for param, field := range map[string]string{
		"compression": "compression", "compression_lzo": "compression_lzo", "allow_compression": "allow_compression",
	} {
		if v := str(p, param); v != "" {
			ep[field] = v
		}
	}
	if boolp(p, "route_no_pull") {
		ep["route_no_pull"] = true
	}
	return ep, nil
}

// openvpnPrefix turns an ifconfig address into the single-host prefix sing-box's address list wants.
func openvpnPrefix(s string) (string, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address", s)
	}
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}
