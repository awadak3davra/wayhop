package importer

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// surge.go reads Surge [Proxy] lines, the form Snell is usually handed out in:
//
//	Name = <type>, <host>, <port>, key=value, ...
//
// Field names follow the Surge manual (its Policies pages, one per type). Each line is rewritten
// into the proxyMap the Clash mappers read, so a Surge line and the same proxy written for mihomo
// import to the same connection. Only Snell v6 is mapped here, because Clash has no v6. Options that
// change what goes on the wire and that WayHop cannot carry (Shadow TLS, TUIC v4, TUIC port hopping)
// refuse the line; Surge's client-side options (test-url, tfo, interface, ...) are ignored.
//
// server-cert-fingerprint-sha256 is a certificate pin. The manual (policies/tls.html) gives it as "SHA-256
// fingerprint (64 hexadecimal characters)" that pins the server certificate "instead of the standard
// X.509 validation", which is what sing-box does with a whole-certificate pin; Sub-Store converts it to
// mihomo's `fingerprint`, whose check hashes the whole certificate. So it is read as one, under the
// rules of the other formats' pins (pin.go), and with Surge naming the server's own certificate, the
// Apply review has no condition to add.

// surgeTypes are the type keywords of Surge's [Proxy] section. A line is read as Surge only when its
// type is one of them, so an INI-style "key = a, b" from some other format is not taken for a proxy.
var surgeTypes = map[string]bool{
	"http": true, "https": true, "h2-connect": true, "socks5": true, "socks5-tls": true, "ss": true,
	"snell": true, "vmess": true, "trojan": true, "tuic": true, "tuic-v5": true, "hysteria2": true,
	"masque": true, "anytls": true, "trust-tunnel": true, "ssh": true, "wireguard": true,
	"tailscale": true, "external": true,
}

// surgeFields splits a declaration at the commas outside double quotes (Surge quotes a value that
// contains commas, e.g. alpn="h2,http/1.1") and drops the quotes.
func surgeFields(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(b.String()))
}

// surgeDecl splits one [Proxy] line into its name, lowercased type and the fields after the type.
func surgeDecl(line string) (name, typ string, fields []string, ok bool) {
	name, rest, found := strings.Cut(line, "=")
	name = strings.TrimSpace(name)
	if !found || name == "" || strings.HasPrefix(name, "[") {
		return "", "", nil, false
	}
	fields = surgeFields(rest)
	typ = strings.ToLower(fields[0])
	if !surgeTypes[typ] {
		return "", "", nil, false
	}
	return name, typ, fields[1:], true
}

// looksLikeSurge reports whether text is a Surge profile (it has a [Proxy] section) or starts with a
// [Proxy] declaration.
func looksLikeSurge(text string) bool {
	first := true
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if surgeComment(line) {
			continue
		}
		if strings.EqualFold(line, "[Proxy]") {
			return true
		}
		if first {
			if _, _, _, ok := surgeDecl(line); ok {
				return true
			}
			first = false
		}
	}
	return false
}

func surgeComment(line string) bool {
	return line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//")
}

// ParseSurge imports every proxy declared in a Surge profile's [Proxy] section, or in bare [Proxy]
// lines pasted without a header. Other sections are skipped, and so are the built-in aliases
// (direct, reject) that may sit in [Proxy].
func ParseSurge(text string) (eps []model.Endpoint, errs []string) {
	text = strings.TrimPrefix(text, "\ufeff")
	section := "proxy" // lines before any header are read as [Proxy] lines
	seen := map[string]bool{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if surgeComment(line) {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "proxy" {
			continue
		}
		name, typ, fields, ok := surgeDecl(line)
		if !ok {
			continue
		}
		e, err := surgeEndpoint(name, typ, fields)
		if err == nil {
			e, err = finalize(e, nil)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("surge proxy %q (line %d): %v", name, i+1, err))
			continue
		}
		if e.ID == "" {
			e.ID = genID(e)
		}
		e.ID = uniqueID(e.ID, seen)
		eps = append(eps, *e)
	}
	if len(eps) == 0 && len(errs) == 0 {
		errs = append(errs, "surge: no proxy declarations found")
	}
	return eps, errs
}

// What a Surge proxy line can express (sourceFields): less than the Clash proxy it is converted to.
// No uTLS fingerprint, ECH or multiplex is mapped, so those stay as stored.
var surgeLineFields = sourceFields{params: []string{"password", "method", "plugin", "plugin_opts", "psk", "version",
	"reuse", "network", "obfs_mode", "obfs_host", "mode", "down_mbps", "hop_ports", "hop_interval", "obfs",
	"obfs_password", "uuid"}, tls: []string{"enabled", "type", "sni", "alpn", "insecure"}, pins: true, transport: true}

// parseSurgeSingle is Parse's answer to pasted Surge lines: the one proxy, or a pointer to
// Subscription for several.
func parseSurgeSingle(raw string) (*model.Endpoint, error) {
	eps, errs := ParseSurge(raw)
	switch {
	case len(eps) == 1 && len(errs) == 0:
		return &eps[0], nil
	case len(eps) == 0 && len(errs) > 0:
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return nil, fmt.Errorf("a Surge profile with %d proxies: paste it under Subscription, which lists them to choose from",
		len(eps)+len(errs))
}

// surgeEndpoint maps one declaration. fields[0] is the host and fields[1] the port.
func surgeEndpoint(name, typ string, fields []string) (*model.Endpoint, error) {
	if len(fields) < 2 {
		return nil, errors.New("needs a host and a port")
	}
	s := map[string]string{}
	for _, f := range fields[2:] {
		if k, v, ok := strings.Cut(f, "="); ok {
			s[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if s["shadow-tls-password"] != "" {
		return nil, errors.New("shadow-tls-password: Shadow TLS is not supported")
	}
	// A pin that is not a SHA-256 hash is refused on every line, also on a type without TLS, where a
	// pin is not kept: the line is wrong either way.
	if pin := s["server-cert-fingerprint-sha256"]; pin != "" {
		if err := addCertPins(&model.TLS{}, "server-cert-fingerprint-sha256", pin); err != nil {
			return nil, err
		}
	}
	c := proxyMap{"type": typ, "name": name, "server": fields[0], "port": fields[1],
		"skip-cert-verify": s["skip-cert-verify"], "alpn": s["alpn"]}
	// sni=off (send none) has no sing-box equivalent; the server name is sent instead.
	if sni := s["sni"]; sni != "" && !strings.EqualFold(sni, "off") {
		c["sni"] = sni
	}
	switch typ {
	case "snell":
		if strings.TrimSpace(s["version"]) == "6" {
			return surgeSnellV6(s, c)
		}
		c["psk"], c["version"], c["reuse"] = s["psk"], s["version"], s["reuse"]
		// Snell relays UDP from v3 on; a separate udp-port is a UDP service sing-box cannot reach.
		c["udp"] = strconv.FormatBool(!surgeOtherUDPPort(s, fields[1]))
		c["obfs-opts.mode"], c["obfs-opts.host"] = s["obfs"], s["obfs-host"]
	case "ss":
		c["cipher"], c["password"] = s["encrypt-method"], s["password"]
		if mode := s["obfs"]; mode != "" {
			c["plugin"], c["plugin-opts.mode"], c["plugin-opts.host"] = "obfs", mode, s["obfs-host"]
		}
	case "trojan", "anytls":
		c["password"] = s["password"]
		if truthy(s["ws"]) {
			surgeWS(s, c)
		}
	case "hysteria2":
		c["password"] = s["password"]
		if d := s["download-bandwidth"]; d != "" {
			c["down"] = d
		}
		if hp := s["port-hopping"]; hp != "" {
			c["ports"] = strings.ReplaceAll(hp, ";", ",")
			c["hop-interval"] = s["port-hopping-interval"]
		}
		switch {
		case s["salamander-password"] != "" && s["gecko-password"] != "":
			return nil, errors.New("salamander-password and gecko-password are mutually exclusive")
		case s["salamander-password"] != "":
			c["obfs"], c["obfs-password"] = "salamander", s["salamander-password"]
		case s["gecko-password"] != "":
			c["obfs"], c["obfs-password"] = "gecko", s["gecko-password"]
		}
	case "tuic-v5":
		if s["port-hopping"] != "" {
			return nil, errors.New("TUIC port hopping is not supported")
		}
		c["type"], c["uuid"], c["password"] = "tuic", s["uuid"], s["password"]
	case "tuic":
		return nil, errors.New("TUIC v4 (token) is not supported; sing-box speaks TUIC v5")
	default:
		return nil, fmt.Errorf("type %q is not imported from a Surge line", typ)
	}
	e, err := proxyToEndpoint(c)
	if err != nil {
		return nil, err
	}
	// A pin only means something over TLS (Surge applies it to the protocols carried over TLS or QUIC),
	// so a Shadowsocks or Snell line's is not kept; it was checked above.
	if pin := s["server-cert-fingerprint-sha256"]; pin != "" && e.TLS != nil && e.TLS.Enabled {
		if err := addCertPins(e.TLS, "server-cert-fingerprint-sha256", pin); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// surgeSnellV6 maps a Snell v6 line, which the Clash mapper does not know. v6 derives its traffic
// profile from the PSK and has no obfuscation; mode must match the server's.
func surgeSnellV6(s map[string]string, c proxyMap) (*model.Endpoint, error) {
	port := atoiDefault(c["port"], 0)
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %q out of range (must be 1-65535)", c["port"])
	}
	if s["psk"] == "" {
		return nil, errors.New("snell: missing psk")
	}
	if o := s["obfs"]; o != "" && o != "none" {
		return nil, fmt.Errorf("snell v6 has no obfuscation (obfs=%s)", o)
	}
	params := map[string]any{"version": 6, "psk": s["psk"]}
	switch m := s["mode"]; m {
	case "":
	case "default", "unshaped", "unsafe-raw":
		params["mode"] = m
	default:
		return nil, fmt.Errorf("snell v6 mode %q (want default, unshaped or unsafe-raw)", m)
	}
	if truthy(s["reuse"]) {
		params["reuse"] = true
	}
	if surgeOtherUDPPort(s, c["port"]) {
		params["network"] = "tcp"
	}
	return &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoSnell,
		Server:   c["server"],
		Port:     port,
		Name:     c["name"],
		Enabled:  true,
		Params:   params,
	}, nil
}

// surgeOtherUDPPort reports a udp-port that differs from the TCP port.
func surgeOtherUDPPort(s map[string]string, port string) bool {
	u := strings.TrimSpace(s["udp-port"])
	return u != "" && u != strings.TrimSpace(port)
}

// surgeWS maps Surge's ws, ws-path and ws-headers ("Host:example.com|X-Token:abc") onto the Clash
// ws-opts keys clashTransport reads.
func surgeWS(s map[string]string, c proxyMap) {
	c["network"] = "ws"
	if p := s["ws-path"]; p != "" {
		c["ws-opts.path"] = p
	}
	for _, h := range strings.Split(s["ws-headers"], "|") {
		if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			c["ws-opts.headers.Host"] = strings.TrimSpace(v)
		}
	}
}
