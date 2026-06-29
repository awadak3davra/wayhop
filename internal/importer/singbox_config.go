package importer

// sing-box config.json import. This is the INVERSE of internal/generator: the
// generator turns the protocol-agnostic model into a sing-box config (outbounds[]
// + a top-level endpoints[] for native WireGuard); this file reads such a config
// back into model.Endpoints so a pasted sing-box config yields connections and a
// generator.Generate(profile) -> ParseSingbox round-trip reproduces the same
// endpoints (by content). It maps each outbound/endpoint by its "type" using the
// EXACT Params keys generator.outboundFor / endpointFor and importer.go's share-
// link parsers use, so a re-Generate accepts the result unchanged.
//
// It is purely additive: a builtin/non-proxy outbound (direct/block/dns/selector/
// urltest, or any inbound) is silently skipped; an UNKNOWN proxy type is collected
// as an error string and skipped (partial success), and the dispatch in
// subscription.go only fires for a genuine sing-box config (looksLikeSingbox is
// strict — valid JSON object with an outbounds OR endpoints array).

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"velinx/internal/model"
)

// looksLikeSingbox reports whether text is a sing-box config.json: valid JSON whose
// top-level object carries an "outbounds" array OR an "endpoints" array. The check
// is intentionally strict so it never mis-claims a non-sing-box JSON, a base64
// subscription blob, or a share link — none of those is a JSON object with an
// outbounds/endpoints array. (json.Valid rejects a share link / base64 body; the
// type-asserted array presence rejects an unrelated JSON like {"a":1} or a clash
// YAML doc.)
func looksLikeSingbox(text string) bool {
	if !json.Valid([]byte(text)) {
		return false
	}
	// Decode only the two top-level keys we care about, leaving each as RawMessage so
	// a huge config isn't fully materialized just to classify it.
	var probe struct {
		Outbounds *json.RawMessage `json:"outbounds"`
		Endpoints *json.RawMessage `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(text), &probe); err != nil {
		return false // not a JSON object (e.g. a top-level array/number/string)
	}
	return isJSONArray(probe.Outbounds) || isJSONArray(probe.Endpoints)
}

// isJSONArray reports whether raw is present and decodes to a JSON array. A present
// "outbounds": {} (object, not array) or "outbounds": null must NOT qualify.
func isJSONArray(raw *json.RawMessage) bool {
	if raw == nil {
		return false
	}
	var arr []json.RawMessage
	return json.Unmarshal(*raw, &arr) == nil
}

// singboxConfig is the minimal shape we read: the outbounds list and the top-level
// endpoints list (sing-box 1.12+ carries native WireGuard as an endpoints entry —
// see generator.endpointFor). Each entry is left as a generic map so the per-type
// mappers can pull only the fields they need.
type singboxConfig struct {
	Outbounds []map[string]any `json:"outbounds"`
	Endpoints []map[string]any `json:"endpoints"`
}

// builtinOutboundTypes are the non-proxy outbound/inbound types a sing-box config
// carries that DO NOT map to an endpoint. They are expected and skipped silently
// (no error): direct/block/dns are builtins, selector/urltest are groups (handled
// by the model's Group, not Endpoint), and any inbound type leaks in only if the
// caller hands us a malformed config — drop it quietly rather than erroring.
var builtinOutboundTypes = map[string]bool{
	"direct": true, "block": true, "dns": true,
	"selector": true, "urltest": true,
	// inbound types (skipped if they ever appear in the outbounds array)
	"mixed": true, "tun": true, "socks_in": true, "http_in": true,
}

// ParseSingbox parses a sing-box config.json into endpoints, returning a per-entry
// error list. It iterates the outbounds array and the endpoints array, mapping each
// by "type" to a model.Endpoint. Builtin/non-proxy types are skipped silently; an
// unknown proxy type is collected as an error and skipped (partial success).
func ParseSingbox(text string) (eps []model.Endpoint, errs []string) {
	var cfg singboxConfig
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return nil, []string{fmt.Sprintf("singbox: parse config: %v", err)}
	}
	seen := map[string]bool{}
	add := func(e *model.Endpoint) {
		if e.ID == "" {
			e.ID = genID(e)
		}
		e.ID = uniqueID(e.ID, seen)
		if e.Name == "" {
			e.Name = strings.ToUpper(string(e.Protocol)) + " " + e.Server
		}
		e.Enabled = true
		eps = append(eps, *e)
	}

	for i, ob := range cfg.Outbounds {
		typ := sbStr(ob, "type")
		if typ == "" {
			errs = append(errs, fmt.Sprintf("singbox: outbound #%d: missing type", i+1))
			continue
		}
		if builtinOutboundTypes[typ] {
			continue // expected builtin / group / inbound — collect nothing
		}
		e, err := singboxOutboundToEndpoint(typ, ob)
		if err != nil {
			errs = append(errs, fmt.Sprintf("singbox: outbound %q: %v", outboundLabel(ob, i), err))
			continue
		}
		add(e)
	}

	for i, ep := range cfg.Endpoints {
		typ := sbStr(ep, "type")
		// sing-box's top-level endpoints array currently only carries "wireguard"; an
		// empty/absent type defaults to wireguard since that is the only endpoint form
		// the generator emits. An unknown endpoint type is an error.
		if typ != "" && typ != "wireguard" {
			errs = append(errs, fmt.Sprintf("singbox: endpoint %q: unsupported endpoint type %q", outboundLabel(ep, i), typ))
			continue
		}
		e, err := singboxWireGuardEndpoint(ep)
		if err != nil {
			errs = append(errs, fmt.Sprintf("singbox: endpoint %q: %v", outboundLabel(ep, i), err))
			continue
		}
		add(e)
	}

	return eps, errs
}

// outboundLabel returns a stable human label for an outbound/endpoint error: its
// tag if present, else "#N".
func outboundLabel(ob map[string]any, i int) string {
	if tag := sbStr(ob, "tag"); tag != "" {
		return tag
	}
	return "#" + strconv.Itoa(i+1)
}

// singboxOutboundToEndpoint maps one proxy outbound (by type) to a model.Endpoint
// with the EXACT Engine/Protocol/Params keys generator.outboundFor + importer.go's
// parsers use, so a re-Generate round-trips. server/server_port -> Server/Port and
// the tag -> Name for every type.
func singboxOutboundToEndpoint(typ string, ob map[string]any) (*model.Endpoint, error) {
	e := &model.Endpoint{
		Engine: model.EngineSingBox,
		Server: sbStr(ob, "server"),
		Port:   sbInt(ob, "server_port"),
		Name:   sbStr(ob, "tag"),
		Params: map[string]any{},
	}
	switch typ {
	case "vless":
		e.Protocol = model.ProtoVLESS
		e.Params["uuid"] = sbStr(ob, "uuid")
		if f := sbStr(ob, "flow"); f != "" {
			e.Params["flow"] = f
		}
		if pe := sbStr(ob, "packet_encoding"); pe != "" {
			e.Params["packet_encoding"] = pe
		}
		e.Transport = transportFromSingbox(ob)
		e.TLS = tlsFromSingbox(ob, e.Server)
	case "vmess":
		e.Protocol = model.ProtoVMess
		e.Params["uuid"] = sbStr(ob, "uuid")
		e.Params["alter_id"] = sbInt(ob, "alter_id")
		if sec := sbStr(ob, "security"); sec != "" {
			e.Params["security"] = sec
		}
		e.Transport = transportFromSingbox(ob)
		e.TLS = tlsFromSingbox(ob, e.Server)
	case "trojan":
		e.Protocol = model.ProtoTrojan
		e.Params["password"] = sbStr(ob, "password")
		e.Transport = transportFromSingbox(ob)
		e.TLS = tlsFromSingbox(ob, e.Server)
	case "shadowsocks":
		e.Protocol = model.ProtoShadowsocks
		e.Params["method"] = sbStr(ob, "method")
		e.Params["password"] = sbStr(ob, "password")
		if sbBool(ob, "udp_over_tcp") {
			e.Params["udp_over_tcp"] = true
		}
		if pl := sbStr(ob, "plugin"); pl != "" {
			e.Params["plugin"] = pl
			if po := sbStr(ob, "plugin_opts"); po != "" {
				e.Params["plugin_opts"] = po
			}
		}
	case "hysteria2":
		e.Protocol = model.ProtoHysteria2
		e.Params["password"] = sbStr(ob, "password")
		// obfs is a nested object {type, password} in sing-box; the model flattens it
		// to obfs / obfs_password (the keys generator.outboundFor reads back).
		if obfs, ok := ob["obfs"].(map[string]any); ok {
			if t := sbStr(obfs, "type"); t != "" {
				e.Params["obfs"] = t
			}
			if pw := sbStr(obfs, "password"); pw != "" {
				e.Params["obfs_password"] = pw
			}
		}
		// server_ports ("start:end" form) -> hop_ports ("start-end"), the importer's
		// spelling that generator.singBoxPortRange converts back.
		if hp := hopPortsFromSingbox(ob["server_ports"]); hp != "" {
			e.Params["hop_ports"] = hp
		}
		e.TLS = tlsFromSingbox(ob, e.Server)
		if e.TLS == nil {
			// Hysteria2 always runs over QUIC+TLS; the generator emits a tls block only
			// when one is present, but a hand-written hy2 outbound may omit it. Synthesize
			// a minimal enabled TLS so the re-generated endpoint stays a valid hy2.
			e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: e.Server}
		}
	case "tuic":
		e.Protocol = model.ProtoTUIC
		e.Params["uuid"] = sbStr(ob, "uuid")
		e.Params["password"] = sbStr(ob, "password")
		if cc := sbStr(ob, "congestion_control"); cc != "" {
			e.Params["congestion_control"] = cc
		}
		if m := sbStr(ob, "udp_relay_mode"); m != "" {
			e.Params["udp_relay_mode"] = m
		}
		if sbBool(ob, "udp_over_stream") {
			e.Params["udp_over_stream"] = true
		}
		if hb := sbStr(ob, "heartbeat"); hb != "" {
			e.Params["heartbeat"] = hb
		}
		if sbBool(ob, "zero_rtt_handshake") {
			e.Params["zero_rtt_handshake"] = true
		}
		e.TLS = tlsFromSingbox(ob, e.Server)
		if e.TLS == nil {
			e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: e.Server}
		}
	case "socks":
		e.Protocol = model.ProtoSOCKS
		if u := sbStr(ob, "username"); u != "" {
			e.Params["username"] = u
		}
		if pw := sbStr(ob, "password"); pw != "" {
			e.Params["password"] = pw
		}
	case "http":
		e.Protocol = model.ProtoHTTP
		if u := sbStr(ob, "username"); u != "" {
			e.Params["username"] = u
		}
		if pw := sbStr(ob, "password"); pw != "" {
			e.Params["password"] = pw
		}
		e.TLS = tlsFromSingbox(ob, e.Server)
	default:
		return nil, fmt.Errorf("unsupported outbound type %q", typ)
	}
	return e, nil
}

// singboxWireGuardEndpoint maps a top-level sing-box endpoints[] "wireguard" entry
// to a ProtoWireGuard model.Endpoint, the inverse of generator.endpointFor. The
// endpoint carries the interface private_key + address (-> local_address) + mtu; its
// single (first) peer carries server/port, public_key (-> peer_public_key), optional
// pre_shared_key, reserved and persistent_keepalive_interval (-> persistent_keepalive).
func singboxWireGuardEndpoint(ep map[string]any) (*model.Endpoint, error) {
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoWireGuard,
		Name:     sbStr(ep, "tag"),
		Params:   map[string]any{},
	}
	priv := sbStr(ep, "private_key")
	if priv == "" {
		return nil, fmt.Errorf("wireguard endpoint: missing private_key")
	}
	e.Params["private_key"] = priv

	if la, ok := ep["address"]; ok {
		e.Params["local_address"] = anyToStringSlice(la)
	}
	if mtu := sbInt(ep, "mtu"); mtu > 0 {
		e.MTU = mtu
	}

	peers, _ := ep["peers"].([]any)
	if len(peers) == 0 {
		return nil, fmt.Errorf("wireguard endpoint: no peers")
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("wireguard endpoint: malformed peer")
	}
	e.Server = sbStr(peer, "address")
	e.Port = sbInt(peer, "port")
	pub := sbStr(peer, "public_key")
	if pub == "" {
		return nil, fmt.Errorf("wireguard endpoint: peer missing public_key")
	}
	e.Params["peer_public_key"] = pub
	if psk := sbStr(peer, "pre_shared_key"); psk != "" {
		e.Params["pre_shared_key"] = psk
	}
	if r, ok := peer["reserved"]; ok {
		e.Params["reserved"] = r
	}
	if ka := sbInt(peer, "persistent_keepalive_interval"); ka > 0 {
		e.PersistentKeepalive = ka
	}
	return e, nil
}

// transportFromSingbox reads an outbound's "transport" block back into a
// model.Transport, the inverse of generator.transportJSON. ws -> ws (path,
// headers.Host -> Host), grpc -> grpc (service_name), http -> http (path, host[0]),
// httpupgrade -> httpupgrade (path, host). Returns nil when no transport is present.
func transportFromSingbox(ob map[string]any) *model.Transport {
	t, ok := ob["transport"].(map[string]any)
	if !ok {
		return nil
	}
	typ := sbStr(t, "type")
	if typ == "" {
		return nil
	}
	tr := &model.Transport{Type: typ}
	switch typ {
	case "ws":
		tr.Path = sbStr(t, "path")
		if hdrs, ok := t["headers"].(map[string]any); ok {
			tr.Host = sbStr(hdrs, "Host")
		}
	case "grpc":
		tr.ServiceName = sbStr(t, "service_name")
	case "http":
		tr.Path = sbStr(t, "path")
		// host is a string LIST in sing-box (domain-fronting round-robin); the model
		// carries a single comma-joined Host, so join the list back.
		tr.Host = joinHosts(t["host"])
	case "httpupgrade":
		tr.Path = sbStr(t, "path")
		tr.Host = sbStr(t, "host") // httpupgrade host is a single string
	default:
		// An unknown transport type round-trips as-is (type only); generator only emits
		// the four above, so this only happens for a hand-written config.
	}
	return tr
}

// tlsFromSingbox reads an outbound's "tls" block back into a model.TLS, the inverse
// of generator.tlsJSON. server_name -> SNI, insecure, alpn, utls.fingerprint ->
// Fingerprint, reality{public_key -> PublicKey, short_id -> ShortID} -> Type
// "reality". Returns nil when tls is absent or not enabled.
func tlsFromSingbox(ob map[string]any, server string) *model.TLS {
	tl, ok := ob["tls"].(map[string]any)
	if !ok || !sbBool(tl, "enabled") {
		return nil
	}
	t := &model.TLS{Enabled: true, Type: "tls"}
	t.SNI = sbStr(tl, "server_name")
	if t.SNI == "" {
		t.SNI = server
	}
	if sbBool(tl, "insecure") {
		t.Insecure = true
	}
	if alpn := anyToStringSlice(tl["alpn"]); len(alpn) > 0 {
		t.ALPN = alpn
	}
	if utls, ok := tl["utls"].(map[string]any); ok {
		if fp := sbStr(utls, "fingerprint"); fp != "" {
			t.Fingerprint = fp
		}
	}
	if reality, ok := tl["reality"].(map[string]any); ok && sbBool(reality, "enabled") {
		t.Type = "reality"
		t.PublicKey = sbStr(reality, "public_key")
		t.ShortID = sbStr(reality, "short_id")
	}
	return t
}

// hopPortsFromSingbox converts a sing-box server_ports value (a list of "start:end"
// range strings, or a single "443:443") back into the importer's hop_ports spelling
// (comma-joined "start-end"), which generator.singBoxPortRange converts forward.
func hopPortsFromSingbox(v any) string {
	ranges := anyToStringSlice(v)
	if len(ranges) == 0 {
		return ""
	}
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		lo, hi, ok := strings.Cut(r, ":")
		if !ok {
			out = append(out, r)
			continue
		}
		if lo == hi {
			out = append(out, lo) // "443:443" -> "443"
		} else {
			out = append(out, lo+"-"+hi)
		}
	}
	return strings.Join(out, ",")
}

// anyToStringSlice coerces a JSON value into a []string, tolerating both a single
// string and a []any of strings (the shape a json.Unmarshal of a string array
// produces). Non-string elements are dropped.
func anyToStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			if s, ok := it.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// joinHosts collapses a sing-box http-transport host value (a string list) into the
// single comma-separated Host the model carries (generator.splitHosts re-splits it).
func joinHosts(v any) string {
	return strings.Join(anyToStringSlice(v), ",")
}

// --- map[string]any accessors (the config is decoded into generic maps) ---

// sbStr reads a string field from a decoded sing-box map, returning "" when absent
// or not a string.
func sbStr(m map[string]any, k string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

// sbInt reads an integer field, tolerating the float64 a JSON number decodes to (as
// well as a native int / json.Number). Returns 0 when absent or unparseable.
func sbInt(m map[string]any, k string) int {
	switch t := m[k].(type) {
	case float64:
		// Reject out-of-int32-range floats (incl. NaN/Inf) instead of overflowing the
		// int(t) conversion to a junk value on 32-bit router arches — mirrors asInt. A
		// real port/MTU/alter_id is tiny, so anything past MaxInt32 is bogus.
		if t < math.MinInt32 || t > math.MaxInt32 {
			return 0
		}
		return int(t)
	case int:
		return t
	case json.Number:
		if n, err := t.Int64(); err == nil {
			if n < math.MinInt32 || n > math.MaxInt32 {
				return 0
			}
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n
		}
	}
	return 0
}

// sbBool reads a boolean field, tolerating the bool / "true" / "1" shapes a value
// can take in a JSON config.
func sbBool(m map[string]any, k string) bool {
	switch t := m[k].(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	}
	return false
}
