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

	"wayhop/internal/model"
)

// Endpoint numeric bounds, mirrored from model/validate.go (minMTU/maxMTU there) so a malformed
// sing-box config is rejected at the import boundary rather than persisted to poison every Apply.
const sbMinMTU, sbMaxMTU = 576, 9200

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
	eps, errs, _ = parseSingbox(text)
	return eps, errs
}

// What a sing-box config can express (sourceFields), across the outbound and endpoint types it reads:
// the params singboxOutboundFields and the 1.14 types (Snell, OpenVPN, OpenConnect, SSH) write, the
// whole TLS block with fragmenting and both kinds of pin, the transport, multiplex, and a WireGuard
// endpoint's MTU and keepalive as the top-level knobs.
var singboxFields = sourceFields{params: []string{"uuid", "alter_id", "security", "flow", "packet_encoding",
	"password", "method", "plugin", "plugin_opts", "udp_over_tcp", "up_mbps", "down_mbps", "hop_ports", "obfs",
	"obfs_password", "obfs_min_packet_size", "obfs_max_packet_size", "hop_interval", "hop_interval_max", "bbr_profile",
	model.ParamQUICInitialPacketSize, model.ParamQUICDisablePMTUD, "disable_chrome_parrot", "congestion_control",
	"udp_relay_mode", "heartbeat", "zero_rtt_handshake", "udp_over_stream", "username",
	"private_key", "peer_public_key", "pre_shared_key", "local_address", "reserved", "peers",
	"psk", "version", "reuse", "userkey", "network", "obfs_mode", "obfs_host", "mode",
	"address", "auth_user_pass", "ca", "cert", "key", "control_wrap", "control_direction", "control_key", "data_ciphers",
	"data_ciphers_fallback", "mtu", "peer_address", "remote_random", "route_no_pull", "servers", "static_key",
	"key_direction", "cipher", "server_name", "server_name_type", "remote_cert_tls", "tls_version_min", "auth",
	"compression", "compression_lzo", "allow_compression",
	"no_udp", "server_cert", "totp_secret", "flavor", "auth_group",
	"user", "private_key_passphrase", "client_version", "host_key", "mac", "kex_algorithm"},
	tls: append(append([]string{}, linkTLSFields...), "fragment", "record_fragment"), pins: true, transport: true,
	mtu: true, keepalive: true, multiplex: true}

// parseSingbox is ParseSingbox with its notes: a multiplex block it kept differently or not at all.
func parseSingbox(text string) (eps []model.Endpoint, errs, notes []string) {
	var cfg singboxConfig
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return nil, []string{fmt.Sprintf("singbox: parse config: %v", err)}, nil
	}
	seen := map[string]bool{}
	// Bound the typed numeric fields at the import boundary (mirrors model/validate.go). The store
	// persist path does NOT re-validate, so an out-of-range value would be durably persisted and then
	// FATAL every future Apply. Returns a non-nil error to skip the endpoint with a per-entry message.
	boundsCheck := func(e *model.Endpoint) error {
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("port %d out of range (must be 1-65535)", e.Port)
		}
		if e.MTU != 0 && (e.MTU < sbMinMTU || e.MTU > sbMaxMTU) {
			return fmt.Errorf("mtu %d out of range (%d-%d)", e.MTU, sbMinMTU, sbMaxMTU)
		}
		if e.PersistentKeepalive != 0 && (e.PersistentKeepalive < 1 || e.PersistentKeepalive > 65535) {
			return fmt.Errorf("persistent_keepalive %d out of range (1-65535)", e.PersistentKeepalive)
		}
		return nil
	}
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
		if err := boundsCheck(e); err != nil {
			errs = append(errs, fmt.Sprintf("singbox: outbound %q: %v", outboundLabel(ob, i), err))
			continue
		}
		// Verbatim, then through the checks the save applies: a block the core would refuse, or one on
		// an outbound that has no such field, is not imported, and the note says so.
		var note string
		e.Multiplex, note = model.NormalizeMultiplex(e.Protocol, multiplexFromSingbox(ob))
		if note != "" {
			notes = append(notes, fmt.Sprintf("singbox: outbound %q: %s", outboundLabel(ob, i), note))
		}
		add(e)
	}

	for i, ep := range cfg.Endpoints {
		typ := sbStr(ep, "type")
		// The generator emits wireguard, openvpn-client and openconnect endpoints; an empty type
		// is wireguard, the form older configs used. Any other endpoint type is an error.
		var e *model.Endpoint
		var err error
		switch typ {
		case "", "wireguard":
			e, err = singboxWireGuardEndpoint(ep)
		case "openvpn-client":
			e, err = singboxOpenVPNEndpoint(ep)
		case "openconnect":
			e, err = singboxOpenConnectEndpoint(ep)
		default:
			errs = append(errs, fmt.Sprintf("singbox: endpoint %q: unsupported endpoint type %q", outboundLabel(ep, i), typ))
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("singbox: endpoint %q: %v", outboundLabel(ep, i), err))
			continue
		}
		if err := boundsCheck(e); err != nil {
			errs = append(errs, fmt.Sprintf("singbox: endpoint %q: %v", outboundLabel(ep, i), err))
			continue
		}
		add(e)
	}

	return eps, errs, notes
}

// multiplexFromSingbox reads an outbound's "multiplex" block as sing-box spells it (the generator's
// multiplexJSON), nil when there is none. The caller normalises it.
func multiplexFromSingbox(ob map[string]any) *model.Multiplex {
	mx, ok := ob["multiplex"].(map[string]any)
	if !ok {
		return nil
	}
	m := &model.Multiplex{
		Enabled:        sbBool(mx, "enabled"),
		Protocol:       sbStr(mx, "protocol"),
		MaxConnections: sbInt(mx, "max_connections"),
		MinStreams:     sbInt(mx, "min_streams"),
		MaxStreams:     sbInt(mx, "max_streams"),
		Padding:        sbBool(mx, "padding"),
	}
	if b, ok := mx["brutal"].(map[string]any); ok && sbBool(b, "enabled") {
		m.Brutal = &model.Brutal{Enabled: true, UpMbps: sbInt(b, "up_mbps"), DownMbps: sbInt(b, "down_mbps")}
	}
	return m
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
	// An ECH config read from a file is on the machine the config came from, and the router cannot
	// read it; an inline config wins over the path in sing-box, so only a path alone is refused.
	if tl, ok := ob["tls"].(map[string]any); ok {
		if ech, ok := tl["ech"].(map[string]any); ok && sbBool(ech, "enabled") && sbText(ech, "config") == "" {
			if err := sbRefuseFiles(ech, "config_path"); err != nil {
				return nil, fmt.Errorf("tls.ech: %w", err)
			}
		}
	}
	e, err := singboxOutboundFields(typ, ob)
	if err != nil {
		return nil, err
	}
	if e.TLS != nil {
		e.TLS.ECH = settleECH(e.TLS.ECH, e.TLS.Type)
		if tl, ok := ob["tls"].(map[string]any); ok {
			if err := singboxPins(tl, e.TLS); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}

// singboxOutboundFields is singboxOutboundToEndpoint's per-type mapping.
func singboxOutboundFields(typ string, ob map[string]any) (*model.Endpoint, error) {
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
			for _, k := range []string{"min_packet_size", "max_packet_size"} {
				if n := sbInt(obfs, k); n > 0 {
					e.Params["obfs_"+k] = n
				}
			}
		}
		// The 1.14 additions (generator/hysteria2_114.go) read back the same way.
		for _, k := range []string{"hop_interval", "hop_interval_max", "bbr_profile"} {
			if v := sbStr(ob, k); v != "" {
				e.Params[k] = v
			}
		}
		if sbBool(ob, "disable_chrome_parrot") {
			e.Params["disable_chrome_parrot"] = true
		}
		sbQUICTuning(ob, e.Params)
		// server_ports ("start:end" form) -> hop_ports ("start-end"), the importer's
		// spelling that generator.singBoxPortRange converts back.
		if hp := hopPortsFromSingbox(ob["server_ports"]); hp != "" {
			e.Params["hop_ports"] = hp
		}
		// Bandwidth hints (congestion-window sizing): the generator emits up_mbps/down_mbps when set,
		// so read them back — else a Generate->import round-trip reverts to unbounded sizing.
		if up := sbInt(ob, "up_mbps"); up > 0 {
			e.Params["up_mbps"] = up
		}
		if down := sbInt(ob, "down_mbps"); down > 0 {
			e.Params["down_mbps"] = down
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
		sbQUICTuning(ob, e.Params)
		e.TLS = tlsFromSingbox(ob, e.Server)
		if e.TLS == nil {
			e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: e.Server}
		}
	case "anytls":
		// AnyTLS is a first-class protocol (parseAnyTLS / clashAnyTLS / the exporter + generator all
		// support it); without this case a generator-emitted anytls outbound hit default and was
		// rejected, breaking the Generate->ParseSingbox round-trip. Mirror trojan (password + TLS),
		// synthesizing a minimal enabled TLS since AnyTLS is TLS-by-definition.
		e.Protocol = model.ProtoAnyTLS
		e.Params["password"] = sbStr(ob, "password")
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
	case "snell":
		if err := fillSnellFromSingbox(e, ob); err != nil {
			return nil, err
		}
	case "ssh":
		if err := fillSSHFromSingbox(e, ob); err != nil {
			return nil, err
		}
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
	if r := sbReserved(peer["reserved"]); r != nil {
		e.Params["reserved"] = r
	}
	if ka := sbInt(peer, "persistent_keepalive_interval"); ka > 0 {
		e.PersistentKeepalive = ka
	}
	// Multi-peer mesh: reconstruct the structured peer list (Params["peers"]) so a re-Generate
	// re-emits EVERY peer — the generator's wgPeers/endpointFor uses it when len>1. Without this a
	// multi-[Peer] sing-box endpoint collapsed to peers[0] on inverse import and the mesh was lost.
	// The top-level Server/peer_public_key above stay set from peers[0] for the single-peer fallback.
	if len(peers) > 1 {
		list := make([]map[string]any, 0, len(peers))
		for _, pv := range peers {
			pm, ok := pv.(map[string]any)
			if !ok {
				continue
			}
			entry := map[string]any{}
			if a := sbStr(pm, "address"); a != "" {
				entry["server"] = a
			}
			if pt := sbInt(pm, "port"); pt > 0 {
				entry["port"] = pt
			}
			if pk := sbStr(pm, "public_key"); pk != "" {
				entry["public_key"] = pk
			}
			if psk := sbStr(pm, "pre_shared_key"); psk != "" {
				entry["pre_shared_key"] = psk
			}
			if aips := anyToStringSlice(pm["allowed_ips"]); len(aips) > 0 {
				entry["allowed_ips"] = aips
			}
			if ka := sbInt(pm, "persistent_keepalive_interval"); ka > 0 {
				entry["persistent_keepalive"] = ka
			}
			if r := sbReserved(pm["reserved"]); r != nil {
				entry["reserved"] = r
			}
			list = append(list, entry)
		}
		e.Params["peers"] = list
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
		// Early data: the model carries it the way the share links do, as "?ed=N" on the path, and
		// the generator turns that back into max_early_data + the Sec-WebSocket-Protocol header. Fold
		// it in so a sing-box outbound (the generator's own output included) keeps its early data on
		// import. Only the Xray-compatible header is expressible in that form; another header name
		// would come back as Sec-WebSocket-Protocol, so the field is left out rather than changed.
		if med := sbInt(t, "max_early_data"); med > 0 && !strings.Contains(tr.Path, "?") &&
			strings.EqualFold(sbStr(t, "early_data_header_name"), "Sec-WebSocket-Protocol") {
			tr.Path += "?ed=" + strconv.Itoa(med)
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
	// TLS handshake / record fragmentation (anti-DPI): the generator emits these for non-Reality
	// TLS outbounds (tlsJSON), so the inverse must read them back or an export→re-import silently
	// disables an explicitly-configured anti-censorship toggle. Reading unconditionally is safe —
	// the generator never emits them alongside a reality block.
	if sbBool(tl, "fragment") {
		t.Fragment = true
	}
	if sbBool(tl, "record_fragment") {
		t.RecordFragment = true
	}
	// Encrypted Client Hello, settled against the protocol and Reality by the caller (settleECH).
	t.ECH = singboxECH(tl)
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

// sbReserved validates a WireGuard/WARP `reserved` field from a JSON-decoded peer map into a
// []int of EXACTLY 3 bytes in 0-255, returning nil for any other shape. sing-box decodes reserved
// as []uint8, so an out-of-range or wrong-length value FATALs the core at config load — and the
// store persist path never re-validates, so an unvalidated passthrough would be durably saved and
// then break EVERY future Apply. Mirrors the share-link/clash importers' parseReserved (which the
// sing-box importer previously bypassed by copying the raw value verbatim). JSON numbers arrive as
// float64 (or json.Number/int/string), so accept each via sbInt-style coercion and range-check.
func sbReserved(v any) []int {
	arr, ok := v.([]any)
	if !ok || len(arr) != 3 {
		return nil
	}
	out := make([]int, 0, 3)
	for _, e := range arr {
		n := sbInt(map[string]any{"v": e}, "v")
		if n < 0 || n > 255 {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// sbQUICTuning reads the QUIC fields sing-box 1.14 gives the hysteria2 and tuic outbounds
// (model.QUICTuningOf) back into params, so a Generate->import round-trip keeps them. A packet size
// quic-go would not use as given is brought as the size the source config ran with
// (model.QUICEffectiveInitialPacketSize), which saving accepts.
func sbQUICTuning(ob map[string]any, params map[string]any) {
	if n := model.QUICEffectiveInitialPacketSize(sbInt(ob, model.ParamQUICInitialPacketSize)); n > 0 {
		params[model.ParamQUICInitialPacketSize] = n
	}
	if sbBool(ob, model.ParamQUICDisablePMTUD) {
		params[model.ParamQUICDisablePMTUD] = true
	}
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
