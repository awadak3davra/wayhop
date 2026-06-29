package exporter

import (
	"strings"
	"testing"

	"velinx/internal/importer"
	"velinx/internal/model"
)

// fuzzexporter_protocols is the set of link-form protocols the fuzzer cycles
// through (one per fuzzed `which` selector value). Only protocols that Export
// renders as a share URI ("link") participate in the re-parse assertions; the
// WireGuard/AmneziaWG cases produce a .conf and are exercised separately.
var fuzzexporter_protocols = []model.Protocol{
	model.ProtoVLESS,
	model.ProtoTrojan,
	model.ProtoHysteria2,
	model.ProtoTUIC,
	model.ProtoShadowsocks,
	model.ProtoVMess,
}

// fuzzexporter_transportTypes are the transport.Type values the fuzzer selects
// among (including "" = raw tcp and an unknown value to probe the default arm).
var fuzzexporter_transportTypes = []string{"", "ws", "grpc", "http", "httpupgrade", "bogus"}

// fuzzexporter_tlsTypes are the tls.Type values the fuzzer selects among.
var fuzzexporter_tlsTypes = []string{"tls", "reality", "weird"}

// fuzzexporter_buildEndpoint deterministically constructs a model.Endpoint from
// the fuzzed scalar inputs. `which`/`transport`/`tlsKind` are reduced modulo the
// respective slice lengths so any byte value maps to a valid selector.
func fuzzexporter_buildEndpoint(which, transport, tlsKind uint8, tlsOn, insecure bool, server, name, uuid, password, sni, path string, port int) model.Endpoint {
	proto := fuzzexporter_protocols[int(which)%len(fuzzexporter_protocols)]
	ttype := fuzzexporter_transportTypes[int(transport)%len(fuzzexporter_transportTypes)]
	tlsT := fuzzexporter_tlsTypes[int(tlsKind)%len(fuzzexporter_tlsTypes)]

	e := model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: proto,
		Name:     name,
		Server:   server,
		Port:     port,
		Params:   map[string]any{},
	}

	switch proto {
	case model.ProtoVLESS:
		e.Params["uuid"] = uuid
		if path != "" {
			e.Params["flow"] = path
		}
	case model.ProtoTrojan:
		e.Params["password"] = password
	case model.ProtoHysteria2:
		e.Params["password"] = password
		if path != "" {
			e.Params["obfs"] = "salamander"
			e.Params["obfs_password"] = path
		}
	case model.ProtoTUIC:
		e.Params["uuid"] = uuid
		e.Params["password"] = password
		if path != "" {
			e.Params["congestion_control"] = "bbr"
			e.Params["udp_relay_mode"] = "native"
		}
	case model.ProtoShadowsocks:
		e.Params["method"] = "aes-256-gcm"
		e.Params["password"] = password
	case model.ProtoVMess:
		e.Params["uuid"] = uuid
		e.Params["alter_id"] = 0
		e.Params["security"] = "auto"
	}

	if ttype != "" {
		e.Transport = &model.Transport{Type: ttype, Path: path, Host: sni, ServiceName: path}
	}
	if tlsOn {
		e.TLS = &model.TLS{
			Enabled:     true,
			Type:        tlsT,
			SNI:         sni,
			Insecure:    insecure,
			Fingerprint: "chrome",
			PublicKey:   uuid,
			ShortID:     password,
		}
		if tlsT == "tls" || tlsT == "reality" {
			e.TLS.ALPN = []string{"h2"}
		}
	}
	return e
}

// FuzzExportRoundTrip fuzzes exporter.Export / ShareLink and the
// Export->importer.Parse round-trip. Invariants asserted:
//
//   - Export must never panic on any constructed endpoint, including ones with
//     nil / wrong-typed Params.
//   - For protocols with a share-URI form, importer.Parse on the produced link
//     must never panic, and when it succeeds it must preserve server, port and
//     protocol.
func FuzzExportRoundTrip(f *testing.F) {
	// Seed corpus: representative endpoints spanning every link protocol plus a
	// transport/tls mix. Arguments: which, transport, tlsKind, tlsOn, insecure,
	// server, name, uuid, password, sni, path, port.
	f.Add(uint8(0), uint8(0), uint8(1), true, false, "203.0.113.10", "Reality",
		"11111111-2222-3333-4444-555555555555", "", "www.microsoft.com", "xtls-rprx-vision", 443) // vless+reality
	f.Add(uint8(1), uint8(1), uint8(0), true, false, "1.2.3.4", "Trojan WS",
		"", "s3cret", "cdn.example.com", "/tj", 443) // trojan+ws+tls
	f.Add(uint8(2), uint8(0), uint8(0), true, false, "5.6.7.8", "HY2",
		"", "hpass", "example.org", "ob", 8443) // hysteria2+obfs
	f.Add(uint8(3), uint8(0), uint8(0), true, true, "tuic.example.com", "tuic",
		"tuic-uuid", "tuic-pass", "tuic.example.com", "x", 443) // tuic insecure
	f.Add(uint8(4), uint8(0), uint8(0), false, false, "9.9.9.9", "SS",
		"", "sspw", "", "", 8388) // shadowsocks
	f.Add(uint8(5), uint8(2), uint8(0), true, false, "vm.example.com", "vm grpc",
		"g-uuid", "", "vm.example.com", "GunService", 2096) // vmess+grpc+tls
	// Edge selectors: unknown transport ("bogus"), unknown tls type ("weird"),
	// empty everything, weird port values, unicode name with fragment chars.
	f.Add(uint8(0), uint8(5), uint8(2), true, false, "", "Узел #1", "", "", "", "", 0)
	f.Add(uint8(2), uint8(0), uint8(0), false, false, "[::1]", "v6", "", "p", "", "", 65535)
	f.Add(uint8(1), uint8(0), uint8(0), true, false, "host:with:colons", "weird", "", "p\nx", "s", "/a b", -1)
	f.Add(uint8(4), uint8(0), uint8(0), false, false, "h", "frag#name?q", "", "", "", "", 99999999)

	f.Fuzz(func(t *testing.T, which, transport, tlsKind uint8, tlsOn, insecure bool, server, name, uuid, password, sni, path string, port int) {
		e := fuzzexporter_buildEndpoint(which, transport, tlsKind, tlsOn, insecure, server, name, uuid, password, sni, path, port)

		// 1) Export must not panic.
		r, ok := func() (Result, bool) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Export PANICKED: %v\nendpoint=%+v", rec, e)
				}
			}()
			return Export(e)
		}()

		// 2) ShareLink must not panic and must agree with Export's link form.
		link, linkOK := func() (string, bool) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("ShareLink PANICKED: %v\nendpoint=%+v", rec, e)
				}
			}()
			return ShareLink(e)
		}()

		// ClashConfig must not panic on any endpoint (export symmetry with the
		// importer-side FuzzParseClash); a non-clash-mappable endpoint is skipped,
		// never a crash.
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("ClashConfig PANICKED: %v\nendpoint=%+v", rec, e)
				}
			}()
			_, _ = ClashConfig([]model.Endpoint{e})
		}()

		if !ok {
			// Link protocols always export ok; if not, nothing more to check.
			return
		}
		if r.Kind != "link" {
			// All fuzzexporter_protocols are link-form; conf is unexpected here.
			t.Fatalf("Export kind = %q, want link, for proto=%s", r.Kind, e.Protocol)
		}
		if !linkOK || link != r.Text {
			t.Fatalf("ShareLink mismatch: ok=%v link=%q vs Export text=%q", linkOK, link, r.Text)
		}

		// 3) Re-parsing the produced link must never panic.
		got, perr := func() (*model.Endpoint, error) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("importer.Parse PANICKED: %v\nlink=%q\nendpoint=%+v", rec, link, e)
				}
			}()
			return importer.Parse(link)
		}()
		if perr != nil {
			// A parse error is acceptable (some adversarial inputs yield an
			// unparseable URI); the contract is only "no panic".
			return
		}

		// 4) When parse succeeds, server/port/protocol must be preserved.
		// vmess carries fields in a base64 JSON blob; ss/others carry them in
		// the URI authority. Servers that the URL layer would mangle (colons,
		// brackets, control chars) are out of the "preserve" contract, so only
		// assert when the round-trip kept a non-empty server.
		if got.Protocol != e.Protocol {
			t.Fatalf("protocol changed: got %q want %q\nlink=%q", got.Protocol, e.Protocol, link)
		}
		// Only assert server/port fidelity for "clean" servers: a plain
		// hostname/IPv4 with no characters that the URI authority parser would
		// reinterpret. Adversarial servers (embedded ':' '@' '/' '#' '?' '['
		// space, control bytes, or empty) are excluded — those are not valid
		// endpoint servers and the importer/url layer may legitimately reshape
		// them. The point of THIS assertion is the happy path.
		if fuzzexporter_cleanServer(e.Server) && e.Port > 0 && e.Port <= 65535 {
			if got.Server != e.Server {
				t.Fatalf("server changed: got %q want %q\nlink=%q", got.Server, e.Server, link)
			}
			if got.Port != e.Port {
				t.Fatalf("port changed: got %d want %d\nlink=%q", got.Port, e.Port, link)
			}
		}
	})
}

// fuzzexporter_cleanServer reports whether s is a plain host with no characters
// that the URI authority / base64 layers would legitimately reshape, and is
// thus expected to round-trip verbatim.
func fuzzexporter_cleanServer(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false // control or non-ASCII
		}
		switch r {
		case ':', '@', '/', '#', '?', '[', ']', '%', ' ':
			return false
		}
	}
	return true
}

// FuzzExportOddParams hammers Export with deliberately malformed Params maps
// (nil map, wrong-typed values for keys the encoders read, unmarshalable-ish
// values) across every protocol Export knows, asserting only that Export and
// ShareLink never panic. This isolates the "untrusted Params" surface from the
// round-trip logic above.
func FuzzExportOddParams(f *testing.F) {
	f.Add(uint8(0), 0, 0, "", false) // vless, nil-ish params
	f.Add(uint8(5), 1, 7, "x", true) // vmess with int/float params
	f.Add(uint8(8), 2, 3, "addr", false)

	f.Fuzz(func(t *testing.T, proto uint8, mode int, n int, sv string, nilMap bool) {
		protocols := []model.Protocol{
			model.ProtoVLESS, model.ProtoTrojan, model.ProtoHysteria2, model.ProtoTUIC,
			model.ProtoShadowsocks, model.ProtoVMess, model.ProtoWireGuard, model.ProtoAmneziaWG,
			model.ProtoSOCKS, model.ProtoHTTP, model.ProtoOlcRTC,
		}
		e := model.Endpoint{
			Protocol: protocols[int(proto)%len(protocols)],
			Server:   sv,
			Port:     n,
		}
		if e.Protocol == model.ProtoAmneziaWG {
			e.Engine = model.EngineAmneziaWG
		} else {
			e.Engine = model.EngineSingBox
		}

		if !nilMap {
			// Populate the keys the encoders read with WRONG types to exercise
			// the type-assertion fallbacks (str/intStr/numStr/localAddr).
			e.Params = map[string]any{}
			wrongVals := []any{
				int(n), int64(n), float64(n), int64(n) * 1000, true, nil,
				[]string{sv}, []any{sv, n, nil}, map[string]any{"k": sv}, sv,
			}
			pick := func(i int) any { return wrongVals[((mode+i)%len(wrongVals)+len(wrongVals))%len(wrongVals)] }
			for i, k := range []string{
				"uuid", "password", "flow", "method", "security", "alter_id",
				"obfs", "obfs_password", "congestion_control", "udp_relay_mode",
				"private_key", "peer_public_key", "pre_shared_key", "local_address",
				"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4",
			} {
				e.Params[k] = pick(i)
			}
		}
		// Sometimes a wrong-typed TLS/Transport pointer-free struct.
		if mode%2 == 0 {
			e.TLS = &model.TLS{Enabled: true, Type: sv, SNI: sv, ALPN: []string{sv}}
		}
		if mode%3 == 0 {
			e.Transport = &model.Transport{Type: sv, Path: sv, Host: sv, ServiceName: sv}
		}

		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Export PANICKED on odd params: %v\nendpoint=%+v", rec, e)
			}
		}()
		r, ok := Export(e)
		_, _ = ShareLink(e)
		// If a conf came back, writing it to disk should also be panic-free
		// (it is just a string), and re-parsing it must not panic either.
		if ok && r.Kind == "conf" {
			if _, perr := importer.Parse(r.Text); perr != nil {
				_ = perr // parse error fine; panic is the only failure mode
			}
		}
		if ok && r.Kind == "link" {
			if strings.HasPrefix(r.Text, "vmess://") || strings.Contains(r.Text, "://") {
				_, _ = importer.Parse(r.Text)
			}
		}
	})
}
