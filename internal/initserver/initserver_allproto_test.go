package initserver

import (
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// allProtoNew is the set of protocols this lane added (AmneziaWG + Reality are
// covered by initserver_test.go / script_more_test.go and stay untouched).
var allProtoNew = []struct {
	id          string
	marker      string // the WR_PROTO marker its fragment must print
	fragment    string // a banner line unique to the fragment
	scheme      string // the client share-link scheme the fragment emits
	wantProto   model.Protocol
	wantTLS     bool // whether the imported endpoint must carry TLS
	wantSelfTLS bool // whether the link must mark the cert insecure (self-signed)
}{
	{ProtoVMess, "WR_PROTO=vmess", "# ---- sing-box VMess", "vmess://", model.ProtoVMess, true, true},
	{ProtoTrojan, "WR_PROTO=trojan", "# ---- sing-box Trojan", "trojan://", model.ProtoTrojan, true, true},
	{ProtoShadowsocks, "WR_PROTO=shadowsocks", "# ---- sing-box Shadowsocks", "ss://", model.ProtoShadowsocks, false, false},
	{ProtoHysteria2, "WR_PROTO=hysteria2", "# ---- sing-box Hysteria2", "hysteria2://", model.ProtoHysteria2, true, true},
	{ProtoTUIC, "WR_PROTO=tuic", "# ---- sing-box TUIC", "tuic://", model.ProtoTUIC, true, true},
	{ProtoAnyTLS, "WR_PROTO=anytls", "# ---- sing-box AnyTLS", "anytls://", model.ProtoAnyTLS, true, true},
	{ProtoSnell, "WR_PROTO=snell", "# ---- sing-box Snell", "wayhop-snell = snell, ", model.ProtoSnell, false, false},
}

// TestNewProtosRegistered confirms each new protocol has a catalog Option with a
// non-empty script and a detector, and ValidOption accepts its id.
func TestNewProtosRegistered(t *testing.T) {
	for _, p := range allProtoNew {
		if !ValidOption(p.id) {
			t.Errorf("%s: not a valid option", p.id)
		}
		o := optionByID(p.id)
		if o == nil {
			t.Fatalf("%s: optionByID returned nil", p.id)
		}
		if o.Script == "" {
			t.Errorf("%s: empty Script", p.id)
		}
		if o.Detect == nil {
			t.Errorf("%s: nil Detect", p.id)
		}
		if o.Name == "" {
			t.Errorf("%s: empty Name", p.id)
		}
	}
}

// TestNewProtosBuildScriptIncludesFragment confirms selecting a protocol emits its
// fragment (banner + marker), reuses the sing-box install, and that an unselected
// protocol's fragment is absent.
func TestNewProtosBuildScriptIncludesFragment(t *testing.T) {
	for _, p := range allProtoNew {
		s := BuildScript([]string{p.id}, "203.0.113.9")
		for _, want := range []string{p.fragment, p.marker, "WR_CLIENT_CONFIG=", "command -v sing-box"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: BuildScript missing %q", p.id, want)
			}
		}
		// The emitted client-config line uses this protocol's scheme.
		if !strings.Contains(s, "WR_CLIENT_CONFIG="+p.scheme) {
			t.Errorf("%s: BuildScript should emit a %s client link", p.id, p.scheme)
		}
		// AmneziaWG and Reality fragments must NOT appear for a single new-proto build.
		if strings.Contains(s, "# ---- AmneziaWG ----") {
			t.Errorf("%s: unexpectedly contains the AmneziaWG fragment", p.id)
		}
	}
}

// TestNewProtosTLSWhereNeeded confirms TLS-bearing protocols write a sing-box TLS
// inbound (and reuse the self-signed cert), while Shadowsocks does not.
func TestNewProtosTLSWhereNeeded(t *testing.T) {
	for _, p := range allProtoNew {
		s := BuildScript([]string{p.id}, "")
		hasTLS := strings.Contains(s, `"tls":{"enabled":true`)
		if hasTLS != p.wantTLS {
			t.Errorf("%s: TLS inbound present=%v, want %v", p.id, hasTLS, p.wantTLS)
		}
		if p.wantSelfTLS {
			if !strings.Contains(s, "openssl req -x509") {
				t.Errorf("%s: TLS proto must generate a self-signed cert", p.id)
			}
			if !strings.Contains(s, "certificate_path") || !strings.Contains(s, "key_path") {
				t.Errorf("%s: TLS inbound must reference cert/key paths", p.id)
			}
		}
	}
}

// TestNewProtosPersistIdentity guards idempotence: each fragment must generate its
// secret(s) only when ABSENT (the `[ -f ... ] || …` guard) so a re-run reuses them
// and existing clients keep working — mirroring the Reality/AmneziaWG key guards.
func TestNewProtosPersistIdentity(t *testing.T) {
	guards := map[string][]string{
		ProtoVMess:       {`[ -f "$SBD/wr-vmess-uuid" ] || sing-box generate uuid`},
		ProtoTrojan:      {`[ -f "$SBD/wr-trojan-pass" ] || sing-box generate rand`},
		ProtoShadowsocks: {`[ -f "$SBD/wr-ss-psk" ] || sing-box generate rand`},
		ProtoHysteria2:   {`[ -f "$SBD/wr-hy2-pass" ] || sing-box generate rand`},
		ProtoTUIC: {
			`[ -f "$SBD/wr-tuic-uuid" ] || sing-box generate uuid`,
			`[ -f "$SBD/wr-tuic-pass" ] || sing-box generate rand`,
		},
		ProtoAnyTLS: {`[ -f "$SBD/wr-anytls-pass" ] || sing-box generate rand`},
		ProtoSnell:  {`[ -f "$SBD/wr-snell-psk" ] || sing-box generate rand --base64 24`},
	}
	for id, want := range guards {
		s := BuildScript([]string{id}, "")
		for _, g := range want {
			if !strings.Contains(s, g) {
				t.Errorf("%s: missing reuse-on-rerun guard %q", id, g)
			}
		}
	}
}

// TestNewProtosMarkerPrecedesConfig re-asserts the ExtractTagged contract for each
// new fragment: WR_PROTO=<id> appears immediately before its WR_CLIENT_CONFIG line
// with no other WR_PROTO marker in between.
func TestNewProtosMarkerPrecedesConfig(t *testing.T) {
	for _, p := range allProtoNew {
		s := BuildScript([]string{p.id}, "")
		iProto := strings.Index(s, p.marker)
		if iProto < 0 {
			t.Errorf("%s: missing marker %q", p.id, p.marker)
			continue
		}
		rest := s[iProto+len(p.marker):]
		iCfg := strings.Index(rest, "WR_CLIENT_CONFIG")
		if iCfg < 0 {
			t.Errorf("%s: no WR_CLIENT_CONFIG follows the marker", p.id)
			continue
		}
		if strings.Contains(rest[:iCfg], "WR_PROTO=") {
			t.Errorf("%s: a second WR_PROTO marker sits between marker and config", p.id)
		}
	}
}

// TestNewProtosClientLinkParses is the round-trip: emit a fragment, simulate the
// installer output (the shell echoes with $VARS expanded), feed it to ExtractTagged,
// and assert the marker attributes it to the right proto AND the share-link imports
// to the expected model.Protocol — proving the emitted links are real, importable
// client configs (not just well-formed strings).
func TestNewProtosClientLinkParses(t *testing.T) {
	for _, p := range allProtoNew {
		link := sampleLink(p.id)
		out := "[wayhop-init] installing\n" + p.marker + "\nWR_CLIENT_CONFIG=" + link + "\n[wayhop-init] done\n"

		tagged := ExtractTagged(out)
		if len(tagged) != 1 {
			t.Fatalf("%s: ExtractTagged returned %d configs, want 1", p.id, len(tagged))
		}
		if tagged[0].Proto != p.id {
			t.Errorf("%s: tagged proto = %q, want %q", p.id, tagged[0].Proto, p.id)
		}
		if tagged[0].Config != link {
			t.Errorf("%s: tagged config mangled\n got=%q\nwant=%q", p.id, tagged[0].Config, link)
		}

		ep, err := importer.Parse(link)
		if err != nil {
			t.Errorf("%s: emitted link does not import: %v\nlink=%q", p.id, err, link)
			continue
		}
		if ep.Protocol != p.wantProto {
			t.Errorf("%s: imported protocol = %q, want %q", p.id, ep.Protocol, p.wantProto)
		}
		if p.wantTLS {
			if ep.TLS == nil || !ep.TLS.Enabled {
				t.Errorf("%s: imported endpoint should carry enabled TLS", p.id)
			} else if p.wantSelfTLS && !ep.TLS.Insecure {
				t.Errorf("%s: self-signed link should import with TLS Insecure=true", p.id)
			}
		}
	}
}

// TestNewProtosDetectFallback confirms each fragment's catalog detector recognises a
// payload of its scheme, so ExtractTagged can still attribute a marker-less config.
func TestNewProtosDetectFallback(t *testing.T) {
	for _, p := range allProtoNew {
		got := DetectProto(sampleLink(p.id))
		if got != p.id {
			t.Errorf("%s: DetectProto(%s…) = %q, want %q", p.id, p.scheme, got, p.id)
		}
	}
}

// TestNewProtosCombinedWithReality confirms a mixed selection emits every fragment
// and every marker — and that the shared sing-box service unit also keeps Reality's
// standalone config.json (so the two coexist in one sing-box process).
func TestNewProtosCombinedWithReality(t *testing.T) {
	sel := []string{ProtoReality, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoSnell}
	s := BuildScript(sel, "198.51.100.5")
	for _, want := range []string{
		"WR_PROTO=vless-reality",
		"WR_PROTO=vmess",
		"WR_PROTO=trojan",
		"WR_PROTO=shadowsocks",
		"WR_PROTO=hysteria2",
		"WR_PROTO=tuic",
		"WR_PROTO=anytls",
		"WR_PROTO=snell",
		"-c /etc/sing-box/config.json", // the superset unit keeps Reality's config
	} {
		if !strings.Contains(s, want) {
			t.Errorf("combined build missing %q", want)
		}
	}
	// The mixed output round-trips: simulate every link and confirm ExtractTagged
	// returns one tagged config per selected protocol, in order.
	var b strings.Builder
	for _, id := range sel {
		b.WriteString("WR_PROTO=" + id + "\nWR_CLIENT_CONFIG=" + sampleLink(id) + "\n")
	}
	tagged := ExtractTagged(b.String())
	if len(tagged) != len(sel) {
		t.Fatalf("ExtractTagged returned %d, want %d", len(tagged), len(sel))
	}
	for i, id := range sel {
		if tagged[i].Proto != id {
			t.Errorf("tagged[%d].Proto = %q, want %q", i, tagged[i].Proto, id)
		}
	}
}

// sampleLink builds a representative client share-link in the exact form each
// fragment emits, used to exercise the importer round-trip and the detectors. The
// vmess link mirrors the fragment's base64(json) payload (add/port/id/net/path/tls/
// sni/allowInsecure keys).
func sampleLink(id string) string {
	switch id {
	case ProtoVMess:
		// base64 of the JSON the fragment prints (with PUBLIC_IP/uuid/sni filled in).
		j := `{"v":"2","ps":"wayhop-vmess","add":"203.0.113.9","port":"8443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","type":"none","host":"wayhop.local","path":"/wayhop","tls":"tls","sni":"wayhop.local","allowInsecure":"1"}`
		return "vmess://" + kbinitserver_b64(j)
	case ProtoTrojan:
		return "trojan://Pa%2Bss%2Fword%3D@203.0.113.9:8444?security=tls&sni=wayhop.local&insecure=1&type=tcp#wayhop-trojan"
	case ProtoShadowsocks:
		return "ss://" + kbinitserver_b64("2022-blake3-aes-256-gcm:c29tZS0zMi1ieXRlLWtleS1iYXNlNjQtcGFkZGVkPT0=") + "@203.0.113.9:8388#wayhop-ss"
	case ProtoHysteria2:
		return "hysteria2://Pa%2Bss%2Fword%3D@203.0.113.9:8445?sni=wayhop.local&insecure=1#wayhop-hy2"
	case ProtoTUIC:
		return "tuic://11111111-2222-3333-4444-555555555555:Pa%2Bss%2Fword%3D@203.0.113.9:8446?sni=wayhop.local&insecure=1&congestion_control=bbr&alpn=h3#wayhop-tuic"
	case ProtoAnyTLS:
		return "anytls://Pa%2Bss%2Fword%3D@203.0.113.9:8447?sni=wayhop.local&insecure=1#wayhop-anytls"
	case ProtoSnell:
		// base64 PSK with '+', '/' and '=' padding, as `sing-box generate rand --base64 24` prints it
		return "wayhop-snell = snell, 203.0.113.9, 8448, psk=Ab+cd/EFgh1234567890ijklmnopQRST, version=6"
	}
	return ""
}

// The Snell fragment needs the 1.14 inbound and refuses an older sing-box before writing it; its
// client line imports as a v6 Snell connection with the PSK intact (padding included).
func TestSnellServerFragment(t *testing.T) {
	s := BuildScript([]string{ProtoSnell}, "")
	guard := strings.Index(s, `if [ "${SBMIN:-0}" -lt 1014 ]; then`)
	write := strings.Index(s, "cat > /etc/sing-box/conf.d/wr-snell.json")
	if guard < 0 || write < 0 || guard > write || !strings.Contains(s[guard:write], "exit 1") {
		t.Fatalf("version guard at %d, config write at %d: the guard must come first and stop", guard, write)
	}
	if !strings.Contains(s, `"type":"snell"`) || !strings.Contains(s, `"version":6`) {
		t.Error("inbound must be Snell v6")
	}
	for _, link := range []string{sampleLink(ProtoSnell), "wayhop-snell = snell, 203.0.113.9, 8448, psk=abcdefghijklmnopqrstuvwxyz012345==, version=6"} {
		ep, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%q: %v", link, err)
		}
		psk := link[strings.Index(link, "psk=")+4 : strings.Index(link, ", version")]
		if ep.Params["version"] != 6 || ep.Params["psk"] != psk || ep.Port != 8448 {
			t.Errorf("imported %+v, want v6 with psk %q on 8448", ep.Params, psk)
		}
	}
	o := optionByID(ProtoSnell)
	for _, other := range catalog {
		if other.ID != ProtoSnell && other.Port == o.Port && other.Transport == o.Transport {
			t.Errorf("port %d/%s already used by %s", o.Port, o.Transport, other.ID)
		}
	}
}

// The AnyTLS fragment refuses a sing-box older than 1.12 BEFORE it writes its inbound: the installer
// keeps an existing sing-box, and an inbound type that sing-box does not know stops the whole service.
func TestAnyTLSRefusesOldCoreBeforeWritingConfig(t *testing.T) {
	s := BuildScript([]string{ProtoAnyTLS}, "")
	guard := strings.Index(s, `if [ "${SBMIN:-0}" -lt 1012 ]; then`)
	write := strings.Index(s, "cat > /etc/sing-box/conf.d/wr-anytls.json")
	if guard < 0 || write < 0 || guard > write {
		t.Fatalf("version guard at %d, config write at %d: the guard must come first", guard, write)
	}
	if !strings.Contains(s[guard:write], "exit 1") {
		t.Error("the guard must stop the script, not just log")
	}
	o := optionByID(ProtoAnyTLS)
	if o == nil || o.Port != 8447 || o.Transport != "tcp" {
		t.Fatalf("option = %+v", o)
	}
	for _, other := range catalog {
		if other.ID != ProtoAnyTLS && other.Port == o.Port && other.Transport == o.Transport {
			t.Errorf("port %d/%s already used by %s", o.Port, o.Transport, other.ID)
		}
	}
}
