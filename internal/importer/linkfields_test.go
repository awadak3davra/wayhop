package importer

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// linkfields_rich are inputs that set many fields at once, beside the fuzz corpus, for the drift
// check below.
func linkfields_rich() []string {
	return []string{
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=reality&sni=example.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&packetEncoding=xudp&type=grpc&serviceName=svc&vcn=example.org#R",
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&fp=chrome&alpn=h2&allowInsecure=1&type=ws&path=%2Fws&host=cdn.example.com&pcs=" + strings.Repeat("a", 64) + "#T",
		"anytls://pw@203.0.113.11:443?sni=example.com&fp=chrome&pcs=" + strings.Repeat("b", 64) + "#A",
		"hysteria2://pw@203.0.113.12:443?sni=example.com&obfs=salamander&obfs-password=x&insecure=1&mport=20000-20010&pinSHA256=" + strings.Repeat("c", 64) + "&vcn=example.org#H",
		"tuic://uuid:pw@203.0.113.13:443?congestion_control=bbr&udp_relay_mode=quic&heartbeat=10s&reduce_rtt=1&udp_over_stream=1&sni=example.com&alpn=h3#U",
		"wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@203.0.113.14:51820?publickey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ%3D&presharedkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI%3D&address=10.0.0.2/32&keepalive=25&mtu=1380&reserved=1,2,3&jc=4&jmin=40&jmax=70#W",
		"ssh://root:pw@203.0.113.15:22#S",
		"proxies:\n" +
			"  - {name: v, type: vless, server: 203.0.113.20, port: 443, uuid: u, flow: xtls-rprx-vision, tls: true, servername: example.com, client-fingerprint: chrome, network: ws, ws-opts: {path: /ws}, smux: {enabled: true, protocol: smux}}\n" +
			"  - {name: h, type: hysteria2, server: 203.0.113.21, port: 443, password: pw, obfs: salamander, obfs-password: x, up: 10, down: 50, ports: 20000-20010, sni: example.com}\n" +
			"  - {name: w, type: wireguard, server: 203.0.113.22, port: 51820, private-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=, ip: 10.0.0.2, mtu: 1380, persistent-keepalive: 25}\n" +
			"  - {name: t, type: tuic, server: 203.0.113.23, port: 443, uuid: u, password: pw, congestion-controller: bbr, udp-relay-mode: quic}\n" +
			"  - {name: s, type: ss, server: 203.0.113.24, port: 8388, cipher: aes-256-gcm, password: pw, plugin: obfs, plugin-opts: {mode: http, host: example.com}}\n",
		`{"outbounds":[` +
			`{"type":"vless","tag":"v","server":"203.0.113.30","server_port":443,"uuid":"u","flow":"xtls-rprx-vision","packet_encoding":"xudp","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"record_fragment":true},"transport":{"type":"ws","path":"/ws"},"multiplex":{"enabled":true,"protocol":"smux"}},` +
			`{"type":"hysteria2","tag":"h","server":"203.0.113.31","server_port":443,"password":"pw","up_mbps":10,"down_mbps":50,"obfs":{"type":"salamander","password":"x"},"initial_packet_size":1200,"disable_path_mtu_discovery":true,"tls":{"enabled":true,"server_name":"example.com"}},` +
			`{"type":"ssh","tag":"s","server":"203.0.113.32","server_port":22,"user":"root","password":"pw","host_key":["ssh-ed25519 AAAA"],"client_version":"SSH-2.0-OpenSSH_9.6"}],` +
			`"endpoints":[{"type":"wireguard","tag":"w","mtu":1380,"address":["10.0.0.2/32"],"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","peers":[{"address":"203.0.113.33","port":51820,"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=","allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":25}]}]}`,
		"[Proxy]\nt = trojan, 203.0.113.40, 443, password=pw, sni=example.com, skip-cert-verify=true, ws=true, ws-path=/ws\nh = hysteria2, 203.0.113.41, 443, password=pw, download-bandwidth=50, port-hopping=20000-20010, salamander-password=x\n",
	}
}

// Each format's list (sourceFields) has to cover what its parser writes, or a value a provider stops
// sending would outlive the re-import. Every input here is parsed, and every field it set must be on
// its format's list: a parser that starts writing a new param fails this until its list says so.
func TestSourceFields_CoverWhatEachParserWrites(t *testing.T) {
	seen := map[string]bool{}
	for _, in := range append(fuzzimporter_seeds(), linkfields_rich()...) {
		eps, _ := ParseSubscription(in)
		if e, err := Parse(in); err == nil {
			eps = append(eps, *e)
		}
		for _, e := range eps {
			if e.Import == "" {
				continue
			}
			spec, ok := fieldsOf(e.Import)
			if !ok {
				t.Errorf("%q: format %q has no list", in, e.Import)
				continue
			}
			seen[e.Import] = true
			for k := range e.Params {
				if !containsPin(spec.params, k) {
					t.Errorf("%s writes param %q, which its list does not name", e.Import, k)
				}
			}
			for k := range jsonFields(e.TLS) {
				if !containsPin(spec.tls, k) && !(spec.pins && containsPin(pinFields, k)) {
					t.Errorf("%s sets TLS field %q, which its list does not name", e.Import, k)
				}
			}
			if (e.Transport != nil && !spec.transport) || (e.MTU != 0 && !spec.mtu) ||
				(e.PersistentKeepalive != 0 && !spec.keepalive) || (e.Multiplex != nil && !spec.multiplex) {
				t.Errorf("%s sets a transport, MTU, keepalive or multiplex its list does not name: %+v", e.Import, e)
			}
		}
	}
	var formats []string
	for f := range seen {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	for _, want := range []string{"clash", "conf", "link:anytls", "link:hysteria2", "link:ss", "link:ssh", "link:trojan",
		"link:tuic", "link:vless", "link:vmess", "link:wireguard", "ovpn", "singbox", "surge"} {
		if !seen[want] {
			t.Errorf("no input exercised format %s (exercised: %v)", want, formats)
		}
	}
}

// reimportOf parses first, stores it with the user's changes made by edit, and imports again.
func reimportOf(t *testing.T, first, again string, edit func(*model.Endpoint)) (have, out model.Endpoint) {
	t.Helper()
	parse := func(in string) model.Endpoint {
		if eps, _ := ParseSubscription(in); len(eps) == 1 {
			return eps[0]
		}
		e, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		return *e
	}
	have = parse(first)
	have.Import = "" // as stored
	edit(&have)
	link := parse(again)
	if link.Import == "" {
		t.Fatalf("%q parsed with no format", again)
	}
	return have, Reimport(have, link)
}

// An ssh:// link carries a user and a password and nothing else: the host keys, private key and
// passphrase typed in the form survive a re-import, or the exit would accept any server key.
func TestReimport_SSHKeepsWhatTheFormAdded(t *testing.T) {
	have, out := reimportOf(t, "ssh://root:pw@203.0.113.15:22#S", "ssh://root@203.0.113.15:22#S", func(e *model.Endpoint) {
		e.Params["host_key"] = []any{"ssh-ed25519 AAAA"}
		e.Params["private_key"] = "-----BEGIN OPENSSH PRIVATE KEY-----"
		e.Params["private_key_passphrase"] = "x"
	})
	if !reflect.DeepEqual(out.Params["host_key"], have.Params["host_key"]) || out.Params["private_key"] == nil || out.Params["private_key_passphrase"] != "x" {
		t.Errorf("the host key, private key or passphrase was wiped: %v", out.Params)
	}
	if _, ok := out.Params["password"]; ok {
		t.Errorf("the password the link dropped is still stored: %v", out.Params)
	}
	// The same link stays the same connection once a key is added in the form: an import of it is an
	// update in place, not a second connection beside the first.
	link, _ := Parse("ssh://root:pw@203.0.113.15:22#S")
	keyed := *link
	keyed.Params = map[string]any{"user": "root", "password": "pw", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----"}
	if ContentKey(keyed) != ContentKey(*link) {
		t.Error("adding a private key in the form makes the ssh:// link a different connection")
	}
}

// A Hysteria2 link carries no QUIC tuning: what the form set stays, what the link dropped (obfs) goes.
func TestReimport_Hysteria2KeepsQUICTuning(t *testing.T) {
	const base = "hysteria2://pw@203.0.113.12:443?sni=example.com"
	_, out := reimportOf(t, base+"&obfs=salamander&obfs-password=x#H", base+"#H", func(e *model.Endpoint) {
		e.Params[model.ParamQUICInitialPacketSize] = 1200
		e.Params[model.ParamQUICDisablePMTUD] = true
		e.Params["disable_chrome_parrot"] = true
		e.Params["up_mbps"] = 10
	})
	if out.Params[model.ParamQUICInitialPacketSize] != 1200 || out.Params[model.ParamQUICDisablePMTUD] != true ||
		out.Params["disable_chrome_parrot"] != true || out.Params["up_mbps"] != 10 {
		t.Errorf("QUIC tuning or bandwidth set in the form was wiped: %v", out.Params)
	}
	if _, ok := out.Params["obfs"]; ok {
		t.Errorf("obfs the link dropped is still stored: %v", out.Params)
	}
}

// A WireGuard .conf, and a wg:// line, can say a keepalive and an MTU, so the values they import win
// wherever the stored ones live: the form moves them to the top-level knobs on any save, which the
// generator reads first, and a provider's new MTU or a keepalive it dropped would otherwise lose to
// them while the import said "updated".
func TestReimport_WireGuardValuesWinWhereverTheyLive(t *testing.T) {
	conf := func(lines ...string) string {
		return strings.Join(append([]string{"[Interface]", "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"Address = 10.7.0.2/32"}, append(lines[:1:1], "[Peer]", "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=",
			"Endpoint = 203.0.113.60:51820", "AllowedIPs = 0.0.0.0/0", lines[1])...), "\n")
	}
	// The form saved it once (a rename): MTU and keepalive moved to the top level.
	moved := func(e *model.Endpoint) {
		e.MTU, e.PersistentKeepalive = 1420, 25
		delete(e.Params, "mtu")
		delete(e.Params, "persistent_keepalive")
	}
	have, out := reimportOf(t, conf("MTU = 1420", "PersistentKeepalive = 25"), conf("MTU = 1280", ""), moved)
	if out.MTU != 0 || out.Params["mtu"] != 1280 || out.PersistentKeepalive != 0 || out.Params["persistent_keepalive"] != nil {
		t.Errorf(".conf: MTU %d/%v keepalive %d/%v, want the .conf's 1280 and no keepalive",
			out.MTU, out.Params["mtu"], out.PersistentKeepalive, out.Params["persistent_keepalive"])
	}
	if got := ClearedWireGuardKnobs(have, out); !reflect.DeepEqual(got, []string{"persistent keepalive"}) {
		t.Errorf(".conf cleared values = %v, want only persistent keepalive", got)
	}
	const wg = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@203.0.113.61:51820?publickey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ%3D&address=10.0.0.2/32"
	have, out = reimportOf(t, wg+"&mtu=1420&keepalive=25#W", wg+"&mtu=1280#W", moved)
	if out.MTU != 0 || out.Params["mtu"] != 1280 || out.PersistentKeepalive != 0 || out.Params["persistent_keepalive"] != nil {
		t.Errorf("wg://: MTU %d/%v keepalive %d/%v, want the link's 1280 and no keepalive",
			out.MTU, out.Params["mtu"], out.PersistentKeepalive, out.Params["persistent_keepalive"])
	}
	if got := ClearedWireGuardKnobs(have, out); !reflect.DeepEqual(got, []string{"persistent keepalive"}) {
		t.Errorf("wg:// cleared values = %v, want only persistent keepalive", got)
	}
}

// A sing-box config expresses the top-level knobs, so a re-import from one takes them, a dropped
// multiplex included.
func TestReimport_SingboxTakesWhatItCanExpress(t *testing.T) {
	cfg := func(extra string) string {
		return `{"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.30","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"example.com"}` + extra + `}]}`
	}
	_, out := reimportOf(t, cfg(`,"multiplex":{"enabled":true,"protocol":"smux"}`), cfg(""), func(e *model.Endpoint) {
		e.Name = "mine"
		e.TLS.Fragment = true
	})
	if out.Multiplex != nil || out.Name != "mine" || out.TLS == nil || out.TLS.Fragment {
		t.Errorf("multiplex %+v name %q fragment %v: want the config's (none, none) and the user's name", out.Multiplex, out.Name, out.TLS != nil && out.TLS.Fragment)
	}
}

// The format tag comes from the client, so it is believed only when its parser produces the
// endpoint's protocol. A missing, unknown or mismatched tag reads the link as saying what it carries,
// except the TLS fields that loosen how the server is checked, and imported pins, which are always the
// link's: a forged tag cannot keep "accept any certificate". A pin the user added stays, since it only
// narrows what is accepted.
func TestReimport_AnUnbelievableTagFailsClosed(t *testing.T) {
	const base = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&type=tcp"
	for _, tag := range []string{"link:ssh", "", "nonsense"} {
		link, _ := Parse(base + "#V")
		link.Import = tag
		have, _ := Parse(base + "&allowInsecure=1&fp=chrome&pcs=" + strings.Repeat("a", 64) + "#V")
		have.Import = ""
		have.TLS.PinPubKeySHA256 = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
		have.Params["note"] = "kept"
		got := Reimport(*have, *link)
		if got.TLS.Insecure || got.TLS.Fingerprint != "" || len(got.TLS.PinCertSHA256) != 0 {
			t.Errorf("tag %q kept a loosening field or an imported pin: %+v", tag, *got.TLS)
		}
		if len(got.TLS.PinPubKeySHA256) != 1 || got.Params["note"] != "kept" {
			t.Errorf("tag %q dropped the user's pin or a param the link does not carry: %+v %v", tag, *got.TLS, got.Params)
		}
	}
}

// The hunter's case: a Clash Hysteria2 proxy re-imported without its bandwidth and its obfs packet
// sizes loses all three, not only the ones the list happened to name.
func TestReimport_ClashHysteria2ClearsWhatTheConfigDropped(t *testing.T) {
	const head = "proxies:\n  - {name: h, type: hysteria2, server: 203.0.113.21, port: 443, password: pw, sni: example.com"
	have, out := reimportOf(t, head+", up: 10, obfs: salamander, obfs-password: x, obfs-min-packet-size: 1200, obfs-max-packet-size: 1300}\n",
		head+"}\n", func(*model.Endpoint) {})
	if have.Params["obfs_min_packet_size"] == nil || have.Params["up_mbps"] == nil {
		t.Fatalf("the first config did not import as this test assumes: %v", have.Params)
	}
	for _, k := range []string{"up_mbps", "obfs", "obfs_min_packet_size", "obfs_max_packet_size"} {
		if v, ok := out.Params[k]; ok {
			t.Errorf("%s = %v survived a config that dropped it", k, v)
		}
	}
}
