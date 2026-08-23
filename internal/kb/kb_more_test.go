package kb

import "testing"

// hasID reports whether Match(line) returns an entry with the given id.
func hasID(line, id string) bool {
	for _, e := range Match(line) {
		if e.ID == id {
			return true
		}
	}
	return false
}

// gotIDs returns the ids Match produced for line (for failure diagnostics).
func gotIDs(line string) []string {
	var ids []string
	for _, e := range Match(line) {
		ids = append(ids, e.ID)
	}
	return ids
}

// entryByID returns the catalog entry with id, or nil.
func entryByID(id string) *Entry {
	for i := range entries {
		if entries[i].ID == id {
			return &entries[i]
		}
	}
	return nil
}

// TestMatchNewProtocolEntries feeds one representative synthetic log line per
// newly-added entry and asserts the expected entry is among the matches.
func TestMatchNewProtocolEntries(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantID string
	}{
		// shadowsocks
		{"ss-bad-header", `shadowsocks: bad header byte from server`, "ss-bad-auth"},
		{"ss-gcm-tag", `cipher: invalid GCM tag, dropping packet`, "ss-bad-auth"},
		{"ss-aead", `stream-aead: failed to decrypt salt`, "ss-bad-auth"},
		// vmess
		{"vmess-decode-header", `VMess: failed to decode request header`, "vmess-auth"},
		{"vmess-read-request", `VMess: failed to read request from client`, "vmess-auth"},
		{"vmess-invalid-user", `proxy/vmess: invalid user`, "vmess-auth"},
		// trojan
		{"trojan-bad-pass", `trojan: invalid password, falling back to web`, "trojan-auth"},
		{"trojan-authfail", `trojan inbound: authentication failed`, "trojan-auth"},
		// self-signed TLS
		{"selfsigned-unknown-authority", `tls: x509: certificate signed by unknown authority`, "gen-self-signed"},
		{"selfsigned-not-trusted", `handshake error: certificate is not trusted`, "gen-self-signed"},
		{"selfsigned-literal", `remote error: self-signed certificate`, "gen-self-signed"},
		// tuic
		{"tuic-auth-timeout", `tuic: authentication timeout, closing connection`, "tuic-auth"},
		{"tuic-wrong-uuid", `TUIC: invalid uuid supplied by client`, "tuic-auth"},
		// quic / udp blocked
		{"quic-no-activity", `quic: timeout: no recent network activity`, "quic-udp-blocked"},
		{"quic-handshake", `quic: handshake did not complete in time`, "quic-udp-blocked"},
		{"quic-no-route", `dial udp 1.2.3.4:443: connect: no route to host`, "quic-udp-blocked"},
		// reality verification
		{"reality-verify-failed", `REALITY: reality verification failed for client`, "xr-reality-verify"},
		{"reality-failed-verify", `REALITY: failed to verify server identity`, "xr-reality-verify"},
		// amneziawg header
		{"awg-unknown-type", `peer(X): received message with unknown type 211`, "awg-bad-header"},
		{"awg-unexpected", `Receiving unexpected packet type from endpoint`, "awg-bad-header"},
		// provisioned inbound: port conflicts
		{"inbound-port-8443", `FATAL start service: listen tcp :8443: bind: address already in use`, "inbound-port-in-use"},
		{"inbound-port-8444", `start inbound/trojan[wr-trojan-in]: listen tcp :8444: address already in use`, "inbound-port-in-use"},
		{"inbound-port-8388", `inbound/shadowsocks: listen tcp :8388: bind: address already in use`, "inbound-port-in-use"},
		{"inbound-port-8445", `FATAL start service: listen udp :8445: bind: address already in use`, "inbound-port-in-use"},
		{"inbound-port-8446", `start inbound/tuic[wr-tuic-in]: bind: :8446: address already in use`, "inbound-port-in-use"},
		// provisioned inbound: VMess auth
		{"inbound-vmess-handle", `inbound/vmess[wr-vmess-in]: failed to handle connection`, "inbound-vmess-auth"},
		{"inbound-vmess-invalid-user", `vmess: invalid user from 1.2.3.4`, "inbound-vmess-auth"},
		{"inbound-vmess-decode", `vmess: failed to decode request header from client`, "inbound-vmess-auth"},
		// provisioned inbound: Trojan auth
		{"inbound-trojan-handle", `inbound/trojan[wr-trojan-in]: failed to handle connection`, "inbound-trojan-auth"},
		{"inbound-trojan-password", `trojan inbound: invalid password from client`, "inbound-trojan-auth"},
		{"inbound-trojan-fallback", `inbound trojan: falling back to fallback handler`, "inbound-trojan-auth"},
		// provisioned inbound: Shadowsocks PSK
		{"inbound-ss-handle", `inbound/shadowsocks[wr-ss-in]: failed to handle connection`, "inbound-ss-psk"},
		{"inbound-ss-gcm", `shadowsocks inbound: invalid GCM tag, dropping`, "inbound-ss-psk"},
		{"inbound-ss-salt", `shadowsocks inbound: salt not unique`, "inbound-ss-psk"},
		// provisioned inbound: Hysteria2 auth
		{"inbound-hy2-handle", `inbound/hysteria2[wr-hy2-in]: failed to handle connection`, "inbound-hy2-auth"},
		{"inbound-hy2-authfail", `hysteria2 inbound: authentication failed for client`, "inbound-hy2-auth"},
		{"inbound-hy2-password", `hysteria2 inbound: invalid password supplied`, "inbound-hy2-auth"},
		// provisioned inbound: TUIC auth
		{"inbound-tuic-handle", `inbound/tuic[wr-tuic-in]: failed to handle connection`, "inbound-tuic-auth"},
		{"inbound-tuic-uuid", `tuic inbound: invalid uuid from client`, "inbound-tuic-auth"},
		{"inbound-tuic-authtimeout", `tuic inbound: authentication timeout for peer`, "inbound-tuic-auth"},
		// provisioned inbound: client rejects self-signed TLS
		{"inbound-tls-bad-cert", `tls: bad certificate from 1.2.3.4`, "inbound-tls-bad-cert"},
		{"inbound-tls-unknown-ca", `tls: unknown certificate authority`, "inbound-tls-bad-cert"},
		{"inbound-tls-remote-cert", `remote error: tls: certificate unknown`, "inbound-tls-bad-cert"},
		// provisioned inbound: QUIC UDP blocked
		{"inbound-quic-hy2-unreachable", `inbound/hysteria2[wr-hy2-in]: udp: network unreachable`, "inbound-quic-blocked"},
		{"inbound-quic-tuic-unreachable", `inbound/tuic[wr-tuic-in]: udp: network unreachable`, "inbound-quic-blocked"},
		{"inbound-quic-listen-blocked", `listen udp :8445: network unreachable`, "inbound-quic-blocked"},
		// config decode / unknown field
		{"decode-unknown-field", `FATAL[0000] decode config at config.json: json: unknown field "type"`, "sb-decode-config"},
		{"read-config-invalid", `read config at /etc/sing-box/config.json: invalid character '}' looking for beginning of object key`, "sb-decode-config"},
		// outbound reset by peer (DPI)
		{"conn-reset-outbound", `ERROR [978206178 5.63s] connection: open outbound connection: read tcp 172.18.0.1:59972->172.66.156.81:80: read: connection reset by peer`, "sb-conn-reset"},
		// network unreachable (IPv6)
		{"net-unreachable-v6", `ERROR connection: open outbound connection: dial tcp [2607:f8b0:4009:803::2004]:443: connect: network is unreachable`, "gen-net-unreachable"},
		// TLS handshake timeout/EOF (transport, not cert-trust)
		{"tls-handshake-deadline", `inbound/anytls[anytls-in]: process connection from 1.2.3.4:37628: TLS handshake: context deadline exceeded`, "sb-tls-handshake-fail"},
		{"tls-handshake-eof", `outbound/vless[nl]: TLS handshake: EOF`, "sb-tls-handshake-fail"},
		// amneziawg awg-quick runtime
		{"awg-resolvconf", `/opt/bin/awg-quick: line 40: resolvconf: command not found`, "awg-resolvconf-missing"},
		{"awg-rtnetlink", `RTNETLINK answers: File exists`, "awg-route-exists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !hasID(c.line, c.wantID) {
				t.Errorf("line %q did not match entry %q (got %v)", c.line, c.wantID, gotIDs(c.line))
			}
		})
	}
}

// TestNewEntriesYieldCauseAndFix verifies each new entry, when matched, carries
// the descriptive fields the Diagnostics UI shows (engine/title/explanation/fix).
func TestNewEntriesYieldCauseAndFix(t *testing.T) {
	want := map[string]string{ // id -> expected engine
		"ss-bad-auth":            "shadowsocks",
		"vmess-auth":             "vmess",
		"trojan-auth":            "trojan",
		"gen-self-signed":        "any",
		"tuic-auth":              "tuic",
		"quic-udp-blocked":       "any",
		"xr-reality-verify":      "xray",
		"awg-bad-header":         "amneziawg",
		"inbound-port-in-use":    "sing-box",
		"inbound-vmess-auth":     "sing-box",
		"inbound-trojan-auth":    "sing-box",
		"inbound-ss-psk":         "sing-box",
		"inbound-hy2-auth":       "sing-box",
		"inbound-tuic-auth":      "sing-box",
		"inbound-tls-bad-cert":   "sing-box",
		"inbound-quic-blocked":   "sing-box",
		"sb-decode-config":       "sing-box",
		"sb-conn-reset":          "sing-box",
		"gen-net-unreachable":    "any",
		"sb-tls-handshake-fail":  "sing-box",
		"awg-resolvconf-missing": "amneziawg",
		"awg-route-exists":       "amneziawg",
	}
	for id, engine := range want {
		e := entryByID(id)
		if e == nil {
			t.Errorf("new entry %q not found in catalog", id)
			continue
		}
		if e.Engine != engine {
			t.Errorf("entry %q engine = %q, want %q", id, e.Engine, engine)
		}
		if e.Title == "" || e.Explanation == "" || e.Fix == "" {
			t.Errorf("entry %q missing descriptive text: %+v", id, e)
		}
		if len(e.Sources) == 0 {
			t.Errorf("entry %q has no Sources", id)
		}
		if e.re == nil {
			t.Errorf("entry %q regexp not compiled", id)
		}
	}
}

// TestNewEntriesNoFalsePositives confirms the new, more specific patterns do not
// fire on benign or unrelated log lines.
func TestNewEntriesNoFalsePositives(t *testing.T) {
	benign := []string{
		"INFO shadowsocks outbound[ss] connected",
		"INFO vmess outbound[vm] dialing server",
		"INFO trojan outbound[tj] handshake complete",
		"INFO tuic outbound established session",
		"DEBUG quic: 1-RTT keys installed, connection ready",
		"REALITY: connection accepted, verification passed",
		"peer(X): received handshake response, session up",
		"tls: handshake complete with verified certificate",
		"connected to peer, handshake complete",
		"inbound TLS handshake: completed successfully",                              // has 'TLS handshake:' but no failure → must NOT hit sb-tls-handshake-fail
		"INFO connection: open outbound connection: dial tcp 1.2.3.4:443: connected", // outbound dial OK → must NOT hit sb-conn-reset / gen-net-unreachable
		"INFO loaded config at config.json successfully",                             // not a decode/read-error line → must NOT hit sb-decode-config
		"INFO route: network reachable via wan",                                      // 'network' + 'reach' but not the unreachable dial signature
	}
	for _, ln := range benign {
		if m := Match(ln); len(m) != 0 {
			t.Errorf("benign line %q matched %d entries (%v), want 0", ln, len(m), gotIDs(ln))
		}
	}
}
