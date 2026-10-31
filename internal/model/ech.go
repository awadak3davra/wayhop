package model

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ECH is Encrypted Client Hello on a TLS connection (sing-box tls.ech, client side): the
// ClientHello's inner part, the real server name with it, is encrypted to a key the server
// publishes, so a firewall that reads the SNI sees only the outer, public name.
//
// A nil *ECH (the zero TLS) leaves every existing profile byte-identical.
type ECH struct {
	Enabled bool `json:"enabled,omitempty"`
	// Config is the server's ECHConfigList in standard base64, the form every share format carries
	// (Xray/v2rayN `ech=`, Hysteria's `ech=`, mihomo's ech-opts.config). Empty means sing-box looks
	// it up at each handshake: an HTTPS record for QueryServerName, or for the SNI.
	Config string `json:"config,omitempty"`
	// QueryServerName is the name whose HTTPS record carries the config when it is not the SNI. Only
	// sing-box 1.13+ has it, and only the DNS lookup uses it.
	QueryServerName string `json:"query_server_name,omitempty"`
}

// echVersion is the ECHConfig version of the published ECH standard (draft 13 onward, RFC 9849):
// the only one Go's crypto/tls and uTLS, and so sing-box, use. Entries of another version are
// skipped by them, so a list holding none of this one fails every handshake.
const echVersion = 0xfe0d

// ECHActive reports whether t asks for ECH where sing-box can do it: TLS on, not Reality (sing-box
// refuses the pair), ECH switched on.
func (t *TLS) ECHActive() bool {
	return t != nil && t.Enabled && t.Type != "reality" && t.ECH != nil && t.ECH.Enabled
}

// ParseECHConfigList decodes an ECH config as a share link or the panel carries it - base64 in any
// alphabet, padded or not, or the "ECH CONFIGS" PEM block sing-box and its keygen print - and
// checks it is a well-formed ECHConfigList with at least one entry a client can use. sing-box's
// own check passes any bytes inside a valid PEM block, so a garbled paste would otherwise load and
// then fail every handshake of the connection.
func ParseECHConfigList(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	var raw []byte
	if strings.Contains(s, "-----BEGIN") {
		block, rest := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("not a PEM block")
		}
		if block.Type != "ECH CONFIGS" {
			return nil, fmt.Errorf("PEM block is %q, want \"ECH CONFIGS\"", block.Type)
		}
		if strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("more than one PEM block")
		}
		raw = block.Bytes
	} else {
		b, ok := decodeECHBase64(s)
		if !ok {
			return nil, errors.New("not base64")
		}
		raw = b
	}
	if err := checkECHConfigList(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// CanonicalECHConfig returns s as standard padded base64, the form the model stores and share links
// carry, or s trimmed when it does not parse (Validate then names what is wrong with it).
func CanonicalECHConfig(s string) string {
	b, err := ParseECHConfigList(s)
	if err != nil {
		return strings.TrimSpace(s)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// decodeECHBase64 decodes base64 in any of the four alphabets, ignoring whitespace (a PEM body or a
// pasted, wrapped value) and reading a space as '+', which is what a query string decoder makes of
// a '+' a link left unescaped.
func decodeECHBase64(s string) ([]byte, bool) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ':
			return '+'
		case '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

// checkECHConfigList checks the framing Go's crypto/tls parses: a uint16 total length matching the
// rest, then entries of {uint16 version, uint16 length, contents}; each version-0xfe0d entry's
// contents are a HPKE key config (config id, KEM id, public key, cipher suites), a maximum name
// length, a public name and extensions, which must fill the entry exactly. It does not judge whether
// the KEM or cipher suites are ones the client supports.
func checkECHConfigList(b []byte) error {
	if len(b) < 2 {
		return errors.New("too short for an ECHConfigList")
	}
	if n := int(binary.BigEndian.Uint16(b)); n != len(b)-2 {
		return fmt.Errorf("ECHConfigList length says %d bytes, %d follow", n, len(b)-2)
	}
	b = b[2:]
	usable := 0
	for len(b) > 0 {
		if len(b) < 4 {
			return errors.New("truncated ECHConfig")
		}
		version, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+n {
			return errors.New("truncated ECHConfig")
		}
		if version == echVersion {
			if err := checkECHConfigContents(b[4 : 4+n]); err != nil {
				return err
			}
			usable++
		}
		b = b[4+n:]
	}
	if usable == 0 {
		return fmt.Errorf("no ECHConfig of version %#04x", echVersion)
	}
	return nil
}

func checkECHConfigContents(c []byte) error {
	bad := errors.New("malformed ECHConfig")
	take := func(n int) ([]byte, bool) {
		if len(c) < n {
			return nil, false
		}
		v := c[:n]
		c = c[n:]
		return v, true
	}
	// A length-prefixed vector: a w-byte (1 or 2) length, then that many bytes, no fewer than least.
	vec := func(w, least int) ([]byte, bool) {
		p, ok := take(w)
		if !ok {
			return nil, false
		}
		n := int(p[0])
		if w == 2 {
			n = int(binary.BigEndian.Uint16(p))
		}
		if n < least {
			return nil, false
		}
		return take(n)
	}
	if _, ok := take(1 + 2); !ok { // config_id, kem_id
		return bad
	}
	if _, ok := vec(2, 1); !ok { // public_key
		return bad
	}
	if suites, ok := vec(2, 4); !ok || len(suites)%4 != 0 { // {kdf_id, aead_id} pairs
		return bad
	}
	if _, ok := take(1); !ok { // maximum_name_length
		return bad
	}
	if _, ok := vec(1, 1); !ok { // public_name
		return bad
	}
	ext, ok := vec(2, 0)
	if !ok || len(c) != 0 {
		return bad
	}
	for len(ext) > 0 { // {uint16 type, opaque data<0..2^16-1>}
		if len(ext) < 4 || len(ext) < 4+int(binary.BigEndian.Uint16(ext[2:])) {
			return bad
		}
		ext = ext[4+int(binary.BigEndian.Uint16(ext[2:])):]
	}
	return nil
}

// echProblem names an ECH setting that sing-box refuses, or that would fail every handshake of the
// connection, in Validate's words; "" when there is none or ECH is off.
func echProblem(e *Endpoint) string {
	t := e.TLS
	if t == nil || !t.Enabled || t.ECH == nil || !t.ECH.Enabled {
		return ""
	}
	if t.Type == "reality" {
		return "ECH cannot be combined with Reality (sing-box refuses the pair)"
	}
	if t.ECH.Config != "" {
		if _, err := ParseECHConfigList(t.ECH.Config); err != nil {
			return "invalid ECH config: " + err.Error()
		}
		return ""
	}
	// sing-quic dials with the plain TLS config and never runs the lookup, so over QUIC the server
	// name would go out in the clear while the connection says ECH.
	if e.Protocol == ProtoHysteria2 || e.Protocol == ProtoTUIC {
		return "ECH from DNS does not work over QUIC (hysteria2, tuic); paste the server's ECH config instead"
	}
	if q := strings.TrimSpace(t.ECH.QueryServerName); q != "" {
		if !IsDNSName(q) {
			if !isASCII(q) {
				return fmt.Sprintf("invalid ECH query server name %q: write it in its punycode (xn--) form", q)
			}
			return fmt.Sprintf("invalid ECH query server name %q (want a domain name)", q)
		}
		return ""
	}
	name := t.SNI
	if name == "" {
		name = e.Server
	}
	if !IsDNSName(name) {
		// A name with letters outside ASCII is a domain, but DNS asks for it in punycode.
		if !isASCII(name) {
			return fmt.Sprintf("ECH from DNS looks up the server name, and %q is not in the form DNS asks for: write the SNI in its punycode (xn--) form, or set a query server name", name)
		}
		return "ECH from DNS looks up the server name, and this connection has none to look up: set the SNI to a domain, or a query server name"
	}
	return ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// IsDNSName reports whether s is a domain name a DNS query can be made for: ASCII labels of letters,
// digits, '-' and '_', 1-63 bytes each, 253 in all, and not an IP address.
func IsDNSName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || net.ParseIP(strings.Trim(s, "[]")) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
