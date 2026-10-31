package model

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Certificate pinning on a TLS connection: the connection accepts the server only when its
// certificate matches a pin, in place of the usual check of the certificate's chain and name.
//
// Two kinds, each a SHA-256 hash, held in TLS.PinCertSHA256 and TLS.PinPubKeySHA256:
//
//   - A whole-certificate pin hashes the server certificate's DER. It is the kind every share format
//     carries: Hysteria's pinSHA256, Xray's pinnedPeerCertSha256 (the pcs= of a v2rayN link) and
//     mihomo's `fingerprint`. Stored as 64 lowercase hex digits, the form those links use; Hysteria's
//     own share link writes exactly that (normalizeCertHash: lowercase, ':' and '-' removed).
//   - A public-key pin hashes the certificate's SubjectPublicKeyInfo (DER), so it survives a renewal
//     that keeps the key. Only sing-box carries it (tls.certificate_public_key_sha256). Stored as
//     standard padded base64, the form sing-box writes and curl's --pinnedpubkey takes.
//
// Either kind is accepted as exactly 64 hex digits (any case, ':' or '-' between the bytes allowed)
// or as canonical standard base64 of 32 bytes (44 characters, padded), the one base64 form sing-box
// itself decodes. A list of pins is separated by commas, semicolons or white space (SplitPinList;
// the panel splits the same way). The generator writes both kinds for sing-box as base64
// (generator/pin.go), from 1.13 for a public-key pin and 1.15 for a whole-certificate pin.
//
// sing-box checks a pin against the server's own (leaf) certificate only, and instead of the chain.
// Xray and mihomo also take the hash of a CA certificate in the chain, which sing-box never matches,
// and Hysteria, with certificate checks on, checks the chain as well as the pin. Nothing in a pin says
// which it is, so the importers note where the pins came from (TLS.PinCertMayBeCA,
// TLS.PinCertBesideChain) and the Apply review states the condition for those connections only.

// pinSize is a SHA-256 hash's length.
const pinSize = 32

// ParsePinSHA256 decodes one pin of either kind to its 32 bytes. A pin made only of hex digits (':'
// and '-' between them allowed) must be exactly 64 of them; anything else must be canonical standard
// base64 of 32 bytes, which is 44 characters with its padding. So 43 or 63 hex digits are refused
// rather than read as base64 of something else, and so are raw or URL-safe base64, which sing-box's
// own decoder refuses too.
func ParsePinSHA256(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if h := strings.NewReplacer(":", "", "-", "").Replace(s); isHexDigits(h) {
		if len(h) != 2*pinSize {
			return nil, fmt.Errorf("%d hex digits, a SHA-256 hash is %d", len(h), 2*pinSize)
		}
		return hex.DecodeString(h)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	switch {
	case err != nil:
		return nil, errors.New("neither 64 hex digits nor standard base64")
	case len(b) != pinSize:
		return nil, fmt.Errorf("%d bytes, a SHA-256 hash is %d", len(b), pinSize)
	case base64.StdEncoding.EncodeToString(b) != s:
		return nil, errors.New("not canonical base64")
	}
	return b, nil
}

// isHexDigits reports whether s is non-empty and holds hex digits only.
func isHexDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F') {
			return false
		}
	}
	return true
}

// CanonicalCertPin returns a whole-certificate pin as 64 lowercase hex digits, or s trimmed when it
// does not parse (Validate then names it).
func CanonicalCertPin(s string) string {
	b, err := ParsePinSHA256(s)
	if err != nil {
		return strings.TrimSpace(s)
	}
	return hex.EncodeToString(b)
}

// CanonicalPubKeyPin returns a public-key pin as standard padded base64, or s trimmed when it does
// not parse.
func CanonicalPubKeyPin(s string) string {
	b, err := ParsePinSHA256(s)
	if err != nil {
		return strings.TrimSpace(s)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// SplitPinList splits a list of pins as a link's pcs= carries it (Xray splits on commas), also
// taking a semicolon or white space between them, as the panel's field does. A pin itself holds no
// white space (ParsePinSHA256), so "AB CD ..." is read as many pins, each refused, on both sides.
func SplitPinList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) })
}

// canonicalPins canonicalises and deduplicates pins, dropping empty entries; nil when none remain.
func canonicalPins(pins []string, canon func(string) string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range pins {
		c := canon(p)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// CanonicalizePins rewrites t's pins in their stored forms, deduplicated. A pin that does not parse
// is kept, trimmed, so that Validate names it instead of it vanishing.
func (t *TLS) CanonicalizePins() {
	if t == nil {
		return
	}
	t.PinCertSHA256 = canonicalPins(t.PinCertSHA256, CanonicalCertPin)
	t.PinPubKeySHA256 = canonicalPins(t.PinPubKeySHA256, CanonicalPubKeyPin)
	t.PinCertMayBeCAOf = canonicalPins(t.PinCertMayBeCAOf, CanonicalCertPin)
	t.PinCertBesideChainOf = canonicalPins(t.PinCertBesideChainOf, CanonicalCertPin)
}

// ParamLegacyPin is where WayHop before certificate pinning kept a Hysteria2 link's pinSHA256 so an
// export could give it back. CertPinsOf reads it as a whole-certificate pin when it parses, so a
// connection imported then gets the pin enforced without being imported again.
const ParamLegacyPin = "pin_sha256"

// ParamVerifyCertName is a link's vcn= (Xray's verifyPeerCertByName): the names the server's
// certificate is checked against instead of the SNI, so the real name can stay out of the SNI.
// sing-box has no such option (it checks the certificate against server_name, which is also the
// SNI), so it is kept only to be exported again, and the Apply review says when it matters.
const ParamVerifyCertName = "vcn"

// CertPinsOf returns e's whole-certificate pins in their stored form: TLS.PinCertSHA256 and the
// legacy Hysteria2 parameter when it parses. Pins that do not parse are left out.
func CertPinsOf(e *Endpoint) []string {
	if e == nil || e.TLS == nil {
		return nil
	}
	var in []string
	for _, p := range e.TLS.PinCertSHA256 {
		if _, err := ParsePinSHA256(p); err == nil {
			in = append(in, p)
		}
	}
	if legacy, _ := e.Params[ParamLegacyPin].(string); legacy != "" {
		if _, err := ParsePinSHA256(legacy); err == nil {
			in = append(in, legacy)
		}
	}
	return canonicalPins(in, CanonicalCertPin)
}

// PubKeyPinsOf returns e's public-key pins in their stored form, leaving out any that do not parse.
func PubKeyPinsOf(e *Endpoint) []string {
	if e == nil || e.TLS == nil {
		return nil
	}
	var in []string
	for _, p := range e.TLS.PinPubKeySHA256 {
		if _, err := ParsePinSHA256(p); err == nil {
			in = append(in, p)
		}
	}
	return canonicalPins(in, CanonicalPubKeyPin)
}

// HasPinIntent reports whether e asks for a pin at all, a malformed one included: what the Apply
// review needs to tell a connection that pins nothing from one whose pin is not enforced.
func HasPinIntent(e *Endpoint) bool {
	if e == nil || e.TLS == nil {
		return false
	}
	legacy, _ := e.Params[ParamLegacyPin].(string)
	return len(e.TLS.PinCertSHA256) > 0 || len(e.TLS.PinPubKeySHA256) > 0 || strings.TrimSpace(legacy) != ""
}

// VerifyCertNames returns the names a link's vcn= asked the certificate to be checked against.
func VerifyCertNames(e *Endpoint) []string {
	if e == nil {
		return nil
	}
	v, _ := e.Params[ParamVerifyCertName].(string)
	var out []string
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// pinProblem names a pin that is not a SHA-256 hash. It is refused rather than left out: the
// generator renders only the pins it can decode, so a connection whose pin did not parse would run
// without the check its owner asked for. The legacy parameter is not checked here: an older WayHop
// stored whatever the link held, and refusing it now would stop the whole profile from applying.
func pinProblem(e *Endpoint) string {
	t := e.TLS
	if t == nil {
		return ""
	}
	for _, p := range t.PinCertSHA256 {
		if _, err := ParsePinSHA256(p); err != nil {
			return fmt.Sprintf("certificate pin %q is not a SHA-256 hash (%v): give 64 hex digits or base64 of 32 bytes", p, err)
		}
	}
	for _, p := range t.PinPubKeySHA256 {
		if _, err := ParsePinSHA256(p); err != nil {
			return fmt.Sprintf("public-key pin %q is not a SHA-256 hash (%v): give base64 of 32 bytes or 64 hex digits", p, err)
		}
	}
	return ""
}
