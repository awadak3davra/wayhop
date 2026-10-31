package initserver

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"wayhop/internal/model"
)

// Certificate pins of the self-signed TLS servers Set up Server makes (QA-138).
//
// The installer hashes the certificate it generated (scriptTLSPins) and prints both pins with the
// client config: the whole-certificate pin inside the link, where WayHop's importer and other
// clients read it (pinSHA256= on Hysteria2, pcs= on Trojan, TUIC and AnyTLS, "pcs" in the VMess JSON),
// and the public-key pin, which no share link carries, on a PubKeyPinMarker line of its own. The
// links keep insecure=1 for clients that cannot pin; the generator leaves insecure out wherever it
// renders a pin, so the router's own connection checks the server by its pins: the public key on
// sing-box 1.13 and later, the whole certificate from 1.15.

// PubKeyPinMarker starts the line on which the installer prints, between a protocol's WR_PROTO
// marker and its client config, the public-key pin (standard base64) of the certificate that
// config's server presents.
const PubKeyPinMarker = "WR_PUBKEY_SHA256="

// The SHA-256 of empty input, as hex and as base64: what dgst prints when a step before it failed and
// fed it nothing. It is a well-formed pin of no certificate, so the installer and the parser refuse it
// by value.
const (
	emptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	emptySHA256B64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
)

// pinCheck is model.ParsePinSHA256, also refusing the hash of empty input.
func pinCheck(p string) error {
	b, err := model.ParsePinSHA256(p)
	if err == nil && hex.EncodeToString(b) == emptySHA256Hex {
		return errors.New("the SHA-256 of empty input, so the installer hashed no certificate")
	}
	return err
}

// checkPubKeyPin returns the public-key pin the installer printed, in its stored form, or "" with a
// note on dropped when it is not a SHA-256 hash.
func checkPubKeyPin(raw string, dropped []string) (string, []string) {
	if raw == "" {
		return "", dropped
	}
	if err := pinCheck(raw); err != nil {
		return "", append(dropped, fmt.Sprintf("left out the public-key pin the installer printed: %v", err))
	}
	return model.CanonicalPubKeyPin(raw), dropped
}

// dropMalformedCertPins returns cfg without a whole-certificate pin that is not a SHA-256 hash, and a
// note for each one it left out. The importer refuses a whole link for such a pin (importer/pin.go),
// which would fail the setup of a server that is up and working; the installer's links keep
// insecure=1, so without the pin the connection is what it was before pins. The installer prints no
// pin it could not compute, so this guards against a broken openssl or a mangled transcript. Only a
// link that holds such a pin is rewritten; any other comes back byte for byte.
func dropMalformedCertPins(cfg string) (string, []string) {
	if body, ok := strings.CutPrefix(cfg, "vmess://"); ok {
		return dropVMessCertPins(cfg, body)
	}
	scheme, rest, ok := strings.Cut(cfg, "://")
	if !ok {
		return cfg, nil
	}
	head, frag, hasFrag := strings.Cut(rest, "#")
	base, query, hasQuery := strings.Cut(head, "?")
	if !hasQuery {
		return cfg, nil
	}
	hy2 := strings.EqualFold(scheme, "hysteria2") || strings.EqualFold(scheme, "hy2")
	var kept, notes []string
	for _, pair := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if key, err := url.QueryUnescape(k); err == nil && (key == "pcs" || (hy2 && key == "pinSHA256")) {
			if why := certPinProblem(key, v, true); why != "" {
				notes = append(notes, why)
				continue
			}
		}
		kept = append(kept, pair)
	}
	if len(notes) == 0 {
		return cfg, nil
	}
	out := scheme + "://" + base
	if len(kept) > 0 {
		out += "?" + strings.Join(kept, "&")
	}
	if hasFrag {
		out += "#" + frag
	}
	return out, notes
}

// dropVMessCertPins is dropMalformedCertPins for a vmess:// link, whose pins are the JSON's "pcs".
func dropVMessCertPins(cfg, body string) (string, []string) {
	body = strings.TrimSpace(body)
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(body); err == nil {
			raw = b
			break
		}
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers as they came if the JSON is written back
	if raw == nil || dec.Decode(&m) != nil {
		return cfg, nil // not a link the importer can read either; it says so
	}
	v, ok := m["pcs"]
	if !ok {
		return cfg, nil
	}
	s, isString := v.(string)
	why := certPinProblem("pcs", s, false)
	if !isString {
		why = "left out the certificate pin the installer printed (pcs): not a string"
	}
	if why == "" {
		return cfg, nil
	}
	delete(m, "pcs")
	b, err := json.Marshal(m)
	if err != nil {
		return cfg, nil
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), []string{why}
}

// certPinProblem says why a link's pin parameter key, with value v (query-escaped when escaped), is
// not what the importer takes, or "" when it is. pcs is a list, as the importer splits it.
func certPinProblem(key, v string, escaped bool) string {
	if escaped {
		u, err := url.QueryUnescape(v)
		if err != nil {
			return fmt.Sprintf("left out the certificate pin the installer printed (%s): not URL-encoded", key)
		}
		v = u
	}
	pins := []string{v}
	if key == "pcs" {
		pins = model.SplitPinList(v)
	}
	for _, p := range pins {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if err := pinCheck(p); err != nil {
			return fmt.Sprintf("left out the certificate pin the installer printed (%s): %v", key, err)
		}
	}
	return ""
}

// ApplyPins puts the pins the installer printed for tc onto ep, the connection imported from
// tc.Config, and returns lines for the job console: what was left out, then what the connection is
// pinned to.
//
// The public-key pin joins ep's TLS pins. The whole-certificate pin is already there, read from the
// link; the importer marks a pcs= pin as one that may name a CA in the chain, as Xray's may, which
// the Apply review warns about where sing-box checks it. This one is the hash of the server's own
// certificate, made by the installer that generated it, so the mark is cleared.
func (tc TaggedConfig) ApplyPins(ep *model.Endpoint) []string {
	notes := append([]string(nil), tc.Dropped...)
	if ep == nil {
		return notes
	}
	t := ep.TLS
	if t == nil || !t.Enabled || t.Type == "reality" {
		if tc.PubKeyPin != "" {
			notes = append(notes, "left out the public-key pin the installer printed: this connection has no TLS certificate to check")
		}
		return notes
	}
	if tc.PubKeyPin != "" {
		t.PinPubKeySHA256 = append(t.PinPubKeySHA256, tc.PubKeyPin)
	}
	t.PinCertMayBeCA, t.PinCertMayBeCAOf = false, nil
	t.CanonicalizePins()
	if s := pinSummary(ep); s != "" {
		notes = append(notes, s)
	}
	return notes
}

// pinSummary is the console line that says what a provisioned TLS connection checks its server by.
func pinSummary(ep *model.Endpoint) string {
	cert, key := len(model.CertPinsOf(ep)) > 0, len(model.PubKeyPinsOf(ep)) > 0
	older := "an older core checks the certificate chain instead"
	if ep.TLS.Insecure {
		older = "an older core accepts any certificate (insecure=1)"
	}
	switch {
	case cert && key:
		return "pinned to this server's certificate: its public key from sing-box 1.13, the whole certificate from 1.15; " + older
	case key:
		return "pinned to this server's public key, which sing-box checks from 1.13; " + older
	case cert:
		return "pinned to this server's whole certificate, which sing-box checks from 1.15; " + older
	case ep.TLS.Insecure:
		return "no certificate pin came with this config, so it accepts any certificate (insecure=1)"
	}
	return ""
}
