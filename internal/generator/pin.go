package generator

import (
	"encoding/base64"
	"fmt"
	"strings"

	"wayhop/internal/model"
)

// Certificate pinning (model/pin.go) in sing-box's outbound TLS options (option/tls.go):
//
//   - certificate_public_key_sha256, the SHA-256 of the certificate's public key, from 1.13.0;
//   - certificate_sha256, the SHA-256 of the whole certificate, from 1.15.0.
//
// Both are lists of base64 hashes, and 1.12 has neither: its decoder refuses an unknown field, which
// would stop every connection sharing the config. With either present sing-box sets
// InsecureSkipVerify and checks the pins instead of the chain (common/tls/std_client.go and
// utls_client.go, so with a uTLS fingerprint too; VerifyPinnedCertificate on 1.15,
// VerifyPublicKeySHA256 before): a pin replaces the chain-and-name check, and it is matched against
// the leaf certificate only. A pin beside certificate or certificate_path is an error there; WayHop
// renders neither of those on a TLS outbound, so the pair never arises.
//
// Fail closed: where the core named by the version cannot carry a pin (or the version is unknown),
// the pin is left out and nothing else changes. A connection with certificate checks on keeps them,
// so a server whose certificate no public CA signs is refused rather than trusted; one whose link
// turned them off ("insecure") keeps that, as before pinning existed. The Apply review names both
// (PinsLeftOut). Where a pin is rendered, `insecure` is left out beside it: the pin already replaces
// the chain check, and it is what authenticates the server.

// pinPubKeyMinMinor is the first sing-box minor with tls.certificate_public_key_sha256.
const pinPubKeyMinMinor = 13

// pinCertMinMinor is the first sing-box minor with tls.certificate_sha256.
const pinCertMinMinor = 15

// pinB64 decodes stored pins (model.CertPinsOf / PubKeyPinsOf, which keep only pins that parse) to
// the standard base64 sing-box decodes a []byte from.
func pinB64(pins []string) []string {
	out := make([]string, 0, len(pins))
	for _, p := range pins {
		if b, err := model.ParsePinSHA256(p); err == nil {
			out = append(out, base64.StdEncoding.EncodeToString(b))
		}
	}
	return out
}

// pinTarget reports whether e's rendered outbound has a TLS block a pin can go into: plain TLS, not
// Reality, whose own verifier replaces any pin check sing-box would set up (reality_client.go).
func pinTarget(e *model.Endpoint, ob map[string]any) (map[string]any, bool) {
	if e == nil || e.TLS == nil || e.TLS.Type == "reality" {
		return nil, false
	}
	tl, ok := ob["tls"].(map[string]any)
	if !ok || tl["reality"] != nil {
		return nil, false
	}
	return tl, true
}

// pinCoreExtras writes e's pins into ob's tls block where the core named by coreVersion carries
// them, and drops `insecure` beside a pin it wrote. A connection without pins is untouched, so its
// render is byte-identical to one made before pinning existed.
func pinCoreExtras(e *model.Endpoint, ob map[string]any, coreVersion string) {
	tl, ok := pinTarget(e, ob)
	if !ok {
		return
	}
	m := coreMinor(coreVersion)
	wrote := false
	if m >= pinCertMinMinor {
		if pins := pinB64(model.CertPinsOf(e)); len(pins) > 0 {
			tl["certificate_sha256"] = pins
			wrote = true
		}
	}
	if m >= pinPubKeyMinMinor {
		if pins := pinB64(model.PubKeyPinsOf(e)); len(pins) > 0 {
			tl["certificate_public_key_sha256"] = pins
			wrote = true
		}
	}
	if wrote {
		delete(tl, "insecure")
	}
}

// pinOutboundTLS is the tls block Generate renders for e before the core is considered, or nil when
// a pin has nowhere to go.
func pinOutboundTLS(e *model.Endpoint) map[string]any {
	if e == nil || e.Engine != model.EngineSingBox || !tlsCapable(e.Protocol) {
		return nil
	}
	tl := tlsJSON(e.TLS)
	if tl == nil {
		return nil
	}
	if _, ok := pinTarget(e, map[string]any{"tls": tl}); !ok {
		return nil
	}
	return tl
}

// PinCoverage is what the core named by a version does with a connection's pins.
type PinCoverage struct {
	// CertLeftOut and PubKeyLeftOut count the well-formed pins of each kind the core cannot carry.
	CertLeftOut, PubKeyLeftOut int
	// Malformed is a pin the generator cannot decode: the legacy Hysteria2 parameter an older WayHop
	// stored as the link held it (model.Validate refuses one anywhere else).
	Malformed bool
	// Enforced: at least one pin is rendered, so the core checks the server against the pins alone.
	Enforced bool
	// CertEnforced: a whole-certificate pin is rendered.
	CertEnforced bool
	// Insecure: nothing is rendered and the connection's certificate checks are off, so it accepts
	// any certificate.
	Insecure bool
}

// PinsOf reports how the core named by coreVersion carries e's pins; ok is false when e asks for
// none, or has no TLS block a pin could go into (Reality, a protocol without TLS, an engine other
// than sing-box).
func PinsOf(e *model.Endpoint, coreVersion string) (c PinCoverage, ok bool) {
	if !model.HasPinIntent(e) {
		return c, false
	}
	tl := pinOutboundTLS(e)
	if tl == nil {
		return c, false
	}
	m := coreMinor(coreVersion)
	cert, pub := model.CertPinsOf(e), model.PubKeyPinsOf(e)
	if m >= pinCertMinMinor {
		c.CertEnforced = len(cert) > 0
	} else {
		c.CertLeftOut = len(cert)
	}
	if m < pinPubKeyMinMinor {
		c.PubKeyLeftOut = len(pub)
	}
	c.Enforced = c.CertEnforced || (m >= pinPubKeyMinMinor && len(pub) > 0)
	legacy, _ := e.Params[model.ParamLegacyPin].(string)
	for _, p := range append(append([]string{legacy}, e.TLS.PinCertSHA256...), e.TLS.PinPubKeySHA256...) {
		if _, err := model.ParsePinSHA256(p); err != nil && strings.TrimSpace(p) != "" {
			c.Malformed = true
		}
	}
	c.Insecure = !c.Enforced && e.TLS.Insecure
	return c, true
}

// PinsLeftOut reports a connection whose pins the core named by coreVersion does not all check
// because it is older than the kind needs, or its version is unknown.
func PinsLeftOut(e *model.Endpoint, coreVersion string) (PinCoverage, bool) {
	c, ok := PinsOf(e, coreVersion)
	return c, ok && (c.CertLeftOut > 0 || c.PubKeyLeftOut > 0)
}

// PinMalformed reports a connection carrying a pin that is not a SHA-256 hash: in practice the legacy
// Hysteria2 parameter an older WayHop stored as the link held it (model.Validate refuses one anywhere
// else). No core can check it, so it is ignored whatever the version.
func PinMalformed(e *model.Endpoint) bool {
	c, ok := PinsOf(e, "")
	return ok && c.Malformed
}

// PinReplacesChainCheck reports a connection with certificate checks on whose Hysteria pinSHA256 the
// core checks. Hysteria's own client checks the chain, name and expiry and then the pin; sing-box
// checks the pin instead (std_client.go sets InsecureSkipVerify beside a pin), so a certificate that
// matches the pin is accepted even once it has expired. Pins from formats that already work that way
// (pcs=, mihomo's fingerprint, a sing-box config, the form) say nothing.
func PinReplacesChainCheck(e *model.Endpoint, coreVersion string) bool {
	c, ok := PinsOf(e, coreVersion)
	if !ok || !c.CertEnforced || e.TLS.Insecure {
		return false
	}
	if e.TLS.PinCertBesideChain {
		return true
	}
	legacy, _ := e.Params[model.ParamLegacyPin].(string)
	_, err := model.ParsePinSHA256(legacy)
	return err == nil
}

// PinsUnusedByReality reports a Reality connection carrying pins (a link's pcs=, or typed in the API):
// Reality authenticates the server by its own key, and sing-box's Reality client replaces any pin
// check, so they are kept only to be exported again.
func PinsUnusedByReality(e *model.Endpoint) bool {
	if e == nil || e.Engine != model.EngineSingBox || !tlsCapable(e.Protocol) || e.TLS == nil || !e.TLS.Enabled || e.TLS.Type != "reality" {
		return false
	}
	return len(e.TLS.PinCertSHA256) > 0 || len(e.TLS.PinPubKeySHA256) > 0
}

// PinCoreNeeded returns the sing-box version that checks every pin e has ("1.15" for a whole-certificate
// pin, "1.13" for a public-key pin) when the core named by coreVersion is known and older, or "".
func PinCoreNeeded(e *model.Endpoint, coreVersion string) string {
	c, ok := PinsOf(e, coreVersion)
	if !ok || coreMinor(coreVersion) < 0 {
		return ""
	}
	switch {
	case c.CertLeftOut > 0:
		return fmt.Sprintf("1.%d", pinCertMinMinor)
	case c.PubKeyLeftOut > 0:
		return fmt.Sprintf("1.%d", pinPubKeyMinMinor)
	}
	return ""
}

// PinsMayNameCA reports a connection whose whole-certificate pins came from a format that also
// accepts a CA's hash in the chain (Xray's pcs=, mihomo's fingerprint) and which the core checks:
// sing-box matches a pin against the server's own certificate only, so a pin that is a CA's fails
// every handshake here.
func PinsMayNameCA(e *model.Endpoint, coreVersion string) bool {
	c, ok := PinsOf(e, coreVersion)
	return ok && c.CertEnforced && e.TLS.PinCertMayBeCA
}

// CertNameUnchecked returns the names a connection's vcn= asked its certificate to be checked
// against that sing-box checks no certificate against: sing-box checks the server_name, which is
// also the SNI, so the check fails unless the certificate covers the SNI too. It says nothing when
// no name is checked at all: a pin is rendered, or certificate checks are off.
func CertNameUnchecked(e *model.Endpoint, coreVersion string) []string {
	names := model.VerifyCertNames(e)
	if len(names) == 0 || e.TLS == nil || e.TLS.Insecure {
		return nil
	}
	tl := pinOutboundTLS(e)
	if tl == nil {
		return nil
	}
	if c, ok := PinsOf(e, coreVersion); ok && c.Enforced {
		return nil
	}
	sni, _ := tl["server_name"].(string)
	if sni == "" {
		sni = e.Server
	}
	var out []string
	for _, n := range names {
		if !strings.EqualFold(n, sni) {
			out = append(out, n)
		}
	}
	return out
}
