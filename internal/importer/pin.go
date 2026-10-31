package importer

import (
	"fmt"
	"net/url"
	"strings"

	"wayhop/internal/model"
)

// Certificate pins in the formats that carry them (model/pin.go):
//
//   - Hysteria2 links: pinSHA256, the lowercase hex SHA-256 of the server's whole certificate, after
//     Hysteria's normalizeCertHash (':' and '-' removed, any case); one value.
//   - VLESS, VMess, Trojan, AnyTLS, TUIC and Hysteria2 links as v2rayN writes and reads them: pcs=
//     (Xray's pinnedPeerCertSha256: whole-certificate hashes in hex, ':' allowed, comma-separated;
//     Xray matches the leaf or a CA in the chain) and vcn= (verifyPeerCertByName: the names the
//     certificate is checked against instead of the SNI). A VMess link carries both in its JSON.
//   - Clash / mihomo: `fingerprint`, a whole-certificate hash in hex (':' allowed) matched against
//     any certificate in the chain. It is not a uTLS fingerprint, which is client-fingerprint; mihomo
//     refuses a browser name there and points to client-fingerprint.
//   - sing-box: tls.certificate_sha256 (1.15) and tls.certificate_public_key_sha256 (1.13), base64.
//
// Each importer notes where the whole-certificate pins came from (model/pin.go): pcs= and mihomo's
// fingerprint may name a CA in the chain (TLS.PinCertMayBeCA), and Hysteria's pinSHA256 is checked
// beside the chain while certificate checks are on (TLS.PinCertBesideChain). The Apply review says
// what sing-box does differently for those connections only.
//
// A pin that is not a SHA-256 hash refuses the connection: Xray, mihomo and sing-box refuse the
// config, and Hysteria accepts it and then matches nothing, so the link cannot work as written, and
// importing it without the pin would trust what the link meant to rule out. vcn has no sing-box
// counterpart (server_name is both the SNI and the name checked), so it is kept in the params to be
// exported again, never moved into the SNI, where it would send the real name in the clear.

// addCertPins appends whole-certificate pins to t in their stored form, or names the first one that
// is not a SHA-256 hash, as the format calls it (key).
func addCertPins(t *model.TLS, key string, pins ...string) error {
	for _, p := range pins {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := model.ParsePinSHA256(p); err != nil {
			return fmt.Errorf("%s %q is not a SHA-256 certificate hash (%v)", key, p, err)
		}
		t.PinCertSHA256 = append(t.PinCertSHA256, model.CanonicalCertPin(p))
	}
	t.CanonicalizePins()
	return nil
}

// linkPins reads a share link's pcs= and vcn= into e, and for Hysteria2 its pinSHA256 too. A link
// without TLS (security=none) has nothing to pin, so both are ignored there.
func linkPins(e *model.Endpoint, q url.Values) error {
	if e.TLS == nil || !e.TLS.Enabled {
		return nil
	}
	if e.Protocol == model.ProtoHysteria2 && strings.TrimSpace(q.Get("pinSHA256")) != "" {
		if err := addCertPins(e.TLS, "pinSHA256", q.Get("pinSHA256")); err != nil {
			return err
		}
		e.TLS.PinCertBesideChain = true
	}
	if pcs := model.SplitPinList(q.Get("pcs")); len(pcs) > 0 {
		if err := addCertPins(e.TLS, "pcs", pcs...); err != nil {
			return err
		}
		e.TLS.PinCertMayBeCA = true
	}
	if v := strings.TrimSpace(q.Get("vcn")); v != "" {
		e.Params[model.ParamVerifyCertName] = v
	}
	return nil
}

// vmessPins reads a VMess link's JSON pcs and vcn (v2rayN's VmessQRCode).
func vmessPins(e *model.Endpoint, m map[string]any) error {
	if e.TLS == nil {
		return nil
	}
	if pcs := model.SplitPinList(asString(m["pcs"])); len(pcs) > 0 {
		if err := addCertPins(e.TLS, "pcs", pcs...); err != nil {
			return err
		}
		e.TLS.PinCertMayBeCA = true
	}
	if v := strings.TrimSpace(asString(m["vcn"])); v != "" {
		e.Params[model.ParamVerifyCertName] = v
	}
	return nil
}

// clashBrowserFingerprints are the names mihomo refuses in `fingerprint` because they belong in
// client-fingerprint (component/ca/fingerprint.go NewFingerprintVerifier).
var clashBrowserFingerprints = map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true,
	"android": true, "edge": true, "360": true, "qq": true, "random": true, "randomized": true}

// clashUTLS returns a Clash proxy's uTLS fingerprint: client-fingerprint, or a browser name an old
// config put in `fingerprint` (WayHop read it there before; mihomo now refuses that spelling, but its
// intent is plain, and reading it keeps an import that worked working).
func clashUTLS(p proxyMap) string {
	if fp := strings.TrimSpace(p["client-fingerprint"]); fp != "" {
		return fp
	}
	if fp := strings.TrimSpace(p["fingerprint"]); clashBrowserFingerprints[strings.ToLower(fp)] {
		return fp
	}
	return ""
}

// clashPins reads a Clash proxy's `fingerprint` as a whole-certificate pin onto e's TLS. A browser
// name there is the uTLS fingerprint clashUTLS reads, not a pin.
func clashPins(p proxyMap, e *model.Endpoint) error {
	fp := strings.TrimSpace(p["fingerprint"])
	if fp == "" || clashBrowserFingerprints[strings.ToLower(fp)] {
		return nil
	}
	if e.TLS == nil || !e.TLS.Enabled {
		return nil
	}
	if err := addCertPins(e.TLS, "fingerprint", fp); err != nil {
		return err
	}
	e.TLS.PinCertMayBeCA = true
	return nil
}

// singboxPins reads a sing-box tls block's pins: certificate_sha256 and certificate_public_key_sha256,
// each a base64 list or a single value.
func singboxPins(tl map[string]any, t *model.TLS) error {
	if err := addCertPins(t, "tls.certificate_sha256", anyToStringSlice(tl["certificate_sha256"])...); err != nil {
		return err
	}
	for _, p := range anyToStringSlice(tl["certificate_public_key_sha256"]) {
		if _, err := model.ParsePinSHA256(p); err != nil {
			return fmt.Errorf("tls.certificate_public_key_sha256 %q is not a SHA-256 hash (%v)", p, err)
		}
		t.PinPubKeySHA256 = append(t.PinPubKeySHA256, p)
	}
	t.CanonicalizePins()
	return nil
}
