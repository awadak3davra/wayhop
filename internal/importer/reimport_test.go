package importer

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

const (
	reimportPin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // the link's pcs=
	reimportOwn = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // typed in the form
	reimportKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="                     // added by Set up Server
)

func reimportParse(t *testing.T, link string) model.Endpoint {
	t.Helper()
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse(%s): %v", link, err)
	}
	return *e
}

// QA-148: importing a link again takes everything the link can express from the link, a value it no
// longer carries included, and keeps only what the user owns: name, switch, health target,
// multiplex, MTU, and the pins the user added.
func TestReimport_TakesTheLinkWholeAndKeepsWhatTheUserOwns(t *testing.T) {
	const base = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&type=tcp"
	first := reimportParse(t, base+"&flow=xtls-rprx-vision&allowInsecure=1&fp=chrome&pcs="+reimportPin+"#vless-de")
	if first.Params["flow"] == nil || !first.TLS.Insecure || first.TLS.Fingerprint != "chrome" || len(first.TLS.PinCertSHA256) != 1 || !first.TLS.PinCertMayBeCA {
		t.Fatalf("the first link did not import as this test assumes: %+v %+v", first.Params, *first.TLS)
	}
	have := first
	have.Name, have.Enabled, have.MTU = "My renamed DE", false, 1380
	have.Health = &model.Health{URL: "https://example.org/generate_204", Interval: 60}
	have.Multiplex = &model.Multiplex{Enabled: true, Protocol: "smux"}
	tls := *first.TLS
	tls.PinCertSHA256 = append([]string{}, reimportPin, reimportOwn) // the user typed a second pin
	tls.PinCertMayBeCAOf = []string{reimportPin}
	tls.PinPubKeySHA256 = []string{reimportKey}
	have.TLS = &tls

	// The provider dropped Vision, allowInsecure, the fingerprint and its pin.
	link := reimportParse(t, base+"#vless-de")
	out := Reimport(have, link)
	if out.ID != have.ID || out.Name != have.Name || out.Enabled || out.MTU != 1380 ||
		!reflect.DeepEqual(out.Health, have.Health) || !reflect.DeepEqual(out.Multiplex, have.Multiplex) {
		t.Errorf("user-owned fields reverted: %+v", out)
	}
	if _, ok := out.Params["flow"]; ok {
		t.Errorf("flow the link dropped is still stored: %v", out.Params)
	}
	if out.TLS.Insecure || out.TLS.Fingerprint != "" {
		t.Errorf("insecure %v / fingerprint %q the link dropped are still stored", out.TLS.Insecure, out.TLS.Fingerprint)
	}
	if !reflect.DeepEqual(out.TLS.PinCertSHA256, []string{reimportOwn}) || out.TLS.PinCertMayBeCA || len(out.TLS.PinCertMayBeCAOf) != 0 {
		t.Errorf("cert pins = %v (may-be-CA %v %v), want only the one the user typed, unmarked",
			out.TLS.PinCertSHA256, out.TLS.PinCertMayBeCA, out.TLS.PinCertMayBeCAOf)
	}
	if !reflect.DeepEqual(out.TLS.PinPubKeySHA256, []string{reimportKey}) {
		t.Errorf("the public-key pin Set up Server added was dropped: %v", out.TLS.PinPubKeySHA256)
	}
	if SameEndpoint(out, have) {
		t.Error("a link that dropped flow, insecure, the fingerprint and a pin is reported unchanged")
	}
	if len(have.TLS.PinCertSHA256) != 2 || have.Params["flow"] == nil {
		t.Error("Reimport wrote into the endpoint it was given")
	}
	if !SameEndpoint(Reimport(out, link), out) {
		t.Error("importing the same link once more is not unchanged")
	}
}

// A link that brings a pin beside one the user typed marks only its own as imported.
func TestReimport_LinkPinsBesideATypedOneNameTheirOwn(t *testing.T) {
	const base = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&type=tcp"
	have := reimportParse(t, base+"#a")
	tls := *have.TLS
	tls.PinCertSHA256 = []string{reimportOwn}
	have.TLS = &tls
	out := Reimport(have, reimportParse(t, base+"&pcs="+reimportPin+"#a"))
	if !reflect.DeepEqual(out.TLS.PinCertSHA256, []string{reimportPin, reimportOwn}) || !out.TLS.PinCertMayBeCA ||
		!reflect.DeepEqual(out.TLS.PinCertMayBeCAOf, []string{reimportPin}) {
		t.Errorf("pins %v may-be-CA %v of %v, want both, the mark naming the link's alone",
			out.TLS.PinCertSHA256, out.TLS.PinCertMayBeCA, out.TLS.PinCertMayBeCAOf)
	}
	if strings.Contains(strings.Join(out.TLS.PinCertMayBeCAOf, ","), reimportOwn) {
		t.Error("the typed pin was marked as imported")
	}
}

// The in-place branch of DedupeNew returns the merge, and the same link twice in one batch updates
// its connection once.
func TestDedupeNew_InPlaceUpdateIsMerged(t *testing.T) {
	have := dedupe_ep("x1", "vless", "1.2.3.4", 443, "u1")
	have.Name = "edited"
	have.Enabled = false
	link := dedupe_ep("x1", "vless", "1.2.3.4", 443, "u1")
	uniq, dupes := DedupeNew([]model.Endpoint{have}, []model.Endpoint{link, link})
	if len(uniq) != 1 || dupes != 1 {
		t.Fatalf("uniq=%d dupes=%d, want one update and one duplicate", len(uniq), dupes)
	}
	if uniq[0].Name != "edited" || uniq[0].Enabled {
		t.Errorf("the update reverted the edit: %+v", uniq[0])
	}
	if !SameEndpoint(uniq[0], have) {
		t.Error("an identical link should leave the connection exactly as stored")
	}
}
