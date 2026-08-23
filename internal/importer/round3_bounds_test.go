package importer

import (
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestParseClash_PortBounds: a clash proxy with an out-of-range port must be rejected at the import
// boundary (skipped with a per-entry error), not accepted and persisted to FATAL every future Apply.
func TestParseClash_PortBounds(t *testing.T) {
	cfg := `proxies:
  - {name: good, type: ss, server: s, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: too-high, type: ss, server: s, port: 70000, cipher: aes-256-gcm, password: p}
  - {name: negative, type: vless, server: s, port: -1, uuid: 11111111-1111-1111-1111-111111111111}
`
	eps, errs := ParseClash(cfg)
	if len(eps) != 1 || eps[0].Name != "good" {
		t.Fatalf("only the in-range proxy should import, got %d: %+v", len(eps), eps)
	}
	if len(errs) != 2 {
		t.Fatalf("both out-of-range ports should error, got errs=%v", errs)
	}
	for _, e := range errs {
		if !strings.Contains(e, "out of range") {
			t.Errorf("expected an out-of-range error, got %q", e)
		}
	}
}

// TestParseSingbox_NumericBounds: MTU/keepalive/port are typed model fields the model constrains
// tightly; an out-of-range value from a pasted sing-box config must be rejected at import, not
// persisted (the store persist path does not re-validate) to poison every future Apply.
func TestParseSingbox_NumericBounds(t *testing.T) {
	// out-of-range server_port on an outbound.
	badPort := `{"outbounds":[{"type":"vless","tag":"p","server":"s","server_port":70000,"uuid":"u"}]}`
	if eps, errs := ParseSingbox(badPort); len(eps) != 0 || len(errs) != 1 || !strings.Contains(errs[0], "out of range") {
		t.Fatalf("bad server_port: eps=%v errs=%v", eps, errs)
	}
	wg := func(mtu, ka int) string {
		return `{"endpoints":[{"type":"wireguard","tag":"w","private_key":"cHJpdg==","address":["10.0.0.2/32"],"mtu":` +
			strconv.Itoa(mtu) + `,"peers":[{"address":"1.2.3.4","port":51820,"public_key":"cHViaw==","persistent_keepalive_interval":` + strconv.Itoa(ka) + `}]}]}`
	}
	if eps, errs := ParseSingbox(wg(9500, 25)); len(eps) != 0 || len(errs) != 1 || !strings.Contains(errs[0], "mtu") {
		t.Fatalf("bad mtu: eps=%v errs=%v", eps, errs)
	}
	if eps, errs := ParseSingbox(wg(1420, 100000)); len(eps) != 0 || len(errs) != 1 || !strings.Contains(errs[0], "persistent_keepalive") {
		t.Fatalf("bad keepalive: eps=%v errs=%v", eps, errs)
	}
	// a valid wireguard endpoint still imports.
	if eps, errs := ParseSingbox(wg(1420, 25)); len(eps) != 1 || len(errs) != 0 {
		t.Fatalf("valid wg rejected: eps=%v errs=%v", eps, errs)
	}
}

// TestDedupeNew_ReslugsCollidingID: an incoming content-new endpoint whose import-generated ID
// collides with an EXISTING endpoint of different content must be re-slugged to a fresh ID, so the
// downstream ID-keyed UpsertEndpoint cannot overwrite the user's differing endpoint (the exact data
// loss the ID-match guard is meant to prevent).
func TestDedupeNew_ReslugsCollidingID(t *testing.T) {
	existing := []model.Endpoint{dedupe_ep("vless-example-com-443", "vless", "example.com", 443, "uuidA")}
	incoming := []model.Endpoint{dedupe_ep("vless-example-com-443", "vless", "example.com", 443, "uuidB")} // same ID, different uuid
	uniq, dupes := DedupeNew(existing, incoming)
	if dupes != 0 || len(uniq) != 1 {
		t.Fatalf("content-new collision must be kept: dupes=%d uniq=%v", dupes, uniq)
	}
	if uniq[0].ID == "vless-example-com-443" {
		t.Fatalf("colliding ID must be re-slugged so UpsertEndpoint can't overwrite the existing endpoint, got %q", uniq[0].ID)
	}
	if uniq[0].Server != "example.com" || uniq[0].Params["uuid"] != "uuidB" {
		t.Fatalf("re-slugged endpoint must keep its own content: %+v", uniq[0])
	}
}
