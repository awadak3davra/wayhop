package importer

import (
	"testing"

	"wayhop/internal/model"
)

func dedupe_ep(id, proto, server string, port int, uuid string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.Protocol(proto),
		Server: server, Port: port, Enabled: true,
		Params: map[string]any{"uuid": uuid},
	}
}

func TestContentKey(t *testing.T) {
	a := dedupe_ep("a", "vless", "1.2.3.4", 443, "u1")
	b := dedupe_ep("b", "vless", "1.2.3.4", 443, "u1") // same content, different id/name
	if ContentKey(a) != ContentKey(b) {
		t.Errorf("same-content endpoints must share a key:\n%s\n%s", ContentKey(a), ContentKey(b))
	}
	for _, diff := range []model.Endpoint{
		dedupe_ep("c", "vless", "1.2.3.4", 443, "u2"),  // different uuid
		dedupe_ep("d", "vless", "1.2.3.4", 8443, "u1"), // different port
		dedupe_ep("e", "trojan", "1.2.3.4", 443, "u1"), // different protocol
		dedupe_ep("f", "vless", "5.6.7.8", 443, "u1"),  // different server
	} {
		if ContentKey(a) == ContentKey(diff) {
			t.Errorf("endpoints differing in an identity field must NOT share a key: %s", ContentKey(diff))
		}
	}
	// Server casing/whitespace is normalized.
	if ContentKey(a) != ContentKey(dedupe_ep("g", "VLESS", " 1.2.3.4 ", 443, "u1")) {
		t.Error("protocol case + server whitespace should be normalized in the key")
	}
}

// withTransport returns a copy of e carrying the given stream transport.
func withTransport(e model.Endpoint, t *model.Transport) model.Endpoint {
	e.Transport = t
	return e
}

// withTLS returns a copy of e carrying the given TLS settings.
func withTLS(e model.Endpoint, s *model.TLS) model.Endpoint {
	e.TLS = s
	return e
}

func TestContentKey_TransportTLS(t *testing.T) {
	base := dedupe_ep("base", "vless", "1.2.3.4", 443, "u1")

	// Same host:port:uuid but different stream transport must yield DISTINCT keys
	// (regression for the bug where ws-vs-grpc variants collapsed to one key and
	// the second was silently dropped on bulk import / never added on refresh).
	ws := withTransport(dedupe_ep("ws", "vless", "1.2.3.4", 443, "u1"),
		&model.Transport{Type: "ws", Path: "/a"})
	grpc := withTransport(dedupe_ep("grpc", "vless", "1.2.3.4", 443, "u1"),
		&model.Transport{Type: "grpc", ServiceName: "svc"})
	if ContentKey(ws) == ContentKey(grpc) {
		t.Errorf("ws vs grpc transports must have DISTINCT keys:\n%s\n%s", ContentKey(ws), ContentKey(grpc))
	}
	// A transport differs from raw TCP (nil transport).
	if ContentKey(ws) == ContentKey(base) {
		t.Error("ws transport must differ from raw-TCP (nil transport)")
	}
	// ws with a different path must differ.
	ws2 := withTransport(dedupe_ep("ws2", "vless", "1.2.3.4", 443, "u1"),
		&model.Transport{Type: "ws", Path: "/b"})
	if ContentKey(ws) == ContentKey(ws2) {
		t.Error("ws transports differing only in path must have distinct keys")
	}

	// Same host:port:uuid but different TLS mode (tls vs reality) must be DISTINCT.
	tlsPlain := withTLS(dedupe_ep("tls", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "tls", SNI: "example.com"})
	reality := withTLS(dedupe_ep("rl", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "reality", SNI: "example.com", PublicKey: "PK", ShortID: "ab"})
	if ContentKey(tlsPlain) == ContentKey(reality) {
		t.Errorf("tls vs reality must have DISTINCT keys:\n%s\n%s", ContentKey(tlsPlain), ContentKey(reality))
	}
	// TLS-enabled differs from no TLS.
	if ContentKey(tlsPlain) == ContentKey(base) {
		t.Error("TLS-enabled endpoint must differ from plaintext (nil TLS)")
	}
	// Reality keys differing only in short_id / public_key must differ.
	reality2 := withTLS(dedupe_ep("rl2", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "reality", SNI: "example.com", PublicKey: "PK", ShortID: "cd"})
	if ContentKey(reality) == ContentKey(reality2) {
		t.Error("reality endpoints differing in short_id must have distinct keys")
	}
	// Different SNI must differ.
	tlsSNI := withTLS(dedupe_ep("sni", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "tls", SNI: "other.com"})
	if ContentKey(tlsPlain) == ContentKey(tlsSNI) {
		t.Error("TLS endpoints differing in SNI must have distinct keys")
	}
	// Different ALPN must differ.
	alpnA := withTLS(dedupe_ep("alpnA", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: []string{"h2"}})
	alpnB := withTLS(dedupe_ep("alpnB", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: []string{"h2", "http/1.1"}})
	if ContentKey(alpnA) == ContentKey(alpnB) {
		t.Error("TLS endpoints differing in ALPN must have distinct keys")
	}

	// CRITICAL invariant: an identical re-parse (same stable fields, only ID/name
	// differ) still produces the SAME key, so genuine re-fetches dedupe.
	wsAgain := withTransport(dedupe_ep("ws-again", "VLESS", " 1.2.3.4 ", 443, "u1"),
		&model.Transport{Type: "WS", Path: "/a", Host: ""})
	wsAgain = withTLS(wsAgain, nil)
	wsNorm := withTLS(ws, nil)
	if ContentKey(wsNorm) != ContentKey(wsAgain) {
		t.Errorf("identical re-parse must share a key (transport normalized):\n%s\n%s",
			ContentKey(wsNorm), ContentKey(wsAgain))
	}
	rlAgain := withTLS(dedupe_ep("rl-again", "vless", "1.2.3.4", 443, "u1"),
		&model.TLS{Enabled: true, Type: "REALITY", SNI: "EXAMPLE.COM", PublicKey: "PK", ShortID: "ab"})
	if ContentKey(reality) != ContentKey(rlAgain) {
		t.Errorf("identical reality re-parse must share a key (type/sni normalized):\n%s\n%s",
			ContentKey(reality), ContentKey(rlAgain))
	}
}

func TestDedupeNew(t *testing.T) {
	existing := []model.Endpoint{dedupe_ep("x1", "vless", "1.2.3.4", 443, "u1")}

	// A new-ID content-dupe of an existing endpoint is dropped; a genuinely new one kept.
	in := []model.Endpoint{
		dedupe_ep("new-a", "vless", "1.2.3.4", 443, "u1"), // dupe of x1 (content) -> drop
		dedupe_ep("new-b", "vless", "9.9.9.9", 443, "u2"), // new -> keep
	}
	uniq, dupes := DedupeNew(existing, in)
	if dupes != 1 || len(uniq) != 1 || uniq[0].ID != "new-b" {
		t.Fatalf("expected 1 dupe + keep new-b, got dupes=%d uniq=%v", dupes, uniq)
	}

	// An incoming endpoint reusing an existing ID is an UPDATE, not a dupe (kept even if
	// its content matches). Legitimate re-import-update path: same ID + same content.
	upd := []model.Endpoint{dedupe_ep("x1", "vless", "1.2.3.4", 443, "u1")}
	uniq, dupes = DedupeNew(existing, upd)
	if dupes != 0 || len(uniq) != 1 {
		t.Fatalf("same-ID update must be kept, not deduped: dupes=%d uniq=%v", dupes, uniq)
	}

	// ID collision with DIFFERENT content must NOT be treated as an in-place update
	// (otherwise an import-generated ID could overwrite a different user endpoint).
	// It is genuinely new content under a colliding ID -> kept via content-dedup.
	collide := []model.Endpoint{dedupe_ep("x1", "vless", "8.8.8.8", 443, "uZ")}
	uniq, dupes = DedupeNew(existing, collide)
	if dupes != 0 || len(uniq) != 1 || uniq[0].Server != "8.8.8.8" {
		t.Fatalf("ID collision w/ different content must NOT overwrite-as-update: dupes=%d uniq=%v", dupes, uniq)
	}

	// ID collision where content ALSO equals an existing endpoint (but NOT the one
	// sharing the ID) still falls through to content-dedup and is dropped.
	existing2 := []model.Endpoint{
		dedupe_ep("id-A", "vless", "1.1.1.1", 443, "uA"),
		dedupe_ep("id-B", "vless", "2.2.2.2", 443, "uB"),
	}
	// Reuses id-A but its content matches id-B -> not an update of id-A, content dup of id-B.
	collide2 := []model.Endpoint{dedupe_ep("id-A", "vless", "2.2.2.2", 443, "uB")}
	uniq, dupes = DedupeNew(existing2, collide2)
	if dupes != 1 || len(uniq) != 0 {
		t.Fatalf("ID collision matching a different endpoint's content must dedup: dupes=%d uniq=%v", dupes, uniq)
	}

	// Within-batch duplicates: first kept, rest dropped.
	batch := []model.Endpoint{
		dedupe_ep("b1", "trojan", "2.2.2.2", 443, "p"),
		dedupe_ep("b2", "trojan", "2.2.2.2", 443, "p"), // dupe of b1 (content)
	}
	uniq, dupes = DedupeNew(nil, batch)
	if dupes != 1 || len(uniq) != 1 || uniq[0].ID != "b1" {
		t.Fatalf("within-batch dedup failed: dupes=%d uniq=%v", dupes, uniq)
	}

	// Empty existing + all-unique incoming: nothing dropped.
	all := []model.Endpoint{
		dedupe_ep("a", "vless", "1.1.1.1", 1, "u"),
		dedupe_ep("b", "vless", "2.2.2.2", 2, "u"),
	}
	uniq, dupes = DedupeNew(nil, all)
	if dupes != 0 || len(uniq) != 2 {
		t.Fatalf("all-unique import must keep everything: dupes=%d uniq=%d", dupes, len(uniq))
	}
}
