package importer

import "testing"

// TestParseShadowsocks_IPv6LiteralHost: an SS link to an IPv6 server (brackets literal OR
// percent-encoded %5B…%5D) must parse to a BARE IPv6 host, not fail "missing host/port".
// Real bug found on-device: the percent-encoded host wasn't decoded before the host:port split.
func TestParseShadowsocks_IPv6LiteralHost(t *testing.T) {
	for _, raw := range []string{
		"ss://aes-256-gcm:sspass123@%5B2001:db8::1%5D:8388#enc", // percent-encoded brackets
		"ss://aes-256-gcm:sspass123@[2001:db8::1]:8388#lit",     // literal brackets
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if e.Server != "2001:db8::1" || e.Port != 8388 {
			t.Fatalf("Parse(%q): server:port = %q:%d, want 2001:db8::1:8388", raw, e.Server, e.Port)
		}
	}
}

// TestParseWireGuard_MTUBounds: an out-of-range MTU overflows sing-box's uint32 endpoint mtu
// (FATAL at config decode -> bricks the whole shared singbox.json), so it must be DROPPED; a
// sane MTU is kept. Real bug found on-device: mtu=999999999999 reached the generated config.
func TestParseWireGuard_MTUBounds(t *testing.T) {
	base := "wireguard://privkeyNoSlash@192.0.2.1:51820?publickey=cHVia2V5"
	over, err := Parse(base + "&mtu=999999999999")
	if err != nil {
		t.Fatalf("Parse over-mtu: %v", err)
	}
	if v, ok := over.Params["mtu"]; ok {
		t.Fatalf("out-of-range mtu must be dropped, got %v", v)
	}
	ok2, err := Parse(base + "&mtu=1280")
	if err != nil {
		t.Fatalf("Parse mtu=1280: %v", err)
	}
	if ok2.Params["mtu"] != 1280 {
		t.Fatalf("mtu = %v, want 1280", ok2.Params["mtu"])
	}
}

// TestParseWireGuard_SlashInKey: a base64 private key containing a raw '/' (~1 in 4 keys) must
// round-trip intact. Was: url.Parse split on the '/', emptying the key and making the pre-'/'
// chunk the host -> a silent dead tunnel. Both the raw and the %2F-encoded forms must work.
func TestParseWireGuard_SlashInKey(t *testing.T) {
	const key = "aB3/dEf5GhI7jKl9MnO1pQr3StU5vWx7Yz9AbC1dE/0="
	const keyEnc = "aB3%2FdEf5GhI7jKl9MnO1pQr3StU5vWx7Yz9AbC1dE%2F0="
	for _, raw := range []string{
		"wireguard://" + key + "@198.51.100.7:51820?publickey=cHVia2V5",
		"wireguard://" + keyEnc + "@198.51.100.7:51820?publickey=cHVia2V5",
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if e.Server != "198.51.100.7" || e.Port != 51820 {
			t.Fatalf("Parse(%q): server:port = %q:%d, want 198.51.100.7:51820", raw, e.Server, e.Port)
		}
		if e.Params["private_key"] != key {
			t.Fatalf("Parse(%q): private_key = %q, want %q", raw, e.Params["private_key"], key)
		}
	}
}

// TestParseWireGuard_IPv6Endpoint: a wg:// IPv6 endpoint (literal or percent-encoded brackets)
// must parse to a bare IPv6 host. Was: percent-encoded %5B…%5D made url.Parse fail outright.
func TestParseWireGuard_IPv6Endpoint(t *testing.T) {
	const key = "QQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEs="
	for _, raw := range []string{
		"wireguard://" + key + "@%5B2606:4700:4700::1111%5D:51820?publickey=cHVia2V5",
		"wireguard://" + key + "@[2606:4700:4700::1111]:51820?publickey=cHVia2V5",
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if e.Server != "2606:4700:4700::1111" || e.Port != 51820 {
			t.Fatalf("Parse(%q): server:port = %q:%d, want 2606:4700:4700::1111:51820", raw, e.Server, e.Port)
		}
	}
}
