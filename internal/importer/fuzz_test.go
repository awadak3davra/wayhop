package importer

import (
	"encoding/base64"
	"strings"
	"testing"

	"velinx/internal/model"
)

// This file fuzzes the untrusted-input surface of the importer: Parse() and
// ParseSubscription(). Both ingest data the user pastes from arbitrary share
// links, subscription URLs, and .conf files, so they must NEVER panic on
// malformed input — an error return is the only acceptable failure mode.
//
// Helpers are prefixed fuzzimporter_ to avoid clashing with importer_* in
// parse_edge_test.go and the bare helpers in the other *_test.go files.

// fuzzimporter_b64std returns a padded std-base64 encoding of s.
func fuzzimporter_b64std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// fuzzimporter_b64rawurl returns a raw (unpadded) url-base64 encoding of s.
func fuzzimporter_b64rawurl(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// fuzzimporter_seeds returns a representative set of inputs spanning every
// protocol branch in Parse(), plus a pile of malformed/garbage inputs. These
// double as the seed corpus for both fuzz targets and as a quick regression
// table (TestFuzzParse_SeedsDoNotPanic).
func fuzzimporter_seeds() []string {
	vmessJSON := `{"v":"2","ps":"VM","add":"vm.example.com","port":"443","id":"uuid-vmess","aid":"0","net":"ws","path":"/p","host":"vm.example.com","tls":"tls","scy":"auto"}`
	ssSIP002 := "ss://" + fuzzimporter_b64rawurl("aes-256-gcm:supersecret") + "@9.9.9.9:8388#SS"
	ssLegacy := "ss://" + fuzzimporter_b64rawurl("chacha20-ietf-poly1305:pass@10.0.0.1:8388") + "#Legacy"

	wgConf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = key==",
		"Address = 10.0.0.2/32",
		"DNS = 1.1.1.1",
		"",
		"[Peer]",
		"PublicKey = pub==",
		"Endpoint = host.example:51820",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")

	awgConf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = priv==",
		"Address = 10.8.0.2/32",
		"Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 0", "S2 = 0",
		"H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4",
		"",
		"[Peer]",
		"PublicKey = peerpub==",
		"PresharedKey = psk==",
		"Endpoint = 203.0.113.10:51820",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")

	olcrtc := strings.Join([]string{
		"auth:",
		"  provider: jitsi",
		"room:",
		"  id: https://meet.example.org/SomeRoom",
		"crypto:",
		"  key: c2VjcmV0",
		"net:",
		"  transport: datachannel",
		"  dns: 1.1.1.1",
	}, "\n")

	return []string{
		// --- valid, well-formed links (one per protocol branch) ---
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#Reality",
		"vless://u@1.1.1.1:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls&sni=cdn.example.com#VLESS-WS",
		"vmess://" + fuzzimporter_b64std(vmessJSON),
		"trojan://secretpass@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#T1",
		ssSIP002,
		ssLegacy,
		"hysteria2://mypassword@1.2.3.4:8443?sni=bing.com&obfs=salamander&obfs-password=xyz&insecure=1#HY2",
		"hy2://pw@1.2.3.4:8443?sni=bing.com#HY2short",
		"tuic://uuid-aaa:passbbb@5.6.7.8:443?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example#TU",
		"wireguard://privkey@1.2.3.4:51820?publickey=PUB&presharedkey=PSK&address=10.0.0.2/32,fd00::2/128#WG",
		"wg://privkey@5.6.7.8?publickey=PUB",
		wgConf,
		awgConf,
		olcrtc,

		// --- empty / whitespace ---
		"",
		"   ",
		"\t\n\r ",

		// --- scheme edge cases / schemeless garbage ---
		"garbage-not-a-link",
		"foo://bar:123",
		"://noscheme",
		"vless://",
		"trojan://",
		"tuic://",
		"hysteria2://",
		"wireguard://",
		"wg://",
		"vmess://",
		"ss://",
		"vless://@",
		"tuic://@",
		"trojan://@",
		"wireguard://@",

		// --- malformed vmess bodies ---
		"vmess://!!!notbase64$$$",
		"vmess://" + fuzzimporter_b64std("not json at all"),
		"vmess://" + fuzzimporter_b64std("{"),
		"vmess://" + fuzzimporter_b64std("[]"),
		"vmess://" + fuzzimporter_b64std("null"),
		"vmess://" + fuzzimporter_b64std("123"),
		"vmess://" + fuzzimporter_b64std(`{"add":"h","port":{"x":1},"id":[1,2]}`),
		"vmess://" + fuzzimporter_b64std(`{"port":99999999999999999999}`),
		"vmess://" + fuzzimporter_b64rawurl("{}"),

		// --- malformed shadowsocks ---
		"ss://!!!notbase64$$$",
		"ss://" + fuzzimporter_b64rawurl("aes-256-gcm:pw") + "@:0#x",
		"ss://" + fuzzimporter_b64rawurl("nopassword") + "@1.2.3.4:8388",
		"ss://@host:1",
		"ss://#onlyfragment",
		"ss://?onlyquery",

		// --- malformed / partial .conf ---
		"[Interface]",
		"[Interface]\n[Peer]",
		"[Interface]\nPrivateKey=k\n[Peer]\nEndpoint=h:1",
		"[Interface]\n=\n=value\nkey=\n[Peer]\nEndpoint=:99999999999",
		"[Interface]\nJc=notanumber\n[Peer]\nEndpoint=h.example",

		// --- olcRTC detection without a usable room ---
		"provider: jitsi",
		"auth:\n  provider: telemost\nnet:\n  transport: datachannel\n",

		// --- subscription-ish multi-line blobs fed to single Parse ---
		"vless://u@h:443#a\ntrojan://p@h:443#b",

		// --- control chars / unicode / very long ---
		"vless://u@\x00\x01\x02:443",
		"trojan://p@日本語.example:443#名前",
		"vless://" + strings.Repeat("a", 4096) + "@h:443",
		strings.Repeat("ss://", 200),

		// --- percent-encoding traps ---
		"vless://u@h:443?path=%ZZ#%ZZ",
		"ss://" + fuzzimporter_b64rawurl("m:p") + "@h:8388#%E0%A4%A",
	}
}

// TestFuzzParse_SeedsDoNotPanic is a plain (non-fuzz) regression check that the
// seed corpus parses without panicking and upholds the structural invariant.
// It runs as part of `go test ./internal/importer/` so the corpus is exercised
// even when the fuzzer is not invoked.
func TestFuzzParse_SeedsDoNotPanic(t *testing.T) {
	for _, in := range fuzzimporter_seeds() {
		fuzzimporter_assertParseInvariant(t, in)
	}
}

// fuzzimporter_assertParseInvariant runs Parse(in) and asserts the contract:
//
//  1. It must not panic (recover surfaces any panic as a test failure with the
//     offending input so the crash is reproducible).
//  2. It must never return (nil, nil): on success the endpoint pointer is
//     non-nil and carries a non-empty Protocol (finalize always sets ID/Name/
//     Enabled, so those are populated too).
//
// NOTE on Server: the importer intentionally tolerates an empty Server on
// success for several branches (vmess without "add", a hostless URL authority,
// olcRTC whose room is not a URL). That is current, deliberate behavior — not a
// panic — so it is NOT asserted here. The non-empty-Server guarantee is checked
// separately against the known-good seed links in TestFuzzParse_ValidSeedsHaveServer.
func fuzzimporter_assertParseInvariant(t *testing.T, in string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse panicked on input %q: %v", in, r)
		}
	}()

	e, err := Parse(in)
	if err != nil {
		if e != nil {
			t.Fatalf("Parse(%q): non-nil endpoint %+v returned alongside error %v", in, e, err)
		}
		return // an error return is acceptable
	}
	if e == nil {
		t.Fatalf("Parse(%q): returned (nil, nil) — neither endpoint nor error", in)
	}
	if e.Protocol == "" {
		t.Fatalf("Parse(%q): success but empty Protocol: %+v", in, e)
	}
	if e.ID == "" {
		t.Fatalf("Parse(%q): success but empty ID (finalize should slug one): %+v", in, e)
	}
	if !e.Enabled {
		t.Fatalf("Parse(%q): success but Enabled=false (finalize should force true): %+v", in, e)
	}
}

// TestFuzzParse_ValidSeedsHaveServer checks the stronger invariant — non-empty
// Server — only against the well-formed seed links that carry a real host, so
// it documents/locks in the happy-path contract without being tripped by the
// deliberately-hostless malformed inputs.
func TestFuzzParse_ValidSeedsHaveServer(t *testing.T) {
	valid := []string{
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=reality&pbk=K&sni=a.com#A",
		"trojan://secretpass@example.com:443?sni=cdn.example.com#T1",
		"vmess://" + fuzzimporter_b64std(`{"add":"vm.example.com","port":"443","id":"u","net":"tcp"}`),
		"ss://" + fuzzimporter_b64rawurl("aes-256-gcm:supersecret") + "@9.9.9.9:8388#SS",
		"hysteria2://pw@1.2.3.4:8443?sni=bing.com#HY2",
		"tuic://u:p@5.6.7.8:443?sni=t.example#TU",
		"wireguard://privkey@1.2.3.4:51820?publickey=PUB#WG",
		"[Interface]\nPrivateKey=k==\n[Peer]\nPublicKey=p==\nEndpoint=host.example:51820",
	}
	for _, in := range valid {
		e, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error %v", in, err)
		}
		if e.Server == "" {
			t.Fatalf("Parse(%q): valid link but empty Server: %+v", in, e)
		}
	}
}

// FuzzParse drives Parse() with the seed corpus plus mutator-generated inputs.
// The only hard contract is "must not panic"; everything else is the structural
// invariant in fuzzimporter_assertParseInvariant.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzimporter_seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked on input %q: %v", in, r)
			}
		}()

		e, err := Parse(in)
		if err != nil {
			if e != nil {
				t.Fatalf("Parse(%q): non-nil endpoint returned with error %v", in, err)
			}
			return
		}
		if e == nil {
			t.Fatalf("Parse(%q): returned (nil, nil)", in)
		}
		if e.Protocol == "" {
			t.Fatalf("Parse(%q): success but empty Protocol", in)
		}
	})
}

// fuzzimporter_subSeeds returns subscription-level seeds: multi-line plaintext
// mixes, base64-wrapped blobs, and pathological line layouts.
func fuzzimporter_subSeeds() []string {
	plainMix := "\n\n  # header\r\n" +
		"vless://u@1.1.1.1:443?security=reality&pbk=K&sni=a.com#A\r\n" +
		"\r\n   \n" +
		"trojan://pw@2.2.2.2:443#B\n" +
		"#another comment\n" +
		"junkline-no-scheme\n"

	innerBlob := "ss://" + fuzzimporter_b64rawurl("aes-256-gcm:secret") + "@4.4.4.4:8388#S\n" +
		"# a comment line\n\n" +
		"hysteria2://pw@2.2.2.2:8443?sni=b.com#B\n" +
		"garbage-not-a-link\n"

	confInSub := "[Interface]\nPrivateKey=k==\n[Peer]\nPublicKey=p==\nEndpoint=host.example:51820\n"

	return []string{
		"",
		"   \n\t\r\n",
		plainMix,
		fuzzimporter_b64std(innerBlob),
		fuzzimporter_b64rawurl(innerBlob),
		confInSub,
		"garbage1\nfoo://x\n# comment\n\nbar-no-scheme\n",
		// every line a different malformed link
		"vmess://!!!\nss://!!!\ntuic://@\nwireguard://\n[Interface]\n",
		// a single very long line
		strings.Repeat("vless://u@h:443#x\n", 500),
		// base64 that decodes to more base64 (no scheme markers)
		fuzzimporter_b64std(fuzzimporter_b64std("vless://u@h:443#x\n")),
		// CR-only line separators
		"vless://u@h:443#a\rtrojan://p@h:443#b\r",
		// control chars sprinkled in
		"vless://u@h:443#a\x00\ntrojan://p@h:443#b\x01",
		// unicode + percent traps
		"vless://u@日本.example:443#名\nss://" + fuzzimporter_b64rawurl("m:p") + "@h:1#%ZZ\n",
	}
}

// TestFuzzParseSubscription_SeedsDoNotPanic is the non-fuzz regression check for
// the subscription seed corpus.
func TestFuzzParseSubscription_SeedsDoNotPanic(t *testing.T) {
	for _, in := range fuzzimporter_subSeeds() {
		fuzzimporter_assertSubInvariant(t, in)
	}
}

// fuzzimporter_assertSubInvariant asserts ParseSubscription's contract: it must
// not panic, must never return nil slices erroneously paired with bad indexing,
// and every endpoint it yields must carry a non-empty Protocol (it only appends
// endpoints that Parse() returned successfully).
func fuzzimporter_assertSubInvariant(t *testing.T, in string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseSubscription panicked on input %q: %v", in, r)
		}
	}()

	eps, errs := ParseSubscription(in)
	for i := range eps {
		if eps[i].Protocol == "" {
			t.Fatalf("ParseSubscription(%q): endpoint %d has empty Protocol: %+v", in, i, eps[i])
		}
		if eps[i].ID == "" {
			t.Fatalf("ParseSubscription(%q): endpoint %d has empty ID: %+v", in, i, eps[i])
		}
	}
	_ = errs // errs may legitimately be nil or populated; just must not panic
}

// FuzzParseSubscription drives ParseSubscription() with the subscription seeds
// plus mutator-generated inputs, asserting it never panics.
func FuzzParseSubscription(f *testing.F) {
	for _, s := range fuzzimporter_subSeeds() {
		f.Add(s)
	}
	// Also seed with single-link forms so the mutator can explore the
	// line-splitting and base64-unwrap paths from richer starting points.
	for _, s := range fuzzimporter_seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseSubscription panicked on input %q: %v", in, r)
			}
		}()

		eps, _ := ParseSubscription(in)
		for i := range eps {
			if eps[i].Protocol == "" {
				t.Fatalf("ParseSubscription(%q): endpoint %d empty Protocol", in, i)
			}
		}
	})
}

// compile-time touch so model stays imported even if assertions change.
var _ = model.ProtoVLESS
