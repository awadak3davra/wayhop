package plugin

import (
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestAWGConfig_V2Params asserts the AmneziaWG 2.0 obfuscation params (S3/S4,
// I1-I5, and H1-H4 ranges) render into the awg-quick .conf — without them a client
// cannot handshake with a 2.0 server like the an AmneziaWG 2.0 server.
func TestAWGConfig_V2Params(t *testing.T) {
	e := model.Endpoint{
		Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{
			"private_key": "PRIV", "peer_public_key": "PUB", "pre_shared_key": "PSK",
			"jc": 5, "jmin": 49, "jmax": 998, "s1": 17, "s2": 110, "s3": 25, "s4": 40,
			"h1": "500000000-900000000", "h2": "1000000000-1400000000",
			"h3": "1500000000-1900000000", "h4": "2000000000-2400000000",
			"i1": "0x11111111111111111111111111111111", "i2": "0x22222222222222222222222222222222",
			"i3": "0x33333333333333333333333333333333", "i4": "0x44444444444444444444444444444444",
			"i5": "0x55555555555555555555555555555555",
		},
	}
	c := awgConfig(e)
	for _, want := range []string{
		"Jc = 5", "S2 = 110", "S3 = 25", "S4 = 40",
		"H1 = 500000000-900000000", "H4 = 2000000000-2400000000",
		"I1 = 0x11111111111111111111111111111111", "I5 = 0x55555555555555555555555555555555",
		"Endpoint = 1.2.3.4:8443",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("awgConfig missing %q\n--- got ---\n%s", want, c)
		}
	}
}

// TestAWGConfig_V1OmitsV2 keeps 1.x endpoints clean: absent 2.0 params emit nothing.
func TestAWGConfig_V1OmitsV2(t *testing.T) {
	e := model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
		Params: map[string]any{
			"private_key": "P", "peer_public_key": "Q",
			"jc": 4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0, "h1": 1, "h2": 2, "h3": 3, "h4": 4,
		},
	}
	c := awgConfig(e)
	for _, bad := range []string{"S3", "S4", "I1", "I5"} {
		if strings.Contains(c, bad) {
			t.Errorf("v1 endpoint must not emit %q:\n%s", bad, c)
		}
	}
}

// TestAWGConfig_LargeNumericH: AmneziaWG H1-H4 are 32-bit magic values that routinely
// exceed 2^31. The .conf importer keeps H as a STRING (numStr passes it through), but
// an AWG endpoint created/edited via the API/UI reaches the renderer with H as a JSON
// NUMBER (float64). numStr's old float64 case `strconv.Itoa(int(t))` OVERFLOWED on a
// 32-bit build (mipsle/mips OpenWrt + Keenetic): int is int32 and int32(float64(3e9))
// saturates to -2147483648, corrupting the rendered `awg setconf` header -> handshake
// fails. FormatInt(int64(t)) is correct on every arch. (On a 64-bit test host int is
// int64 so the old code also produced the right string; the negative-value assertion
// is the cross-arch regression marker. The 32-bit overflow is proven separately via
// int32(float64(3e9)) == -2147483648.)
func TestAWGConfig_LargeNumericH(t *testing.T) {
	e := model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{
			"private_key": "P", "peer_public_key": "Q",
			"h1": float64(3000000000), "h2": float64(4294967295), "jc": float64(4),
		},
	}
	c := awgConfig(e)
	for _, want := range []string{"H1 = 3000000000", "H2 = 4294967295", "Jc = 4"} {
		if !strings.Contains(c, want) {
			t.Errorf("awgConfig missing %q (numStr float64 32-bit overflow?)\n--- got ---\n%s", want, c)
		}
	}
	if strings.Contains(c, "-2147483648") {
		t.Errorf("awgConfig emitted the 32-bit-overflowed H value:\n%s", c)
	}
}

// TestAWGConfig_NumericIDropped: I1-I5 are hex "magic-packet" strings; a NUMERIC value
// (raw POST /api/endpoints or hand-edited profile.json) renders as a bare decimal that
// `awg setconf` rejects → the interface never comes up while its bind_interface outbound
// still routes to it (silent dead tunnel). A numeric I must be DROPPED (iface comes up
// without that junk param), a string I kept. H1-H4 (number-or-string) are unaffected.
func TestAWGConfig_NumericIDropped(t *testing.T) {
	c := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{
			"private_key": "P", "peer_public_key": "Q",
			"i1": float64(12345),                       // numeric (raw API) → must be dropped
			"i2": "0x22222222222222222222222222222222", // valid hex string → kept
			"h1": float64(3000000000),                  // numeric H stays (legitimate)
		},
	})
	if strings.Contains(c, "I1 =") {
		t.Errorf("numeric i1 must be dropped (malformed for awg setconf):\n%s", c)
	}
	if strings.Contains(c, "12345") {
		t.Errorf("numeric i1 value leaked into the conf:\n%s", c)
	}
	if !strings.Contains(c, "I2 = 0x22222222222222222222222222222222") {
		t.Errorf("string i2 must be kept:\n%s", c)
	}
	if !strings.Contains(c, "H1 = 3000000000") {
		t.Errorf("numeric H1 must still render (fix is I-key-only):\n%s", c)
	}
}

// TestAWGConfig_MTU asserts the [Interface] MTU is rendered when set (it is applied
// on bring-up via `ip link set mtu`, so it must survive into the conf) and omitted
// when absent (so awgUp never sets a bogus MTU).
func TestAWGConfig_MTU(t *testing.T) {
	withMTU := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q", "mtu": 1280},
	})
	if !strings.Contains(withMTU, "MTU = 1280") {
		t.Errorf("awgConfig missing MTU:\n%s", withMTU)
	}
	noMTU := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q"},
	})
	if strings.Contains(noMTU, "MTU") {
		t.Errorf("awgConfig emitted MTU when absent:\n%s", noMTU)
	}
}

// TestAWGConfig_TypedMTUKeepalive: the typed Endpoint fields (set by the UI, which drops the
// Params copy on edit) must render into the AWG conf — else a UI-edited tunnel loses them at
// bring-up + export. Typed value wins over a stale Params copy.
func TestAWGConfig_TypedMTUKeepalive(t *testing.T) {
	conf := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		MTU: 1280, PersistentKeepalive: 25,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q"},
	})
	if !strings.Contains(conf, "MTU = 1280") {
		t.Errorf("typed MTU not in awg conf:\n%s", conf)
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("typed PersistentKeepalive not in awg conf:\n%s", conf)
	}
	conf2 := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		MTU:    1320,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q", "mtu": 1280},
	})
	if !strings.Contains(conf2, "MTU = 1320") || strings.Contains(conf2, "MTU = 1280") {
		t.Errorf("typed MTU should win over the stale Params copy:\n%s", conf2)
	}
}

// TestAWGStrip checks the conf fed to `awg setconf` keeps the crypto/peer/junk
// fields but drops the ip-layer lines (Address/DNS/MTU) that setconf rejects.
func TestAWGStrip(t *testing.T) {
	conf := "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.3/32\nMTU = 1320\nJc = 5\nS3 = 25\nI1 = 0xdead\n[Peer]\nPublicKey = pub\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:8443\n"
	out := awgStrip(conf)
	for _, bad := range []string{"Address", "MTU =", "DNS"} {
		if strings.Contains(out, bad) {
			t.Errorf("awgStrip kept %q:\n%s", bad, out)
		}
	}
	for _, good := range []string{"PrivateKey = abc", "Jc = 5", "S3 = 25", "I1 = 0xdead", "PublicKey = pub", "Endpoint = 1.2.3.4:8443"} {
		if !strings.Contains(out, good) {
			t.Errorf("awgStrip dropped %q:\n%s", good, out)
		}
	}
}
