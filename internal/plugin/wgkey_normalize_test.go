package plugin

import (
	"encoding/base64"
	"strings"
	"testing"

	"wakeroute/internal/model"
)

// TestAWGConfigNormalizesKeys verifies a url-safe-encoded AmneziaWG key is rendered into
// the awg-quick conf as standard base64 WITH padding — the only form amneziawg-tools'
// key_from_base64 accepts (44 chars ending in '='; it rejects url-safe and unpadded keys).
// Without this the interface fails to come up while its bind_interface outbound still
// routes to the dead tunnel.
func TestAWGConfigNormalizesKeys(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 5) // forces +/ in std so url-safe (-_) differs
	}
	stdKey := base64.StdEncoding.EncodeToString(raw)
	urlKey := base64.URLEncoding.EncodeToString(raw)
	if stdKey == urlKey {
		t.Fatal("test bytes do not distinguish std from url-safe; choose others")
	}
	e := model.Endpoint{
		Protocol: model.ProtoAmneziaWG, Engine: model.EngineAmneziaWG,
		Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{
			"private_key": urlKey, "peer_public_key": urlKey, "pre_shared_key": urlKey,
			"local_address": "10.9.0.2/32",
		},
	}
	conf := awgConfig(e)
	for _, want := range []string{
		"PrivateKey = " + stdKey + "\n",
		"PublicKey = " + stdKey + "\n",
		"PresharedKey = " + stdKey + "\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing normalized line %q\n---\n%s", want, conf)
		}
	}
	if strings.Contains(conf, urlKey) {
		t.Errorf("url-safe key leaked into conf verbatim\n---\n%s", conf)
	}
}

// TestNormalizeWGKeyPlugin unit-tests the helper: every accepted base64 variant maps to
// std-with-pad, while a non-key string (a placeholder or a newline-injection attempt) is
// returned unchanged so confLine still truncates it.
func TestNormalizeWGKeyPlugin(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 5)
	}
	want := base64.StdEncoding.EncodeToString(raw)
	for name, in := range map[string]string{
		"std":    base64.StdEncoding.EncodeToString(raw),
		"rawstd": base64.RawStdEncoding.EncodeToString(raw),
		"url":    base64.URLEncoding.EncodeToString(raw),
		"rawurl": base64.RawURLEncoding.EncodeToString(raw),
	} {
		if got := normalizeWGKey(in); got != want {
			t.Errorf("%s: normalizeWGKey(%q) = %q, want %q", name, in, got, want)
		}
	}
	for _, s := range []string{"PRIV", "GOODPRIV\nPublicKey = ATTACKER", ""} {
		if got := normalizeWGKey(s); got != s {
			t.Errorf("non-key %q should pass through unchanged, got %q", s, got)
		}
	}
}
