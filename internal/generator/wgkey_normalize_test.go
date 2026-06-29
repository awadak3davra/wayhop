package generator

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestNormalizeWGKey verifies a WireGuard key given in any base64 variant validWGKey
// accepts is emitted as standard base64 WITH padding — the only form sing-box's
// WireGuard key decoder accepts (it rejects url-safe `-`/`_` AND unpadded keys
// verbatim with "decode private/public key: illegal base64 data", fatally failing the
// whole shared config on apply).
func TestNormalizeWGKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 5) // forces +/ in std so url-safe (-_) differs
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
		if !validWGKey(in) {
			t.Errorf("%s: input %q should be a valid WG key", name, in)
		}
	}
	// A string that does not decode to a 32-byte key is returned unchanged (the
	// optional pre_shared_key is normalized without a prior validWGKey gate).
	if got := normalizeWGKey("not-a-key"); got != "not-a-key" {
		t.Errorf("invalid key should pass through unchanged, got %q", got)
	}
}

// TestWGKeyEncodingsSingBoxCheck is the end-to-end guard: a WireGuard endpoint whose
// private/peer-public/pre-shared keys are in each base64 variant validWGKey accepts
// must produce a config the real sing-box accepts. Runs only when WR_SINGBOX points at
// a sing-box binary (the CI singbox-check job sets it after downloading sing-box).
func TestWGKeyEncodingsSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i*37 + 5)
	}
	for _, tc := range []struct{ name, key string }{
		{"std", base64.StdEncoding.EncodeToString(raw)},
		{"rawstd", base64.RawStdEncoding.EncodeToString(raw)},
		{"url", base64.URLEncoding.EncodeToString(raw)},
		{"rawurl", base64.RawURLEncoding.EncodeToString(raw)},
	} {
		ep := model.Endpoint{
			ID: "p-wg", Name: "wg", Protocol: model.ProtoWireGuard, Engine: model.EngineSingBox,
			Server: "1.2.3.4", Port: 51820, Enabled: true,
			Params: map[string]any{
				"private_key": tc.key, "peer_public_key": tc.key, "pre_shared_key": tc.key,
				"local_address": []string{"10.0.0.2/32"},
			},
		}
		p := &model.Profile{
			Endpoints: []model.Endpoint{ep},
			Rules:     []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
		}
		res, err := Generate(p, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
		if err != nil {
			t.Errorf("%s: generate: %v", tc.name, err)
			continue
		}
		data, _ := json.MarshalIndent(res.Config, "", "  ")
		f := filepath.Join(t.TempDir(), tc.name+".json")
		_ = os.WriteFile(f, data, 0o600)
		if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
			t.Errorf("%s WG key rejected by sing-box: %s", tc.name, strings.TrimSpace(string(out)))
		}
	}
}
