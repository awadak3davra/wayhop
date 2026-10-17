package plugin

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

// The kernel path hands awgStrip(awgConfig(e)) to `awg setconf`. These tests hold that text to
// amneziawg-tools 3.1 (src/config.c at ee0f0a9aa34ff0a0da4b3433b9512781cfe02843, the pinned
// v3.1.20260812): every key is one process_line matches, and every key it carries is one the module
// the plugin chose can take - awg.Decide puts a connection on the kernel module only when the module's
// generation reaches awg.Need, so it is enough that no line asks for more than Need says.

// toolsKeys31 are the keys process_line matches at the pinned commit, [Interface] then [Peer].
var toolsKeys31 = map[string]bool{
	"ListenPort": true, "FwMark": true, "PrivateKey": true,
	"Jc": true, "Jmin": true, "Jmax": true, "S1": true, "S2": true, "S3": true, "S4": true,
	"H1": true, "H2": true, "H3": true, "H4": true, "I1": true, "I2": true, "I3": true, "I4": true, "I5": true,
	"HeaderProtectionKey": true, "ContentPaddingAddition": true, "RekeyAfterTime": true, "RekeyTimeout": true,
	"RejectAfterTime": true, "KeepaliveTimeout": true, "MaxHandshakeAttempts": true,
	"RandomTrailers": true, "DisableCookies": true,
	"Endpoint": true, "PublicKey": true, "AllowedIPs": true, "PersistentKeepalive": true, "PresharedKey": true,
	"AdvancedSecurity": true,
}

// settingOfToolsKey maps the conf keys that carry an AmneziaWG setting back to the setting's name in
// the model, the name awg.Need weighs it by.
var settingOfToolsKey = map[string]string{
	"Jc": "jc", "Jmin": "jmin", "Jmax": "jmax", "S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
	"H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4", "I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
	"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
	"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
	"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
	"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
}

func setconfLines(e model.Endpoint) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(awgStrip(awgConfig(e)), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "[") {
			continue
		}
		key, value, _ := strings.Cut(ln, "=")
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func kernelConfEndpoint() model.Endpoint {
	return model.Endpoint{
		ID: "ep-kconf", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.9", Port: 51820, MTU: 1280,
		Params: map[string]any{
			"private_key": "PRIV", "peer_public_key": "PUB", "local_address": "10.8.0.2/32",
			"jc": 4, "s1": 16, "s2": 16, "s3": 16, "s4": 16, "h1": "100-200",
		},
	}
}

// A 3.1 connection's conf: every key spelled as the tools match it, the protection key in the one
// base64 spelling they read, ranges as written, a switch that is on as "on", one that is off left out.
func TestKernelConf_AWG31KeysAreTheToolsSpellings(t *testing.T) {
	key := bytes.Repeat([]byte{0xfb}, 32)
	e := kernelConfEndpoint()
	e.Params["header_protection_key"] = base64.RawURLEncoding.EncodeToString(key)
	e.Params["content_padding_addition"] = "10-20"
	e.Params["rekey_after_time"] = float64(120)
	e.Params["rekey_timeout"] = int64(5)
	e.Params["reject_after_time"] = "180"
	e.Params["keepalive_timeout"] = "10-15"
	e.Params["max_handshake_attempts"] = 3
	e.Params["random_trailers"] = true
	e.Params["disable_cookies"] = "off"
	got := setconfLines(e)
	for k := range got {
		if !toolsKeys31[k] {
			t.Errorf("%q is not a key amneziawg-tools 3.1 reads; setconf would refuse the file", k)
		}
	}
	for k, v := range map[string]string{
		"HeaderProtectionKey": base64.StdEncoding.EncodeToString(key), "ContentPaddingAddition": "10-20",
		"RekeyAfterTime": "120", "RekeyTimeout": "5", "RejectAfterTime": "180", "KeepaliveTimeout": "10-15",
		"MaxHandshakeAttempts": "3", "RandomTrailers": "on",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, written := got["DisableCookies"]; written {
		t.Error("DisableCookies = off was written; a 3.0 module would be sent an attribute it does not know")
	}
	for _, ipLayer := range []string{"Address", "MTU", "DNS"} {
		if _, written := got[ipLayer]; written {
			t.Errorf("%s reached setconf, which refuses it", ipLayer)
		}
	}
}

// No line asks for a newer generation than the connection needs, for every setting awg knows on its
// own and for all of them together - so the module awg.Decide picked for the connection takes every
// line. A setting that is set is never left out either: the server would stop answering.
func TestKernelConf_NoLineBeyondNeed(t *testing.T) {
	valueFor := func(key string) any {
		switch key {
		case "random_trailers", "disable_cookies":
			return "on"
		case "header_protection_key":
			return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		case "i1", "i2", "i3", "i4", "i5":
			return "<r 8>"
		}
		return "7"
	}
	all := kernelConfEndpoint()
	for _, key := range awg.Settings() {
		e := kernelConfEndpoint()
		e.Params[key] = valueFor(key)
		all.Params[key] = valueFor(key)
		checkNoLineBeyondNeed(t, e, key)
	}
	checkNoLineBeyondNeed(t, all, "every setting")
}

func checkNoLineBeyondNeed(t *testing.T, e model.Endpoint, what string) {
	t.Helper()
	need := awg.Need(e.Params)
	written := map[string]bool{}
	for k := range setconfLines(e) {
		setting, ok := settingOfToolsKey[k]
		if !ok {
			continue
		}
		written[setting] = true
		if g := awg.Introduced(setting); g > need {
			t.Errorf("%s: %s is generation %v, beyond the %v the connection needs", what, k, g, need)
		}
	}
	for key, value := range e.Params {
		if awg.Introduced(key) != awg.GenNone && awg.SettingText(value) != "" && !written[key] {
			t.Errorf("%s: %s is set and was left out", what, key)
		}
	}
}
