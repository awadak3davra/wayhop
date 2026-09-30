package importer

import (
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

// awg31Conf is a 3.1 [Interface] spelled as amneziawg-tools v3.1.20260812 reads it (src/config.c).
const awg31Conf = `[Interface]
PrivateKey = aPriv
Jc = 4
S1 = 40
H1 = 100000-200000
I1 = <b 0xc0ff00><r 16><c>
HeaderProtectionKey = hpk
ContentPaddingAddition = 0-16
RekeyAfterTime = 120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 3-5
RandomTrailers = off
DisableCookies = on
[Peer]
PublicKey = srvPub
Endpoint = 192.0.2.10:443
AllowedIPs = 0.0.0.0/0`

// Every 3.x key reaches Params under its UAPI name. Before, all of them were dropped, and upstream
// requires each (Jc/Jmin/Jmax aside) to match the server's.
func TestParseConf_AWG31(t *testing.T) {
	e, err := parseConf(awg31Conf)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"header_protection_key": "hpk", "content_padding_addition": "0-16",
		"rekey_after_time": "120", "rekey_timeout": "5", "reject_after_time": "180",
		"keepalive_timeout": "10", "max_handshake_attempts": "3-5",
		"random_trailers": false, "disable_cookies": true,
		"i1": "<b 0xc0ff00><r 16><c>",
	}
	for k, v := range want {
		if e.Params[k] != v {
			t.Errorf("%s = %v (%T), want %v (%T)", k, e.Params[k], e.Params[k], v, v)
		}
	}
}

// The 3.x keys identify AmneziaWG on their own, as J/S/H do.
func TestParseConf_AWG31KeysAloneMeanAmneziaWG(t *testing.T) {
	e, err := parseConf("[Interface]\nPrivateKey = a\nHeaderProtectionKey = k\n[Peer]\nPublicKey = b\nEndpoint = 192.0.2.10:443\n")
	if err != nil {
		t.Fatal(err)
	}
	if e.Protocol != model.ProtoAmneziaWG || e.Engine != model.EngineAmneziaWG {
		t.Fatalf("detected as %v/%v", e.Protocol, e.Engine)
	}
}

// A switch the tools would refuse fails the import, as it fails `awg setconf`; it is not stored as
// "off" behind the operator's back.
func TestParseConf_AWG31UnreadableSwitchFails(t *testing.T) {
	_, err := parseConf(strings.Replace(awg31Conf, "RandomTrailers = off", "RandomTrailers = maybe", 1))
	if err == nil || !strings.Contains(err.Error(), "RandomTrailers") {
		t.Fatalf("an unreadable RandomTrailers imported: %v", err)
	}
}

// Every AmneziaWG setting the importer stores is one awg.Need weighs, and the other way round. A
// setting stored but not weighed is what a native writer could drop without the planner noticing -
// a tunnel the router reports as up and the server never answers - and a weighed setting nothing
// imports is a table that has drifted from the configs it describes.
func TestImportedAWGSettingsAreWeighed(t *testing.T) {
	stored := map[string]bool{}
	for _, k := range awgKeys {
		stored[k] = true
	}
	for _, k := range awgKeysHex {
		stored[k] = true
	}
	for _, k := range awgKeys3 {
		stored[k.param] = true
	}
	for _, k := range awgBools3 {
		stored[k.param] = true
	}
	weighed := map[string]bool{}
	for _, k := range awg.Settings() {
		weighed[k] = true
		if !stored[k] {
			t.Errorf("awg.Need weighs %s, which no .conf import stores", k)
		}
	}
	for k := range stored {
		if !weighed[k] {
			t.Errorf("the importer stores %s, which awg.Need does not weigh", k)
		}
	}
}
