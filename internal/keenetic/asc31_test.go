package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

func awg31Endpoint() map[string]any {
	p := awgEndpoint().Params
	p["s3"], p["s4"] = 20, 21
	p["i1"] = "<b 0xdead>"
	p["header_protection_key"] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	p["content_padding_addition"] = "0-1"
	p["rekey_after_time"], p["rekey_timeout"] = "100-120", "3-7"
	p["reject_after_time"], p["keepalive_timeout"], p["max_handshake_attempts"] = "150-180", "5-15", "15-20"
	p["random_trailers"] = true
	return p
}

func TestWireguardCommands_WritesTheThirtyOneArgumentLineOnFirmware52(t *testing.T) {
	e := awgEndpoint()
	e.Protocol = model.ProtoAmneziaWG
	e.Params = awg31Endpoint()
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 3, AWGGeneration: awg.Gen31})
	if err != nil {
		t.Fatal(err)
	}
	var asc string
	for _, c := range cmds {
		if rest, ok := strings.CutPrefix(c, "wireguard asc "); ok {
			asc = rest
		}
	}
	want := `5 49 998 17 110 1111111111 2222222222 3333333333 4444444444 20 21 "<b 0xdead>" "" "" "" "" ` +
		`AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= 0 1 100 120 3 7 150 180 5 15 15 20 1 0`
	if asc != want {
		t.Fatalf("asc line\n got %s\nwant %s", asc, want)
	}
	// It reads back as the same 31 positions.
	a, err := ParseWGAsc(asc)
	if err != nil || a.Named31()["rekey-after-time"] != "100-120" || a.Named31()["random-trailers"] != "1" {
		t.Fatalf("written line does not read back: %v %v", err, a.Named31())
	}
}

func TestWireguardCommands_ThreeXStaysRefusedWithoutTheFirmwareProof(t *testing.T) {
	e := awgEndpoint()
	e.Protocol = model.ProtoAmneziaWG
	e.Params = awg31Endpoint()
	for _, gen := range []awg.Generation{awg.GenNone, awg.Gen1, awg.Gen2} {
		if _, err := WireguardCommands(e, WireguardOpts{Index: 3, AWGGeneration: gen}); err == nil {
			t.Errorf("generation %v wrote a 3.x endpoint", gen)
		}
	}
}

func TestWireguardCommands_ThreeXWithoutKeyOrTimersIsRefusedNotGuessed(t *testing.T) {
	e := awgEndpoint()
	e.Protocol = model.ProtoAmneziaWG
	e.Params = awg31Endpoint()
	delete(e.Params, "header_protection_key")
	delete(e.Params, "rekey_timeout")
	_, err := WireguardCommands(e, WireguardOpts{Index: 3, AWGGeneration: awg.Gen31})
	if err == nil || !strings.Contains(err.Error(), "header_protection_key") || !strings.Contains(err.Error(), "rekey_timeout") {
		t.Fatalf("incomplete 3.x endpoint: %v", err)
	}
	if got := ASC31Missing(e.Params); len(got) != 2 {
		t.Fatalf("ASC31Missing = %v", got)
	}
	if ASC31Missing(awgEndpoint().Params) != nil {
		t.Fatal("a 1.x endpoint reported missing 3.x settings")
	}
}
