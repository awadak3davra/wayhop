package importer

import (
	"testing"

	"velinx/internal/model"
)

// TestParseConf_AWG2 round-trips an AmneziaWG 2.0 [Interface]: S3/S4 stay ints,
// H1-H4 ranges stay strings (atoi would zero them), and I1-I5 hex magic stay
// strings. 1.x values (Jc…) remain ints.
func TestParseConf_AWG2(t *testing.T) {
	conf := `[Interface]
PrivateKey = aPriv
Address = 10.0.0.2/32
Jc = 5
Jmin = 49
Jmax = 998
S1 = 17
S2 = 110
S3 = 25
S4 = 40
H1 = 500000000-900000000
H2 = 1000000000-1400000000
H3 = 1500000000-1900000000
H4 = 2000000000-2400000000
I1 = 0x11111111111111111111111111111111
I2 = 0x22222222222222222222222222222222
[Peer]
PublicKey = srvPub
PresharedKey = psk
Endpoint = 203.0.113.10:8443
AllowedIPs = 0.0.0.0/0`
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Protocol != model.ProtoAmneziaWG || e.Engine != model.EngineAmneziaWG {
		t.Fatalf("not detected as AmneziaWG: proto=%v engine=%v", e.Protocol, e.Engine)
	}
	if e.Params["jc"] != 5 || e.Params["s3"] != 25 || e.Params["s4"] != 40 {
		t.Errorf("int params wrong: jc=%v s3=%v s4=%v", e.Params["jc"], e.Params["s3"], e.Params["s4"])
	}
	if e.Params["h1"] != "500000000-900000000" {
		t.Errorf("h1 range = %v (%T), want string", e.Params["h1"], e.Params["h1"])
	}
	if e.Params["i1"] != "0x11111111111111111111111111111111" || e.Params["i2"] != "0x22222222222222222222222222222222" {
		t.Errorf("i1/i2 wrong: %v / %v", e.Params["i1"], e.Params["i2"])
	}
}

// TestParseConf_AWG_MTU asserts the [Interface] MTU is carried into params — it is
// an ip-layer field (not understood by `awg setconf`) that the bring-up applies via
// `ip link set mtu`, so dropping it would leave the tunnel at the kernel default.
// TestParseConf_AWG_LargeSingleH: AWG 1.x H1-H4 are single 32-bit "magic" values
// that routinely exceed 2^31. They must be kept as STRINGS — atoiDefault
// (strconv.Atoi) overflows them to 0 on a 32-bit (mipsle/mips) build, zeroing the
// AWG header so the handshake fails. Jc/S* are small and stay ints.
func TestParseConf_AWG_LargeSingleH(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nJc = 4\nH1 = 3000000000\nH2 = 4294967295\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:8443\nAllowedIPs = 0.0.0.0/0"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Params["h1"] != "3000000000" {
		t.Fatalf("h1 = %v (%T), want string \"3000000000\" (atoi overflows it to 0 on 32-bit)", e.Params["h1"], e.Params["h1"])
	}
	if e.Params["h2"] != "4294967295" {
		t.Fatalf("h2 = %v (%T), want string \"4294967295\"", e.Params["h2"], e.Params["h2"])
	}
	if e.Params["jc"] != 4 {
		t.Fatalf("jc = %v (%T), want int 4 (small value stays int)", e.Params["jc"], e.Params["jc"])
	}
}

func TestParseConf_AWG_MTU(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nMTU = 1280\nJc = 4\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:8443\nAllowedIPs = 0.0.0.0/0"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Params["mtu"] != 1280 {
		t.Errorf("mtu param = %v (%T), want 1280 (int)", e.Params["mtu"], e.Params["mtu"])
	}
	// A conf without MTU must not invent one (else awgUp would set a bogus MTU).
	e2, _ := parseConf("[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:8443\nAllowedIPs = 0.0.0.0/0")
	if _, ok := e2.Params["mtu"]; ok {
		t.Errorf("mtu present when conf had none: %v", e2.Params["mtu"])
	}
}

// TestParseConf_PlainWireGuardMTU: a PLAIN WireGuard .conf (no junk params) must also
// carry MTU — it goes on the sing-box endpoint, and dropping it (e.g. WARP's 1280)
// fragments/blackholes large packets.
func TestParseConf_PlainWireGuardMTU(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = p\nEndpoint = 162.159.192.1:2408\nAllowedIPs = 0.0.0.0/0"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Protocol != model.ProtoWireGuard {
		t.Fatalf("protocol = %s, want wireguard (no junk params)", e.Protocol)
	}
	if e.Params["mtu"] != 1280 {
		t.Fatalf("mtu = %v (%T), want 1280 (int) for plain WireGuard", e.Params["mtu"], e.Params["mtu"])
	}
}

// TestParseConf_MultiLineAddress: Address is a repeatable wg-quick key — a
// dual-stack .conf lists v4 and v6 on separate lines. Both must be carried; the
// old overwrite kept only the last (silently dropping the IPv4 address).
func TestParseConf_MultiLineAddress(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\nAddress = fd00::2/64\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	la, ok := e.Params["local_address"].([]string)
	if !ok || len(la) != 2 || la[0] != "10.0.0.2/24" || la[1] != "fd00::2/64" {
		t.Fatalf("local_address = %v, want [10.0.0.2/24 fd00::2/64] (both addresses kept)", e.Params["local_address"])
	}
	// The single comma-separated form must still work (regression).
	e2, _ := parseConf("[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24, fd00::2/64\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0")
	if la2, _ := e2.Params["local_address"].([]string); len(la2) != 2 {
		t.Fatalf("comma form local_address = %v, want 2", e2.Params["local_address"])
	}
}

func TestParseConf_PersistentKeepalive(t *testing.T) {
	// PersistentKeepalive from [Peer] must be carried (NAT mapping survival).
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nJc = 4\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:8443\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Params["persistent_keepalive"] != 25 {
		t.Errorf("persistent_keepalive = %v (%T), want 25 (int)", e.Params["persistent_keepalive"], e.Params["persistent_keepalive"])
	}
	// Absent in the conf -> must not be invented.
	e2, _ := parseConf("[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:8443\nAllowedIPs = 0.0.0.0/0")
	if _, ok := e2.Params["persistent_keepalive"]; ok {
		t.Errorf("persistent_keepalive present when conf had none: %v", e2.Params["persistent_keepalive"])
	}
}
