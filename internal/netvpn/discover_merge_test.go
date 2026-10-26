package netvpn

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// keeneticListing5x is the layout `ndmc -c "show interface"` prints on KeeneticOS 5.x (captured
// 2026-10), sanitized: fake keys, doc-range addresses, generic labels. Wireguard6 is switched on
// but has no handshake ("state: up", "link: down", "connected: no"). Wireguard5 is absent: it was
// deleted in the web UI.
const keeneticListing5x = `Interface, name = "Wireguard0"
               id: Wireguard0
            index: 0
   interface-name: Wireguard0
             type: Wireguard
      description: Exit_Cyprus
           traits: Ip
           traits: Wireguard
             link: up
        connected: yes
            state: up
              mtu: 1280
             ipv6:
            defaultgw: no
        wireguard:
           public-key: KEY0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          listen-port: 43556
               status: up
          summary:

Interface, name = "Wireguard4"
               id: Wireguard4
            index: 4
   interface-name: Wireguard4
             type: Wireguard
      description: Exit_Belarus
             link: up
        connected: yes
            state: up
        wireguard:
           public-key: KEY4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          listen-port: 40001
               status: up
          summary:

Interface, name = "Wireguard6"
               id: Wireguard6
            index: 6
   interface-name: Wireguard6
             type: Wireguard
      description: RU_exit
             link: down
        connected: no
            state: up
        wireguard:
           public-key: KEY6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          listen-port: 40002
               status: down
          summary:
`

func TestParseNDMInterfaces_KeeneticOS5Listing(t *testing.T) {
	got := parseNDMInterfaces(keeneticListing5x)
	want := []struct {
		iface, ndm, name, key string
		active                bool
	}{
		{"nwg0", "Wireguard0", "Exit_Cyprus", "KEY0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", true},
		{"nwg4", "Wireguard4", "Exit_Belarus", "KEY4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", true},
		// Switched on, never connected: the admin state alone used to call it up.
		{"nwg6", "Wireguard6", "RU_exit", "KEY6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false},
	}
	if len(got) != len(want) {
		t.Fatalf("want %d tunnels, got %d: %#v", len(want), len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Iface != w.iface || g.NDMName != w.ndm || g.Name != w.name || g.PublicKey != w.key || g.Source != SourceNDM {
			t.Errorf("tunnel[%d] = %+v, want iface %s ndm %s name %s key %s", i, g, w.iface, w.ndm, w.name, w.key)
		}
		if g.Active(0) != w.active {
			t.Errorf("tunnel[%d] %s Active = %v, want %v", i, w.ndm, g.Active(0), w.active)
		}
	}
}

// A single-interface show nests peers inside the wireguard: block. A peer's own (empty)
// description and the summary's "link: running" must not overwrite the interface's fields, and the
// peer's key must not replace the interface's.
func TestParseNDMInterfaceStatus_NestedBlocksDoNotLeak(t *testing.T) {
	in := `               id: Wireguard0
            index: 0
   interface-name: Wireguard0
             type: Wireguard
      description: Exit_Cyprus
             link: up
        connected: yes
            state: up
        wireguard:
           public-key: IFACEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          listen-port: 43556
               status: up

                 peer:
                      public-key: PEERKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                     description:
                      local-port: 43556
                          online: yes

          summary:
                layer:
                     conf: running
                     link: running
`
	got := ParseNDMInterfaceStatus(in)
	if len(got) != 1 {
		t.Fatalf("want 1 interface, got %d: %#v", len(got), got)
	}
	g := got[0]
	if g.Description != "Exit_Cyprus" || g.Link != "up" || g.PublicKey != "IFACEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || g.ListenPort != 43556 {
		t.Fatalf("nested lines leaked into the interface: %+v", g)
	}
}

// A switch port's sub-block carries its own interface-name:, which used to open a bogus interface
// that then collected the parent's later fields.
func TestParseNDMInterfaceStatus_PortSubBlockIsNotAnInterface(t *testing.T) {
	in := `Interface, name = "GigabitEthernet0"
               id: GigabitEthernet0
   interface-name: GigabitEthernet0
             type: GigabitEthernet
             port, name = 1:
                    id: GigabitEthernet0/0
        interface-name: 1
                  type: Port
                  link: down
             link: up
        connected: yes
`
	got := ParseNDMInterfaceStatus(in)
	if len(got) != 1 || got[0].Name != "GigabitEthernet0" || got[0].Type != "GigabitEthernet" || got[0].Link != "up" {
		t.Fatalf("port sub-block corrupted the listing: %#v", got)
	}
}

// The regression this file exists for: a Keenetic that also runs an Entware awg tunnel. The awg
// dump is not empty, and that used to stop discovery before NDM was asked, so the router's own
// tunnels were never listed.
func TestMergeDiscovered_KeeneticWithEntwareAWG(t *testing.T) {
	ndm := parseNDMInterfaces(keeneticListing5x)
	runtime := parseWgDump(strings.Join([]string{
		"awg1\tPRIV\tAWG1KEY\t57728\toff",
		"awg1\tPEER\t(none)\t192.0.2.7:8443\t10.0.0.0/24\t1700000000\t1\t2\t25",
		"wr_1a2b3c4d\tPRIV\tWRKEY\t40000\toff", // WayHop's own plugin tunnel
	}, "\n"), "amneziawg")
	got := mergeDiscovered(ndm, runtime, nil)
	var ifaces []string
	for _, v := range got {
		ifaces = append(ifaces, v.Iface)
	}
	if strings.Join(ifaces, ",") != "nwg0,nwg4,nwg6,awg1" {
		t.Fatalf("merged ifaces = %v, want the three NDM tunnels then awg1, and no wr_ device", ifaces)
	}
	if got[3].Source != SourceRuntime || got[3].ConfigListed() {
		t.Fatalf("an awg-quick tunnel is runtime-only: %+v", got[3])
	}
}

func TestMergeDiscovered_DumpEnrichesNDMRow(t *testing.T) {
	ndm := []DiscoveredVPN{{Iface: "nwg0", NDMName: "Wireguard0", Source: SourceNDM, Name: "Exit"}}
	runtime := []DiscoveredVPN{{Iface: "nwg0", PublicKey: "K", ListenPort: 5, Source: SourceRuntime,
		Peers: []Peer{{PublicKey: "P", Endpoint: "192.0.2.1:51820"}}}}
	got := mergeDiscovered(ndm, runtime, nil)
	if len(got) != 1 || got[0].Source != SourceNDM || got[0].Name != "Exit" || got[0].PublicKey != "K" || len(got[0].Peers) != 1 {
		t.Fatalf("dump must add peers to the NDM row, not a second row: %#v", got)
	}
}

func TestMergeDiscovered_UCIBacksRuntimeAndListsDownTunnels(t *testing.T) {
	runtime := []DiscoveredVPN{{Iface: "wg0", Type: "wireguard", PublicKey: "K0", Source: SourceRuntime}}
	uci := []DiscoveredVPN{
		{Iface: "wg0", Type: "wireguard", PublicKey: "K0", Name: "Home", Source: SourceUCI},
		{Iface: "wg1", Type: "wireguard", PublicKey: "K1", Name: "Office", Source: SourceUCI},
		{Iface: "wr_00000001", Type: "amneziawg", Source: SourceUCI}, // WayHop's native writer
	}
	got := mergeDiscovered(nil, runtime, uci)
	if len(got) != 2 {
		t.Fatalf("want wg0 and wg1, got %#v", got)
	}
	if got[0].Iface != "wg0" || got[0].Source != SourceUCI || got[0].Name != "Home" {
		t.Fatalf("a running uci tunnel is configuration-backed and takes its label: %+v", got[0])
	}
	if got[1].Iface != "wg1" || !got[1].ConfigListed() || got[1].Active(0) {
		t.Fatalf("a configured tunnel that is down is listed, inactive: %+v", got[1])
	}
}

// RFC 7748 section 6.1: Alice's X25519 key pair, written in hex as the RFC prints it (a
// base64 literal of key shape would read as a leaked key to the publish scan).
var (
	rfcPrivate = hexToBase64("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	rfcPublic  = hexToBase64("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
)

func hexToBase64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestPublicKeyOf(t *testing.T) {
	if got := publicKeyOf(rfcPrivate); got != rfcPublic {
		t.Fatalf("publicKeyOf(RFC 7748 Alice) = %q, want %q", got, rfcPublic)
	}
	for _, bad := range []string{"", "not base64", "c2hvcnQ="} {
		if got := publicKeyOf(bad); got != "" {
			t.Fatalf("publicKeyOf(%q) = %q, want empty", bad, got)
		}
	}
}

func TestParseUCITunnels(t *testing.T) {
	in := strings.Join([]string{
		"network.lan=interface",
		"network.lan.proto='static'",
		"network.wg0=interface",
		"network.wg0.proto='wireguard'",
		"network.wg0.private_key='" + rfcPrivate + "'",
		"network.wg0.addresses='10.0.0.2/32'",
		"network.@wireguard_wg0[0]=wireguard_wg0",
		"network.@wireguard_wg0[0].description='Office VPN'",
		"network.@wireguard_wg0[0].public_key='PEERKEY'",
		"network.@wireguard_wg0[0].endpoint_host='198.51.100.9'",
		"network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'",
		"network.awg0=interface",
		"network.awg0.proto='amneziawg'",
		"network.awg0.private_key='bad'",
	}, "\n")
	got := parseUCITunnels(in)
	if len(got) != 2 || got[0].Iface != "awg0" || got[1].Iface != "wg0" {
		t.Fatalf("want awg0 and wg0 sorted, got %#v", got)
	}
	wg := got[1]
	if wg.Type != "wireguard" || wg.Name != "Office VPN" || wg.PublicKey != rfcPublic || wg.Source != SourceUCI {
		t.Fatalf("wg0 = %+v", wg)
	}
	if len(wg.Peers) != 1 || wg.Peers[0].Endpoint != "198.51.100.9:51820" || !wg.FullTunnel() {
		t.Fatalf("wg0 peers = %#v", wg.Peers)
	}
	if got[0].Type != "amneziawg" || got[0].PublicKey != "" {
		t.Fatalf("awg0 = %+v", got[0])
	}
	if strings.Contains(strings.Join([]string{wg.PublicKey, wg.Name, wg.Peers[0].PublicKey}, " "), rfcPrivate) {
		t.Fatalf("the private key leaked")
	}
}
