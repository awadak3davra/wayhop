package netvpn

import (
	"reflect"
	"testing"
)

func TestParseNDMInterfaces(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []DiscoveredVPN
	}{
		{
			name: "empty",
			in:   "",
			want: nil,
		},
		{
			name: "single wireguard tunnel",
			in: "interface-name: Wireguard0\n" +
				"    description: WG_A\n" +
				"    type: Wireguard\n" +
				"    link: up\n" +
				"    connected: yes\n" +
				"    state: up\n",
			want: []DiscoveredVPN{
				{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg", Name: "WG_A"},
			},
		},
		{
			name: "mixed interfaces — non-wireguard ignored",
			in: "interface-name: GigabitEthernet1\n" +
				"    description: WAN\n" +
				"    type: Port\n" +
				"    link: up\n" +
				"interface-name: Wireguard0\n" +
				"    description: ND_NL\n" +
				"    type: Wireguard\n" +
				"    connected: yes\n" +
				"interface-name: Bridge0\n" +
				"    type: Bridge\n" +
				"    link: up\n" +
				"interface-name: Wireguard1\n" +
				"    description: ND_RU\n" +
				"    type: Wireguard\n" +
				"    state: up\n",
			want: []DiscoveredVPN{
				{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg", Name: "ND_NL"},
				{Iface: "nwg1", NDMName: "Wireguard1", Type: "amneziawg", Name: "ND_RU"},
			},
		},
		{
			name: "case-insensitive type + CRLF line endings, no description ⇒ empty Name",
			in:   "interface-name: Wireguard2\r\n    type: WIREGUARD\r\n    link: up\r\n",
			want: []DiscoveredVPN{
				{Iface: "nwg2", NDMName: "Wireguard2", Type: "amneziawg", Name: ""},
			},
		},
		{
			name: "interface with no type is skipped",
			in: "interface-name: Wireguard0\n" +
				"    description: WG_A\n" +
				"    link: up\n",
			want: nil,
		},
		{
			name: "lines without a colon are ignored",
			in: "garbage line with no colon\n" +
				"interface-name: Wireguard0\n" +
				"    type: Wireguard\n" +
				"another garbage line\n",
			want: []DiscoveredVPN{
				{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNDMInterfaces(tt.in)
			// ndmUp (the admin/link verdict) is covered in TestParseNDMInterfaces_ActiveState;
			// this table asserts identity parsing only, so normalize it out before comparing.
			for i := range got {
				got[i].ndmUp = nil
				if got[i].Source != SourceNDM {
					t.Errorf("tunnel[%d] Source = %q, want %q", i, got[i].Source, SourceNDM)
				}
				got[i].Source = ""
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseNDMInterfaces() = %#v, want %#v", got, tt.want)
			}
			// The listing prints no peers, and a flat block has no layout to tell the interface's
			// key from a peer's, so neither is read.
			for _, d := range got {
				if d.PublicKey != "" || d.Peers != nil {
					t.Errorf("expected empty PublicKey/Peers, got PublicKey=%q Peers=%#v", d.PublicKey, d.Peers)
				}
			}
		})
	}
}

// TestParseNDMInterfaces_ActiveState verifies the fix for the "Keenetic tunnels always inactive"
// bug: `ndmc show interface` lists no peers, so Active() must read the NDM admin/link verdict
// (state:/link:+connected:) rather than a peer handshake that can never exist here. now is set far
// in the future so the old peer-only Active() would return false for BOTH rows.
func TestParseNDMInterfaces_ActiveState(t *testing.T) {
	const future = 9999999999
	in := "interface-name: Wireguard0\n" + // explicit admin state up ⇒ active
		"    type: Wireguard\n" +
		"    description: ND_NL\n" +
		"    state: up\n" +
		"interface-name: Wireguard1\n" + // link up + connected yes, no state ⇒ active
		"    type: Wireguard\n" +
		"    link: up\n" +
		"    connected: yes\n" +
		"interface-name: Wireguard2\n" + // admin state down ⇒ inactive
		"    type: Wireguard\n" +
		"    state: down\n"
	got := parseNDMInterfaces(in)
	if len(got) != 3 {
		t.Fatalf("want 3 tunnels, got %d: %#v", len(got), got)
	}
	if !got[0].Active(future) {
		t.Errorf("Wireguard0 (state:up) must report Active, peerless NDM tunnel")
	}
	if !got[1].Active(future) {
		t.Errorf("Wireguard1 (link:up + connected:yes) must report Active")
	}
	if got[2].Active(future) {
		t.Errorf("Wireguard2 (state:down) must report inactive")
	}
}

// realShowInterfaceKeenetic is a SANITIZED subset of a real `show interface` on KeeneticOS 5.01
// (fake keys/MACs, doc-range IPs, generic descriptions) — kept structurally faithful to prove the
// parser survives the real format: header "Interface, name =" lines (no colon), id:/index: BEFORE
// interface-name:, multiple traits:, a nested `port, name = N:` sub-block with its own
// interface-name:/type: Port/link:, bridge `interface, link = yes:` member lines, a `wireguard:`
// sub-block with status:, and AccessPoint interfaces. Only the three Wireguard tunnels must survive
// discovery — nothing nested must leak in or corrupt them.
const realShowInterfaceKeenetic = `Interface, name = "GigabitEthernet0"
               id: GigabitEthernet0
            index: 0
   interface-name: GigabitEthernet0
             type: GigabitEthernet
           traits: Mac
           traits: Switch
             link: up
        connected: yes
            state: up
             port, name = 1:
                    id: GigabitEthernet0/0
                 index: 0
        interface-name: 1
                 label: 1
                  type: Port
                  link: up
                 speed: 1000

Interface, name = "Home"
               id: Bridge0
            index: 0
   interface-name: Home
             type: Bridge
           traits: Ethernet
             link: up
        connected: yes
            state: up
          address: 203.0.113.1
           bridge:
            interface, link = yes: GigabitEthernet0/Vlan1
            interface, link = yes: WifiMaster0/AccessPoint0

Interface, name = "AccessPoint"
               id: WifiMaster0/AccessPoint0
            index: 0
   interface-name: AccessPoint
             type: AccessPoint
             link: up
        connected: yes
            state: up
             ssid: ExampleNet

Interface, name = "Wireguard1"
               id: Wireguard1
            index: 1
   interface-name: Wireguard1
             type: Wireguard
      description: wg-exit-nl
           traits: Ip
           traits: Wireguard
             link: up
        connected: yes
            state: up
              mtu: 1280
          address: 198.51.100.82
        wireguard:
           public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
          listen-port: 45234
               status: up

Interface, name = "Wireguard2"
               id: Wireguard2
            index: 2
   interface-name: Wireguard2
             type: Wireguard
      description: wg-vps-lan
           traits: Ip
           traits: Wireguard
             link: up
        connected: yes
            state: up
              mtu: 1420
        wireguard:
           public-key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
          listen-port: 42475
               status: up

Interface, name = "Wireguard7"
               id: Wireguard7
            index: 7
   interface-name: Wireguard7
             type: Wireguard
      description: wg-disabled
           traits: Ip
           traits: Wireguard
             link: down
        connected: no
            state: down
        wireguard:
           public-key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
          listen-port: 51111
               status: down
`

// TestParseNDMInterfaces_RealKeeneticFormat runs the parser over realistic KeeneticOS 5.01 output:
// exactly the three Wireguard tunnels must be discovered (ethernet/bridge/wifi/nested ports dropped),
// with the up ones Active and the down one inactive — the on-device proof that the discovery +
// active-state fix works on the real, richly-nested `show interface` format, not just toy fixtures.
func TestParseNDMInterfaces_RealKeeneticFormat(t *testing.T) {
	got := parseNDMInterfaces(realShowInterfaceKeenetic)
	if len(got) != 3 {
		t.Fatalf("want exactly 3 Wireguard tunnels (nested ports/bridges/wifi filtered), got %d: %#v", len(got), got)
	}
	want := []struct {
		iface, ndm, name, key string
		port                  int
		active                bool
	}{
		{"nwg1", "Wireguard1", "wg-exit-nl", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 45234, true},
		{"nwg2", "Wireguard2", "wg-vps-lan", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", 42475, true},
		{"nwg7", "Wireguard7", "wg-disabled", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", 51111, false},
	}
	const future = 9999999999
	for i, w := range want {
		if got[i].Iface != w.iface || got[i].NDMName != w.ndm || got[i].Name != w.name {
			t.Errorf("tunnel[%d] identity = {Iface:%q NDMName:%q Name:%q}, want {%q %q %q}",
				i, got[i].Iface, got[i].NDMName, got[i].Name, w.iface, w.ndm, w.name)
		}
		if got[i].Active(future) != w.active {
			t.Errorf("tunnel[%d] %s Active = %v, want %v", i, w.ndm, got[i].Active(future), w.active)
		}
		// The interface's own key and port come from its wireguard: sub-block; the listing
		// prints no peers.
		if got[i].PublicKey != w.key || got[i].ListenPort != w.port || got[i].Peers != nil {
			t.Errorf("tunnel[%d] key/port/peers = %q / %d / %#v, want %q / %d / none",
				i, got[i].PublicKey, got[i].ListenPort, got[i].Peers, w.key, w.port)
		}
	}
}

func TestNDMKernelIface(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Wireguard0", "nwg0"},
		{"Wireguard1", "nwg1"},
		{"Wireguard10", "nwg10"},
		{"WIREGUARD2", "nwg2"},
	}
	for _, tt := range tests {
		if got := ndmKernelIface(tt.in); got != tt.want {
			t.Errorf("ndmKernelIface(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitNDMKV(t *testing.T) {
	tests := []struct {
		in       string
		key, val string
		ok       bool
	}{
		{"type: Wireguard", "type", "Wireguard", true},
		{"interface-name: Wireguard0", "interface-name", "Wireguard0", true},
		{"connected:", "connected", "", true},
		{"no colon here", "", "", false},
		{": orphan value", "", "", false},
	}
	for _, tt := range tests {
		key, val, ok := splitNDMKV(tt.in)
		if key != tt.key || val != tt.val || ok != tt.ok {
			t.Errorf("splitNDMKV(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.in, key, val, ok, tt.key, tt.val, tt.ok)
		}
	}
}
