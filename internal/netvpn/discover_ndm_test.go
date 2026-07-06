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
				"    description: ND_VPS\n" +
				"    type: Wireguard\n" +
				"    link: up\n" +
				"    connected: yes\n" +
				"    state: up\n",
			want: []DiscoveredVPN{
				{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg", Name: "ND_VPS"},
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
				"    description: ND_VPS\n" +
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseNDMInterfaces() = %#v, want %#v", got, tt.want)
			}
			// Discovered NDM tunnels must never carry peers or a public key,
			// since `show interface` does not expose them.
			for _, d := range got {
				if d.PublicKey != "" || d.Peers != nil {
					t.Errorf("expected empty PublicKey/Peers, got PublicKey=%q Peers=%#v", d.PublicKey, d.Peers)
				}
			}
		})
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
