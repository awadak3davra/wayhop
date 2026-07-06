package netvpn

import (
	"reflect"
	"testing"
)

func TestInterfaceStatusUp(t *testing.T) {
	tests := []struct {
		name                   string
		link, connected, state string
		want                   bool
	}{
		{"explicit state up wins", "down", "no", "up", true},
		{"explicit state down wins over link", "up", "yes", "down", false},
		{"no state, link up + connected yes ⇒ up", "up", "yes", "", true},
		{"no state, link up but not connected ⇒ down", "up", "no", "", false},
		{"no state, link down ⇒ down", "down", "yes", "", false},
		{"case-insensitive", "UP", "YES", "", true},
		{"all empty ⇒ down", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InterfaceStatusUp(tt.link, tt.connected, tt.state); got != tt.want {
				t.Errorf("InterfaceStatusUp(%q,%q,%q) = %v, want %v", tt.link, tt.connected, tt.state, got, tt.want)
			}
		})
	}
}

func TestParseNDMInterfaceStatus(t *testing.T) {
	// Reuse the exact line format the discovery fixtures use, but assert on the NEW
	// status struct (link/connected/state) that parseNDMInterfaces discards.
	in := "interface-name: Wireguard0\n" +
		"    description: ND_VPS\n" +
		"    type: Wireguard\n" +
		"    link: up\n" +
		"    connected: yes\n" +
		"    state: up\n" +
		"interface-name: GigabitEthernet1\n" +
		"    description: WAN\n" +
		"    type: Port\n" +
		"    link: up\n" +
		"interface-name: Wireguard5\r\n" + // CRLF + admin-down while physically up
		"    type: Wireguard\r\n" +
		"    link: up\r\n" +
		"    connected: yes\r\n" +
		"    state: down\r\n"
	want := []NDMInterfaceStatus{
		{Name: "Wireguard0", Type: "Wireguard", Description: "ND_VPS", Link: "up", Connected: "yes", State: "up", Up: true},
		// no state + connected absent ⇒ Up=false even though link is up.
		{Name: "GigabitEthernet1", Type: "Port", Description: "WAN", Link: "up", Up: false},
		// admin-down while physically up: explicit state wins ⇒ Up=false.
		{Name: "Wireguard5", Type: "Wireguard", Link: "up", Connected: "yes", State: "down", Up: false},
	}

	got := ParseNDMInterfaceStatus(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseNDMInterfaceStatus() =\n  %#v\nwant\n  %#v", got, want)
	}
}

func TestParseNDMInterfaceStatus_Empty(t *testing.T) {
	if got := ParseNDMInterfaceStatus(""); got != nil {
		t.Errorf("ParseNDMInterfaceStatus(\"\") = %#v, want nil", got)
	}
}

// TestParseNDMInterfaceStatus_LookupByName demonstrates the intended consumer pattern:
// resolve a single interface's REAL up/down by NDM name.
func TestParseNDMInterfaceStatus_LookupByName(t *testing.T) {
	in := "interface-name: Wireguard5\n    type: Wireguard\n    state: down\n"
	found := false
	for _, s := range ParseNDMInterfaceStatus(in) {
		if s.Name == "Wireguard5" {
			found = true
			if s.Up {
				t.Errorf("Wireguard5 reported Up, want down (state: down)")
			}
		}
	}
	if !found {
		t.Fatal("Wireguard5 not found in parsed status")
	}
}
