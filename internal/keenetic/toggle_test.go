package keenetic

import (
	"reflect"
	"testing"
)

func TestToggleCommands(t *testing.T) {
	tests := []struct {
		name    string
		ndmName string
		up      bool
		want    []string
		wantErr bool
	}{
		{"enable", "Wireguard5", true, []string{"interface Wireguard5", "up"}, false},
		{"disable", "Wireguard5", false, []string{"interface Wireguard5", "down"}, false},
		{"disable ethernet-style name", "GigabitEthernet1", false, []string{"interface GigabitEthernet1", "down"}, false},
		{"empty name rejected", "", true, nil, true},
		{"whitespace rejected", "Wireguard 5", true, nil, true},
		{"newline injection rejected", "Wireguard5\ninterface WAN", false, nil, true},
		{"semicolon injection rejected", "Wireguard5; up", false, nil, true},
		{"quote injection rejected", "Wireguard5\"", false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToggleCommands(tt.ndmName, tt.up)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToggleCommands(%q,%v) err = %v, wantErr %v", tt.ndmName, tt.up, err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToggleCommands(%q,%v) = %#v, want %#v", tt.ndmName, tt.up, got, tt.want)
			}
		})
	}
}

// TestToggleCommands_NeverDestructive is the safety invariant: a toggle must never emit a
// `no interface` (delete) or any config/key line — only the interface selector + admin verb.
func TestToggleCommands_NeverDestructive(t *testing.T) {
	for _, up := range []bool{true, false} {
		got, err := ToggleCommands("Wireguard5", up)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected exactly 2 commands (select + verb), got %#v", got)
		}
		if got[0] != "interface Wireguard5" {
			t.Errorf("first command = %q, want the plain interface selector", got[0])
		}
		for _, c := range got {
			if c == "no interface Wireguard5" {
				t.Errorf("toggle emitted a DESTRUCTIVE delete: %q", c)
			}
		}
	}
}

func TestSaveCommand(t *testing.T) {
	if got := SaveCommand(); got != "system configuration save" {
		t.Errorf("SaveCommand() = %q, want %q", got, "system configuration save")
	}
}
