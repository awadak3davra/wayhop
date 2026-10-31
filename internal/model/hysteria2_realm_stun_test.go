package model

import (
	"reflect"
	"testing"
)

// STUN entries are host, host:port or an address. What failed to split used to pass as a "host" and
// fail only at runtime: a second colon, an empty port, a stray character, a comma-joined pair.
func TestHy2RealmSTUNListRefusesMalformedEntries(t *testing.T) {
	for _, bad := range []string{"stun.example.com:3478:1", "stun.example.com:", "st%un.example.com",
		"192.0.2.7:3478,198.51.100.7:3478", "stun.example.com:0", "-stun.example.com"} {
		if _, err := hy2RealmSTUNList([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	got, err := hy2RealmSTUNList([]string{"stun.example.com", "192.0.2.7:3478", "[2001:db8::1]:3478", "[2001:db8::2]", "2001:db8::3"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"stun.example.com", "192.0.2.7:3478", "[2001:db8::1]:3478", "2001:db8::2", "2001:db8::3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
