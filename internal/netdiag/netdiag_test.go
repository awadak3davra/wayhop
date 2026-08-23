package netdiag

import (
	"context"
	"testing"
)

func TestValidTarget(t *testing.T) {
	ok := []string{"8.8.8.8", "google.com", "my-host.local", "2001:db8::1", "vpn.example.org"}
	bad := []string{"a; rm -rf /", "host && evil", "a b", "$(whoami)", "`id`", "", "a|b", "x>y"}
	for _, s := range ok {
		if !ValidTarget(s) {
			t.Errorf("ValidTarget(%q)=false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidTarget(s) {
			t.Errorf("ValidTarget(%q)=true, want false (injection guard)", s)
		}
	}
}

// TestValidIface guards the interface name bound into `ping -I` / `traceroute -i`:
// real iface names pass, "" and metacharacter/flag injection are rejected.
func TestValidIface(t *testing.T) {
	ok := []string{"awg0", "awg1", "eth0", "br-lan", "tun-keen", "wan", "lan2"}
	bad := []string{"", "-froot", "a b", "a;b", "$(x)", "a/b", "thisnameiswaytoolong"}
	for _, s := range ok {
		if !ValidIface(s) {
			t.Errorf("ValidIface(%q)=false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidIface(s) {
			t.Errorf("ValidIface(%q)=true, want false (guard)", s)
		}
	}
}

func TestPingLoopback(t *testing.T) {
	r := Ping(context.Background(), "127.0.0.1", 2)
	if !r.Ok {
		t.Fatalf("loopback ping reported not ok (loss=%d): %s", r.LossPct, r.Output)
	}
}
