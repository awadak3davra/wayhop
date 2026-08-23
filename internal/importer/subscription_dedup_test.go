package importer

import (
	"strings"
	"testing"
)

// Two VLESS nodes on the same host:port that differ only by transport/UUID produce
// the same genID (protocol+server+port). ParseSubscription must keep their IDs
// distinct so a bulk import doesn't silently overwrite one with the other.
func TestParseSubscriptionDedupesCollidingIDs(t *testing.T) {
	sub := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=/ws#WS",
		"vless://22222222-2222-2222-2222-222222222222@cdn.example.com:443?type=grpc&security=tls&sni=cdn.example.com&serviceName=grpc#GRPC",
	}, "\n")

	eps, errs := ParseSubscription(sub)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(eps))
	}
	if eps[0].ID == eps[1].ID {
		t.Fatalf("colliding IDs not de-duplicated: both %q", eps[0].ID)
	}
	if eps[1].ID != eps[0].ID+"-2" {
		t.Fatalf("second ID = %q, want %q", eps[1].ID, eps[0].ID+"-2")
	}
	// The distinct nodes survive (no overwrite): different UUIDs preserved.
	if eps[0].Params["uuid"] == eps[1].Params["uuid"] {
		t.Fatalf("both endpoints have uuid %v — one overwrote the other", eps[0].Params["uuid"])
	}
}

// A normal single endpoint keeps its natural slug (no suffix), so existing IDs
// and the share-link round trip are unaffected.
func TestParseSubscriptionSingleKeepsNaturalID(t *testing.T) {
	eps, errs := ParseSubscription("vless://11111111-1111-1111-1111-111111111111@host.example:443?type=tcp&security=none#one")
	if len(errs) != 0 || len(eps) != 1 {
		t.Fatalf("eps=%d errs=%v, want 1/none", len(eps), errs)
	}
	if eps[0].ID != "vless-host-example-443" {
		t.Fatalf("single ID = %q, want vless-host-example-443", eps[0].ID)
	}
}
