package importer

import (
	"testing"
)

// peerListFrom asserts Params["peers"] is the importer's native []map[string]any
// shape and returns it, failing the test otherwise.
func peerListFrom(t *testing.T, params map[string]any) []map[string]any {
	t.Helper()
	raw, ok := params["peers"]
	if !ok {
		t.Fatalf("Params has no \"peers\" key")
	}
	list, ok := raw.([]map[string]any)
	if !ok {
		t.Fatalf("Params[\"peers\"] is %T, want []map[string]any", raw)
	}
	return list
}

// TestParseConf_MultiPeer: a .conf with TWO [Peer] sections must accumulate BOTH
// into Params["peers"] (a wg-quick mesh config previously collapsed to the last
// peer). The legacy single-peer keys must reflect the FIRST peer (backward-compat).
func TestParseConf_MultiPeer(t *testing.T) {
	conf := `[Interface]
PrivateKey = aPriv
Address = 10.0.0.2/24
[Peer]
PublicKey = peerOnePub
PresharedKey = pskOne
Endpoint = 198.51.100.1:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
[Peer]
PublicKey = peerTwoPub
Endpoint = 203.0.113.7:8443
AllowedIPs = 0.0.0.0/0, ::/0`
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}

	// Legacy single-peer keys come from the FIRST peer.
	if e.Server != "198.51.100.1" || e.Port != 51820 {
		t.Errorf("primary server/port = %q/%d, want 198.51.100.1/51820", e.Server, e.Port)
	}
	if e.Params["peer_public_key"] != "peerOnePub" {
		t.Errorf("peer_public_key = %v, want peerOnePub (first peer)", e.Params["peer_public_key"])
	}
	if e.Params["pre_shared_key"] != "pskOne" {
		t.Errorf("pre_shared_key = %v, want pskOne (first peer)", e.Params["pre_shared_key"])
	}
	if e.Params["persistent_keepalive"] != 25 {
		t.Errorf("persistent_keepalive = %v, want 25 (first peer)", e.Params["persistent_keepalive"])
	}

	peers := peerListFrom(t, e.Params)
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}

	if peers[0]["server"] != "198.51.100.1" || peers[0]["port"] != 51820 {
		t.Errorf("peer[0] server/port = %v/%v, want 198.51.100.1/51820", peers[0]["server"], peers[0]["port"])
	}
	if peers[0]["public_key"] != "peerOnePub" {
		t.Errorf("peer[0] public_key = %v, want peerOnePub", peers[0]["public_key"])
	}
	if peers[0]["pre_shared_key"] != "pskOne" {
		t.Errorf("peer[0] pre_shared_key = %v, want pskOne", peers[0]["pre_shared_key"])
	}
	if peers[0]["persistent_keepalive"] != 25 {
		t.Errorf("peer[0] persistent_keepalive = %v, want 25", peers[0]["persistent_keepalive"])
	}
	if aips, ok := peers[0]["allowed_ips"].([]string); !ok || len(aips) != 1 || aips[0] != "10.0.0.0/24" {
		t.Errorf("peer[0] allowed_ips = %v, want [10.0.0.0/24]", peers[0]["allowed_ips"])
	}

	if peers[1]["server"] != "203.0.113.7" || peers[1]["port"] != 8443 {
		t.Errorf("peer[1] server/port = %v/%v, want 203.0.113.7/8443", peers[1]["server"], peers[1]["port"])
	}
	if peers[1]["public_key"] != "peerTwoPub" {
		t.Errorf("peer[1] public_key = %v, want peerTwoPub", peers[1]["public_key"])
	}
	// Second peer carried no PSK / keepalive — those keys must be ABSENT, not zeroed.
	if _, ok := peers[1]["pre_shared_key"]; ok {
		t.Errorf("peer[1] pre_shared_key present when conf had none: %v", peers[1]["pre_shared_key"])
	}
	if _, ok := peers[1]["persistent_keepalive"]; ok {
		t.Errorf("peer[1] persistent_keepalive present when conf had none: %v", peers[1]["persistent_keepalive"])
	}
	if aips, ok := peers[1]["allowed_ips"].([]string); !ok || len(aips) != 2 {
		t.Errorf("peer[1] allowed_ips = %v, want 2 entries", peers[1]["allowed_ips"])
	}
}

// TestParseConf_SinglePeerStillHasPeersList: a single-[Peer] .conf keeps the legacy
// Params keys AND now exposes a one-element peers list — existing single-peer
// readers must be unaffected (the legacy keys are unchanged).
func TestParseConf_SinglePeerStillHasPeersList(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/24\n[Peer]\nPublicKey = onlyPub\nEndpoint = 198.51.100.9:51820\nAllowedIPs = 0.0.0.0/0"
	e, err := parseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if e.Server != "198.51.100.9" || e.Params["peer_public_key"] != "onlyPub" {
		t.Errorf("legacy keys wrong: server=%q peer_public_key=%v", e.Server, e.Params["peer_public_key"])
	}
	peers := peerListFrom(t, e.Params)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if peers[0]["server"] != "198.51.100.9" || peers[0]["public_key"] != "onlyPub" {
		t.Errorf("peer[0] = %v, want server 198.51.100.9 / public_key onlyPub", peers[0])
	}
}

// TestParseConf_MissingEndpointStillErrors: a [Peer] with no Endpoint must still
// be rejected (the first-peer Endpoint drives the primary Server).
func TestParseConf_MissingEndpointStillErrors(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0"
	if _, err := parseConf(conf); err == nil {
		t.Fatal("expected error for [Peer] missing Endpoint, got nil")
	}
}
