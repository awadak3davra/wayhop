package server

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// Shared fixtures for the apply-stack tests: desired/host tuples that never touch the developer
// host, tool identities and endpoints of every engine.

func executionTestKernelTools() (ExecutionToolIdentityV1, ExecutionToolIdentityV1) {
	return ExecutionToolIdentityV1{
			Tool: executionToolNFT, ResolvedPath: "/usr/sbin/nft",
			ContentSHA256: strings.Repeat("3", 64), Version: "nftables v1.1.0", Runnable: true,
		}, ExecutionToolIdentityV1{
			Tool: executionToolIP, ResolvedPath: "/sbin/ip",
			ContentSHA256: strings.Repeat("4", 64), Version: "ip utility, iproute2-6.12.0", Runnable: true,
		}
}

func executionAWGEndpoint(id string) model.Endpoint {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	preSharedKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820, Enabled: true,
		Params: map[string]any{
			"private_key": privateKey, "peer_public_key": publicKey,
			"pre_shared_key": preSharedKey, "local_address": []string{"10.8.0.2/32"},
		},
	}
}

// executionNativeTestTuple is an OpenWrt native-first fixture: one WayHop-owned AmneziaWG endpoint the
// native planner can create as a netifd interface.
func executionNativeTestTuple(t *testing.T) (DesiredSnapshot, HostSnapshotV1, executionNativeCaptureV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "mixed"
	cfg.Offload = "auto"
	cfg.NativeFirewallZone = "vpn"
	endpoint := model.Endpoint{
		ID: "ep-native", Name: "native", Enabled: true,
		Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.9", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIVATE-MARKER", "peer_public_key": "PUBLIC-MARKER",
			"local_address": []string{"10.20.0.2/32"},
			"allowed_ips":   []string{"0.0.0.0/0"}, "jc": 5,
		},
	}
	desired, err := newDesiredSnapshot(cfg, model.Profile{Endpoints: []model.Endpoint{endpoint}}, 7)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.RawCapabilities.Native["amneziawg"] = true
	delete(probe.RawCapabilities.Installable, "amneziawg")
	probe.RawCapabilities.NetifdProtos["amneziawg"] = true
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := executionNativeCaptureV1{
		NetworkUCI:   "network.lan=interface\n",
		FirewallUCI:  "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n",
		RouterProtos: netvpn.RouterProtos{"amneziawg": true}, FirewallZone: "vpn",
	}
	return desired, host, capture
}
