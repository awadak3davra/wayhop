package netvpn

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// discoverUCI lists the wireguard/amneziawg interfaces configured in OpenWrt's network config.
//
// The dumps only see interfaces that are running, so on OpenWrt a tunnel that was down, disabled or
// still waiting for its WAN was invisible: it could not be adopted, and an adopted one read as
// missing. uci lists it either way, under the section name netifd also gives the device. The bool
// reports whether uci exists here; a uci that exists and fails is an error, since a partial look
// must not be read as "these tunnels were deleted".
func discoverUCI(ctx context.Context) ([]DiscoveredVPN, bool, error) {
	out, err := exec.CommandContext(ctx, "uci", "-q", "show", "network").Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, false, nil // not an OpenWrt host
		}
		return nil, true, fmt.Errorf("uci show network: %w", err)
	}
	return parseUCITunnels(string(out)), true, nil
}

// parseUCITunnels turns `uci show network` into discovered tunnels, sorted by interface name.
// Like the dump parser it keeps no secret: the private key is used only to derive the interface's
// public key, which is the identity a tunnel keeps across renames. A peer's description is the
// only human label LuCI stores for a tunnel, so the first one names it. Pure, so it is tested with
// captured samples.
func parseUCITunnels(out string) []DiscoveredVPN {
	ifaces := ParseUCIShow(out)
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Strings(names)
	res := make([]DiscoveredVPN, 0, len(names))
	for _, name := range names {
		in := ifaces[name]
		d := DiscoveredVPN{
			Iface:     name,
			Type:      string(in.Proto.resolve()),
			PublicKey: publicKeyOf(in.PrivateKey),
			Source:    SourceUCI,
		}
		for _, p := range in.Peers {
			if d.Name == "" {
				d.Name = strings.TrimSpace(p.Description)
			}
			peer := Peer{PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs}
			if p.EndpointHost != "" {
				port := p.EndpointPort
				if port == 0 {
					port = 51820 // netifd's default for an endpoint without a port
				}
				peer.Endpoint = net.JoinHostPort(p.EndpointHost, strconv.Itoa(port))
			}
			d.Peers = append(d.Peers, peer)
		}
		res = append(res, d)
	}
	return res
}

// publicKeyOf derives a WireGuard public key from a base64 private key, or "" when the value is
// not a 32-byte key. X25519 clamps the scalar itself, exactly as `wg pubkey` does.
func publicKeyOf(private string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(private))
	if err != nil || len(raw) != 32 {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
