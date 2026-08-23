package netvpn

import (
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

var awgObfuscationKeys = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
}

// ProtoForModel reports whether a WayHop protocol has a router-native WireGuard-family form.
func ProtoForModel(protocol model.Protocol) (Proto, bool) {
	switch protocol {
	case model.ProtoAmneziaWG:
		return ProtoAmneziaWG, true
	case model.ProtoWireGuard:
		return ProtoWireGuard, true
	default:
		return "", false
	}
}

// InterfaceName is the single stable native interface identity shared by routing, preview and
// execution. It is derived rather than caller-chosen so those planes cannot point at different
// devices for the same endpoint.
func InterfaceName(endpoint model.Endpoint) string { return util.AWGIface(endpoint.ID) }

// InterfaceFromEndpoint converts a model endpoint into the exact native device desired by the
// OpenWrt writer. It is pure and accepts both in-memory and JSON-round-tripped Params shapes.
func InterfaceFromEndpoint(endpoint model.Endpoint, name string, protocol Proto) (AWGInterface, error) {
	if err := ValidInterfaceName(name); err != nil {
		return AWGInterface{}, err
	}
	if _, warp := endpoint.Params["reserved"]; warp {
		return AWGInterface{}, fmt.Errorf(
			"endpoint %q carries a WARP client id (reserved), which no native router protocol has an option for",
			endpoint.Name)
	}
	iface := AWGInterface{
		Name:        name,
		Proto:       protocol,
		PrivateKey:  modelParamString(endpoint.Params, "private_key"),
		Addresses:   modelParamStrings(endpoint.Params, "local_address"),
		MTU:         endpoint.MTU,
		Obfuscation: map[string]string{},
	}
	if iface.PrivateKey == "" {
		return AWGInterface{}, fmt.Errorf("endpoint %q has no private key, so the interface could never come up", endpoint.Name)
	}
	if len(iface.Addresses) == 0 {
		return AWGInterface{}, fmt.Errorf("endpoint %q has no interface address, so the tunnel would carry nothing", endpoint.Name)
	}
	if iface.MTU == 0 {
		iface.MTU = modelParamInt(endpoint.Params, "mtu")
	}
	if endpoint.Protocol == model.ProtoAmneziaWG {
		for _, key := range awgObfuscationKeys {
			if value := modelParamString(endpoint.Params, key); value != "" {
				iface.Obfuscation[key] = value
			}
		}
	}
	iface.Peers = peersFromEndpoint(endpoint)
	if len(iface.Peers) == 0 {
		return AWGInterface{}, fmt.Errorf("endpoint %q has no peer, so the interface could never carry traffic", endpoint.Name)
	}
	for index := range iface.Peers {
		if len(iface.Peers[index].AllowedIPs) == 0 {
			iface.Peers[index].AllowedIPs = strings.Split(util.WGAllowedIPs(endpoint.Params), ", ")
		}
	}
	return iface, nil
}

// ValidInterfaceName protects the UCI and kernel name boundary.
func ValidInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("no interface name given")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name %q is longer than the 15 characters a kernel interface can carry", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return fmt.Errorf("interface name %q contains %q; only letters, digits and underscore are allowed", name, string(r))
		}
	}
	return nil
}

func peersFromEndpoint(endpoint model.Endpoint) []AWGPeer {
	var peers []AWGPeer
	for _, raw := range modelParamList(endpoint.Params, "peers") {
		peerMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		peer := AWGPeer{
			PublicKey:           modelParamString(peerMap, "public_key"),
			PresharedKey:        modelParamString(peerMap, "pre_shared_key"),
			EndpointHost:        modelParamString(peerMap, "server"),
			EndpointPort:        modelParamInt(peerMap, "port"),
			AllowedIPs:          modelParamStrings(peerMap, "allowed_ips"),
			PersistentKeepalive: modelParamInt(peerMap, "persistent_keepalive"),
		}
		if peer.PublicKey != "" {
			peers = append(peers, peer)
		}
	}
	if len(peers) != 0 {
		return peers
	}
	if publicKey := modelParamString(endpoint.Params, "peer_public_key"); publicKey != "" {
		keepalive := endpoint.PersistentKeepalive
		if keepalive == 0 {
			keepalive = modelParamInt(endpoint.Params, "persistent_keepalive")
		}
		peers = append(peers, AWGPeer{
			PublicKey: publicKey, PresharedKey: modelParamString(endpoint.Params, "pre_shared_key"),
			EndpointHost: endpoint.Server, EndpointPort: endpoint.Port,
			AllowedIPs: modelParamStrings(endpoint.Params, "allowed_ips"), PersistentKeepalive: keepalive,
		})
	}
	return peers
}

func modelParamString(values map[string]any, key string) string {
	switch value := values[key].(type) {
	case string:
		return value
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(value, 'f', -1, 64)
	case int:
		return strconv.Itoa(value)
	case bool:
		if value {
			return "1"
		}
		return "0"
	}
	return ""
}

func modelParamInt(values map[string]any, key string) int {
	switch value := values[key].(type) {
	case int:
		return value
	case float64:
		return int(value)
	case string:
		result, _ := strconv.Atoi(value)
		return result
	}
	return 0
}

func modelParamStrings(values map[string]any, key string) []string {
	switch value := values[key].(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		var result []string
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				result = append(result, text)
			}
		}
		return result
	case string:
		if value != "" {
			return []string{value}
		}
	}
	return nil
}

func modelParamList(values map[string]any, key string) []any {
	switch value := values[key].(type) {
	case []any:
		return value
	case []map[string]any:
		result := make([]any, len(value))
		for index := range value {
			result[index] = value[index]
		}
		return result
	}
	return nil
}
