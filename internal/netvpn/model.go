package netvpn

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/util"
)

var awgObfuscationKeys = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
}

// awgKeys30 are the settings generation 3.0 added, by the name the model stores them under. Each is
// written as the option awg_<name>, the name the amneziawg netifd handler reads and hands to
// `awg setconf` as HeaderProtectionKey, ContentPaddingAddition, RekeyAfterTime, RekeyTimeout,
// RejectAfterTime, KeepaliveTimeout and MaxHandshakeAttempts (amneziawg-tools src/config.c at
// v3.1.20260812). All but the key are "n" or "lo-hi" ranges of 16-bit values.
var awgKeys30 = []string{
	"header_protection_key", "content_padding_addition",
	"rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
}

// awgSwitches31 are the two switches generation 3.1 added, written as awg_random_trailers and
// awg_disable_cookies, which the handler reads as uci booleans and hands to `awg setconf` as
// RandomTrailers = on and DisableCookies = on.
var awgSwitches31 = []string{"random_trailers", "disable_cookies"}

// AWGGeneration is the generation this writer expresses on any router, whatever its kernel module:
// awgObfuscationKeys stops at 2.0 (S3/S4, H ranges, I1-I5). It is what the writer has always written,
// and what it still writes where the module is older than 3.0 or could not be probed.
const AWGGeneration = awg.Gen2

// AWGMaxGeneration is the newest generation this writer can express: the 3.0 settings and the 3.1
// switches above, each written only where the router's own kernel module carries it.
const AWGMaxGeneration = awg.Gen31

// AWGWriterGeneration is the generation the UCI writer expresses on a router whose loaded AmneziaWG
// kernel module is kernel (awg.ProbeHost's classification).
//
// The 3.x options are gated on the module because the module is what would lose them: amneziawg-tools
// 3.1 sends every key it is given as a netlink attribute, and a 3.0 module does not take RandomTrailers
// or DisableCookies (generation.go says why that looks configured and is not). Below 3.0 - or with no
// module found - the writer stays at AWGGeneration, which it wrote before it looked at the module at
// all, so nothing that runs today changes. The netifd handler is the other thing that could lose them;
// see HandlerAWGGeneration.
func AWGWriterGeneration(kernel awg.Generation) awg.Generation {
	switch {
	case kernel > AWGMaxGeneration:
		return AWGMaxGeneration
	case kernel > AWGGeneration:
		return kernel
	}
	return AWGGeneration
}

// HandlerAWGGeneration is the newest generation an amneziawg netifd handler passes on to
// `awg setconf`, read from the handler script itself (/lib/netifd/proto/amneziawg.sh): a 3.x option
// counts when the script names it, as a handler that reads it does (the community handler declares
// each awg_<name> with proto_config_add_* and reads it with config_get, by name).
//
// A 3.1 module behind a handler written before 3.0 would be handed a section whose
// awg_header_protection_key the handler never reads: the interface comes up without it and the server
// does not answer. So the module generation a capture passes on should be min(module, handler); an
// unreadable script reads as "" here, AWGGeneration, which keeps 3.x connections on WayHop's engine.
func HandlerAWGGeneration(script string) awg.Generation {
	names := func(keys []string) bool {
		for _, key := range keys {
			if !strings.Contains(script, "awg_"+key) {
				return false
			}
		}
		return true
	}
	switch {
	case !names(awgKeys30):
		return AWGGeneration
	case !names(awgSwitches31):
		return awg.Gen30
	}
	return AWGMaxGeneration
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
// OpenWrt writer, at the writer's baseline generation (AWGGeneration). It is pure and accepts both
// in-memory and JSON-round-tripped Params shapes.
func InterfaceFromEndpoint(endpoint model.Endpoint, name string, protocol Proto) (AWGInterface, error) {
	return InterfaceFromEndpointFor(endpoint, name, protocol, awg.GenNone)
}

// InterfaceFromEndpointFor is InterfaceFromEndpoint on a router whose loaded AmneziaWG kernel module is
// kernel: the 3.x settings the module carries are written too (AWGWriterGeneration), and those it does
// not are refused by name.
func InterfaceFromEndpointFor(endpoint model.Endpoint, name string, protocol Proto, kernel awg.Generation) (AWGInterface, error) {
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
		// A setting with no option here is refused, not skipped: upstream requires every setting except
		// Jc/Jmin/Jmax to match the server's, so the interface would be written, come up and never be
		// answered. The native planner refuses such an endpoint first, with a better message; this is
		// the writer holding the same line for every other caller.
		gen := AWGWriterGeneration(kernel)
		if beyond := awg.Beyond(endpoint.Params, gen); len(beyond) != 0 {
			return AWGInterface{}, fmt.Errorf(
				"endpoint %q uses AmneziaWG %s settings (%s), which the UCI interface WayHop writes cannot carry on "+
					"this router: it writes up to generation %s here (%s)",
				endpoint.Name, awg.Need(endpoint.Params), strings.Join(beyond, ", "), gen, KernelModuleWords(kernel))
		}
		for _, key := range awgObfuscationKeys {
			if value := modelParamString(endpoint.Params, key); value != "" {
				iface.Obfuscation[key] = value
			}
		}
		if gen >= awg.Gen30 {
			if err := addAWG30(iface.Obfuscation, endpoint.Params); err != nil {
				return AWGInterface{}, fmt.Errorf("endpoint %q: %w", endpoint.Name, err)
			}
		}
		if gen >= awg.Gen31 {
			if err := addAWG31(iface.Obfuscation, endpoint.Params); err != nil {
				return AWGInterface{}, fmt.Errorf("endpoint %q: %w", endpoint.Name, err)
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

// headerProtectionNonce is HEADER_PROTECTION_NONCE_SIZE in the kernel module's
// src/header_protection.h: with a header protection key set, src/netlink.c refuses the whole
// configuration (-EINVAL) unless each of S1-S4 is at least this large.
const headerProtectionNonce = 12

// addAWG30 adds the 3.0 settings params carries to obf, checked as the module and the tools check
// them, so a value they would refuse - or take wrongly - is refused here by name, before anything is
// written, rather than by netifd after it:
//   - the header protection key goes out in the one spelling `awg setconf` reads (key_from_base64:
//     44 characters of standard base64), whatever base64 the config carried; and only with every
//     padding S1-S4 large enough for the nonce, which the module otherwise refuses.
//   - a range goes out as written once it reads as "n" or "lo-hi" of 16-bit values: amneziawg-tools
//     takes a larger number without complaint and keeps its low 16 bits (u16_range_from_string), so
//     70000 would run as 4464.
//
// The values are read by awg.SettingText, the reading Need judged them by.
func addAWG30(obf map[string]string, params map[string]any) error {
	for _, key := range awgKeys30 {
		value := strings.TrimSpace(awg.SettingText(params[key]))
		if value == "" {
			continue
		}
		if key != "header_protection_key" {
			if _, _, err := awg.ParseRange(value, math.MaxUint16); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			obf[key] = value
			continue
		}
		std, ok := standardKey(value)
		if !ok {
			return fmt.Errorf("header_protection_key is not a 32-byte base64 key")
		}
		for i := 1; i <= 4; i++ {
			s := obf["s"+strconv.Itoa(i)]
			if n, err := strconv.ParseUint(s, 10, 64); err != nil || n < headerProtectionNonce {
				if s == "" {
					s = "not set"
				}
				return fmt.Errorf("with a header_protection_key every padding S1-S4 must be at least %d, "+
					"the size of the nonce it carries, and S%d is %s", headerProtectionNonce, i, s)
			}
		}
		obf[key] = std
	}
	return nil
}

// addAWG31 adds a 3.1 switch that is on to obf as '1', the uci boolean the netifd handler reads
// (config_get_bool) before it writes "RandomTrailers = on" for `awg setconf`.
//
// A switch that is off is not written. Off is every generation's default and the handler writes no
// line for it either way; LuCI's checkbox removes the option rather than store '0'; and the plugin's
// kernel path leaves the line out too. Writing '0' would only add a difference with LuCI, and an
// interface restart the first time a router's module reaches 3.1. A value that is neither on nor off
// is refused, as `awg setconf` refuses it.
func addAWG31(obf map[string]string, params map[string]any) error {
	for _, key := range awgSwitches31 {
		on, err := awgSwitch(params[key])
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if on {
			obf[key] = boolOpt(true)
		}
	}
	return nil
}

// awgSwitch reads a 3.1 switch in any shape the model stores one: a JSON bool from an import, text or
// a number from the API. Unset and empty are off, as the handler treats an empty option.
func awgSwitch(value any) (bool, error) {
	switch v := value.(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return false, nil
		}
		return awg.ParseBool(v)
	}
	text := awg.SettingText(value)
	if text == "" {
		return false, fmt.Errorf("unreadable value %v", value)
	}
	return awg.ParseBool(text)
}

// standardKey re-encodes a 32-byte key given in any base64 alphabet, padded or not, as the standard
// padded form amneziawg-tools requires - the same set the plugin's kernel path accepts.
func standardKey(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return base64.StdEncoding.EncodeToString(b), true
		}
	}
	return "", false
}

// KernelModuleWords says what the UCI writer's generation was chosen by (AWGWriterGeneration), in
// words for a refusal or a review: the module it found, or that it found none it could write 3.x for.
func KernelModuleWords(kernel awg.Generation) string {
	if kernel == awg.GenNone {
		return "no AmneziaWG kernel module of generation 3.0 or newer is known on this router"
	}
	return "the router's AmneziaWG kernel module is generation " + kernel.String()
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
	case int64:
		// Need weighs an int64 (awg.SettingText reads it), so the writer must not read it as unset.
		return strconv.FormatInt(value, 10)
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
