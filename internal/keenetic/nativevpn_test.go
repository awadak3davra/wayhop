package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

// TestWireguardCommands_KeyCanonicalizedAndGuarded: a url-safe key is re-encoded to the
// std-base64-with-padding KeeneticOS requires (else the interface fails to come up), and a control
// char in a key is truncated so it can't inject extra RCI command lines.
func TestWireguardCommands_KeyCanonicalizedAndGuarded(t *testing.T) {
	std := "AAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="     // valid 32-byte std-base64 key
	urlSafe := "AAAAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // same 32 bytes, url-safe alphabet (- for +)
	e := model.Endpoint{
		ID: "k", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard, Server: "1.1.1.1", Port: 51820,
		Params: map[string]any{
			"private_key":     urlSafe,
			"peer_public_key": std,
			"pre_shared_key":  "bad\nallow-ips 0.0.0.0 0.0.0.0", // control char -> RCI-injection attempt
			"local_address":   []string{"10.0.0.2/32"},
		},
	}
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 1})
	if err != nil {
		t.Fatalf("WireguardCommands: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "wireguard private-key "+std) || strings.Contains(joined, urlSafe) {
		t.Errorf("url-safe private key must be re-encoded to std base64:\n%s", joined)
	}
	var pskCmd string
	for _, c := range cmds {
		if strings.Contains(c, "preshared-key") {
			pskCmd = c
		}
	}
	if pskCmd != "    preshared-key bad" {
		t.Errorf("preshared-key must be truncated at the control char (no RCI injection); got %q", pskCmd)
	}
}

// TestWireguardCommands_NoRCIInjection: a control char (newline) in the endpoint Name (description
// line) or Server (endpoint line) must be truncated so it can't inject an extra NDM command into
// the batched, line-based /rci/parse stream — the same protection wgKey gives the key fields.
func TestWireguardCommands_NoRCIInjection(t *testing.T) {
	key := "AAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	e := model.Endpoint{
		ID: "x", Name: "vpn\nsystem configuration factory-reset",
		Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "1.2.3.4\nno interface Wireguard0", Port: 51820,
		Params: map[string]any{
			"private_key":     key,
			"peer_public_key": key,
			"local_address":   []string{"10.0.0.2/32"},
		},
	}
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 0})
	if err != nil {
		t.Fatalf("WireguardCommands: %v", err)
	}
	for _, c := range cmds {
		if strings.ContainsRune(c, '\n') {
			t.Errorf("command line contains a newline (RCI injection possible): %q", c)
		}
		if strings.Contains(c, "factory-reset") || strings.Contains(c, "no interface Wireguard0") {
			t.Errorf("injected NDM command survived a control char: %q", c)
		}
	}
}

// awgEndpoint an example AmneziaWG interface: AmneziaWG 1.x params.
func awgEndpoint() model.Endpoint {
	return model.Endpoint{
		ID: "wg_a", Name: "WG_A", Engine: model.EngineAmneziaWG, Server: "203.0.113.10", Port: 443,
		Enabled: true,
		Params: map[string]any{
			"private_key": "PRIVKEYbase64==", "peer_public_key": "AAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"jc": 5, "jmin": 49, "jmax": 998, "s1": 17, "s2": 110,
			"h1": 1111111111, "h2": 2222222222, "h3": 3333333333, "h4": 4444444444,
			"local_address": []string{"10.0.1.10/32"}, "mtu": 1420, "persistent_keepalive": 21,
		},
	}
}

// TestWireguardCommands_MatchesLiveNDM: the renderer must emit the EXACT native command set
// KeeneticOS uses (validated against the live `show running-config interface Wireguard0`),
// so a future Apply produces a config the router accepts verbatim.
func TestWireguardCommands_MatchesLiveNDM(t *testing.T) {
	cmds, err := WireguardCommands(awgEndpoint(), WireguardOpts{Index: 0, Metric: 32764})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	for _, want := range []string{
		"interface Wireguard0",
		"description WG_A",
		"security-level public",
		"ip address 10.0.1.10 255.255.255.255", // /32 → dotted mask
		"ip mtu 1420",
		"ip global 32764",
		"ip tcp adjust-mss pmtu",
		"wireguard private-key PRIVKEYbase64==",
		"wireguard asc 5 49 998 17 110 1111111111 2222222222 3333333333 4444444444", // exact live 9-arg form
		"wireguard peer AAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"    endpoint 203.0.113.10:443",
		"    keepalive-interval 21",
		"    allow-ips 0.0.0.0 0.0.0.0", // 0.0.0.0/0 → KeeneticOS form
		"    connect",
		"up",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing line %q\n--- got ---\n%s", want, got)
		}
	}
	if cmds[0] != "interface Wireguard0" {
		t.Errorf("must start with the interface decl, got %q", cmds[0])
	}
	if cmds[len(cmds)-1] != "up" {
		t.Errorf("must end with `up`, got %q", cmds[len(cmds)-1])
	}
	// asc must precede the peer; private-key must precede asc.
	if i, j := idx(cmds, "wireguard asc"), idx(cmds, "wireguard peer"); i < 0 || j < 0 || i > j {
		t.Errorf("asc(%d) must precede peer(%d)", i, j)
	}
}

func TestWireguardCommands_PlainWGNoAsc(t *testing.T) {
	e := model.Endpoint{
		ID: "wg", Name: "Plain WG", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "1.2.3.4", Port: 51820, Enabled: true,
		Params: map[string]any{"private_key": "k", "peer_public_key": "P", "local_address": []string{"10.0.0.2/32"}},
	}
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 3})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	if strings.Contains(got, "wireguard asc") {
		t.Errorf("plain WireGuard must emit NO asc line:\n%s", got)
	}
	if !strings.Contains(got, "wireguard peer P") || !strings.Contains(got, `description "Plain WG"`) {
		t.Errorf("plain WG render wrong:\n%s", got)
	}
}

func TestWireguardCommands_AWG2Extended(t *testing.T) {
	e := awgEndpoint()
	e.Params["s3"], e.Params["s4"] = 25, 40
	e.Params["i1"], e.Params["i2"], e.Params["i3"], e.Params["i4"], e.Params["i5"] = "0x11", "0x22", "0x33", "0x44", "0x55"
	cmds, _ := WireguardCommands(e, WireguardOpts{Index: 5})
	got := strings.Join(cmds, "\n")
	if !strings.Contains(got, "wireguard asc 5 49 998 17 110 1111111111 2222222222 3333333333 4444444444 25 40 0x11 0x22 0x33 0x44 0x55") {
		t.Errorf("AWG 2.0 extended asc wrong:\n%s", got)
	}
}

// TestWireguardCommands_AWG2PartialExtKeepsAlignment: a partial 2.0 set (I1-I5 present,
// S3/S4 absent) must fill the empty S3/S4 slots with "0" so I1 does not collapse into the
// S3 position when NDM whitespace-tokenizes the `wireguard asc` line.
func TestWireguardCommands_AWG2PartialExtKeepsAlignment(t *testing.T) {
	e := awgEndpoint()
	e.Params["i1"], e.Params["i2"], e.Params["i3"], e.Params["i4"], e.Params["i5"] = "0x11", "0x22", "0x33", "0x44", "0x55"
	// deliberately NOT setting s3/s4
	cmds, _ := WireguardCommands(e, WireguardOpts{Index: 5})
	got := strings.Join(cmds, "\n")
	if !strings.Contains(got, "wireguard asc 5 49 998 17 110 1111111111 2222222222 3333333333 4444444444 0 0 0x11 0x22 0x33 0x44 0x55") {
		t.Errorf("partial AWG 2.0 ext must fill empty S3/S4 with 0 to keep positional alignment:\n%s", got)
	}
	for _, line := range cmds {
		if strings.Contains(line, "wireguard asc") && strings.Contains(line, "  ") {
			t.Errorf("asc line has a collapsed empty slot (double space) that misaligns positional args: %q", line)
		}
	}
}

// TestWireguardCommands_IPv6EndpointBracketed: an IPv6-literal peer server must be bracketed in the
// `endpoint` NDM line ([v6]:port). A bare server:port concatenation makes the port ambiguous, and the
// module's own splitEndpoint (net.SplitHostPort) then mis-parses it so the tunnel never dials.
func TestWireguardCommands_IPv6EndpointBracketed(t *testing.T) {
	e := awgEndpoint()
	e.Server = "2001:db8::1"
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 5})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	if !strings.Contains(got, "endpoint [2001:db8::1]:443") {
		t.Errorf("IPv6 peer endpoint must be bracketed [v6]:port:\n%s", got)
	}
	if strings.Contains(got, "endpoint 2001:db8::1:443") {
		t.Errorf("unbracketed IPv6 endpoint is ambiguous and mis-parsed:\n%s", got)
	}
}

func TestWireguardCommands_Errors(t *testing.T) {
	if _, err := WireguardCommands(model.Endpoint{ID: "x", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS}, WireguardOpts{}); err == nil {
		t.Error("non-WG endpoint must error")
	}
	if _, err := WireguardCommands(model.Endpoint{ID: "x", Engine: model.EngineAmneziaWG, Server: "1.1.1.1", Port: 1}, WireguardOpts{}); err == nil {
		t.Error("missing keys must error")
	}
}

func TestCidrToAddrMask(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0/0":     "0.0.0.0 0.0.0.0",
		"10.0.0.0/24":   "10.0.0.0 255.255.255.0",
		"10.0.1.10/32":  "10.0.1.10 255.255.255.255",
		"10.0.1.10":     "10.0.1.10 255.255.255.255", // bare → /32
		"2001:db8::/32": "2001:db8:: 32",
		"::/0":          ":: 0",
	}
	for in, want := range cases {
		got, err := cidrToAddrMask(in)
		if err != nil || got != want {
			t.Errorf("cidrToAddrMask(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := cidrToAddrMask("not-an-ip"); err == nil {
		t.Error("bad cidr must error")
	}
}

func idx(ss []string, prefix string) int {
	for i, s := range ss {
		if strings.HasPrefix(strings.TrimSpace(s), prefix) {
			return i
		}
	}
	return -1
}

// TestWireguardCommands_BareV6AllowIPs: a BARE (non-CIDR) IPv6 local_address — the form a Clash
// import stores from the ipv6 field — must still emit `allow-ips :: 0`, so the native peer carries
// IPv6. Detecting v6 with ParsePrefix alone (which rejects a bare IP) dropped ::/0, leaking the
// tunnel's v6 traffic to the WAN. A dual-stack (v4 CIDR + bare v6) endpoint must emit BOTH allow-ips.
func TestWireguardCommands_BareV6AllowIPs(t *testing.T) {
	key := "AAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	e := model.Endpoint{
		ID: "v6", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard, Server: "1.1.1.1", Port: 51820,
		Params: map[string]any{
			"private_key":     key,
			"peer_public_key": key,
			"local_address":   []string{"10.0.0.2/32", "fd00::2"}, // bare v6, no /prefix (Clash form)
		},
	}
	cmds, err := WireguardCommands(e, WireguardOpts{Index: 2})
	if err != nil {
		t.Fatalf("WireguardCommands: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "allow-ips 0.0.0.0 0.0.0.0") {
		t.Errorf("v4 allow-ips missing:\n%s", joined)
	}
	if !strings.Contains(joined, "allow-ips :: 0") {
		t.Errorf("a bare IPv6 local_address must still emit `allow-ips :: 0` (else v6 leaks to WAN):\n%s", joined)
	}
	// The bare v6 address is also configured on the interface (synthesized /128).
	if !strings.Contains(joined, "ip address fd00::2 128") {
		t.Errorf("bare v6 interface address must be emitted as /128:\n%s", joined)
	}
}

// AWGGeneration is what `wireguard asc` carries, not a label: every setting of that generation or
// older lands in its positional slot, and every newer one is refused by name rather than left out.
func TestAWGGenerationIsWhatAscWrites(t *testing.T) {
	slots := append(append([]string{}, ascBase...), ascExt...)
	for _, key := range awg.Settings() {
		value := any("77")
		if key == "random_trailers" || key == "disable_cookies" {
			value = "on"
		}
		e := awgEndpoint()
		e.Protocol = model.ProtoAmneziaWG
		e.Params[key] = value
		cmds, err := WireguardCommands(e, WireguardOpts{Index: 3})
		need := awg.Need(map[string]any{key: value})
		if need > AWGGeneration {
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s (generation %v) was not refused by name: %v", key, need, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (generation %v) was refused: %v", key, need, err)
			continue
		}
		var args []string
		for _, c := range cmds {
			if rest, ok := strings.CutPrefix(c, "wireguard asc "); ok {
				args = strings.Fields(rest)
			}
		}
		slot := -1
		for i, k := range slots {
			if k == key {
				slot = i
			}
		}
		if slot < 0 || slot >= len(args) || args[slot] != "77" {
			t.Errorf("%s (generation %v) is not in its asc slot %d: %v", key, need, slot, args)
		}
	}
}
