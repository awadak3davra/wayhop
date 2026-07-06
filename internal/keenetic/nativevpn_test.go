package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// awgEndpoint mirrors the live Wireguard0 (ND_VPS) on the Hopper SE: AmneziaWG 1.x params.
func awgEndpoint() model.Endpoint {
	return model.Endpoint{
		ID: "nd_vps", Name: "ND_VPS", Engine: model.EngineAmneziaWG, Server: "203.0.113.10", Port: 443,
		Enabled: true,
		Params: map[string]any{
			"private_key": "PRIVKEYbase64==", "peer_public_key": "4D7mmd1+wm1m9dFeno1lLHVHaweYiLP73hHNHt877hE=",
			"jc": 5, "jmin": 49, "jmax": 998, "s1": 17, "s2": 110,
			"h1": 1149587024, "h2": 361067711, "h3": 2146576297, "h4": 1053221975,
			"local_address": []string{"10.8.1.10/32"}, "mtu": 1420, "persistent_keepalive": 21,
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
		"description ND_VPS",
		"security-level public",
		"ip address 10.8.1.10 255.255.255.255", // /32 → dotted mask
		"ip mtu 1420",
		"ip global 32764",
		"ip tcp adjust-mss pmtu",
		"wireguard private-key PRIVKEYbase64==",
		"wireguard asc 5 49 998 17 110 1149587024 361067711 2146576297 1053221975", // exact live 9-arg form
		"wireguard peer 4D7mmd1+wm1m9dFeno1lLHVHaweYiLP73hHNHt877hE=",
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
	if !strings.Contains(got, "wireguard asc 5 49 998 17 110 1149587024 361067711 2146576297 1053221975 25 40 0x11 0x22 0x33 0x44 0x55") {
		t.Errorf("AWG 2.0 extended asc wrong:\n%s", got)
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
		"10.8.1.10/32":  "10.8.1.10 255.255.255.255",
		"10.8.1.10":     "10.8.1.10 255.255.255.255", // bare → /32
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
