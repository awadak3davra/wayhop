package netvpn

import (
	"strings"
	"testing"
)

// The fixture is the awg0 interface as it actually exists on the AX3000T (OpenWrt 25.12.2,
// luci-proto-amneziawg), keys replaced. If the renderer cannot reproduce the shape of a tunnel the
// router is already running, it cannot be trusted to create one.
func liveShapedIface() AWGInterface {
	return AWGInterface{
		Name:       "awg0",
		PrivateKey: "PRIVATE",
		Addresses:  []string{"10.0.0.30/32"},
		MTU:        1280,
		Obfuscation: map[string]string{
			"jc": "5", "jmin": "49", "jmax": "998",
			"s1": "17", "s2": "110", "s3": "25", "s4": "40",
			"h1": "500000000-900000000", "h2": "1000000000-1400000000",
			"h3": "1500000000-1900000000", "h4": "2000000000-2400000000",
			"i1": "0x11111111111111111111111111111111",
			"i5": "0x55555555555555555555555555555555",
		},
		Peers: []AWGPeer{{
			Description:         "WG_A_v2",
			PublicKey:           "PUBKEY",
			PresharedKey:        "PSK",
			EndpointHost:        "203.0.113.10",
			EndpointPort:        8443,
			PersistentKeepalive: 21,
			AllowedIPs:          []string{"10.0.0.0/24", "0.0.0.0/0"},
		}},
	}
}

func joined(cmds []string) string { return strings.Join(cmds, "\n") }

func TestRenderUCI_MatchesTheSchemaTheRouterActuallyUses(t *testing.T) {
	got := joined(RenderUCI(liveShapedIface()))

	// Option names are not guesses — each of these appears verbatim in /etc/config/network on the
	// device. A renderer that invents a plausible-but-wrong name produces a section LuCI will show
	// and netifd will ignore, which is worse than an error.
	must := []string{
		"uci set network.awg0=interface",
		"uci set network.awg0.proto='amneziawg'",
		"uci set network.awg0.mtu='1280'",
		"uci add_list network.awg0.addresses='10.0.0.30/32'",
		"uci set network.awg0.awg_jc='5'",
		"uci set network.awg0.awg_s3='25'",                                 // 2.x/3.x
		"uci set network.awg0.awg_i1='0x11111111111111111111111111111111'", // 3.x hex header
		"uci set network.awg0_peer1=amneziawg_awg0",                        // section TYPE per iface
		"uci set network.awg0_peer1.endpoint_host='203.0.113.10'",
		"uci set network.awg0_peer1.endpoint_port='8443'",
		"uci set network.awg0_peer1.persistent_keepalive='21'",
		"uci add_list network.awg0_peer1.allowed_ips='0.0.0.0/0'",
	}
	for _, m := range must {
		if !strings.Contains(got, m) {
			t.Errorf("plan is missing:\n  %s\ngot:\n%s", m, got)
		}
	}
}

// The single most consequential line in the plan. With route_allowed_ips on, netifd installs a route
// for every allowed-IP, and a full-tunnel peer therefore installs a default route — putting netifd in
// charge of the route table that WayHop's PBR already owns. The failure is silent: traffic leaves by
// the wrong exit and everything still "works".
func TestRenderUCI_NeverLetsNetifdOwnTheRoutes(t *testing.T) {
	got := joined(RenderUCI(liveShapedIface()))
	if !strings.Contains(got, "uci set network.awg0_peer1.route_allowed_ips='0'") {
		t.Fatalf("route_allowed_ips is not forced to 0; netifd would install a default route:\n%s", got)
	}
	if strings.Contains(got, "route_allowed_ips='1'") {
		t.Fatalf("route_allowed_ips is enabled somewhere in the plan:\n%s", got)
	}
}

// Re-applying an unchanged tunnel must leave the same configuration, not one with its lists doubled.
// uci add_list appends, so every list has to be cleared first — and the delete has to be quiet, or
// the very first create aborts the batch on an option that was never there.
func TestRenderUCI_IsIdempotent(t *testing.T) {
	// Re-applying over an interface that ALREADY exists is the scenario the clearing is for. Asking
	// the create-from-nothing path for it would be asking for a `uci -q delete` against an option
	// that is not there — which the router rejects with exit 1, as the first live write discovered.
	cur := liveShapedIface()
	got := joined(RenderUCIFrom(liveShapedIface(), &cur))
	for _, opt := range []string{"network.awg0.addresses", "network.awg0_peer1.allowed_ips"} {
		del := "uci -q delete " + opt
		if !strings.Contains(got, del) {
			t.Errorf("list %s is never cleared, so a second apply would append to it", opt)
		}
		if i, j := strings.Index(got, del), strings.Index(got, "uci add_list "+opt); i < 0 || j < 0 || i > j {
			t.Errorf("%s is cleared after it is filled, which empties what was just written", opt)
		}
	}
}

// A description or key carrying a single quote must not be able to end the quoting and have the rest
// read as further shell words. This is the one place in the plan where operator-supplied text meets a
// shell.
func TestRenderUCI_QuotesHostileValues(t *testing.T) {
	iface := liveShapedIface()
	payload := "it's fine'; uci set network.wan.proto='none"
	iface.Peers[0].Description = payload

	var line string
	for _, c := range RenderUCI(iface) {
		if strings.HasPrefix(c, "uci set network.awg0_peer1.description=") {
			line = c
		}
	}
	if line == "" {
		t.Fatal("no description command was rendered, so nothing was tested")
	}
	val := strings.TrimPrefix(line, "uci set network.awg0_peer1.description=")

	// The first cut of this asserted that the plan does not CONTAIN "uci set network.wan.proto=".
	// That was the wrong property and the test failed on correct output: the payload is legitimately
	// present as DATA inside the quoted value. What matters is whether a shell would read it as data
	// or as a second command — so parse it back the way a shell does and compare.
	if got := shellUnquote(t, val); got != payload {
		t.Fatalf("the value does not round-trip through shell single-quoting:\n  want %q\n  got  %q\n  raw  %s",
			payload, got, val)
	}
}

// shellUnquote reverses one POSIX single-quoted word: the text is literal between quotes, and a
// quote itself arrives as the four characters '\” — close, escaped quote, reopen. Anything else at
// the top level means the value was not a single quoted word, which is the failure being hunted.
func shellUnquote(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	if !strings.HasPrefix(s, "'") {
		t.Fatalf("value is not single-quoted: %s", s)
	}
	i := 0
	for i < len(s) {
		if s[i] != '\'' {
			t.Fatalf("value has text outside quoting at offset %d — a shell would read it as another word: %s", i, s)
		}
		i++ // opening quote
		for i < len(s) && s[i] != '\'' {
			b.WriteByte(s[i])
			i++
		}
		if i >= len(s) {
			t.Fatalf("unterminated quote: %s", s)
		}
		i++ // closing quote
		// The escape is the two characters \' — a quote outside quoting. The REOPENING quote that
		// follows belongs to the next iteration, so only two are consumed here. Taking three
		// swallowed that reopening quote and left the loop staring at content, which is what made
		// this helper reject correct output.
		if strings.HasPrefix(s[i:], `\'`) {
			b.WriteByte('\'')
			i += 2
		}
	}
	return b.String()
}

// Removal has to take the peers with it. An orphaned amneziawg_awg0 section pointing at an interface
// that no longer exists is exactly the mess that makes people distrust a tool writing their config.
func TestRemoveUCI_TakesPeersToo(t *testing.T) {
	got := joined(RemoveUCI("awg0", 2))
	for _, m := range []string{
		"uci -q delete network.awg0_peer1",
		"uci -q delete network.awg0_peer2",
		"uci -q delete network.awg0",
	} {
		if !strings.Contains(got, m) {
			t.Errorf("removal is missing %q:\n%s", m, got)
		}
	}
}

// The plan must never contain the commit or the reload: a preview that applies itself is not a
// preview, and the operator asked to see the commands before anything is written.
func TestRenderUCI_PlanDoesNotApplyItself(t *testing.T) {
	got := joined(RenderUCI(liveShapedIface()))
	for _, forbidden := range []string{"uci commit", "/etc/init.d/network", "reload", "restart"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("the plan contains a device-mutating command (%q):\n%s", forbidden, got)
		}
	}
	if c := joined(CommitCmds()); !strings.Contains(c, "uci commit network") ||
		!strings.Contains(c, "reload") {
		t.Fatalf("CommitCmds should carry exactly the mutating tail, got: %s", c)
	}
	if strings.Contains(joined(CommitCmds()), "restart") {
		t.Fatal("network restart drops the session that requested it; reload is the safe verb")
	}
}

// The conditional that the router taught us, and that nothing was checking. RenderUCIFrom clears a
// list option before rebuilding it, because add_list appends — but `uci -q delete` on an option that
// is not there exits 1, and a batch aborts. The first real write to the AX3000T died seven commands
// in on exactly that and the applier reverted a half-written interface.
//
// Both directions matter. Emitting the delete unconditionally breaks every FIRST write; omitting it
// when the option does exist makes a re-apply double the list. A mutation sweep found neither covered.
func TestRenderUCIFrom_ClearsAListOnlyWhenThereIsOneToClear(t *testing.T) {
	iface := AWGInterface{
		Name:       "awg9",
		PrivateKey: "cHJpdmF0ZQ==",
		Addresses:  []string{"10.0.0.2/32"},
		Peers:      []AWGPeer{{PublicKey: "cHVibGlj", AllowedIPs: []string{"0.0.0.0/0"}}},
	}

	fresh := strings.Join(RenderUCI(iface), "\n")
	if strings.Contains(fresh, "uci -q delete network.awg9.addresses") {
		t.Error("a brand-new interface is told to delete an addresses list that does not exist; " +
			"`uci -q delete` exits 1 there and takes the rest of the batch with it")
	}
	if strings.Contains(fresh, "delete network.awg9_peer1.allowed_ips") {
		t.Error("a brand-new peer is told to delete an allowed_ips list that does not exist")
	}

	existing := AWGInterface{
		Name:      "awg9",
		Addresses: []string{"10.0.0.9/32"},
		Peers:     []AWGPeer{{PublicKey: "b2xk", AllowedIPs: []string{"10.9.0.0/24"}}},
	}
	update := strings.Join(RenderUCIFrom(iface, &existing), "\n")
	if !strings.Contains(update, "uci -q delete network.awg9.addresses") {
		t.Error("an existing addresses list is not cleared before being rebuilt, so add_list appends " +
			"to it and a re-apply lists every address twice")
	}
	if !strings.Contains(update, "delete network.awg9_peer1.allowed_ips") {
		t.Error("an existing allowed_ips list is not cleared before being rebuilt")
	}
}

// `disabled` is written on EVERY apply, for every peer, whatever its value. uci set does not remove
// options it was not told about, so a peer switched off in LuCI stays off after a write that meant
// it on — and the post-write comparison reports a perfect match, because it is telling the truth
// about every field it looks at. Nothing was asserting the option is emitted at all.
func TestRenderUCI_WritesDisabledForEveryPeerEitherWay(t *testing.T) {
	iface := AWGInterface{
		Name:       "awg9",
		PrivateKey: "cHJpdmF0ZQ==",
		Peers: []AWGPeer{
			{PublicKey: "b25l", AllowedIPs: []string{"0.0.0.0/0"}},
			{PublicKey: "dHdv", AllowedIPs: []string{"10.0.0.0/8"}, Disabled: true},
		},
	}
	cmds := strings.Join(RenderUCI(iface), "\n")

	if !strings.Contains(cmds, "uci set network.awg9_peer1.disabled='0'") {
		t.Error("an ENABLED peer gets no disabled option, so a peer previously switched off in LuCI " +
			"would silently stay off:\n" + cmds)
	}
	if !strings.Contains(cmds, "uci set network.awg9_peer2.disabled='1'") {
		t.Error("a disabled peer is not written as disabled:\n" + cmds)
	}
	if n := strings.Count(cmds, ".disabled="); n != len(iface.Peers) {
		t.Errorf("disabled was written %d time(s) for %d peers; it belongs on every one", n, len(iface.Peers))
	}
}
