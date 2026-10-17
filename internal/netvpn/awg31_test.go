package netvpn

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"sort"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/model"
)

// hpk is a header protection key whose bytes spell '+' and '/' in standard base64, so the URL-safe
// form a config may carry differs from the form amneziawg-tools reads.
var hpk = bytes.Repeat([]byte{0xfb}, 32)

var (
	hpkStd = base64.StdEncoding.EncodeToString(hpk)    // what `awg setconf` reads
	hpkURL = base64.RawURLEncoding.EncodeToString(hpk) // what the config carries here
)

// awg31Endpoint is an AmneziaWG 3.1 connection in the shapes the model stores values in: strings from
// an import, a float64 from a JSON round trip, an int64 and an int from code, and a JSON bool.
func awg31Endpoint() model.Endpoint {
	return model.Endpoint{
		ID: "ep-awg31", Name: "awg31", Enabled: true,
		Protocol: model.ProtoAmneziaWG, Engine: model.EngineAmneziaWG,
		Server: "198.51.100.7", Port: 51820, PersistentKeepalive: 25, MTU: 1280,
		Params: map[string]any{
			"private_key": "PRIV", "peer_public_key": "PUB",
			"local_address": []string{"10.7.0.2/32"}, "allowed_ips": []string{"0.0.0.0/0"},
			"jc": 4, "jmin": 40, "jmax": 70, "s1": 16, "s2": 24, "s3": 32, "s4": 12,
			"h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800", "i1": "<r 8>",
			"header_protection_key":    hpkURL,
			"content_padding_addition": "10-20",
			"rekey_after_time":         float64(120),
			"rekey_timeout":            "5",
			"reject_after_time":        int64(180),
			"keepalive_timeout":        "10-15",
			"max_handshake_attempts":   3,
			"random_trailers":          true,
			"disable_cookies":          "off",
		},
	}
}

// awg31Golden is the whole plan for awg31Endpoint on a router whose module is generation 3.1. Every
// option name is one the amneziawg netifd handler reads (proto_amneziawg_init_config); the handler
// writes a `Key=value` line for each non-empty one and RandomTrailers=on for the switch.
func awg31Golden() []string {
	return []string{
		"uci set network.awg31=interface",
		"uci set network.awg31.proto='amneziawg'",
		"uci set network.awg31.private_key='PRIV'",
		"uci add_list network.awg31.addresses='10.7.0.2/32'",
		"uci set network.awg31.mtu='1280'",
		"uci set network.awg31.awg_content_padding_addition='10-20'",
		"uci set network.awg31.awg_h1='100-200'",
		"uci set network.awg31.awg_h2='300-400'",
		"uci set network.awg31.awg_h3='500-600'",
		"uci set network.awg31.awg_h4='700-800'",
		"uci set network.awg31.awg_header_protection_key='" + hpkStd + "'",
		"uci set network.awg31.awg_i1='<r 8>'",
		"uci set network.awg31.awg_jc='4'",
		"uci set network.awg31.awg_jmax='70'",
		"uci set network.awg31.awg_jmin='40'",
		"uci set network.awg31.awg_keepalive_timeout='10-15'",
		"uci set network.awg31.awg_max_handshake_attempts='3'",
		"uci set network.awg31.awg_random_trailers='1'",
		"uci set network.awg31.awg_reject_after_time='180'",
		"uci set network.awg31.awg_rekey_after_time='120'",
		"uci set network.awg31.awg_rekey_timeout='5'",
		"uci set network.awg31.awg_s1='16'",
		"uci set network.awg31.awg_s2='24'",
		"uci set network.awg31.awg_s3='32'",
		"uci set network.awg31.awg_s4='12'",
		"uci set network.awg31_peer1=amneziawg_awg31",
		"uci set network.awg31_peer1.public_key='PUB'",
		"uci set network.awg31_peer1.endpoint_host='198.51.100.7'",
		"uci set network.awg31_peer1.endpoint_port='51820'",
		"uci set network.awg31_peer1.persistent_keepalive='25'",
		"uci set network.awg31_peer1.route_allowed_ips='0'",
		"uci set network.awg31_peer1.disabled='0'",
		"uci add_list network.awg31_peer1.allowed_ips='0.0.0.0/0'",
	}
}

func without(cmds []string, drop ...string) []string {
	var out []string
	for _, c := range cmds {
		keep := true
		for _, d := range drop {
			if strings.Contains(c, d) {
				keep = false
			}
		}
		if keep {
			out = append(out, c)
		}
	}
	return out
}

func renderFor(t *testing.T, e model.Endpoint, kernel awg.Generation) ([]string, error) {
	t.Helper()
	iface, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, kernel)
	if err != nil {
		return nil, err
	}
	return RenderUCI(iface), nil
}

func diffLines(t *testing.T, got, want []string) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	t.Errorf("plan differs from the golden one\n got:\n  %s\nwant:\n  %s",
		strings.Join(got, "\n  "), strings.Join(want, "\n  "))
}

// The golden plans per kernel module generation: 3.1 writes every option; 3.0 refuses the 3.1 switch
// by name and writes the rest; 2 refuses every 3.x setting by name, as it did before it looked at the
// module.
func TestRenderUCI_GoldenPerKernelGeneration(t *testing.T) {
	got, err := renderFor(t, awg31Endpoint(), awg.Gen31)
	if err != nil {
		t.Fatal(err)
	}
	diffLines(t, got, awg31Golden())

	_, err = renderFor(t, awg31Endpoint(), awg.Gen30)
	if err == nil || !strings.Contains(err.Error(), "(random_trailers)") ||
		!strings.Contains(err.Error(), "generation 3.0 here") {
		t.Errorf("3.0 module: %v, want random_trailers refused by name", err)
	}
	for _, kernel := range []awg.Generation{awg.GenNone, awg.Gen1, awg.Gen2} {
		_, err := renderFor(t, awg31Endpoint(), kernel)
		if err == nil || !strings.Contains(err.Error(),
			"content_padding_addition, header_protection_key, keepalive_timeout, max_handshake_attempts, "+
				"random_trailers, reject_after_time, rekey_after_time, rekey_timeout") {
			t.Errorf("%v module: %v, want every 3.x setting refused by name", kernel, err)
		}
	}

	// The same connection with its switch off is a 3.0 connection: the 3.0 and 3.1 modules get the
	// same plan, and an off switch is never written.
	off := awg31Endpoint()
	off.Params["random_trailers"] = false
	want := without(awg31Golden(), "awg_random_trailers")
	for _, kernel := range []awg.Generation{awg.Gen30, awg.Gen31} {
		got, err := renderFor(t, off, kernel)
		if err != nil {
			t.Fatalf("%v module: %v", kernel, err)
		}
		diffLines(t, got, want)
	}
}

// A connection of generation 2 or older gets the same plan on every module, with its switches spelled
// out as off: a router whose module reaches 3.1 rewrites nothing and restarts nothing.
func TestRenderUCI_Generation2PlanIsTheSameOnEveryModule(t *testing.T) {
	e := awg31Endpoint()
	for _, key := range awgKeys30 {
		delete(e.Params, key)
	}
	e.Params["random_trailers"] = "off"
	e.Params["disable_cookies"] = false
	want := without(awg31Golden(), "awg_content_padding", "awg_header_protection", "awg_keepalive_timeout",
		"awg_max_handshake", "awg_random_trailers", "awg_reject_after", "awg_rekey_")
	for _, kernel := range []awg.Generation{awg.GenNone, awg.Gen1, awg.Gen2, awg.Gen30, awg.Gen31} {
		got, err := renderFor(t, e, kernel)
		if err != nil {
			t.Fatalf("%v module: %v", kernel, err)
		}
		diffLines(t, got, want)
	}
}

func TestAWGWriterGeneration(t *testing.T) {
	for kernel, want := range map[awg.Generation]awg.Generation{
		awg.GenNone: awg.Gen2, awg.Gen1: awg.Gen2, awg.Gen2: awg.Gen2,
		awg.Gen30: awg.Gen30, awg.Gen31: awg.Gen31, awg.Gen31 + 1: awg.Gen31,
	} {
		if got := AWGWriterGeneration(kernel); got != want {
			t.Errorf("AWGWriterGeneration(%v) = %v, want %v", kernel, got, want)
		}
	}
}

// The writer's key lists are awg's table, split by generation: every setting Need knows is written by
// exactly one of them, under the generation that introduced it.
func TestWriterKeysAreTheSettingsTable(t *testing.T) {
	var all []string
	for _, key := range awgObfuscationKeys {
		if g := awg.Introduced(key); g > AWGGeneration {
			t.Errorf("%s is generation %v, above the baseline list's %v", key, g, AWGGeneration)
		}
		all = append(all, key)
	}
	for _, key := range awgKeys30 {
		if awg.Introduced(key) != awg.Gen30 {
			t.Errorf("%s is listed as 3.0 and introduced in %v", key, awg.Introduced(key))
		}
		all = append(all, key)
	}
	for _, key := range awgSwitches31 {
		if awg.Introduced(key) != awg.Gen31 {
			t.Errorf("%s is listed as 3.1 and introduced in %v", key, awg.Introduced(key))
		}
		all = append(all, key)
	}
	sort.Strings(all)
	if !reflect.DeepEqual(all, awg.Settings()) {
		t.Errorf("the writer's keys %v are not the settings Need knows %v", all, awg.Settings())
	}
}

// Every setting reaches the interface up to the generation the module carries, and every newer one is
// refused by name, on every module generation.
func TestWriterWritesUpToTheModulesGeneration(t *testing.T) {
	for _, kernel := range []awg.Generation{awg.GenNone, awg.Gen1, awg.Gen2, awg.Gen30, awg.Gen31} {
		gen := AWGWriterGeneration(kernel)
		for _, key := range awg.Settings() {
			value, written := any("7"), "7"
			switch key {
			case "random_trailers", "disable_cookies":
				value, written = "on", "1"
			case "header_protection_key":
				value, written = hpkURL, hpkStd
			}
			e := nativeModelEndpoint()
			for _, s := range []string{"s1", "s2", "s3", "s4"} {
				e.Params[s] = 12
			}
			e.Params[key] = value
			got, err := InterfaceFromEndpointFor(e, InterfaceName(e), ProtoAmneziaWG, kernel)
			need := awg.Need(map[string]any{key: value})
			switch {
			case need > gen:
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Errorf("module %v: %s (generation %v) was not refused by name: %v", kernel, key, need, err)
				}
			case err != nil:
				t.Errorf("module %v: %s (generation %v) was refused: %v", kernel, key, need, err)
			case got.Obfuscation[key] != written:
				t.Errorf("module %v: %s (generation %v) = %q, want %q", kernel, key, need, got.Obfuscation[key], written)
			}
		}
	}
}

// Ranges go out as written once they read as 16-bit "n" or "lo-hi"; anything the tools would refuse,
// or would truncate to 16 bits without a word, is refused by name.
func TestWriterChecksAWG30Ranges(t *testing.T) {
	for value, want := range map[any]string{
		"100-200": "100-200", " 7 ": "7", "65535": "65535", float64(30): "30", int64(9): "9", "0-0": "0-0",
	} {
		e := awg31Endpoint()
		e.Params["rekey_timeout"] = value
		iface, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31)
		if err != nil || iface.Obfuscation["rekey_timeout"] != want {
			t.Errorf("rekey_timeout %#v: %q, %v; want %q", value, iface.Obfuscation["rekey_timeout"], err, want)
		}
	}
	for _, value := range []any{"70000", "200-100", "1-70000", "abc", "1-", "-1", "1.5", float64(-1)} {
		e := awg31Endpoint()
		e.Params["keepalive_timeout"] = value
		if _, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31); err == nil ||
			!strings.Contains(err.Error(), "keepalive_timeout") {
			t.Errorf("keepalive_timeout %#v: %v, want refused by name", value, err)
		}
	}
}

// The header protection key goes out in the spelling the tools read, and only with every padding able
// to hold its nonce - which the module otherwise refuses for the whole interface.
func TestWriterChecksTheHeaderProtectionKey(t *testing.T) {
	for _, value := range []string{hpkStd, hpkURL, base64.RawStdEncoding.EncodeToString(hpk), base64.URLEncoding.EncodeToString(hpk)} {
		e := awg31Endpoint()
		e.Params["header_protection_key"] = value
		iface, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31)
		if err != nil || iface.Obfuscation["header_protection_key"] != hpkStd {
			t.Errorf("key %q: %q, %v; want %q", value, iface.Obfuscation["header_protection_key"], err, hpkStd)
		}
	}
	for name, mutate := range map[string]func(p map[string]any){
		"not a key":     func(p map[string]any) { p["header_protection_key"] = "k" },
		"16 bytes":      func(p map[string]any) { p["header_protection_key"] = base64.StdEncoding.EncodeToString(hpk[:16]) },
		"S4 below 12":   func(p map[string]any) { p["s4"] = 11 },
		"S2 not set":    func(p map[string]any) { delete(p, "s2") },
		"S3 not a size": func(p map[string]any) { p["s3"] = "big" },
	} {
		e := awg31Endpoint()
		mutate(e.Params)
		if _, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31); err == nil ||
			!strings.Contains(err.Error(), "header_protection_key") {
			t.Errorf("%s: %v, want the key refused", name, err)
		}
	}
}

// A switch is '1' when on in any shape the model stores it, absent when off or empty, and refused when
// it reads as neither - as `awg setconf` refuses it.
func TestWriterEncodesTheAWG31Switches(t *testing.T) {
	for _, on := range []any{true, "on", "ON", "1", "true", float64(1), 2} {
		e := awg31Endpoint()
		e.Params["disable_cookies"] = on
		iface, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31)
		if err != nil || iface.Obfuscation["disable_cookies"] != "1" {
			t.Errorf("disable_cookies %#v: %q, %v; want '1'", on, iface.Obfuscation["disable_cookies"], err)
		}
	}
	for _, off := range []any{false, "off", "0", "", "  ", float64(0), nil} {
		e := awg31Endpoint()
		e.Params["disable_cookies"] = off
		iface, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31)
		if _, written := iface.Obfuscation["disable_cookies"]; err != nil || written {
			t.Errorf("disable_cookies %#v: %v, %v; want nothing written", off, iface.Obfuscation, err)
		}
	}
	for _, bad := range []any{"maybe", []any{"on"}} {
		e := awg31Endpoint()
		e.Params["disable_cookies"] = bad
		if _, err := InterfaceFromEndpointFor(e, "awg31", ProtoAmneziaWG, awg.Gen31); err == nil ||
			!strings.Contains(err.Error(), "disable_cookies") {
			t.Errorf("disable_cookies %#v: %v, want refused by name", bad, err)
		}
	}
}

// What the writer stages reads back as what it intended, 3.x options included: the post-write check
// passes on a correct write, so it can only fail on a wrong one.
func TestPlan_AWG31RoundTripsThroughUCIShow(t *testing.T) {
	iface, err := InterfaceFromEndpointFor(awg31Endpoint(), "awg31", ProtoAmneziaWG, awg.Gen31)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlanFor(iface, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.VerifyAgainst(afterWrite(p)); len(d) != 0 {
		t.Fatalf("a 3.1 interface did not read back as written: %v", d)
	}
	if got := ParseUCIShow(afterWrite(p))["awg31"].Obfuscation; got["random_trailers"] != "1" ||
		got["header_protection_key"] != hpkStd || got["rekey_after_time"] != "120" {
		t.Errorf("read back: %v", got)
	}
}

// After the module reaches 3.1, an unchanged generation-2 connection intends exactly what the router
// already has; a 3.1 switch turned off is deleted by name, with a warning, because `uci set` never
// removes an option.
func TestPlan_ModuleUpgradeAndSwitchOff(t *testing.T) {
	gen2 := awg31Endpoint()
	for _, key := range append(append([]string{}, awgKeys30...), awgSwitches31...) {
		delete(gen2.Params, key)
	}
	before, err := InterfaceFromEndpointFor(gen2, "awg31", ProtoAmneziaWG, awg.Gen2)
	if err != nil {
		t.Fatal(err)
	}
	was, err := BuildPlanFor(before, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatal(err)
	}
	device := afterWrite(was)
	after, err := InterfaceFromEndpointFor(gen2, "awg31", ProtoAmneziaWG, awg.Gen31)
	if err != nil {
		t.Fatal(err)
	}
	upgraded, err := BuildPlanFor(after, testRouterProtos, "vpn", device, liveFirewallShow)
	if err != nil {
		t.Fatal(err)
	}
	if d := DiffInterface(upgraded.Intended, upgraded.Expected); len(d) != 0 {
		t.Errorf("the upgrade changes a generation-2 connection: %v", d)
	}

	on, err := InterfaceFromEndpointFor(awg31Endpoint(), "awg31", ProtoAmneziaWG, awg.Gen31)
	if err != nil {
		t.Fatal(err)
	}
	created, err := BuildPlanFor(on, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatal(err)
	}
	offEndpoint := awg31Endpoint()
	offEndpoint.Params["random_trailers"] = "off"
	off, err := InterfaceFromEndpointFor(offEndpoint, "awg31", ProtoAmneziaWG, awg.Gen31)
	if err != nil {
		t.Fatal(err)
	}
	switched, err := BuildPlanFor(off, testRouterProtos, "vpn", afterWrite(created), liveFirewallShow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(joined(switched.Commands), "uci -q delete network.awg31.awg_random_trailers") ||
		!strings.Contains(strings.Join(switched.Warnings, "\n"), "awg_random_trailers is set on the router") {
		t.Errorf("switching RandomTrailers off does not remove it:\n%s\nwarnings: %v", joined(switched.Commands), switched.Warnings)
	}
}

// The handler is read for the options it names: one that predates 3.0 caps the writer at 2, one
// that names the 3.0 options and not the switches at 3.0. The excerpt follows the community handler's
// own declarations.
func TestHandlerAWGGeneration(t *testing.T) {
	var gen2, gen30, gen31 strings.Builder
	for _, key := range awgObfuscationKeys {
		gen2.WriteString("\tproto_config_add_string \"awg_" + key + "\"\n")
	}
	gen30.WriteString(gen2.String())
	for _, key := range awgKeys30 {
		gen30.WriteString("\tproto_config_add_string \"awg_" + key + "\"\n")
	}
	gen31.WriteString(gen30.String())
	for _, key := range awgSwitches31 {
		gen31.WriteString("\tproto_config_add_boolean \"awg_" + key + "\"\n")
	}
	partial := strings.Replace(gen30.String(), "awg_max_handshake_attempts", "awg_max_attempts", 1)
	for script, want := range map[string]awg.Generation{
		"": awg.Gen2, gen2.String(): awg.Gen2, partial: awg.Gen2, gen30.String(): awg.Gen30, gen31.String(): awg.Gen31,
	} {
		if got := HandlerAWGGeneration(script); got != want {
			t.Errorf("HandlerAWGGeneration(%d bytes) = %v, want %v", len(script), got, want)
		}
	}
	// A 3.1 module behind a pre-3.0 handler writes generation 2: min(module, handler).
	if got := AWGWriterGeneration(min(awg.Gen31, HandlerAWGGeneration(gen2.String()))); got != awg.Gen2 {
		t.Errorf("a pre-3.0 handler let the writer reach %v", got)
	}
}

// The header protection key is a shared secret: a difference in it is reported, never echoed.
func TestDiffInterface_RedactsTheHeaderProtectionKey(t *testing.T) {
	want := AWGInterface{Name: "awg31", Obfuscation: map[string]string{"header_protection_key": hpkStd}}
	got := AWGInterface{Name: "awg31", Obfuscation: map[string]string{"header_protection_key": strings.Repeat("A", 43) + "="}}
	d := DiffInterface(want, got)
	if len(d) != 1 || d[0].Field != "awg_header_protection_key" {
		t.Fatalf("diff = %v, want one difference on the key", d)
	}
	if strings.Contains(d[0].String(), hpkStd) || strings.Contains(d[0].String(), "AAAA") ||
		d[0].Want != "(present, 44 chars)" {
		t.Errorf("the key leaked into the report: %s", d[0])
	}
	if d := DiffInterface(want, want); len(d) != 0 {
		t.Errorf("equal keys differ: %v", d)
	}
}
