package generator

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Every refusal names what to fix, and none lets a half-understood override through: these reach
// the operator as the reason a Settings save was refused.
func TestParseCoreOverride_Refuses(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"not json", `{"log":`, "not valid JSON"},
		{"array", `[{"log":{}}]`, "must be a JSON object"},
		{"string", `"log"`, "must be a JSON object"},
		{"null", `null`, "must be a JSON object"},
		{"trailing text", `{"log":{}} {"dns":{}}`, "text after its JSON object"},
		{"too big", `{"x":"` + strings.Repeat("a", CoreOverrideMaxBytes) + `"}`, "the limit is"},
		{"prepend not object", `{"prepend":[{"tag":"x"}]}`, "prepend must be an object"},
		{"prepend inbounds", `{"prepend":{"inbounds":[{"type":"mixed"}]}}`, `prepend "inbounds" is not supported`},
		{"prepend rule_set", `{"prepend":{"route.rule_set":[{"tag":"x"}]}}`, `prepend "route.rule_set" is not supported`},
		{"prepend not array", `{"prepend":{"route.rules":{"outbound":"direct"}}}`, `prepend "route.rules" must be an array`},
		{"prepend item not object", `{"prepend":{"outbounds":["direct"]}}`, `prepend "outbounds" item 1 must be a JSON object`},
		{"patch replaces the array", `{"route":{"rules":[]},"prepend":{"route.rules":[{"outbound":"direct"}]}}`, "merge patch also sets route.rules"},
		{"patch deletes the parent", `{"dns":null,"prepend":{"dns.servers":[{"tag":"x","type":"local"}]}}`, "merge patch also sets dns"},
		{"patch replaces the parent", `{"route":"x","prepend":{"route.rules":[{"outbound":"direct"}]}}`, "merge patch also sets route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCoreOverride(tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseCoreOverride(%.60s) = %v, want an error containing %q", tc.text, err, tc.want)
			}
		})
	}
	for _, blank := range []string{"", "  \n\t"} {
		if o, err := ParseCoreOverride(blank); o != nil || err != nil {
			t.Errorf("blank override %q = (%v, %v), want no override", blank, o, err)
		}
	}
	// A prepend beside a patch of a DIFFERENT key under the same parent is not a conflict.
	if _, err := ParseCoreOverride(`{"route":{"final":"direct"},"prepend":{"route.rules":[{"outbound":"direct"}]}}`); err != nil {
		t.Errorf("route.final beside a route.rules prepend: %v", err)
	}
}

func applyOverride(t *testing.T, cfg map[string]any, text string) map[string]any {
	t.Helper()
	if err := ApplyCoreOverride(cfg, text, 0); err != nil {
		t.Fatalf("ApplyCoreOverride: %v", err)
	}
	// Compare as JSON, which is what the core reads.
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func jsonObject(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return m
}

// RFC 7396: objects merge key by key at any depth, null deletes, and every other value - an array
// included - replaces. A nested object that is new arrives without its nulls.
func TestApplyCoreOverride_MergePatch(t *testing.T) {
	cfg := map[string]any{
		"log":   map[string]any{"level": "warn", "timestamp": true},
		"route": map[string]any{"final": "auto", "auto_detect_interface": true, "rules": []map[string]any{{"outbound": "direct"}}},
		"experimental": map[string]any{
			"cache_file": map[string]any{"enabled": true},
			"clash_api":  map[string]any{"external_controller": "127.0.0.1:9090"},
		},
		"inbounds": []map[string]any{{"type": "mixed", "tag": "mixed-in"}},
	}
	got := applyOverride(t, cfg, `{
		"log": {"level": "info"},
		"route": {"final": "direct", "auto_detect_interface": null},
		"experimental": {"cache_file": null},
		"inbounds": [{"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": 1080}],
		"ntp": {"enabled": true, "server": null}
	}`)
	want := jsonObject(t, `{
		"log": {"level": "info", "timestamp": true},
		"route": {"final": "direct", "rules": [{"outbound": "direct"}]},
		"experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
		"inbounds": [{"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": 1080}],
		"ntp": {"enabled": true}
	}`)
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("merged config:\n%s", gb)
	}
	// A top-level null deletes the key outright.
	if got := applyOverride(t, map[string]any{"log": map[string]any{}, "dns": map[string]any{}}, `{"dns": null}`); got["dns"] != nil || got["log"] == nil {
		t.Errorf("top-level null: %v", got)
	}
}

// Prepended items go in front of the generated ones, in the order written, and keep the generated
// element type that code after Generate (the KeeneticOS TUN binder, FitTUNToCore) asserts. Route
// rules go after the guards WayHop's own rules lead with (here the one sniff), never ahead of them.
func TestApplyCoreOverride_PrependOrder(t *testing.T) {
	cfg := map[string]any{
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": []map[string]any{{"action": "sniff"}, {"outbound": "auto"}}},
	}
	err := ApplyCoreOverride(cfg, `{"prepend": {
		"outbounds": [{"type": "direct", "tag": "lan-out"}],
		"route.rules": [{"domain_suffix": ["a.example"], "action": "reject"}, {"domain_suffix": ["b.example"], "outbound": "lan-out"}],
		"dns.rules": [{"domain_suffix": ["a.example"], "action": "reject"}]
	}}`, 1)
	if err != nil {
		t.Fatal(err)
	}
	outs, ok := cfg["outbounds"].([]map[string]any)
	if !ok || len(outs) != 2 || outs[0]["tag"] != "lan-out" || outs[1]["tag"] != "direct" {
		t.Errorf("outbounds = %#v", cfg["outbounds"])
	}
	rules, ok := cfg["route"].(map[string]any)["rules"].([]map[string]any)
	if !ok || len(rules) != 4 {
		t.Fatalf("route.rules = %#v", cfg["route"])
	}
	var order []string
	for _, r := range rules {
		b, _ := json.Marshal(r)
		order = append(order, string(b))
	}
	wantOrder := []string{
		`{"action":"sniff"}`,
		`{"action":"reject","domain_suffix":["a.example"]}`,
		`{"domain_suffix":["b.example"],"outbound":"lan-out"}`,
		`{"outbound":"auto"}`,
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("route.rules order:\n%s", strings.Join(order, "\n"))
	}
	// More guards than rules (a config whose rules are all guards) puts the prepended ones last.
	all := map[string]any{"route": map[string]any{"rules": []any{map[string]any{"action": "sniff"}}}}
	if err := ApplyCoreOverride(all, `{"prepend":{"route.rules":[{"action":"reject"}]}}`, 5); err != nil {
		t.Fatal(err)
	}
	if r := all["route"].(map[string]any)["rules"].([]any); len(r) != 2 || r[0].(map[string]any)["action"] != "sniff" {
		t.Errorf("all guards: %v", r)
	}
	// No DNS plane was generated: the prepended list is the whole list.
	dns, _ := cfg["dns"].(map[string]any)
	if r, _ := dns["rules"].([]any); len(r) != 1 {
		t.Errorf("dns = %#v", cfg["dns"])
	}
	// A decoded config (the KeeneticOS fallback core arrives encoded) keeps its []any lists.
	decoded := jsonObject(t, `{"outbounds":[{"type":"direct","tag":"direct"}]}`)
	if err := ApplyCoreOverride(decoded, `{"prepend":{"outbounds":[{"type":"block","tag":"b"}]}}`, 0); err != nil {
		t.Fatal(err)
	}
	if o, _ := decoded["outbounds"].([]any); len(o) != 2 || o[0].(map[string]any)["tag"] != "b" {
		t.Errorf("decoded outbounds = %#v", decoded["outbounds"])
	}
}

// The merge copies an object before it changes it, so a map the generator hands to two configs is
// never edited through one of them.
func TestApplyCoreOverride_DoesNotEditSharedObjects(t *testing.T) {
	shared := map[string]any{"level": "warn"}
	cfg := map[string]any{"log": shared}
	if err := ApplyCoreOverride(cfg, `{"log":{"level":"debug"}}`, 0); err != nil {
		t.Fatal(err)
	}
	if shared["level"] != "warn" || cfg["log"].(map[string]any)["level"] != "debug" {
		t.Errorf("shared = %v, cfg.log = %v", shared, cfg["log"])
	}
}

// Numbers reach the core as written: decoding through float64 would turn 1e21 into 1e+21 and lose a
// large integer's last digits.
// `sing-box check` passes a rule to an outbound the config does not have, and the core then fails
// every connection the rule matches, so the override's own rules are held to the tags the patched
// config really has: generated ones, endpoints, and the outbounds the override itself adds.
func TestApplyCoreOverride_RefusesARuleToAMissingOutbound(t *testing.T) {
	gen := func() map[string]any {
		return map[string]any{
			"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}, {"type": "urltest", "tag": "auto"}},
			"endpoints": []map[string]any{{"type": "wireguard", "tag": "wg"}},
			"route":     map[string]any{"rules": []map[string]any{{"outbound": "generated-only"}}},
		}
	}
	for _, ok := range []string{
		`{"prepend":{"route.rules":[{"domain_suffix":["a"],"outbound":"auto"},{"ip_cidr":["192.0.2.0/24"],"outbound":"wg"},{"action":"sniff"}]}}`,
		`{"prepend":{"outbounds":[{"type":"direct","tag":"mine"}],"route.rules":[{"domain_suffix":["a"],"outbound":"mine"}]}}`,
		`{"route":{"rules":[{"domain_suffix":["a"],"outbound":"direct"}]}}`,
		`{"log":{"level":"info"}}`, // the generated rule's dangling tag is not the override's to judge
	} {
		if err := ApplyCoreOverride(gen(), ok, 0); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"prepend":{"route.rules":[{"action":"sniff"},{"domain_suffix":["a"],"outbound":"nl-group"}]}}`,
		`{"route":{"rules":[{"domain_suffix":["a"],"outbound":"nl-group"}]}}`,
		// The patch deleted the outbound the prepended rule names.
		`{"outbounds":[{"type":"direct","tag":"direct"}],"prepend":{"route.rules":[{"outbound":"auto"}]}}`,
	} {
		err := ApplyCoreOverride(gen(), bad, 0)
		if err == nil || !strings.Contains(err.Error(), "which this config does not have") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestApplyCoreOverride_KeepsNumbersAsWritten(t *testing.T) {
	cfg := map[string]any{}
	if err := ApplyCoreOverride(cfg, `{"x":{"mark":18446744073709551615}}`, 0); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	if string(b) != `{"x":{"mark":18446744073709551615}}` {
		t.Errorf("got %s", b)
	}
}

func TestCoreOverrideKeysAndOpenListeners(t *testing.T) {
	o, err := ParseCoreOverride(`{
		"log": {"level": "info"},
		"inbounds": [
			{"type": "tun", "tag": "tun-in"},
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
			{"type": "socks", "tag": "v6lo", "listen": "::1", "listen_port": 1081},
			{"type": "socks", "tag": "nolisten", "listen_port": 1082},
			{"type": "mixed", "tag": "lan", "listen": "0.0.0.0", "listen_port": 7891},
			{"type": "http", "listen": "::", "listen_port": 8080},
			{"type": "socks", "tag": "lanip", "listen": "192.0.2.1", "listen_port": 1083}
		],
		"experimental": {"clash_api": {"external_controller": ":9090"}},
		"prepend": {"route.rules": [{"action": "sniff"}], "dns.servers": [{"type": "local", "tag": "l"}]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := o.Keys(), []string{"dns", "experimental", "inbounds", "log", "route"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Keys() = %v, want %v", got, want)
	}
	want := []string{
		"inbound lan (mixed) on 0.0.0.0:7891",
		"inbound #6 (http) on [::]:8080",
		"inbound lanip (socks) on 192.0.2.1:1083",
		"Clash API controller on :9090",
	}
	if got := o.OpenListeners(); !reflect.DeepEqual(got, want) {
		t.Errorf("OpenListeners() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	loop, _ := ParseCoreOverride(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}},"log":{"level":"info"}}`)
	if got := loop.OpenListeners(); len(got) != 0 {
		t.Errorf("loopback-only override reported %v", got)
	}
}

// A service listens like an inbound (an ssm-api with listen 0.0.0.0 bound 0.0.0.0 on 1.14.4, and
// manages a Shadowsocks inbound's users from there), so one beyond loopback is named the same way.
func TestCoreOverrideOpenListeners_Services(t *testing.T) {
	o, err := ParseCoreOverride(`{
		"inbounds": [{"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": 8388}],
		"services": [
			{"type": "ssm-api", "tag": "ssm", "listen": "0.0.0.0", "listen_port": 9999, "servers": {"/": "ss"}},
			{"type": "resolved", "tag": "lo", "listen": "127.0.0.1", "listen_port": 5353},
			{"type": "derp", "tag": "nolisten", "listen_port": 3478},
			{"type": "derp", "listen": "192.0.2.1", "listen_port": 3479}
		]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"service ssm (ssm-api) on 0.0.0.0:9999",
		"service #4 (derp) on 192.0.2.1:3479",
	}
	if got := o.OpenListeners(); !reflect.DeepEqual(got, want) {
		t.Errorf("OpenListeners() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The review warns when an override takes from WayHop what its own features use the core through,
// and stays quiet for one that keeps it: a controller on WayHop's port on every address, the same
// secret, inbounds restated with the probe among them, rules added by prepend.
func TestCoreOverrideDaemonLosses(t *testing.T) {
	use := DaemonUse{ClashAddr: "127.0.0.1:9090", ClashSecret: "s3cret", Probe: true}
	for _, tc := range []struct {
		text string
		want []string
	}{
		{`{"experimental":{"clash_api":null}}`, []string{"experimental.clash_api deleted"}},
		{`{"experimental":null}`, []string{"experimental deleted"}},
		{`{"experimental":{"clash_api":"off"}}`, []string{"experimental.clash_api replaced"}},
		{`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9999","secret":"x"}}}`,
			[]string{"experimental.clash_api.external_controller changed", "experimental.clash_api.secret changed"}},
		{`{"experimental":{"clash_api":{"external_controller":null}}}`, []string{"experimental.clash_api.external_controller changed"}},
		{`{"experimental":{"clash_api":{"secret":null}}}`, []string{"experimental.clash_api.secret changed"}},
		{`{"inbounds":[{"type":"mixed","tag":"m","listen_port":7890}]}`, []string{"inbounds replaced", "inbound probe-in dropped"}},
		{`{"inbounds":null}`, []string{"inbounds deleted", "inbound probe-in dropped"}},
		{`{"inbounds":[{"type":"mixed","tag":"probe-in","listen_port":17890}]}`, []string{"inbounds replaced"}},
		{`{"route":{"rules":[{"outbound":"direct"}]}}`, []string{"route.rules replaced"}},
		{`{"route":null}`, []string{"route deleted"}},
		// Kept: nothing to say.
		{`{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090","secret":"s3cret"}}}`, nil},
		{`{"experimental":{"clash_api":{"external_controller":":9090","default_mode":"rule"}}}`, nil},
		{`{"experimental":{"cache_file":null},"route":{"final":"direct"},"prepend":{"route.rules":[{"outbound":"direct"}]}}`, nil},
	} {
		o, err := ParseCoreOverride(tc.text)
		if err != nil {
			t.Fatalf("%s: %v", tc.text, err)
		}
		var got []string
		for _, l := range o.DaemonLosses(use) {
			got = append(got, l.Item)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: DaemonLosses = %q, want %q", tc.text, got, tc.want)
		}
	}
	// No Clash API generated, no probe port: nothing of those to lose.
	o, _ := ParseCoreOverride(`{"experimental":{"clash_api":null},"inbounds":[]}`)
	if got := o.DaemonLosses(DaemonUse{}); len(got) != 1 || got[0].Kind != LossInbounds {
		t.Errorf("without a Clash API or probe: %+v", got)
	}
}

// Generate carries the override as its last step, and refuses one that does not parse rather than
// emitting the config without it.
//
// The prepended route rules go after WayHop's guards - the probe rules, the TUN's sniff and the
// endpoint bypass - and before the profile's own rules and lists: a broad prepended rule ahead of the
// bypass would send a tunnel's own server traffic into a tunnel.
func TestGenerate_CarriesCoreOverride(t *testing.T) {
	profile := func() *model.Profile {
		p := probeProfile()
		p.Endpoints[0].Server = "198.51.100.7"
		p.Rules = append([]model.Rule{{ID: "u", DomainSuffix: []string{"user.example"}, Outbound: "de"}}, p.Rules...)
		return p
	}
	text := `{"log":{"level":"info"},"route":{"final":"direct"},"prepend":{"route.rules":[{"network":["tcp","udp"],"outbound":"nl"}]}}`
	res, err := Generate(profile(), Options{MixedPort: 7890, ProbePort: 17890, TunEnabled: true, CoreOverride: text})
	if err != nil {
		t.Fatal(err)
	}
	if lvl := res.Config["log"].(map[string]any)["level"]; lvl != "info" {
		t.Errorf("log.level = %v", lvl)
	}
	route := res.Config["route"].(map[string]any)
	if route["final"] != "direct" {
		t.Errorf("route.final = %v", route["final"])
	}
	rules := route["rules"].([]map[string]any)
	var order []string
	for _, r := range rules {
		switch {
		case r["auth_user"] != nil:
			if len(order) == 0 || order[len(order)-1] != "probe" {
				order = append(order, "probe")
			}
		case r["action"] == "sniff":
			order = append(order, "sniff")
		case r["ip_cidr"] != nil && r["outbound"] == "direct":
			order = append(order, "bypass")
		case r["network"] != nil:
			order = append(order, "prepended")
		case r["domain_suffix"] != nil:
			order = append(order, "user")
		case r["rule_set"] != nil:
			order = append(order, "list")
		default:
			order = append(order, fmt.Sprint(r))
		}
	}
	if got, want := strings.Join(order, ","), "probe,sniff,bypass,prepended,user,list"; got != want {
		t.Errorf("route.rules order = %s, want %s", got, want)
	}
	plain, err := Generate(profile(), Options{MixedPort: 7890, ProbePort: 17890, TunEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Config["route"].(map[string]any)["rules"].([]map[string]any)) != len(rules)-1 {
		t.Error("the override added more than its one rule")
	}
	if _, err := Generate(probeProfile(), Options{MixedPort: 7890, CoreOverride: `{"log":`}); err == nil ||
		!strings.Contains(err.Error(), "core override") {
		t.Errorf("a malformed override must stop generation, got %v", err)
	}
}

// TestCoreOverrideSingBoxCheck runs the real `sing-box check` on a generated config carrying an
// override with a log level, a prepended outbound and route rule, and a deleted nested key.
func TestCoreOverrideSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	// No TUN: its auto_redirect fails `check` off Linux, and the override does not depend on it.
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, ProbePort: 17890, ClashSecret: "s3cret", CoreVersion: ver,
		CoreOverride: `{
			"log": {"level": "info"},
			"experimental": {"cache_file": null},
			"prepend": {
				"outbounds": [{"type": "direct", "tag": "override-direct"}],
				"route.rules": [{"domain_suffix": ["example.org"], "outbound": "override-direct"}]
			}
		}`})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, kept := res.Config["experimental"].(map[string]any)["cache_file"]; kept {
		t.Fatal("experimental.cache_file survived its null")
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "override.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the overridden config: %v\n%s", err, out)
	}

	// And the guard holds for the hand-edit mistake WayHop cannot see: a misspelt key is what Apply's
	// `sing-box check` refuses before anything is written. (A rule naming a missing outbound is not:
	// see the note at the top of override.go.)
	bad, err := Generate(probeProfile(), Options{MixedPort: 7890, CoreVersion: ver,
		CoreOverride: `{"log":{"levle":"info"}}`})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ = json.MarshalIndent(bad.Config, "", "  ")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err == nil {
		t.Fatalf("sing-box check accepted a misspelt key:\n%s", out)
	}
}
