package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/generator"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// coreOverrideText is the override these tests save: a log level, a rule in front of the generated
// ones, and a SOCKS inbound open to the LAN beside the generated mixed one.
const coreOverrideText = `{
	"log": {"level": "info"},
	"inbounds": [
		{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
		{"type": "socks", "tag": "lan-socks", "listen": "0.0.0.0", "listen_port": 1080}
	],
	"prepend": {"route.rules": [{"domain_suffix": ["example.org"], "action": "reject"}]}
}`

// overriddenCore asserts that a core config carries coreOverrideText.
func overriddenCore(t *testing.T, label string, raw []byte) {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("%s: %v\n%s", label, err, raw)
	}
	if lvl := cfg["log"].(map[string]any)["level"]; lvl != "info" {
		t.Errorf("%s: log.level = %v", label, lvl)
	}
	// The prepended rule comes right after WayHop's guards (probe rules, sniff, endpoint bypass) and
	// ahead of every other generated rule.
	rules, _ := cfg["route"].(map[string]any)["rules"].([]any)
	at := -1
	for i, v := range rules {
		r := v.(map[string]any)
		if r["action"] == "reject" && r["domain_suffix"] != nil {
			at = i
			break
		}
		guard := r["auth_user"] != nil || r["action"] == "sniff" || (r["ip_cidr"] != nil && r["outbound"] == "direct")
		if !guard {
			t.Errorf("%s: generated rule %d %v comes before the prepended one", label, i, r)
		}
	}
	if at < 0 {
		t.Errorf("%s: the prepended rule is missing: %v", label, rules)
	}
	if ins, _ := cfg["inbounds"].([]any); len(ins) != 2 {
		t.Errorf("%s: inbounds = %v", label, cfg["inbounds"])
	}
}

// The bytes Apply checks with `sing-box check` are the bytes it writes, and both carry the override,
// inside the fail-safe Test window.
func TestRunApply_ChecksAndWritesTheOverriddenCore(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	s.cfg.CoreOverride = coreOverrideText
	var checked, written []byte
	check, write := s.execOps.checkCore, s.execOps.core
	s.execOps.checkCore = func(ctx context.Context, b []byte) error {
		checked = append([]byte(nil), b...)
		return check(ctx, b)
	}
	s.execOps.core = func(ctx context.Context, a executionCoreArtifactV1) error {
		written = append([]byte(nil), a.Config...)
		return write(ctx, a)
	}

	res, aerr := s.runApply(context.Background(), applyRequest{})
	if aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if !res.Failsafe.Pending {
		t.Errorf("a Test apply must arm the fail-safe window: %+v", res.Failsafe)
	}
	if len(checked) == 0 || !bytes.Equal(checked, written) {
		t.Fatalf("checked %d bytes, wrote %d: Apply must write exactly what it checked", len(checked), len(written))
	}
	overriddenCore(t, "applied core", written)
}

// The preview (GET /api/generate) shows the same override Apply writes.
func TestHandleGenerate_CarriesCoreOverride(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	s.cfg.CoreOverride = coreOverrideText
	w := httptest.NewRecorder()
	s.handleGenerate(w, httptest.NewRequest(http.MethodGet, "/api/generate", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	overriddenCore(t, "preview", body.Config)
}

// Every generator option builder the daemon has passes the saved override through.
func TestGeneratorOptionBuilders_CarryCoreOverride(t *testing.T) {
	desired := DesiredSnapshot{Config: *config.Default()}
	desired.Config.RoutingMode = "mixed"
	desired.Config.CoreOverride = coreOverrideText
	opts, err := executionGeneratorOptions(desired, nil)
	if err != nil || opts.CoreOverride != coreOverrideText {
		t.Errorf("executionGeneratorOptions: %q, %v", opts.CoreOverride, err)
	}
	if got := executionKeeneticCompatibilityOptions(desired).CoreOverride; got != coreOverrideText {
		t.Errorf("executionKeeneticCompatibilityOptions: %q", got)
	}
	s, _ := applytest_server(t)
	s.cfg.CoreOverride = coreOverrideText
	if got, _ := s.genOptionsWithPlan(nil, s.config()); got.CoreOverride != coreOverrideText {
		t.Errorf("genOptionsWithPlan: %q", got.CoreOverride)
	}
}

// On KeeneticOS the compatibility TUN is bound to wrtun0 after the override: an override that
// restates `inbounds` still gets the five fields NDM's routes depend on, and one that drops the
// capture TUN is refused rather than written.
func TestBindKeeneticCompatibilityTUN_AfterOverride(t *testing.T) {
	p := coreVersionProfile()
	res, err := generator.Generate(&p, generator.Options{MixedPort: 7890, TunEnabled: true,
		CoreOverride: `{"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"mine","auto_route":true}]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := bindKeeneticCompatibilityTUN(res.Config); err != nil {
		t.Fatalf("bind: %v", err)
	}
	tun := res.Config["inbounds"].([]map[string]any)[0]
	if tun["interface_name"] != "wrtun0" || tun["auto_route"] != false || tun["stack"] != "gvisor" {
		t.Errorf("bound TUN = %v", tun)
	}
	res, err = generator.Generate(&p, generator.Options{MixedPort: 7890, TunEnabled: true,
		CoreOverride: `{"inbounds":[{"type":"mixed","tag":"m","listen_port":7890}]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := bindKeeneticCompatibilityTUN(res.Config); err == nil {
		t.Error("an override without the capture TUN must not bind")
	}
}

// The KeeneticOS fallback core, which arrives encoded, carries the override too.
func TestFitFallbackCore_AppliesTheOverride(t *testing.T) {
	in := []byte(`{"log":{"level":"warn"},"inbounds":[{"type":"tun","tag":"tun-a","stack":"gvisor"}],"route":{"rules":[{"inbound":["tun-a"],"outbound":"a"}]}}`)
	out, err := fitFallbackCore(in, "1.13.21", `{"log":{"level":"info"},"prepend":{"route.rules":[{"action":"sniff"}]}}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if cfg["log"].(map[string]any)["level"] != "info" || len(rules) != 2 || rules[0].(map[string]any)["action"] != "sniff" {
		t.Errorf("fallback core:\n%s", out)
	}
	if _, err := fitFallbackCore(in, "", `{"log":`, nil); err == nil {
		t.Error("a malformed override must not be passed on")
	}
	// An override written against the generated config names its groups, which this per-connection
	// core does not have; check would pass it and the core would fail those connections.
	if _, err := fitFallbackCore(in, "", `{"prepend":{"route.rules":[{"domain_suffix":["a.example"],"outbound":"auto"}]}}`, nil); err == nil ||
		!strings.Contains(err.Error(), `outbound "auto"`) {
		t.Errorf("a rule to a group the fallback core lacks: %v", err)
	}
}

// On KeeneticOS, NDM routes each connection into its wrtunN device on the fallback core. An override
// that restates `inbounds` (one written for the generated config does) must not take those devices
// away or make this core route: sing-box check passes either, and the fail-safe, which pings outside
// the core, would not see the connections go nowhere. The datapath is re-asserted, and a TUN of the
// override's own that routes is refused.
func TestFitFallbackCore_KeepsTheNDMDatapath(t *testing.T) {
	e := model.Endpoint{ID: "vless1", Name: "v", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.9", Port: 443, Enabled: true, Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}}
	plan, err := keenetic.SingboxFallback([]*model.Endpoint{&e}, keenetic.FallbackOptions{ProbePort: 17890, ClashSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan.Config)

	routing := `{"inbounds":[{"type":"tun","tag":"tun-in","address":["192.0.2.5/30"],"auto_route":true,"strict_route":true},` +
		`{"type":"mixed","tag":"lan","listen":"192.0.2.1","listen_port":7891}]}`
	if _, err := fitFallbackCore(raw, "1.13.21", routing, plan.IfaceFor); err == nil || !strings.Contains(err.Error(), `"tun-in" is a TUN that routes`) {
		t.Errorf("a routing TUN on the fallback core: %v", err)
	}

	out, err := fitFallbackCore(raw, "1.13.21", `{"inbounds":[{"type":"mixed","tag":"lan","listen":"192.0.2.1","listen_port":7891}],`+
		`"prepend":{"route.rules":[{"domain_suffix":["example.net"],"action":"reject"}]}}`, plan.IfaceFor)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	tags := map[string]map[string]any{}
	for _, in := range cfg.Inbounds {
		tags[in["tag"].(string)] = in
	}
	tun := tags["tun-vless1"]
	if tun == nil || tun["interface_name"] != plan.IfaceFor["vless1"] || tun["auto_route"] != false || tun["strict_route"] != false {
		t.Errorf("tun-vless1 = %v", tun)
	}
	if s := tags["socks-vless1"]; s == nil || s["listen"] != "127.0.0.1" {
		t.Errorf("socks-vless1 = %v", s)
	}
	if tags["lan"] == nil {
		t.Error("the override's own inbound was dropped")
	}
	// Every inbound a connection's rule names exists (the probe inbound is the review's to warn about,
	// core.override_daemon_loss), and the prepended rule follows the probe rules.
	for i, r := range cfg.Route.Rules {
		named, _ := r["inbound"].([]any)
		for _, tag := range named {
			if tag != generator.ProbeInboundTag && tags[tag.(string)] == nil {
				t.Errorf("rule %d names inbound %v, which the core does not have", i, tag)
			}
		}
		if r["action"] == "reject" && (i == 0 || cfg.Route.Rules[i-1]["auth_user"] == nil) {
			t.Errorf("the prepended rule is at %d, not right after the probe rules: %v", i, cfg.Route.Rules)
		}
	}
}

func findingByID(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

// The review says an override is active and which keys it touches (advisory), names a listener it
// opens beyond loopback (privacy, not a blocker), and blocks only an override that cannot be applied.
func TestBuildPlan_CoreOverrideFindings(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	s.cfg.CoreOverride = coreOverrideText
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	active := findingByID(plan.Findings, "core.override")
	if active == nil {
		t.Fatalf("no core.override finding in %+v", plan.Findings)
	}
	if strings.Join(active.Items, ",") != "inbounds,log,route" || active.Blocks != platform.BlocksNothing || active.AckRequired {
		t.Errorf("core.override = %+v", *active)
	}
	open := findingByID(plan.Findings, "core.override_open_listener")
	if open == nil || open.Severity != platform.SeverityPrivacy || open.Blocks != platform.BlocksNothing || open.AckRequired ||
		strings.Join(open.Items, ",") != "inbound lan-socks (socks) on 0.0.0.0:1080" {
		t.Errorf("core.override_open_listener = %+v", open)
	}
	if strings.Contains(active.Detail+open.Detail, "0.0.0.0\", \"listen_port") {
		t.Error("a finding carries the override's text")
	}
	for _, f := range plan.Findings {
		if strings.HasPrefix(f.ID, "core.override") && f.hard() {
			t.Errorf("%s blocks Apply", f.ID)
		}
	}
	// coreOverrideText restates inbounds without the probe: said, with what stops working.
	if loss := findingByID(plan.Findings, "core.override_daemon_loss"); loss == nil ||
		strings.Join(loss.Items, ",") != "inbounds replaced,inbound probe-in dropped" {
		t.Errorf("core.override_daemon_loss = %+v", loss)
	}

	// A config.json edited by hand past Validate: the review blocks, before Apply gets to it.
	s.cfg.CoreOverride = `{"prepend":{"inbounds":[]}}`
	plan, err = s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if bad := findingByID(plan.Findings, "core.override_invalid"); bad == nil || !bad.hard() || plan.Verdict != VerdictBlocked {
		t.Errorf("invalid override: finding %+v, verdict %s", bad, plan.Verdict)
	}
}

// An override that takes the Clash API away, or WayHop's guard rules with the generated route rules,
// leaves a core that runs and passes sing-box check while health, failover, the Connections page,
// the speed test and the Telegram bot quietly stop: the review warns, naming them, and does not block.
func TestBuildPlan_CoreOverrideDaemonLoss(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	s.cfg.CoreOverride = `{"experimental":{"clash_api":null},"route":{"rules":[{"outbound":"direct"}]}}`
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	loss := findingByID(plan.Findings, "core.override_daemon_loss")
	if loss == nil {
		t.Fatalf("no core.override_daemon_loss in %+v", plan.Findings)
	}
	if strings.Join(loss.Items, ",") != "experimental.clash_api deleted,route.rules replaced" ||
		loss.Severity != platform.SeverityDegraded || loss.Blocks != platform.BlocksNothing || loss.AckRequired || loss.hard() {
		t.Errorf("core.override_daemon_loss = %+v", *loss)
	}
	for _, want := range []string{"failover", "Telegram bot", "speed test", "bypass"} {
		if !strings.Contains(loss.Detail, want) {
			t.Errorf("the detail does not say %q stops: %s", want, loss.Detail)
		}
	}
	if loss.Code != "CORE_OVERRIDE_DAEMON_LOSS" || loss.Remedy == "" {
		t.Errorf("code %q, remedy %q", loss.Code, loss.Remedy)
	}

	// The same Clash API on every address, and rules added by prepend, take nothing.
	s.cfg.CoreOverride = `{"experimental":{"clash_api":{"external_controller":"0.0.0.0:` + strconv.Itoa(s.cfg.Ports.Clash) + `"}},` +
		`"prepend":{"route.rules":[{"domain_suffix":["example.net"],"action":"reject"}]}}`
	if plan, err = s.buildPlan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if f := findingByID(plan.Findings, "core.override_daemon_loss"); f != nil {
		t.Errorf("an override that keeps what WayHop uses: %+v", *f)
	}
}

// With no proxy core in the datapath the override changes nothing, and the review says so instead
// of reporting listeners that will never open.
func TestCoreOverrideFindings_NoCore(t *testing.T) {
	got := coreOverrideFindings(coreOverrideText, false, generator.DaemonUse{})
	if len(got) != 3 {
		t.Fatalf("want one advisory per key and no listener finding, got %+v", got)
	}
	for _, f := range got {
		if f.ID != "core.override" || !strings.Contains(f.Detail, "runs no proxy core") {
			t.Errorf("%+v", f)
		}
	}
	if coreOverrideFindings("", true, generator.DaemonUse{}) != nil {
		t.Error("no override, no finding")
	}
}

// A shared export masks the override (it can carry credentials), and importing that export keeps the
// override the router has rather than storing the mask.
func TestConfigImport_KeepsTheRedactedCoreOverride(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.cfg.CoreOverride = coreOverrideText
	exported := s.config().Redacted()
	if exported.CoreOverride != config.RedactedMark {
		t.Fatalf("export carries the override: %q", exported.CoreOverride)
	}
	body, _ := json.Marshal(exported)
	w := httptest.NewRecorder()
	s.handleConfigImport(w, httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if got := s.config().CoreOverride; got != coreOverrideText {
		t.Errorf("after import: %q", got)
	}
}

// A Settings save refuses a malformed override, so it never reaches Apply.
func TestPutConfig_RefusesAMalformedCoreOverride(t *testing.T) {
	s, _ := sharehandlers_server(t)
	cfg := s.config()
	cfg.CoreOverride = `{"prepend":{"route.rule_set":[{"tag":"x"}]}}`
	body, _ := json.Marshal(cfg)
	w := httptest.NewRecorder()
	s.handlePutConfig(w, httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not supported") {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if s.config().CoreOverride != "" {
		t.Error("the refused override was stored")
	}
}
