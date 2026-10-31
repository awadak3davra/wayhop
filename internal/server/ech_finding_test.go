package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// testECHConfig is an ECHConfigList `sing-box generate ech-keypair example.com` printed (1.13.21).
const testECHConfig = "AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

func echServerEndpoint(id string, e *model.ECH) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "192.0.2.40", Port: 443, Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000040"},
		TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", ECH: e}}
}

// What the core leaves out of ECH is said in the review: a query server name a 1.12 core has no
// option for (the lookup then asks for the SNI's record), a 1.12 built with Go older than 1.24 (no
// ECH at all), and that a DNS lookup goes through the router's DNS rules. The config a Reality link
// brought is not: the import says it once, and nothing on the Apply review could clear it.
func TestEndpointFindings_ECH(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	size := 1
	setCore := func(answer string) {
		size++ // a new binary is a new probe (the cache keys on size and mtime)
		if err := os.WriteFile(bin, []byte(strings.Repeat("v", size)), 0o755); err != nil {
			t.Fatal(err)
		}
		s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	}
	s.cfg.SingBox.Bin = bin
	qsn := echServerEndpoint("qsn", &model.ECH{Enabled: true, QueryServerName: "example.net"})
	static := echServerEndpoint("static", &model.ECH{Enabled: true, Config: testECHConfig})
	reality := echServerEndpoint("reality", &model.ECH{Config: testECHConfig})
	reality.TLS.Type, reality.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	plain := echServerEndpoint("plain", nil)
	findings := func() map[string]PlanFinding {
		out := map[string]PlanFinding{}
		prof := model.Profile{Endpoints: []model.Endpoint{qsn, static, reality, plain},
			DNS: &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true}}}}
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if strings.HasPrefix(f.ID, "endpoint.tls.ech.") {
				if prev, ok := out[f.ID]; ok {
					f.Item = prev.Item + "," + f.Item
				}
				out[f.ID] = f
			}
		}
		return out
	}

	setCore("sing-box version 1.12.17\n\nEnvironment: go1.25.6 linux/arm64\n")
	got := findings()
	if f := got["endpoint.tls.ech.qsn"]; f.Item != "qsn" || f.Blocks != platform.BlocksFeature || f.Reason != platform.ReasonBinaryTooOld {
		t.Fatalf("1.12 with a query name: %+v (all %v)", f, got)
	}
	if f := got["endpoint.tls.ech.dns"]; f.Item != "qsn" || f.Blocks != platform.BlocksNothing {
		t.Fatalf("DNS note: %+v", f)
	}
	if f, ok := got["endpoint.tls.ech.reality"]; ok {
		t.Fatalf("Reality: said on every Apply, with nothing to do about it: %+v", f)
	}
	if _, ok := got["endpoint.tls.ech.core"]; ok {
		t.Fatal("a 1.12 built with Go 1.25 has ECH")
	}
	folded := foldFindings([]PlanFinding{got["endpoint.tls.ech.qsn"], got["endpoint.tls.ech.dns"]}, nil)
	for _, f := range folded {
		switch f.ID {
		case "endpoint.tls.ech.qsn":
			if !f.AckRequired || f.Code != "ECH_QUERY_NAME_NEEDS_NEWER_CORE" || !strings.Contains(f.Detail, "1.13") {
				t.Errorf("qsn folded = %+v", f)
			}
		case "endpoint.tls.ech.dns":
			if f.AckRequired || f.hard() || !strings.Contains(f.Detail, "FakeIP") {
				t.Errorf("dns folded = %+v", f)
			}
		}
	}

	setCore("sing-box version 1.12.17\n\nEnvironment: go1.23.4 linux/mipsle\n")
	got = findings()
	if f := got["endpoint.tls.ech.core"]; f.Item != "qsn,static" || f.Blocks != platform.BlocksFeature {
		t.Fatalf("1.12 built with Go 1.23: %+v (all %v)", f, got)
	}
	if _, ok := got["endpoint.tls.ech.qsn"]; ok {
		t.Fatal("no ECH at all: the query name is not the thing to say")
	}
	if _, ok := got["endpoint.tls.ech.dns"]; ok {
		t.Fatal("no ECH at all: no lookup to note")
	}

	setCore("sing-box version 1.13.21\n\nEnvironment: go1.25.12 linux/arm64\n")
	got = findings()
	if _, ok := got["endpoint.tls.ech.qsn"]; ok {
		t.Fatal("1.13 carries the query name")
	}
	if _, ok := got["endpoint.tls.ech.dns"]; !ok {
		t.Fatal("the DNS note does not depend on the core")
	}
}

// The Check button says what the review says: on a 1.12 core the query name is left out, and a 1.12
// built without ECH applies the connection without it, though the config checks clean.
func TestEndpointCheckSaysWhatECHTheCoreLeavesOut(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.12.17\n\nEnvironment: go1.25.6 linux/arm64\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	if err := s.store.UpsertEndpoint(echServerEndpoint("e", &model.ECH{Enabled: true, QueryServerName: "example.net"})); err != nil {
		t.Fatal(err)
	}
	check := func() map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints/e/check", nil)
		r.SetPathValue("id", "e")
		w := httptest.NewRecorder()
		s.handleEndpointCheck(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if out := check(); out["ok"] != false || !strings.Contains(out["error"].(string), "sing-box 1.13") ||
		!strings.Contains(out["error"].(string), "runs sing-box version 1.12.17, so") {
		t.Fatalf("1.12 core: check = %v", out)
	}
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.12.17\n\nEnvironment: go1.23.4 linux/mipsle\n"
	if out := check(); out["ok"] != false || !strings.Contains(out["error"].(string), "no ECH") {
		t.Fatalf("1.12 built with Go 1.23: check = %v", out)
	}
}

// The panel's save refuses what the core would refuse or never use, and the bulk import stores such
// a connection disabled with the reason (EndpointParamProblem, as for every other param).
func TestUpsertEndpointRefusesECHThatCannotWork(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for name, e := range map[string]model.Endpoint{
		"garbage config": echServerEndpoint("g", &model.ECH{Enabled: true, Config: "AAAA"}),
		"ECH on Reality": func() model.Endpoint {
			x := echServerEndpoint("r", &model.ECH{Enabled: true, Config: testECHConfig})
			x.TLS.Type = "reality"
			return x
		}(),
		"DNS with an IP": func() model.Endpoint {
			x := echServerEndpoint("i", &model.ECH{Enabled: true})
			x.TLS.SNI = "192.0.2.40"
			return x
		}(),
		"DNS over QUIC": func() model.Endpoint {
			x := echServerEndpoint("q", &model.ECH{Enabled: true})
			x.Protocol = model.ProtoTUIC
			return x
		}(),
	} {
		body, _ := json.Marshal(e)
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		s.handleUpsertEndpoint(w, r)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "ECH") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	ok := echServerEndpoint("ok", &model.ECH{Enabled: true, Config: testECHConfig})
	body, _ := json.Marshal(ok)
	w := httptest.NewRecorder()
	s.handleUpsertEndpoint(w, httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("a good config: %d %s", w.Code, w.Body.String())
	}
	prof := s.store.Profile()
	if got := prof.EndpointByID("ok"); got == nil || got.TLS.ECH == nil || got.TLS.ECH.Config != testECHConfig {
		t.Fatalf("stored = %+v", got)
	}
}

// Where the ECH lookup goes is said in the review: through the connection it is for (WayHop's own
// secure DNS default rides the main exit's group), which never answers while the connection is down,
// is to be acknowledged; to plain DNS, where the name ECH hides goes out in the clear, is a privacy
// note. A uTLS fingerprint that cannot carry ECH, applied as chrome, is said too.
func TestEndpointFindings_ECHLookupAndFingerprint(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	s.coreVersionOf = func(context.Context, string) (string, error) {
		return "sing-box version 1.13.21\n\nEnvironment: go1.25.12 linux/arm64\n", nil
	}
	nl := echServerEndpoint("nl", &model.ECH{Enabled: true, QueryServerName: "example.net"})
	safari := echServerEndpoint("safari", &model.ECH{Enabled: true, Config: testECHConfig})
	safari.TLS.Fingerprint = "safari"
	chrome := echServerEndpoint("chrome", &model.ECH{Enabled: true, Config: testECHConfig})
	chrome.TLS.Fingerprint = "chrome"
	base := model.Profile{Endpoints: []model.Endpoint{nl, safari, chrome},
		Groups: []model.Group{{ID: "grp", Name: "grp", Type: model.GroupFallback, Members: []string{"nl", "direct"}}},
		Rules:  []model.Rule{{ID: "def", Default: true, Outbound: "grp"}}}
	base.DNS = secureDNSTemplate(&base)
	findings := func(prof model.Profile) map[string]PlanFinding {
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if strings.HasPrefix(f.ID, "endpoint.tls.ech.") {
				if prev, ok := out[f.ID]; ok {
					f.Item = prev.Item + "," + f.Item
				}
				out[f.ID] = f
			}
		}
		return out
	}

	got := findings(base)
	if base.DNS.Servers[0].Detour != "grp" {
		t.Fatalf("the secure default's DoH rides %q", base.DNS.Servers[0].Detour)
	}
	if f := got["endpoint.tls.ech.dns_loop"]; f.Item != "nl" || f.Blocks != platform.BlocksFeature {
		t.Fatalf("the lookup through its own group: %+v (all %v)", f, got)
	}
	if _, ok := got["endpoint.tls.ech.dns"]; ok {
		t.Error("the loop says what the general note would")
	}
	if f := got["endpoint.tls.ech.fingerprint"]; f.Item != "safari" || f.Blocks != platform.BlocksNothing {
		t.Fatalf("fingerprint: %+v", f)
	}
	for _, f := range foldFindings([]PlanFinding{got["endpoint.tls.ech.dns_loop"], got["endpoint.tls.ech.fingerprint"]}, nil) {
		switch f.ID {
		case "endpoint.tls.ech.dns_loop":
			if !f.AckRequired || f.hard() || f.Code != "ECH_LOOKUP_THROUGH_ITSELF" || !strings.Contains(f.Remedy, "DNS rule") {
				t.Errorf("loop folded = %+v", f)
			}
		case "endpoint.tls.ech.fingerprint":
			if f.AckRequired || f.hard() || f.Code != "ECH_FINGERPRINT_REPLACED" || !strings.Contains(f.Detail, "chrome") {
				t.Errorf("fingerprint folded = %+v", f)
			}
		}
	}

	// A DNS rule that sends the name to the router's own resolver ends the loop, and sends it in the clear.
	local := base
	local.DNS = secureDNSTemplate(&base)
	local.DNS.Rules = []model.DNSRule{{ID: "r", DomainSuffix: []string{"example.net"}, Server: "dns_local"}}
	got = findings(local)
	if _, ok := got["endpoint.tls.ech.dns_loop"]; ok {
		t.Errorf("the rule takes the lookup off the group: %v", got)
	}
	f, ok := got["endpoint.tls.ech.dns_clear"]
	if !ok || f.Item != "nl" || f.Severity != platform.SeverityPrivacy || f.Blocks != platform.BlocksNothing {
		t.Fatalf("plain DNS: %+v (all %v)", f, got)
	}
	if folded := foldFindings([]PlanFinding{f}, nil); folded[0].AckRequired || folded[0].Code != "ECH_NAME_IN_CLEAR_DNS" ||
		!strings.Contains(folded[0].Detail, "plain DNS") {
		t.Errorf("clear folded = %+v", folded[0])
	}

	// Encrypted, and not through the connection: the general note alone.
	direct := base
	direct.DNS = secureDNSTemplate(&base)
	direct.DNS.Servers[0].Detour = ""
	got = findings(direct)
	_, loop := got["endpoint.tls.ech.dns_loop"]
	_, clear := got["endpoint.tls.ech.dns_clear"]
	if _, note := got["endpoint.tls.ech.dns"]; loop || clear || !note {
		t.Errorf("direct DoH: %v", got)
	}
}

// A bulk import (the subscription dialog's) says once that a Reality link's ECH config is not used,
// and stores a QUIC connection that asked for the DNS lookup disabled, asking for the server's config,
// instead of bringing it up without ECH and saying nothing.
func TestBulkImportSaysWhatECHCannotDo(t *testing.T) {
	s, _ := sharehandlers_server(t)
	reality := echServerEndpoint("reality", &model.ECH{Config: testECHConfig})
	reality.TLS.Type, reality.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	tuic := echServerEndpoint("tuic", &model.ECH{Enabled: true})
	tuic.Protocol, tuic.Params = model.ProtoTUIC, map[string]any{"uuid": "00000000-0000-4000-8000-000000000041", "password": "pw"}
	body, _ := json.Marshal(map[string]any{"endpoints": []model.Endpoint{reality, tuic}})
	w := httptest.NewRecorder()
	s.handleBulkEndpoints(w, httptest.NewRequest(http.MethodPost, "/api/endpoints/bulk", strings.NewReader(string(body))))
	var out struct {
		Saved          int      `json:"saved"`
		StoredDisabled []string `json:"stored_disabled"`
		Notes          []string `json:"notes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(out.Notes) != 1 || !strings.HasPrefix(out.Notes[0], "reality (vless): ") || !strings.Contains(out.Notes[0], "Reality") {
		t.Errorf("notes = %q", out.Notes)
	}
	if len(out.StoredDisabled) != 1 || !strings.HasPrefix(out.StoredDisabled[0], "tuic (tuic): ") ||
		!strings.Contains(out.StoredDisabled[0], "paste the server's ECH config") {
		t.Errorf("stored_disabled = %q", out.StoredDisabled)
	}
	prof := s.store.Profile()
	if got := prof.EndpointByID("tuic"); got == nil || got.Enabled || got.TLS.ECH == nil || !got.TLS.ECH.Enabled {
		t.Errorf("tuic stored = %+v", got)
	}
	if got := prof.EndpointByID("reality"); got == nil || !got.Enabled {
		t.Errorf("reality stored = %+v", got)
	}
}
