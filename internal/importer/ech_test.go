package importer

import (
	"net/url"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// testECHConfig is an ECHConfigList `sing-box generate ech-keypair example.com` printed (1.13.21).
const testECHConfig = "AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

const testECHPEM = "-----BEGIN ECH CONFIGS-----\nAEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEA\nAQABAAIAAQADAAtleGFtcGxlLmNvbQAA\n-----END ECH CONFIGS-----"

func sameECH(a, b *model.ECH) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func TestECHFromShareLinks(t *testing.T) {
	esc := url.QueryEscape
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(testECHConfig)
	on := &model.ECH{Enabled: true, Config: testECHConfig}
	for _, c := range []struct {
		name, link string
		want       *model.ECH
	}{
		{"vless, escaped (v2rayN)", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=" + esc(testECHConfig) + "#v", on},
		{"vless, '+' left raw", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=" + testECHConfig + "#v", on},
		{"vless, url-safe alphabet", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=" + urlSafe + "#v", on},
		{"trojan", "trojan://pw@192.0.2.2:443?sni=example.com&ech=" + esc(testECHConfig) + "#t", on},
		{"anytls (v2rayN)", "anytls://pw@192.0.2.3:443?sni=example.com&ech=" + esc(testECHConfig) + "#a", on},
		{"hysteria2 (Hysteria's own)", "hysteria2://pw@192.0.2.4:443/?sni=example.com&ech=" + esc(testECHConfig) + "#h", on},
		{"hysteria2 realm", "hysteria2+realm://tok@example.net/r1?auth=pw&sni=example.com&ech=" + esc(testECHConfig) + "#r", on},
		{"tuic (v2rayN)", "tuic://00000000-0000-4000-8000-000000000001:pw@192.0.2.5:443?sni=example.com&ech=" + esc(testECHConfig) + "#u", on},
		// Xray's "[queryName+]dnsURL": the record is looked up through the router's DNS, so only the
		// query name is kept.
		{"Xray DNS form with a query name", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=" + esc("example.net+https://dns.example.com/dns-query") + "#v",
			&model.ECH{Enabled: true, QueryServerName: "example.net"}},
		{"Xray DNS form, '+' left raw", "trojan://pw@192.0.2.2:443?sni=example.com&ech=example.net+udp://192.0.2.53#t",
			&model.ECH{Enabled: true, QueryServerName: "example.net"}},
		{"Xray DNS form without a query name", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=" + esc("h2c://192.0.2.53/dns-query") + "#v",
			&model.ECH{Enabled: true}},
		{"empty ech=", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&ech=#v", nil},
		{"no TLS, no ECH", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?ech=" + esc(testECHConfig) + "#v", nil},
		// v2rayN writes ech= on Reality links too; sing-box refuses the pair, so the config is kept off.
		{"Reality keeps the config off", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=reality&sni=example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&ech=" + esc(testECHConfig) + "#v",
			&model.ECH{Config: testECHConfig}},
		{"Reality drops the DNS form", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=reality&sni=example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&ech=" + esc("udp://192.0.2.53") + "#v", nil},
		{"Reality drops a garbled config", "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=reality&sni=example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&ech=AAAA#v", nil},
	} {
		e, err := Parse(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got *model.ECH
		if e.TLS != nil {
			got = e.TLS.ECH
		}
		if !sameECH(got, c.want) {
			t.Errorf("%s: ECH = %+v, want %+v", c.name, got, c.want)
		}
		if p := model.EndpointParamProblem(e); p != "" {
			t.Errorf("%s: imported connection has a problem: %s", c.name, p)
		}
	}
	// A garbled config on a TLS link is kept as given: the import stores the connection disabled and
	// says why, rather than quietly dropping the ECH the link asked for.
	e, err := Parse("trojan://pw@192.0.2.2:443?sni=example.com&ech=AAAA#t")
	if err != nil {
		t.Fatal(err)
	}
	if !sameECH(e.TLS.ECH, &model.ECH{Enabled: true, Config: "AAAA"}) || !strings.Contains(model.EndpointParamProblem(e), "invalid ECH config") {
		t.Errorf("garbled ech= = %+v, problem %q", e.TLS.ECH, model.EndpointParamProblem(e))
	}
	// sing-quic never runs the lookup, so the DNS form cannot work over QUIC. It is kept all the same,
	// so the import stores the connection disabled and asks for the server's config, rather than
	// bringing it up without the ECH the link asked for and saying nothing.
	for link, want := range map[string]*model.ECH{
		"hysteria2://pw@192.0.2.4:443/?sni=example.com&ech=" + url.QueryEscape("udp://192.0.2.53") + "#h": {Enabled: true},
		"tuic://00000000-0000-4000-8000-000000000001:pw@192.0.2.5:443?sni=example.com&ech=" + url.QueryEscape("example.net+udp://192.0.2.53") + "#u": {
			Enabled: true, QueryServerName: "example.net"},
	} {
		e, err := Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if p := model.EndpointParamProblem(e); !sameECH(e.TLS.ECH, want) || !strings.Contains(p, "paste the server's ECH config") {
			t.Errorf("%s: ECH = %+v, problem %q", link, e.TLS.ECH, p)
		}
	}
}

func TestECHFromClash(t *testing.T) {
	yaml := `proxies:
  - name: vless-block
    type: vless
    server: 192.0.2.1
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    servername: example.com
    ech-opts:
      enable: true
      config: ` + testECHConfig + `
  - {name: trojan-flow, type: trojan, server: 192.0.2.2, port: 443, password: pw, sni: example.com, ech-opts: {enable: true, query-server-name: example.net}}
  - name: hy2
    type: hysteria2
    server: 192.0.2.4
    port: 443
    password: pw
    sni: example.com
    ech-opts: {enable: true, config: "` + testECHConfig + `"}
  - name: tuic-dns
    type: tuic
    server: 192.0.2.5
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    password: pw
    ech-opts:
      enable: true
  - {name: vmess-off, type: vmess, server: 192.0.2.6, port: 443, uuid: 00000000-0000-4000-8000-000000000001, tls: true, ech-opts: {enable: false, config: ` + testECHConfig + `}}
  - {name: anytls, type: anytls, server: 192.0.2.7, port: 443, password: pw, sni: example.com, ech-opts: {enable: true}}
  - name: vless-reality
    type: vless
    server: 192.0.2.8
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    servername: example.com
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
    ech-opts:
      enable: true
      config: ` + testECHConfig + `
`
	eps, errs := ParseClash(yaml)
	if len(errs) > 0 {
		t.Fatalf("errs: %v", errs)
	}
	want := map[string]*model.ECH{
		"vless-block":   {Enabled: true, Config: testECHConfig},
		"trojan-flow":   {Enabled: true, QueryServerName: "example.net"},
		"hy2":           {Enabled: true, Config: testECHConfig},
		"tuic-dns":      {Enabled: true}, // kept: the import stores it disabled and asks for the config
		"vmess-off":     nil,             // mihomo ignores the block unless enable is true
		"anytls":        {Enabled: true},
		"vless-reality": {Config: testECHConfig},
	}
	if len(eps) != len(want) {
		t.Fatalf("got %d endpoints", len(eps))
	}
	for _, e := range eps {
		if !sameECH(e.TLS.ECH, want[e.Name]) {
			t.Errorf("%s: ECH = %+v, want %+v", e.Name, e.TLS.ECH, want[e.Name])
		}
	}
}

func TestECHFromSingboxConfig(t *testing.T) {
	cfg := `{"outbounds":[
  {"type":"vless","tag":"lines","server":"192.0.2.1","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEA","AQABAAIAAQADAAtleGFtcGxlLmNvbQAA","-----END ECH CONFIGS-----"]}}},
  {"type":"trojan","tag":"string","server":"192.0.2.2","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true,"config":"` + strings.ReplaceAll(testECHPEM, "\n", `\n`) + `"}}},
  {"type":"anytls","tag":"dns","server":"192.0.2.3","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true,"query_server_name":"example.net"}}},
  {"type":"hysteria2","tag":"hy2-dns","server":"192.0.2.4","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true}}},
  {"type":"vless","tag":"inline-wins","server":"192.0.2.5","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEA","AQABAAIAAQADAAtleGFtcGxlLmNvbQAA","-----END ECH CONFIGS-----"],"config_path":"/etc/ech.pem"}}},
  {"type":"vless","tag":"path","server":"192.0.2.6","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":true,"config_path":"/etc/ech.pem"}}},
  {"type":"vless","tag":"off","server":"192.0.2.7","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
   "tls":{"enabled":true,"server_name":"example.com","ech":{"enabled":false,"config_path":"/etc/ech.pem"}}}
]}`
	eps, errs := ParseSingbox(cfg)
	if len(errs) != 1 || !strings.Contains(errs[0], "config_path") || !strings.Contains(errs[0], "path") {
		t.Fatalf("want config_path refused for \"path\" alone, got %v", errs)
	}
	want := map[string]*model.ECH{
		"lines":       {Enabled: true, Config: testECHConfig},
		"string":      {Enabled: true, Config: testECHConfig},
		"dns":         {Enabled: true, QueryServerName: "example.net"},
		"hy2-dns":     {Enabled: true}, // kept, as from a link
		"inline-wins": {Enabled: true, Config: testECHConfig},
		"off":         nil,
	}
	if len(eps) != len(want) {
		t.Fatalf("got %d endpoints: %+v", len(eps), eps)
	}
	for _, e := range eps {
		if w, ok := want[e.Name]; !ok || !sameECH(e.TLS.ECH, w) {
			t.Errorf("%s: ECH = %+v, want %+v", e.Name, e.TLS.ECH, w)
		}
	}
}
