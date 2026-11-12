package importer

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCipherSuitesImportAndReimport(t *testing.T) {
	const suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	link := "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&cs=" + suites + "#V"
	e, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
	if !reflect.DeepEqual(e.TLS.CipherSuites, want) {
		t.Fatalf("VLESS cs = %v, want %v", e.TLS.CipherSuites, want)
	}

	old := *e
	oldTLS := *e.TLS
	old.TLS = &oldTLS
	old.TLS.CipherSuites = []string{"TLS_OLD_SUITE"}
	merged := Reimport(old, *e)
	if !reflect.DeepEqual(merged.TLS.CipherSuites, want) {
		t.Errorf("re-import cs = %v, want the link's %v", merged.TLS.CipherSuites, want)
	}
	plain, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com#V")
	if err != nil {
		t.Fatal(err)
	}
	if got := Reimport(merged, *plain).TLS.CipherSuites; len(got) != 0 {
		t.Errorf("a link without cs kept %v", got)
	}

	vm, _ := json.Marshal(map[string]any{
		"v": "2", "add": "203.0.113.11", "port": 443, "id": "11111111-2222-3333-4444-555555555555",
		"tls": "tls", "sni": "example.com", "cs": suites,
	})
	v, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(vm))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.TLS.CipherSuites, want) {
		t.Errorf("VMess cs = %v, want %v", v.TLS.CipherSuites, want)
	}

	cfg := `{"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.12","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"example.com","cipher_suites":["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}}]}`
	eps, _ := ParseSubscription(cfg)
	if len(eps) != 1 {
		t.Fatalf("sing-box endpoints = %d, want one", len(eps))
	}
	s := eps[0]
	if got := s.TLS.CipherSuites; len(got) != 1 || got[0] != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("sing-box cipher_suites = %v", got)
	}
}
