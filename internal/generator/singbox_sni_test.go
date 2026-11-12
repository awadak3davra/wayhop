package generator

import (
	"bytes"
	"encoding/json"
	"testing"

	"wayhop/internal/model"
)

func TestGenerateDNSServerSNI(t *testing.T) {
	// Acceptance test 11:
	// Generator: tls.server_name present with SNI; byte-identical without.

	// 1. Verify byte-identical without SNI:
	baseDNS := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "cf", Type: "https", Server: "1.1.1.1", Enabled: true},
			{Tag: "quad9", Type: "tls", Server: "9.9.9.9", Enabled: true},
			{Tag: "quic-srv", Type: "quic", Server: "94.140.14.14", Enabled: true},
			{Tag: "h3-srv", Type: "h3", Server: "1.1.1.1", Enabled: true},
			{Tag: "plain", Type: "udp", Server: "8.8.8.8", Enabled: true},
		},
		Final: "cf",
	}
	dnsEmptySNI := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "cf", Type: "https", Server: "1.1.1.1", SNI: "", Enabled: true},
			{Tag: "quad9", Type: "tls", Server: "9.9.9.9", SNI: "", Enabled: true},
			{Tag: "quic-srv", Type: "quic", Server: "94.140.14.14", SNI: "", Enabled: true},
			{Tag: "h3-srv", Type: "h3", Server: "1.1.1.1", SNI: "", Enabled: true},
			{Tag: "plain", Type: "udp", Server: "8.8.8.8", SNI: "", Enabled: true},
		},
		Final: "cf",
	}

	opts := Options{CoreVersion: "1.12.17"}
	resBase, err := Generate(genDNSProfile(baseDNS), opts)
	if err != nil {
		t.Fatalf("Generate base: %v", err)
	}
	resEmpty, err := Generate(genDNSProfile(dnsEmptySNI), opts)
	if err != nil {
		t.Fatalf("Generate empty SNI: %v", err)
	}

	jsonBase, err := json.Marshal(resBase.Config)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}
	jsonEmpty, err := json.Marshal(resEmpty.Config)
	if err != nil {
		t.Fatalf("marshal empty SNI: %v", err)
	}

	if !bytes.Equal(jsonBase, jsonEmpty) {
		t.Fatalf("expected byte-identical output with empty SNI, got:\nBase:  %s\nEmpty: %s", jsonBase, jsonEmpty)
	}

	// 2. Verify tls.server_name present when SNI is set on encrypted servers,
	// and omitted on unencrypted servers even if SNI is provided.
	dnsWithSNI := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "cf", Type: "https", Server: "1.1.1.1", SNI: "cloudflare-dns.com", Enabled: true},
			{Tag: "quad9", Type: "tls", Server: "9.9.9.9", SNI: "dns.quad9.net", Enabled: true},
			{Tag: "quic-srv", Type: "quic", Server: "94.140.14.14", SNI: "dns.adguard-dns.com", Enabled: true},
			{Tag: "h3-srv", Type: "h3", Server: "1.1.1.1", SNI: "cloudflare-dns.com", Enabled: true},
			{Tag: "plain", Type: "udp", Server: "8.8.8.8", SNI: "dns.google", Enabled: true},
		},
		Final: "cf",
	}

	profWithSNI := genDNSProfile(dnsWithSNI)
	if err := profWithSNI.ValidateDNS(); err != nil {
		t.Fatalf("ValidateDNS failed with SNI: %v", err)
	}

	resSNI, err := Generate(profWithSNI, opts)
	if err != nil {
		t.Fatalf("Generate with SNI: %v", err)
	}

	dnsBlock, ok := resSNI.Config["dns"].(map[string]any)
	if !ok {
		t.Fatalf("no dns block in config")
	}
	servers, ok := dnsBlock["servers"].([]map[string]any)
	if !ok {
		t.Fatalf("no servers in dns block")
	}

	serverByTag := make(map[string]map[string]any)
	for _, s := range servers {
		tag, _ := s["tag"].(string)
		serverByTag[tag] = s
	}

	for _, tc := range []struct {
		tag     string
		wantSNI string
	}{
		{"cf", "cloudflare-dns.com"},
		{"quad9", "dns.quad9.net"},
		{"quic-srv", "dns.adguard-dns.com"},
		{"h3-srv", "cloudflare-dns.com"},
	} {
		srv, exists := serverByTag[tc.tag]
		if !exists {
			t.Errorf("server %q missing from emitted config", tc.tag)
			continue
		}
		tlsObj, ok := srv["tls"].(map[string]any)
		if !ok {
			t.Errorf("server %q expected tls block, got none: %#v", tc.tag, srv)
			continue
		}
		if gotSNI, _ := tlsObj["server_name"].(string); gotSNI != tc.wantSNI {
			t.Errorf("server %q tls.server_name = %q, want %q", tc.tag, gotSNI, tc.wantSNI)
		}
	}

	// Plain UDP server must not have tls emitted:
	plainSrv, exists := serverByTag["plain"]
	if !exists {
		t.Fatalf("plain server missing")
	}
	if _, hasTLS := plainSrv["tls"]; hasTLS {
		t.Errorf("plain UDP server must not emit tls block, got: %#v", plainSrv["tls"])
	}
}
