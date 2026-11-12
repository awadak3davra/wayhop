package exporter

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"wayhop/internal/model"
)

func TestCipherSuitesExport(t *testing.T) {
	suites := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
	q := url.Values{}
	setTLSQuery(q, &model.TLS{Enabled: true, Type: "tls", CipherSuites: suites})
	if got := q.Get("cs"); got != suites[0]+","+suites[1] {
		t.Errorf("VLESS/Trojan cs = %q", got)
	}

	e := model.Endpoint{Name: "v", Protocol: model.ProtoVMess, Server: "203.0.113.10", Port: 443,
		Params: map[string]any{"uuid": "u"}, TLS: &model.TLS{Enabled: true, Type: "tls", CipherSuites: suites}}
	raw := vmessLink(e)
	body, err := base64.StdEncoding.DecodeString(raw[len("vmess://"):])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded["cs"]; got != suites[0]+","+suites[1] {
		t.Errorf("VMess cs = %v", got)
	}
}
