package generator

import (
	"testing"

	"wayhop/internal/model"
)

func TestCipherSuitesOnlyUseStandardTLS(t *testing.T) {
	suites := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	plain := tlsJSON(&model.TLS{Enabled: true, Type: "tls", CipherSuites: suites})
	if got, ok := plain["cipher_suites"].([]string); !ok || len(got) != 1 || got[0] != suites[0] {
		t.Errorf("standard TLS cipher_suites = %v", plain["cipher_suites"])
	}

	utls := tlsJSON(&model.TLS{Enabled: true, Type: "tls", Fingerprint: "chrome", CipherSuites: suites})
	if _, ok := utls["cipher_suites"]; ok {
		t.Errorf("uTLS must use its own ClientHello, got cipher_suites: %v", utls)
	}
	reality := tlsJSON(&model.TLS{Enabled: true, Type: "reality", CipherSuites: suites})
	if _, ok := reality["cipher_suites"]; ok {
		t.Errorf("Reality must not carry cipher_suites: %v", reality)
	}
}
