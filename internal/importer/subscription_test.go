package importer

import (
	"encoding/base64"
	"testing"
)

func TestParseSubscriptionBase64(t *testing.T) {
	links := "vless://uuid-1@1.1.1.1:443?security=reality&pbk=K&sni=a.com#A\n" +
		"hysteria2://pw@2.2.2.2:8443?sni=b.com#B\n" +
		"# a comment line\n" +
		"garbage-not-a-link\n"
	blob := base64.StdEncoding.EncodeToString([]byte(links))

	eps, errs := ParseSubscription(blob)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d (errs=%v)", len(eps), errs)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error (the garbage line), got %d: %v", len(errs), errs)
	}
}

func TestParseSubscriptionPlain(t *testing.T) {
	ss := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@4.4.4.4:8388#S"
	plain := "trojan://pw@3.3.3.3:443#T\n" + ss + "\n"
	eps, _ := ParseSubscription(plain)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(eps))
	}
}
