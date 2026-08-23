package importer

import (
	"strings"
	"testing"
)

// LOOP-021: a share link IS the secret — the UUID/password/private key rides in it — and a malformed
// one used to be echoed verbatim into the importer's error, which /api/import returns as its response
// body and the subscription path folds into its error list (reaching toasts, last_error, logs). These
// tests use unique credential sentinels and assert none of them survive into any error, while the
// user still gets the scheme (and, for a subscription, the line number) to locate the bad entry.
//
// A "%zz" is an invalid percent-escape, so url.Parse — and thus Parse — fails on an otherwise
// credential-shaped link, exercising exactly the path that leaked.

func TestParse_MalformedLinkDoesNotLeakCredential(t *testing.T) {
	const uuid = "SENTINEL-UUID-1111-2222-3333"
	_, err := Parse("vless://" + uuid + "%zz@host.example:443?flow=xtls-rprx-vision")
	if err == nil {
		t.Fatal("expected Parse to fail on the invalid percent-escape")
	}
	if strings.Contains(err.Error(), uuid) {
		t.Fatalf("a malformed vless link leaked its UUID into the error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "vless") {
		t.Errorf("the error should still name the scheme for the user, got %q", err.Error())
	}
}

func TestParseSubscription_DoesNotLeakCredentialLines(t *testing.T) {
	const secret = "SENTINEL-PASSWORD-9f8e7d6c"
	sub := "vless://good-uuid@1.1.1.1:443#ok\n" +
		"trojan://" + secret + "%zz@bad.example:443#node\n"
	eps, errs := ParseSubscription(sub)
	if len(eps) != 1 {
		t.Fatalf("want 1 good endpoint, got %d", len(eps))
	}
	if len(errs) != 1 {
		t.Fatalf("want exactly 1 error, got %d: %v", len(errs), errs)
	}
	if strings.Contains(errs[0], secret) {
		t.Fatalf("the subscription error leaked the credential line: %q", errs[0])
	}
	// The bad entry is the second line; the error locates it by line number and scheme.
	if !strings.Contains(errs[0], "line 2") {
		t.Errorf("error should carry the line number, got %q", errs[0])
	}
	if !strings.Contains(errs[0], "trojan") {
		t.Errorf("error should carry the scheme, got %q", errs[0])
	}
}
