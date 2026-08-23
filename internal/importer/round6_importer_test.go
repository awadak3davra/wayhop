package importer

import (
	"encoding/base64"
	"testing"
)

// TestParseShadowsocks_SIP002TrailingSlash: the SIP002-canonical Shadowsocks URI has an optional '/'
// between host:port and the '?plugin' query (the spec's own plugin example uses it). It must parse,
// not be silently dropped with 'ss: missing host/port' because net.SplitHostPort saw port="8388/".
func TestParseShadowsocks_SIP002TrailingSlash(t *testing.T) {
	ui := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass123"))
	for _, raw := range []string{
		"ss://" + ui + "@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp#Node", // canonical plugin form
		"ss://" + ui + "@1.2.3.4:8388/#Node",                                 // plain trailing slash
		"ss://" + ui + "@1.2.3.4:8388#Node",                                  // no slash (must still work)
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: parse error: %v", raw, err)
		}
		if e.Server != "1.2.3.4" || e.Port != 8388 {
			t.Errorf("%s: server/port = %q/%d, want 1.2.3.4/8388", raw, e.Server, e.Port)
		}
	}
}

// TestParse_RejectsOutOfRangePort: a share link with an out-of-range but digit-valid port (url.Parse
// accepts it) must be rejected at the parse boundary, not persisted to FATAL every future Apply.
func TestParse_RejectsOutOfRangePort(t *testing.T) {
	ui := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	for _, raw := range []string{
		"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:999999#x",
		"trojan://pw@1.2.3.4:70000#x",
		"ss://" + ui + "@1.2.3.4:88888#x",
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: out-of-range port must be rejected", raw)
		}
	}
	if _, err := Parse("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#ok"); err != nil {
		t.Errorf("valid port rejected: %v", err)
	}
}
