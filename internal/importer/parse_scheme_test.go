package importer

import (
	"testing"

	"wayhop/internal/model"
)

// TestParse_UppercaseScheme: an upper/mixed-case scheme (VMESS:// / SS://, which other clients
// treat case-insensitively) must import. Was: the dispatcher lowercased the scheme for routing
// but the vmess/ss parsers stripped "vmess://"/"ss://" case-sensitively, so the prefix survived
// and the body failed to decode ("invalid base64 body" / mis-split SS creds).
func TestParse_UppercaseScheme(t *testing.T) {
	js := `{"v":"2","ps":"up","add":"1.2.3.4","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"tcp","tls":""}`
	b := importer_b64std(js)
	for _, raw := range []string{"vmess://" + b, "VMESS://" + b, "VmEsS://" + b} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%s…): %v", raw[:8], err)
		}
		if e.Protocol != model.ProtoVMess || e.Server != "1.2.3.4" {
			t.Fatalf("Parse(%s…): proto/server = %s/%s", raw[:8], e.Protocol, e.Server)
		}
	}
	for _, raw := range []string{"ss://aes-256-gcm:pw@1.2.3.4:8388", "SS://aes-256-gcm:pw@1.2.3.4:8388"} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if e.Protocol != model.ProtoShadowsocks || e.Server != "1.2.3.4" || e.Port != 8388 {
			t.Fatalf("Parse(%q): proto/server/port = %s/%s/%d", raw, e.Protocol, e.Server, e.Port)
		}
	}
}
