package initserver

import (
	"strings"
	"testing"
)

// TestBuildScriptHysteria2Salamander: a provisioned Hysteria2 server enables Salamander
// obfuscation (server inbound + a persisted obfs password), and the generated client link
// carries obfs=salamander&obfs-password so a WR-imported endpoint matches the server. WR's
// importer/generator already round-trip those params, so this closes the loop end-to-end.
func TestBuildScriptHysteria2Salamander(t *testing.T) {
	s := BuildScript([]string{ProtoHysteria2}, "203.0.113.9")

	if !strings.Contains(s, `"obfs":{"type":"salamander","password":"$HY2OBFS"}`) {
		t.Errorf("Hysteria2 server inbound is missing the Salamander obfs block:\n%s", s)
	}
	if !strings.Contains(s, "wr-hy2-obfs") {
		t.Error("the Salamander obfs password is not generated/persisted")
	}
	if !strings.Contains(s, "obfs=salamander&obfs-password=$HY2OBFSENC") {
		t.Errorf("client link is missing the salamander obfs params:\n%s", s)
	}
}
