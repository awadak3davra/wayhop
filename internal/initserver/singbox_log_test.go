package initserver

import (
	"strings"
	"testing"
)

// A provisioned sing-box logs warnings only: with no log block it logs at trace, and its info lines
// alone are a journal of every user's destinations (QA-052). Both unit writers drop the fragment in,
// so it is there whichever protocol ran last.
func TestScriptSingboxLogsWarningsOnly(t *testing.T) {
	const frag = `cat > /etc/sing-box/conf.d/wr-log.json <<'WRLOG'
{"log":{"level":"warn","timestamp":true}}
WRLOG`
	for _, proto := range []string{ProtoReality, ProtoShadowsocks} {
		s := BuildScript([]string{proto}, "198.51.100.9")
		if !strings.Contains(s, frag) {
			t.Errorf("%s: the script does not write the warn-level log fragment", proto)
		}
	}
	if n := strings.Count(scriptReality+singboxServiceUnit, frag); n != 2 {
		t.Errorf("log fragment written by %d unit writers, want both", n)
	}
}
