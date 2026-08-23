package initserver

import (
	"strconv"
	"strings"
	"testing"
)

// TestUpdateSingBoxScript_SanitizesVersion is the regression guard for the remote
// command-injection fix: the update version reaches the remote shell via VER=%q and the
// ${VER} download URL, so the builder must embed ONLY the extracted x.y.z. A crafted
// version must never carry shell metacharacters into the generated script.
func TestUpdateSingBoxScript_SanitizesVersion(t *testing.T) {
	cases := map[string]string{
		"1.12.17":           "1.12.17",
		"v1.12.17":          "1.12.17",
		"1.2.3$(reboot)":    "1.2.3",
		"1.2.3`id`":         "1.2.3",
		"9.9.9; rm -rf /":   "9.9.9",
		"$(curl evil)1.0.0": "1.0.0",
		"nope":              "", // no x.y.z → "" → the script's own [ -n "$VER" ] guard aborts
	}
	for in, want := range cases {
		script := UpdateSingBoxScript(in)
		wantLine := "VER=" + strconv.Quote(want) // VER=%q
		if !strings.Contains(script, wantLine+"\n") {
			t.Errorf("UpdateSingBoxScript(%q): want VER line %q, got script:\n%s", in, wantLine, script[:min(220, len(script))])
		}
		// No injection residue from the crafted input. (NB: the template legitimately
		// contains `rm -rf "$TMP"` for temp cleanup, so we check the injection-specific
		// fragments, e.g. the "; rm -rf" the payload would add, not "rm -rf" alone.)
		for _, bad := range []string{"$(reboot)", "`id`", "; rm -rf", "curl evil"} {
			if strings.Contains(script, bad) {
				t.Errorf("UpdateSingBoxScript(%q): leaked %q into the generated script", in, bad)
			}
		}
	}
}

// TestCapWriter_BoundsOutput guards the OOM fix in Provision: capWriter keeps at most max
// bytes yet always reports a full write (so the child process is never blocked).
func TestCapWriter_BoundsOutput(t *testing.T) {
	cw := &capWriter{max: 10}
	n, err := cw.Write([]byte("0123456789ABCDEF")) // 16 bytes, cap 10
	if err != nil || n != 16 {
		t.Fatalf("Write = (%d,%v), want (16,nil) — must report the full write", n, err)
	}
	if got := cw.String(); got != "0123456789" {
		t.Errorf("capped buffer = %q, want first 10 bytes", got)
	}
	cw.Write([]byte("more output that must be dropped"))
	if got := cw.String(); len(got) != 10 {
		t.Errorf("buffer len = %d after extra writes, want 10 (stays capped)", len(got))
	}
}
