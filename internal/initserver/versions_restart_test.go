package initserver

import (
	"os/exec"
	"strings"
	"testing"
)

// TestUpdateSingBoxScript_VerifiesRestartAndRollsBack guards the fix: the sing-box update
// must confirm the SERVICE actually restarted (not just that the new binary prints a
// version) and roll back to the backup + report WR_UPDATE_ERR if it didn't — otherwise a
// config-incompatible upgrade silently leaves the VPS endpoint dead while reporting success.
func TestUpdateSingBoxScript_VerifiesRestartAndRollsBack(t *testing.T) {
	s := UpdateSingBoxScript("1.12.17")
	for _, want := range []string{
		"is-active",         // systemd service-up check
		"pgrep -x sing-box", // non-systemd fallback
		"wayhop.bak",        // rollback source
		"WR_UPDATE_ERR=",    // failure signal → UpdateConfirmed ok=false
		"WR_UPDATE_OK=",     // success signal (happy path)
	} {
		if !strings.Contains(s, want) {
			t.Errorf("UpdateSingBoxScript missing %q (restart-verify/rollback regression):\n%s", want, s)
		}
	}
	// The success echo must be GATED behind the service check, not emitted unconditionally.
	ifIdx := strings.Index(s, "if systemctl is-active")
	okIdx := strings.Index(s, "WR_UPDATE_OK=")
	if ifIdx < 0 || okIdx < ifIdx {
		t.Errorf("WR_UPDATE_OK must come AFTER the is-active gate (if@%d, ok@%d)", ifIdx, okIdx)
	}
}

// TestUpdateSingBoxScript_ShellSyntax runs the generated script through `sh -n` (parse-only)
// so a shell typo in the update/rollback logic can't ship to a VPS. Skips where sh is absent.
func TestUpdateSingBoxScript_ShellSyntax(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH — skipping shell syntax check (runs in CI / dev)")
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(UpdateSingBoxScript("1.12.17"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n rejected the generated update script: %v\n%s", err, out)
	}
}
