package keenetic

import (
	"context"
	"strings"
	"testing"
)

// TestRCIErrors_RealFormats validates the parser against responses captured verbatim from
// the live reference router (KeeneticOS 5.1.0 RCI).
func TestRCIErrors_RealFormats(t *testing.T) {
	// Exact error object from an invalid command on the device.
	errObj := `{"prompt":"(config)","status":[{"status":"error","code":"7405600","ident":"Command::Base","message":"no such command: foobar-nonexistent-xyz."}]}`
	if errs := rciErrors([]byte(errObj)); len(errs) != 1 || errs[0] != "no such command: foobar-nonexistent-xyz." {
		t.Errorf("error object → %v", errs)
	}

	// Successful show (data, no status array) → no errors.
	if errs := rciErrors([]byte(`{"release":"5.01.C.0.0-1","title":"5.1.0","arch":"aarch64"}`)); len(errs) != 0 {
		t.Errorf("ok show → %v, want none", errs)
	}

	// Batch [success, error] → the error surfaces.
	batch := `[{"release":"5.1.0"},{"prompt":"(config)","status":[{"status":"error","message":"bad route"}]}]`
	if errs := rciErrors([]byte(batch)); len(errs) != 1 || errs[0] != "bad route" {
		t.Errorf("batch → %v", errs)
	}

	// Batch all-success → none (a config command may report status:message/ok).
	if errs := rciErrors([]byte(`[{"release":"5.1.0"},{"status":[{"status":"message","message":"ok"}]}]`)); len(errs) != 0 {
		t.Errorf("all-success batch → %v", errs)
	}

	// status warning/message are NOT errors.
	if errs := rciErrors([]byte(`{"status":[{"status":"warning","message":"heads up"}]}`)); len(errs) != 0 {
		t.Errorf("warning → %v, want none", errs)
	}

	// ident fallback when message empty.
	if errs := rciErrors([]byte(`{"status":[{"status":"error","ident":"Command::Foo"}]}`)); len(errs) != 1 || errs[0] != "Command::Foo" {
		t.Errorf("ident fallback → %v", errs)
	}

	// Garbage → no panic, no errors.
	if errs := rciErrors([]byte(`not json`)); len(errs) != 0 {
		t.Errorf("garbage → %v", errs)
	}
}

// TestParseBatch_NDMError: an NDM-rejected command (HTTP 200 + error status) makes ParseBatch
// fail, so Apply/Teardown can't report success on a half-applied config.
func TestParseBatch_NDMError(t *testing.T) {
	ts, _ := fakeKeenetic(t, "admin", "secret")
	c, _ := NewRCIClient(ts.URL, "admin", "secret")
	_, err := c.ParseBatch(context.Background(), []string{"interface Wireguard10", "FAILCMD bad"})
	if err == nil || !strings.Contains(err.Error(), "mock rejected FAILCMD") {
		t.Errorf("ParseBatch must surface the NDM command error, got %v", err)
	}
}

// TestParse_NDMError: a SINGLE Parse must also fail closed on an NDM rejection (NDM returns HTTP 200
// with a status=="error" body), not just ParseBatch — else a one-command Apply reports success on a
// rejected command.
func TestParse_NDMError(t *testing.T) {
	ts, _ := fakeKeenetic(t, "admin", "secret")
	c, _ := NewRCIClient(ts.URL, "admin", "secret")
	if _, err := c.Parse(context.Background(), "FAILCMD bad"); err == nil || !strings.Contains(err.Error(), "mock rejected FAILCMD") {
		t.Errorf("Parse must surface the NDM command error, got %v", err)
	}
	if _, err := c.Parse(context.Background(), "interface Wireguard10"); err != nil {
		t.Errorf("Parse of a valid command must succeed, got %v", err)
	}
}
