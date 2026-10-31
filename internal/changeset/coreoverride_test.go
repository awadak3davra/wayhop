package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// The core override is in the Apply revision, so changing it must produce a review row (or the panel
// raises "unapplied changes" over an empty list), the row must name keys and never the text (a
// prepended outbound carries credentials), and it must undo like the other settings.
func TestDiffAndUndo_CoreOverride(t *testing.T) {
	secret := `{"log":{"level":"info"},"prepend":{"outbounds":[{"type":"trojan","tag":"t","password":"hunter2"}]}}`
	p := model.Profile{}
	for _, tc := range []struct {
		name, before, after, wantBefore, wantAfter string
	}{
		{"set", "", secret, "none", "touches log, outbounds"},
		{"cleared", secret, "", "touches log, outbounds", "none"},
		{"edited, same keys", `{"log":{"level":"info"}}`, `{"log":{"level":"debug"}}`, "touches log", "touches log (edited)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, d := config.Config{CoreOverride: tc.before}, config.Config{CoreOverride: tc.after}
			var row *Change
			for _, c := range Diff("a", "b", p, p, b, d).Changes {
				if c.Field == "Core override" {
					c := c
					row = &c
				}
			}
			if row == nil {
				t.Fatal("no review row for a changed core override")
			}
			if row.Before != tc.wantBefore || row.After != tc.wantAfter || !row.MayInterrupt {
				t.Errorf("row = %q -> %q (may interrupt %v)", row.Before, row.After, row.MayInterrupt)
			}
			if strings.Contains(row.Before+row.After, "hunter2") {
				t.Error("the review row carries the override's text")
			}
			_, got, err := Undo(p, p, b, d, UndoRequest{Scope: ScopeField, ID: "settings", Field: "Core override"})
			if err != nil || got.CoreOverride != tc.before {
				t.Errorf("undo = %q, %v; want the baseline %q", got.CoreOverride, err, tc.before)
			}
		})
	}
}
