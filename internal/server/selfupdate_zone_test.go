package server

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/localtz"
	"wayhop/internal/updatetx"
)

// QA-131. The rollback note reaches the panel (last_update_note) and the bot's boot alert in the
// router's zone, named. time.Local is UTC on Keenetic and OpenWrt, so a rollback at 22:20 router time
// in UTC+3 read 19:20, next to bot times in router time. The zone is five hours off this host's own,
// so a time formatted in time.Local cannot pass.
func TestTheRollbackNoteNamesTheRoutersTime(t *testing.T) {
	s, _ := txServer(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	_, off := at.In(time.Local).Zone()
	zone := time.FixedZone("", off+5*3600)
	s.updZone = func() *time.Location { return zone }
	line := `{"result":"rolled_back","reason":"the new build does not stay running","to":"v0.5.8","by":"panel","at":` +
		strconv.FormatInt(at.Unix(), 10) + "}\n"
	if err := os.WriteFile(filepath.Join(s.updateDir(), updatetx.ResultFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	local := at.In(zone)
	want := "rolled back at " + local.Format("2006-01-02 15:04") + " (" + localtz.Label(local) + ")"

	out := map[string]any{}
	s.selfUpdateReport(out)
	if n, _ := out["last_update_note"].(string); !strings.Contains(n, want) {
		t.Errorf("last_update_note = %q; want it to say %q", n, want)
	}

	s.startedAt = at.Add(30 * time.Second)
	if bi := s.readBootInfo(); !strings.Contains(bi.UpdateNote, want) {
		t.Errorf("boot alert note = %q; want it to say %q", bi.UpdateNote, want)
	}
}
