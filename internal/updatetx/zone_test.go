package updatetx

import (
	"strings"
	"testing"
	"time"

	"wayhop/internal/localtz"
)

// QA-131. The note is written in the zone of the now it is given, and names it. Go's time.Local is UTC
// on Keenetic and OpenWrt, so a rollback the router's clock put at 22:20 in UTC+3 read 19:20 in the
// panel, the bot's /update view and the boot alert, beside bot times in router time. The zone here is
// five hours off this host's own, so a time formatted in time.Local cannot pass.
func TestNoteIsWrittenInTheGivenZone(t *testing.T) {
	_, off := time.Now().Zone()
	router := time.FixedZone("", off+5*3600)
	at := time.Date(2026, 10, 30, 22, 20, 0, 0, router)
	for _, result := range []string{"rolled_back", "failed"} {
		r := Result{Result: result, To: "v0.5.8", Reason: "the new build does not stay running", At: at.Unix()}
		n := r.Note(at.Add(time.Minute))
		if want := "at 2026-10-30 22:20 (" + localtz.Label(at) + "):"; !strings.Contains(n, want) {
			t.Errorf("%s: note %q, want it to say %q", result, n, want)
		}
	}
}
