package updater

import (
	"strings"
	"testing"
)

// The refusal the test router actually produced, and what was wrong with it.
//
//	not enough free space to install olcrtc in /usr/bin (~24 MiB free, need ~31 MiB for the
//	unpacked binary) — free space, mount external storage, or install over SSH
//
// Both numbers are true and the refusal itself is correct — the overlay there is 60.6 MiB with
// 23.9 MiB free, so the pre-flight is right to stop. What the sentence does not do is tell the
// operator what to DO with it: the amount to free has to be worked out by subtracting two rounded
// figures, and "mount external storage" names nothing the panel can act on, because the install
// directory is fixed to the directory of the configured sing-box binary
// (server.go: updater.New(filepath.Dir(cfg.SingBox.Bin), …)). That path IS an editable field on the
// Settings page, so the lever exists — it was just never named.
func TestFlashRefusalIsActionable(t *testing.T) {
	// The router's own numbers: 23.9 MiB free against a 31 MiB need.
	const avail = 23*1024*1024 + 900*1024
	const need = 31 * 1024 * 1024
	msg := flashRefusal("olcrtc", "/usr/bin", avail, need).Error()

	for _, want := range []string{
		"olcrtc",          // which engine
		"/usr/bin",        // where it would have gone
		"~23 MiB",         // what is free
		"~31 MiB",         // what it needs
		"8 MiB",           // THE SHORTFALL: how much has to be freed, rounded up so acting on it works
		"sing-box binary", // the setting that decides the directory — the lever "mount external storage" implied and never named
		"SSH",             // the way out that needs no panel at all
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the disk refusal does not mention %q — a refusal the operator cannot act on is a dead end.\ngot: %s", want, msg)
		}
	}
}

// The shortfall must round UP. Freeing the floored difference leaves the pre-flight refusing again,
// which turns a number presented as an instruction into a second dead end.
func TestFlashShortfallRoundsUp(t *testing.T) {
	cases := []struct {
		avail, need uint64
		want        uint64
	}{
		{avail: 24 << 20, need: 31 << 20, want: 7},
		{avail: 23*1024*1024 + 900*1024, need: 31 << 20, want: 8}, // 7.1 MiB short -> 8, not 7
		{avail: 31 << 20, need: 31 << 20, want: 0},
		{avail: 40 << 20, need: 31 << 20, want: 0}, // never negative
		{avail: 31<<20 - 1, need: 31 << 20, want: 1},
	}
	for _, c := range cases {
		if got := shortfallMiB(c.avail, c.need); got != c.want {
			t.Errorf("shortfallMiB(%d, %d) = %d, want %d", c.avail, c.need, got, c.want)
		}
	}
}

// The self-update refusal names a directory the panel cannot move, so it must NOT repeat the engine
// advice about the sing-box binary setting — but it owes the operator the same number.
func TestSelfFlashRefusalNamesTheShortfallButNotTheEngineLever(t *testing.T) {
	p := selfPlan{known: true, room: 23*1024*1024 + 900*1024, need: 40 << 20}
	msg := selfRefusal("/usr/bin", p, 0).Error()
	if !strings.Contains(msg, "17 MiB") {
		t.Errorf("the self-update refusal does not say how much to free.\ngot: %s", msg)
	}
	if strings.Contains(msg, "sing-box binary") {
		t.Errorf("the self-update refusal points at a setting that does not move the daemon's own directory.\ngot: %s", msg)
	}
}

// Below "the new binary fits" the running daemon cannot do better in place: it holds its own inode
// until it restarts. The installer can (it stops the daemon and keeps the old binary compressed), so
// the refusal names it with the room it needs — but only when that room is actually there.
func TestSelfRefusalNamesTheInstallerOnlyWhenItWouldFit(t *testing.T) {
	const mib = 1 << 20
	old := uint64(14 * mib)
	// 10 MiB of room against a 14 MiB binary: in place no, compressed (~7.7 + 2 MiB) yes.
	fits := selfRefusal("/usr/sbin", selfPlan{known: true, room: 10 * mib, need: 14*mib + selfMargin}, old).Error()
	if !strings.Contains(fits, "re-run the installer") || !strings.Contains(fits, "keeps the old binary compressed") {
		t.Errorf("the refusal does not name the installer that would fit.\ngot: %s", fits)
	}
	// 5 MiB: not even the compressed copy fits, so the installer must not be offered as the way out.
	none := selfRefusal("/usr/sbin", selfPlan{known: true, room: 5 * mib, need: 14*mib + selfMargin}, old).Error()
	if strings.Contains(none, "installer") {
		t.Errorf("the refusal offers an installer run that would refuse too.\ngot: %s", none)
	}
	if !strings.Contains(none, "11 MiB") {
		t.Errorf("the refusal does not say how much to free (16 needed, 5 there).\ngot: %s", none)
	}
}
