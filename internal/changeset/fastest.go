package changeset

import (
	"fmt"
	"strings"
	"time"

	"wayhop/internal/model"
)

// candidatesWord is a list's tunnel set for a review row.
func candidatesWord(c []string) string {
	if len(c) == 0 {
		return "its outbound only"
	}
	return strings.Join(c, ", ")
}

// FastestWord renders a list's fastest-tunnel setting for a review row: every field that changes the
// runtime choice appears, so any edit to it shows as a difference.
func FastestWord(f *model.FastestPolicy) string {
	if f == nil {
		return "off"
	}
	var b strings.Builder
	if f.Enabled {
		b.WriteString("on")
	} else {
		b.WriteString("off")
	}
	mode := string(f.Mode)
	if mode == "" {
		mode = "auto" // the list's own default (mixed for a media list, else latency); no list here
	}
	fmt.Fprintf(&b, "; mode %s; every %d s; switch when %d ms and %d %% faster; at least %d s on a tunnel; all down: %s",
		mode, f.Interval(), f.DeltaMs(), f.DeltaPct(), f.Dwell(), f.AllDown())
	if len(f.Targets) > 0 {
		b.WriteString("; targets " + strings.Join(f.Targets, ", "))
	}
	if f.Pinned != "" {
		b.WriteString("; pinned to " + f.Pinned)
		if f.PinnedUntil > 0 {
			b.WriteString(" until " + time.Unix(f.PinnedUntil, 0).UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	if len(f.Excluded) > 0 {
		b.WriteString("; excluded " + strings.Join(f.Excluded, ", "))
	}
	if f.ResetOnSwitch {
		b.WriteString("; resets connections")
	}
	if f.Notify {
		b.WriteString("; tells Telegram")
	}
	return b.String()
}
