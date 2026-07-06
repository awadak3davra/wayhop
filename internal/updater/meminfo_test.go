package updater

import "testing"

const miB = 1 << 20

func TestEnoughMemForUpdate(t *testing.T) {
	const gz = "sing-box-linux-arm64.tar.gz" // compressed -> 3x unpacked
	const bare = "olcrtc-linux-arm64"        // bare binary -> 1x
	cases := []struct {
		name      string
		avail     uint64
		known     bool
		assetSize int64
		assetName string
		want      bool
	}{
		{"unknown avail never blocks", 0, false, 25 * miB, gz, true},
		{"unknown asset size never blocks", 10 * miB, true, 0, gz, true},
		// sing-box .tar.gz: 25 MiB compressed -> 75 unpacked + 16 floor = 91 MiB.
		{"sing-box blocked (38 MiB avail, ~91 need)", 38 * miB, true, 25 * miB, gz, false},
		{"sing-box allowed (128 MiB avail)", 128 * miB, true, 25 * miB, gz, true},
		// wayhop self-update .tar.gz: 6 MiB -> 18 unpacked + 16 = 34 MiB.
		{"self-update allowed (38 MiB avail, ~34 need)", 38 * miB, true, 6 * miB, gz, true},
		// bare binary is NOT tripled: 27 MiB olcrtc -> 27 + 16 = 43 MiB (not ~97).
		{"bare olcrtc allowed (50 MiB avail, ~43 need)", 50 * miB, true, 27 * miB, bare, true},
		{"bare olcrtc blocked (40 MiB avail, ~43 need)", 40 * miB, true, 27 * miB, bare, false},
		{"exact boundary allowed", updateMemNeed(10*miB, gz), true, 10 * miB, gz, true},
		{"one byte under blocks", updateMemNeed(10*miB, gz) - 1, true, 10 * miB, gz, false},
	}
	for _, c := range cases {
		if got := enoughMemForUpdate(c.avail, c.known, c.assetSize, c.assetName); got != c.want {
			t.Errorf("%s: enoughMemForUpdate(%d,%v,%d,%q) = %v, want %v (need ~%d MiB)",
				c.name, c.avail, c.known, c.assetSize, c.assetName, got, c.want, updateMemNeed(c.assetSize, c.assetName)>>20)
		}
	}
}

func TestUpdateMemNeed(t *testing.T) {
	// compressed: 3x + 16 MiB restart floor.
	if got, want := updateMemNeed(10*miB, "x.tar.gz"), uint64(10*miB)*3+(16*miB); got != want {
		t.Errorf("updateMemNeed(10 MiB gz) = %d, want %d", got, want)
	}
	// bare: 1x + 16 MiB (matches the disk fix — a raw binary is already unpacked).
	if got, want := updateMemNeed(10*miB, "olcrtc-linux-arm64"), uint64(10*miB)+(16*miB); got != want {
		t.Errorf("updateMemNeed(10 MiB bare) = %d, want %d", got, want)
	}
}

// TestUpdateMemGate_DeviceReport prints the real update-RAM decision for the host it runs on
// (cross-compile with `go test -c` + run on the router to see the on-device verdict).
func TestUpdateMemGate_DeviceReport(t *testing.T) {
	avail, ok := availMemBytes()
	t.Logf("availMemBytes() = %d MiB (ok=%v)", avail>>20, ok)
	for _, c := range []struct {
		label string
		size  int64
		asset string
	}{
		{"sing-box (~25 MiB .tar.gz)", 25 * miB, "sing-box-linux-arm64.tar.gz"},
		{"olcRTC (~27 MiB bare)", 27 * miB, "olcrtc-linux-arm64"},
		{"wayhop self-update (~6 MiB .tar.gz)", 6 * miB, "wayhop-arm64.tar.gz"},
	} {
		allowed := enoughMemForUpdate(avail, ok, c.size, c.asset)
		verdict := "BLOCKED (clean error, no OOM)"
		if allowed {
			verdict = "ALLOWED"
		}
		t.Logf("  %-38s need ~%4d MiB -> %s", c.label, updateMemNeed(c.size, c.asset)>>20, verdict)
		if ok {
			if want := avail >= updateMemNeed(c.size, c.asset); allowed != want {
				t.Errorf("%s: gate=%v but (avail>=need)=%v", c.label, allowed, want)
			}
		}
	}
}
