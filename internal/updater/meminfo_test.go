package updater

import "testing"

const miB = 1 << 20

func TestEnoughMemForDownload(t *testing.T) {
	cases := []struct {
		name      string
		avail     uint64
		known     bool
		assetSize int64
		want      bool
	}{
		{"unknown avail never blocks", 0, false, 25 * miB, true},
		{"unknown asset size never blocks", 10 * miB, true, 0, true},
		{"ax3000t sing-box blocked (38 MiB avail, ~95 MiB need)", 38 * miB, true, 25 * miB, false},
		{"ax3000t self-update allowed (38 MiB avail, ~29 MiB need)", 38 * miB, true, 6 * miB, true},
		{"plenty of ram allows a big asset", 512 * miB, true, 25 * miB, true},
		{"exact boundary is allowed", peakInstallRAM(10 * miB), true, 10 * miB, true},
		{"one byte under boundary blocks", peakInstallRAM(10*miB) - 1, true, 10 * miB, false},
	}
	for _, c := range cases {
		if got := enoughMemForDownload(c.avail, c.known, c.assetSize); got != c.want {
			t.Errorf("%s: enoughMemForDownload(%d, %v, %d) = %v, want %v (need ~%d MiB)",
				c.name, c.avail, c.known, c.assetSize, got, c.want, peakInstallRAM(c.assetSize)>>20)
		}
	}
}

func TestPeakInstallRAM(t *testing.T) {
	// ~3.5x the compressed size + 8 MiB margin.
	if got, want := peakInstallRAM(10*miB), uint64(10*miB)*7/2+(8*miB); got != want {
		t.Errorf("peakInstallRAM(10 MiB) = %d, want %d", got, want)
	}
	if peakInstallRAM(0) != (8 * miB) {
		t.Errorf("peakInstallRAM(0) should be just the 8 MiB margin, got %d", peakInstallRAM(0))
	}
}

// TestInstallRAMGate_DeviceReport prints the real install-RAM decision for the host it runs on
// (cross-compile with `go test -c` and run the binary on the AX3000T to see the on-device verdict).
// It asserts the gate agrees with the arithmetic for the host's measured available memory.
func TestInstallRAMGate_DeviceReport(t *testing.T) {
	avail, ok := availMemBytes()
	t.Logf("availMemBytes() = %d MiB (ok=%v)", avail>>20, ok)
	for _, c := range []struct {
		name string
		size int64
	}{
		{"sing-box (~25 MiB asset)", 25 * miB},
		{"olcRTC (~15 MiB asset)", 15 * miB},
		{"velinx self-update (~6 MiB asset)", 6 * miB},
	} {
		allowed := enoughMemForDownload(avail, ok, c.size)
		verdict := "BLOCKED (clean error, no OOM)"
		if allowed {
			verdict = "ALLOWED"
		}
		t.Logf("  %-38s need ~%4d MiB -> %s", c.name, peakInstallRAM(c.size)>>20, verdict)
		if ok {
			if want := avail >= peakInstallRAM(c.size); allowed != want {
				t.Errorf("%s: gate=%v but (avail %d >= need %d) = %v", c.name, allowed, avail, peakInstallRAM(c.size), want)
			}
		}
	}
}
