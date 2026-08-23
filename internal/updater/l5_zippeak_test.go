package updater

import "testing"

// TestPeakInstallDiskCountsTheStagedZip (L5): the pre-flight that exists to refuse BEFORE a mid-write
// ENOSPC has to count every byte that is on disk at the peak.
//
// A .zip cannot be streamed — zip needs random access, so streamAssetToFile writes the whole archive
// to dstPath+".zip" on the TARGET filesystem and unpacks it from there. Both files exist at once.
// The estimate counted only the unpacked binary, so it was short by the archive.
//
// Not hypothetical: Xray-core is in this catalogue and publishes zips — the release checked while
// writing this carried Xray-linux-arm64-v8a.zip at 18.8 MB, so an Xray install was pre-flighted
// ~18.8 MB short. tar.gz/tgz/gz stream straight through and never land, so their figure must NOT
// move: an estimate that grows for them would refuse installs that fit.
func TestPeakInstallDiskCountsTheStagedZip(t *testing.T) {
	const size = 19_712_000 // ~18.8 MiB, the real Xray arm64 asset

	zip := peakInstallDisk(size, "Xray-linux-arm64-v8a.zip", false)
	tgz := peakInstallDisk(size, "sing-box-1.13.19-linux-arm64.tar.gz", false)

	// Both inflate 3x for the unpacked binary and carry the same 4 MiB slack; only the zip also
	// holds the archive.
	if want := tgz + uint64(size); zip != want {
		t.Errorf("a staged zip must add its own bytes: got %d, want %d (tar.gz figure %d + asset %d)",
			zip, want, tgz, size)
	}
	if tgz != uint64(size)*3+(4<<20) {
		t.Errorf("the streamed figure must not move: got %d", tgz)
	}

	// A bare (already-unpacked) binary is neither inflated nor staged.
	bare := peakInstallDisk(size, "wayhop-arm64", false)
	if bare != uint64(size)+(4<<20) {
		t.Errorf("a bare binary is 1x plus slack: got %d", bare)
	}

	// The backup doubles the BINARY, not the archive: two copies of the binary can exist, only one
	// copy of the zip ever does.
	zipBak := peakInstallDisk(size, "Xray-linux-arm64-v8a.zip", true)
	if want := uint64(size)*3*2 + uint64(size) + (4 << 20); zipBak != want {
		t.Errorf("with a backup: got %d, want %d", zipBak, want)
	}
}
