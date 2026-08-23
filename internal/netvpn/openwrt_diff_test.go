package netvpn

import (
	"strings"
	"testing"
)

// Identical views must produce no difference, or the write path refuses every legitimate change and
// the safety check becomes something to switch off.
func TestDiffInterface_IdenticalIsSilent(t *testing.T) {
	a := liveShapedIface()
	if d := DiffInterface(a, liveShapedIface()); len(d) != 0 {
		t.Fatalf("two identical tunnels reported %d difference(s): %v", len(d), d)
	}
}

// The case this exists for: somebody changed the tunnel in LuCI between the snapshot and the write.
func TestDiffInterface_CatchesAnEditMadeElsewhere(t *testing.T) {
	want := liveShapedIface()
	got := liveShapedIface()
	got.MTU = 1420
	got.Peers[0].EndpointHost = "203.0.113.9"

	d := DiffInterface(want, got)
	joined := joinDiffs(d)
	for _, expect := range []string{"mtu", "peer1.endpoint_host"} {
		if !strings.Contains(joined, expect) {
			t.Errorf("a changed %s was not reported:\n%s", expect, joined)
		}
	}
}

// An obfuscation parameter present on the DEVICE and absent from the plan is the exact shape of a
// hand-edit. Comparing only over the plan's keys would walk straight past it.
func TestDiffInterface_SeesAParamOnlyTheDeviceHas(t *testing.T) {
	want := liveShapedIface()
	got := liveShapedIface()
	got.Obfuscation["i3"] = "0xdeadbeef" // added on the router, unknown to the plan

	d := DiffInterface(want, got)
	if !strings.Contains(joinDiffs(d), "awg_i3") {
		t.Fatalf("a parameter only the device carries was not reported: %v", d)
	}
}

// Key material must never appear in a diff: this output goes into logs and an HTTP response, and a
// safety check that leaks the thing it protects is worse than no check.
func TestDiffInterface_NeverEchoesSecrets(t *testing.T) {
	want := liveShapedIface()
	want.PrivateKey = "SECRET-PRIVATE-KEY"
	want.Peers[0].PublicKey = "SECRET-PUBLIC-KEY"
	want.Peers[0].PresharedKey = "SECRET-PSK"

	got := liveShapedIface()
	got.PrivateKey = "DIFFERENT-PRIVATE-KEY"
	got.Peers[0].PublicKey = "DIFFERENT-PUBLIC-KEY"
	got.Peers[0].PresharedKey = ""

	joined := joinDiffs(DiffInterface(want, got))
	for _, secret := range []string{
		"SECRET-PRIVATE-KEY", "DIFFERENT-PRIVATE-KEY",
		"SECRET-PUBLIC-KEY", "DIFFERENT-PUBLIC-KEY", "SECRET-PSK",
	} {
		if strings.Contains(joined, secret) {
			t.Errorf("the diff echoed key material (%q):\n%s", secret, joined)
		}
	}
	// It still has to SAY they differ, or redaction has quietly disabled the comparison.
	for _, field := range []string{"private_key", "peer1.public_key", "peer1.preshared_key"} {
		if !strings.Contains(joined, field) {
			t.Errorf("%s differs but was not reported at all:\n%s", field, joined)
		}
	}
}

// A peer added or removed elsewhere changes what every later index means, so the per-peer comparison
// is skipped and the count reported instead — comparing peer2 against a different peer2 would
// produce a page of differences that describe nothing.
func TestDiffInterface_PeerCountMismatchStopsThere(t *testing.T) {
	want := liveShapedIface()
	got := liveShapedIface()
	got.Peers = append(got.Peers, AWGPeer{PublicKey: "OTHER", EndpointHost: "198.51.100.1"})

	d := DiffInterface(want, got)
	joined := joinDiffs(d)
	if !strings.Contains(joined, "peer count") {
		t.Fatalf("a differing peer count was not reported: %s", joined)
	}
	if strings.Contains(joined, "peer1.") {
		t.Errorf("per-peer fields were compared despite a count mismatch:\n%s", joined)
	}
}

func joinDiffs(d []Difference) string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.String())
	}
	return strings.Join(out, "\n")
}

// The option that decides whether the peer runs at all. It exists in luci-proto-amneziawg and NOT in
// luci-proto-wireguard, which this protocol was forked from — so reasoning from the WireGuard schema
// walks straight past it. A verification that compares every other field and not this one reports a
// perfect match on a tunnel that is switched off.
func TestDiffInterface_NoticesADisabledPeer(t *testing.T) {
	want := liveShapedIface() // intended: the peer runs
	got := liveShapedIface()
	got.Peers[0].Disabled = true // on the router somebody switched it off

	d := DiffInterface(want, got)
	if !strings.Contains(joinDiffs(d), "peer1.disabled") {
		t.Fatalf("a disabled peer was reported as matching: %v", d)
	}
}
