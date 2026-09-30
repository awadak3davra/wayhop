//go:build linux

package awg

import (
	"errors"
	"testing"
)

// The controller family "nlctrl" is registered by every Linux kernel, so asking about it drives the
// real socket round trip - the request encoding, the native byte order, the reply parser - on
// whatever machine runs the test, with no AmneziaWG module needed. The fixtures in
// generation_test.go prove the parser against the wire format; this proves the syscalls around it.
func TestQueryFamily_RealKernelController(t *testing.T) {
	v, m, err := queryFamily("nlctrl")
	if err != nil {
		t.Fatalf("querying the always-present nlctrl family failed: %v", err)
	}
	if v == 0 {
		t.Fatalf("nlctrl answered version 0 (maxattr %d)", m)
	}
	// Its maxattr is NOT checked: modern kernels give nlctrl per-operation policies and no family-wide
	// maxattr, so 0 is correct there (measured). amneziawg is different - src/netlink.c sets
	// `.maxattr = WGDEVICE_A_MAX` on the family itself, which is the number Classify reads.
	_ = m
}

// An unregistered family is the kernel's ENOENT, which is how "the amneziawg module is not loaded"
// reaches the probe - it has to arrive as errFamilyNotFound, not as a failure.
func TestQueryFamily_UnregisteredFamilyIsNotFound(t *testing.T) {
	if _, _, err := queryFamily("wh-nofamily"); !errors.Is(err, errFamilyNotFound) {
		t.Fatalf("an unregistered family came back as %v, want errFamilyNotFound", err)
	}
}

// A family name longer than 15 bytes fails the controller's own policy (GENL_NAMSIZ is 16 with the
// NUL), so the kernel refuses the REQUEST - that must surface as a probe error, never as "no such
// family", or a malformed query would read as "module not loaded". Found by running the first draft
// of the test above with a 21-character name.
func TestQueryFamily_OverlongNameIsAnErrorNotAbsence(t *testing.T) {
	_, _, err := queryFamily("wayhop-no-such-family")
	if err == nil || errors.Is(err, errFamilyNotFound) {
		t.Fatalf("an over-long family name came back as %v; it must be a probe error", err)
	}
	t.Logf("kernel refused the over-long name: %v", err)
}

// On a host without the module the probe must report generation none and no error - that is the
// state of every Keenetic and of any OpenWrt before its kmod is installed.
func TestProbeHost_WithoutModuleIsNotAnError(t *testing.T) {
	p := ProbeHost()
	if p.Err != "" {
		t.Fatalf("ProbeHost reported a failure: %s", p.Err)
	}
	if p.GenlVersion == 0 && p.Kernel != GenNone {
		t.Fatalf("no family but classified as %v", p.Kernel)
	}
}
