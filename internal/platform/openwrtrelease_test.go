package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOpenWrtRelease(t *testing.T) {
	// The file as OpenWrt 24.10 writes it (single quotes), plus the shapes that must not get through.
	text := "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.8'\nDISTRIB_REVISION='r28872-0e2a8d6c55'\n" +
		"DISTRIB_TARGET='mediatek/filogic'\nDISTRIB_ARCH='aarch64_cortex-a53'\n" +
		"DISTRIB_DESCRIPTION='OpenWrt 24.10.8 r28872-0e2a8d6c55'\n"
	if got := ParseOpenWrtRelease(text); got != (OpenWrtRelease{Release: "24.10.8", Target: "mediatek/filogic", Arch: "aarch64_cortex-a53"}) {
		t.Errorf("parsed %+v", got)
	}
	if got := ParseOpenWrtRelease(`DISTRIB_RELEASE="25.12.5"` + "\nDISTRIB_TARGET=x86/64\n"); got.Release != "25.12.5" || got.Target != "x86/64" {
		t.Errorf("double quotes / bare value: %+v", got)
	}
	hostile := "DISTRIB_RELEASE='24.10.8; reboot'\nDISTRIB_TARGET='<script>'\nDISTRIB_ARCH=''\n"
	if got := ParseOpenWrtRelease(hostile); got != (OpenWrtRelease{}) {
		t.Errorf("values not shaped like a release were kept: %+v", got)
	}
}

func TestDetectOpenWrtRelease(t *testing.T) {
	old := openWrtReleaseFile
	t.Cleanup(func() { openWrtReleaseFile = old })
	openWrtReleaseFile = filepath.Join(t.TempDir(), "absent")
	if _, ok := DetectOpenWrtRelease(); ok {
		t.Error("a release read from a file that is not there")
	}
	openWrtReleaseFile = filepath.Join(t.TempDir(), "openwrt_release")
	if err := os.WriteFile(openWrtReleaseFile, []byte("DISTRIB_RELEASE='24.10.8'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := DetectOpenWrtRelease(); !ok || got.Release != "24.10.8" {
		t.Errorf("%+v %v", got, ok)
	}
}
