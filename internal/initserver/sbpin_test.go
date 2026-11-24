package initserver

import (
	"strings"
	"testing"
)

const sum64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPinFromAssets(t *testing.T) {
	p := PinFromAssets("v1.12.17", map[string]string{
		"sing-box-1.12.17-linux-amd64.tar.gz": "sha256:" + sum64,
		"sing-box-1.12.17-linux-arm64.tar.gz": "SHA256:" + strings.ToUpper(sum64),
		"sing-box-1.12.17-linux-armv7.tar.gz": "sha256:short",
		"sing-box-1.12.17-windows-amd64.zip":  "sha256:" + sum64,
	})
	if p == nil || p.Version != "1.12.17" || p.SHA256["amd64"] != sum64 || p.SHA256["arm64"] != sum64 {
		t.Fatalf("pin = %+v", p)
	}
	if _, ok := p.SHA256["armv7"]; ok {
		t.Error("a malformed digest was pinned")
	}
	for _, tag := range []string{"v1.13.0-beta.1", "latest", "1.2"} {
		if PinFromAssets(tag, map[string]string{"sing-box-x-linux-amd64.tar.gz": "sha256:" + sum64}) != nil {
			t.Errorf("tag %q produced a pin", tag)
		}
	}
	if PinFromAssets("v1.12.17", map[string]string{}) != nil {
		t.Error("a release without digests produced a pin")
	}
}

// Every server install of sing-box goes through wr_sb_install, which refuses a tarball it cannot
// check; a pin from the router fixes the version and the digest for the script.
func TestBuildScriptChecksSingBox(t *testing.T) {
	s := BuildScript([]string{"vless-reality"}, "")
	for _, want := range []string{"wr_sb_install() {", "sha256sum -c -", `[ ${#SUM} -eq 64 ]`, "wr_sb_install || exit 1"} {
		if !strings.Contains(s, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if strings.Contains(s, "SB_PIN_VER=") {
		t.Error("an unpinned script set a pinned version")
	}
	if strings.Count(s, "install -m755") != 1 {
		t.Errorf("sing-box is installed outside wr_sb_install (%d install lines)", strings.Count(s, "install -m755"))
	}
	pinned := BuildScriptPinned([]string{"vless-reality"}, "", &SingBoxPin{Version: "1.12.17", SHA256: map[string]string{"amd64": sum64, "arm64": "x'; id; '"}})
	if !strings.Contains(pinned, "SB_PIN_VER='1.12.17'") || !strings.Contains(pinned, "SB_PIN_SHA_amd64='"+sum64+"'") {
		t.Errorf("the pin is missing from the script")
	}
	if strings.Contains(pinned, "id;") {
		t.Error("an invalid digest reached the script")
	}
}

func TestUpdateSingBoxScriptChecksDigest(t *testing.T) {
	s := UpdateSingBoxScriptPinned("1.12.17", &SingBoxPin{Version: "1.12.17", SHA256: map[string]string{"arm64": sum64}})
	for _, want := range []string{"SB_PIN_SHA_arm64='" + sum64 + "'", "releases/tags/v${VER}", "sha256sum -c -", "WR_UPDATE_ERR=no sha256"} {
		if !strings.Contains(s, want) {
			t.Errorf("the update script lacks %q", want)
		}
	}
	other := UpdateSingBoxScriptPinned("1.12.18", &SingBoxPin{Version: "1.12.17", SHA256: map[string]string{"arm64": sum64}})
	if strings.Contains(other, "SB_PIN_SHA_arm64='") {
		t.Error("a pin for another version was used")
	}
}
