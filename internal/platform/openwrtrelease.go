package platform

import (
	"os"
	"regexp"
	"strings"
)

// OpenWrtRelease is what /etc/openwrt_release says about the running build: the release and the
// target/subtarget, which together pick the one kmod directory in WayHop's feed built for this
// kernel (awg/openwrt/<release>/<target>/<subtarget>/), and the package architecture.
type OpenWrtRelease struct {
	Release string `json:"release,omitempty"` // DISTRIB_RELEASE, e.g. "24.10.8"
	Target  string `json:"target,omitempty"`  // DISTRIB_TARGET, e.g. "mediatek/filogic"
	Arch    string `json:"arch,omitempty"`    // DISTRIB_ARCH, e.g. "aarch64_cortex-a53"
}

// openWrtReleaseFile is read by DetectOpenWrtRelease; a variable so tests can point it elsewhere.
var openWrtReleaseFile = "/etc/openwrt_release"

// openWrtValueRe keeps a value to the characters a release, target or arch is made of, so whatever the
// file holds is safe to put in a sentence on the panel.
var openWrtValueRe = regexp.MustCompile(`^[A-Za-z0-9._/+-]{1,64}$`)

// ParseOpenWrtRelease reads the KEY='value' lines of /etc/openwrt_release. Pure. A value that is
// missing or not shaped like one is left empty rather than guessed.
func ParseOpenWrtRelease(text string) OpenWrtRelease {
	var r OpenWrtRelease
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '\'' || val[0] == '"') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		if !openWrtValueRe.MatchString(val) {
			continue
		}
		switch strings.TrimSpace(key) {
		case "DISTRIB_RELEASE":
			r.Release = val
		case "DISTRIB_TARGET":
			r.Target = val
		case "DISTRIB_ARCH":
			r.Arch = val
		}
	}
	return r
}

// DetectOpenWrtRelease reads /etc/openwrt_release; ok is false where there is none (not OpenWrt).
func DetectOpenWrtRelease() (OpenWrtRelease, bool) {
	b, err := os.ReadFile(openWrtReleaseFile)
	if err != nil {
		return OpenWrtRelease{}, false
	}
	return ParseOpenWrtRelease(string(b)), true
}
