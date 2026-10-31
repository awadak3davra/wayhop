package updater

import "testing"

// Regression for the ARMv7 install bug: a suffix-less "-linux-arm" asset must be
// matchable for arch "arm", while 64-bit names must not be.
func TestMatchAssetBareArm(t *testing.T) {
	cases := []struct {
		name, arch string
		want       bool
	}{
		{"hysteria-linux-arm", "arm", true}, // the previously-missed case
		{"hysteria-linux-armv5", "arm", true},
		{"hysteria-linux-armv7", "arm", true},
		{"foo-linux-arm.tar.gz", "arm", true},
		{"hysteria-linux-arm64", "arm", false}, // 64-bit must not match 32-bit arm
		{"hysteria-linux-aarch64", "arm", false},
		{"hysteria-linux-arm64", "arm64", true},
		{"hysteria-linux-amd64", "arm", false},
	}
	for _, c := range cases {
		if got := matchAsset(c.name, c.arch); got != c.want {
			t.Errorf("matchAsset(%q,%q) = %v, want %v", c.name, c.arch, got, c.want)
		}
	}
}

// pickAsset must prefer the most specific arm build so an ARMv7 router never
// settles for armv5 when a better asset exists, and never selects arm64.
func TestPickAssetArmPreference(t *testing.T) {
	assets := func(names ...string) []Asset {
		out := make([]Asset, len(names))
		for i, n := range names {
			out[i] = Asset{Name: n}
		}
		return out
	}
	cases := []struct {
		names []string
		arch  string
		want  string // "" => nil
	}{
		// Hysteria-style: bare arm preferred over armv5, never arm64.
		{[]string{"h-linux-arm", "h-linux-arm64", "h-linux-armv5"}, "arm", "h-linux-arm"},
		// Explicit armv7 beats a bare arm even if bare comes first.
		{[]string{"x-linux-arm", "x-linux-armv7"}, "arm", "x-linux-armv7"},
		// armhf counts as the specific (armv7-class) build.
		{[]string{"x-linux-armv5", "x-linux-armhf"}, "arm", "x-linux-armhf"},
		// Xray's real v26.10.29 names, in release order: arm32-v7a, not the v5 build listed first.
		{[]string{"Xray-linux-arm32-v5.zip", "Xray-linux-arm32-v6.zip", "Xray-linux-arm32-v7a.zip", "Xray-linux-arm64-v8a.zip"}, "arm", "Xray-linux-arm32-v7a.zip"},
		// mihomo v1.19.33's real names: the .gz binary, never the distro packages listed before it,
		// and the softfloat MIPS build over hardfloat.
		{[]string{"mihomo-linux-arm64-v1.19.33.deb", "mihomo-linux-arm64-v1.19.33.gz", "mihomo-linux-arm64-v1.19.33.pkg.tar.zst", "mihomo-linux-arm64-v1.19.33.rpm"}, "arm64", "mihomo-linux-arm64-v1.19.33.gz"},
		{[]string{"mihomo-linux-armv7-v1.19.33.deb", "mihomo-linux-armv7-v1.19.33.gz", "mihomo-linux-armv7-v1.19.33.rpm"}, "arm", "mihomo-linux-armv7-v1.19.33.gz"},
		{[]string{"mihomo-linux-mipsle-hardfloat-v1.19.33.gz", "mihomo-linux-mipsle-softfloat-v1.19.33.gz"}, "mipsle", "mihomo-linux-mipsle-softfloat-v1.19.33.gz"},
		{[]string{"dnscrypt-proxy-linux_arm-2.1.20.tar.gz.minisig", "dnscrypt-proxy-linux_arm-2.1.20.tar.gz"}, "arm", "dnscrypt-proxy-linux_arm-2.1.20.tar.gz"},
		// Only a package -> nothing installable rather than a package written out as the binary.
		{[]string{"x-linux-arm64.deb"}, "arm64", ""},
		// Only armv5 present -> still installable (not nil).
		{[]string{"x-linux-armv5", "x-linux-arm64"}, "arm", "x-linux-armv5"},
		// No arm asset at all -> nil.
		{[]string{"x-linux-amd64", "x-linux-arm64"}, "arm", ""},
		// Non-arm arch: first match wins (scoring neutral).
		{[]string{"x-linux-amd64", "x-other-amd64"}, "amd64", "x-linux-amd64"},
	}
	for _, c := range cases {
		got := pickAsset(assets(c.names...), c.arch)
		gotName := ""
		if got != nil {
			gotName = got.Name
		}
		if gotName != c.want {
			t.Errorf("pickAsset(%v, %q) = %q, want %q", c.names, c.arch, gotName, c.want)
		}
	}
}
