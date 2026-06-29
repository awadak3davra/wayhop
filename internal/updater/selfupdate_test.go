package updater

import "testing"

func TestSelfAsset(t *testing.T) {
	assets := []Asset{
		{Name: "velinx-0.1.0-arm64.tar.gz"},
		{Name: "velinx-0.1.0-arm64-openwrt.tar.gz"},
		{Name: "velinx-0.1.0-amd64.tar.gz"},
		{Name: "velinx-0.1.0-arm.tar.gz"},
		{Name: "velinx-0.1.0-mipsle-openwrt.tar.gz"},
		{Name: "SHA256SUMS"},
	}
	cases := map[string]string{
		"arm64":  "velinx-0.1.0-arm64-openwrt.tar.gz", // openwrt package preferred
		"amd64":  "velinx-0.1.0-amd64.tar.gz",
		"arm":    "velinx-0.1.0-arm.tar.gz", // must NOT match arm64
		"mipsle": "velinx-0.1.0-mipsle-openwrt.tar.gz",
		"mips":   "", // none present (must NOT grab mipsle)
	}
	for arch, want := range cases {
		got := ""
		if a := selfAsset(assets, arch); a != nil {
			got = a.Name
		}
		if got != want {
			t.Errorf("selfAsset(%q) = %q, want %q", arch, got, want)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"0.1.0-ef26078", "v0.1.1", true},
		{"0.1.0-ef26078", "v0.1.0", false},
		{"0.1.0", "v0.2.0", true},
		{"0.2.0", "v0.1.9", false},
		{"0.1.0-dev", "nightly-9822def", false}, // unparseable latest -> don't auto-update
		{"", "v0.1.0", true},                    // unknown current -> treat as older
		{"0.1.0", "v0.1.0", false},
		{"0.9.0", "v0.10.0", true}, // numeric per-component, not lexical
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}
