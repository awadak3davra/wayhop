package platform

import "testing"

func mkProbes(files map[string]bool, procVersion string) probes {
	return probes{
		fileExists:  func(p string) bool { return files[p] },
		procVersion: func() string { return procVersion },
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]bool
		proc  string
		want  Platform
	}{
		// Live reference router signals: ndmc present + keenetic.com/-ndm- kernel.
		{"keenetic-ndmc", map[string]bool{"/bin/ndmc": true}, "Linux version 4.9-ndm-5 (developers@keenetic.com)", Keenetic},
		{"keenetic-procversion-only", nil, "Linux version 4.9-ndm-5 (developers@keenetic.com)", Keenetic},
		{"keenetic-name", nil, "Linux version 5.x Keenetic", Keenetic},
		// Keenetic wins even if OpenWrt-ish paths coexist (Entware on KeeneticOS).
		{"keenetic-over-openwrt", map[string]bool{"/bin/ndmc": true, "/sbin/uci": true}, "4.9-ndm-5", Keenetic},
		// OpenWrt markers.
		{"openwrt-release", map[string]bool{"/etc/openwrt_release": true}, "Linux version 6.12.74", OpenWrt},
		{"openwrt-fw4", map[string]bool{"/sbin/fw4": true}, "generic linux", OpenWrt},
		// Neither.
		{"unknown", nil, "Linux version 6.8 generic", Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := detect(mkProbes(c.files, c.proc)); got != c.want {
				t.Errorf("detect = %q, want %q", got, c.want)
			}
		})
	}
}
