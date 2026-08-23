package importer

import "testing"

// FuzzParseConf hammers the hand-rolled WireGuard / AmneziaWG `.conf` reader with
// arbitrary input. parseConf runs on UNTRUSTED pasted configs (a user routinely
// pastes a WARP / AmneziaWG / mesh .conf) and does a lot of section + key/value +
// CSV + reserved-bytes + multi-[Peer] parsing, so the fuzz contract is simply:
// NEVER panic or hang on any input. (Correctness of well-formed configs is covered
// by conf_awg2_test.go + conf_multipeer_test.go.)
func FuzzParseConf(f *testing.F) {
	seeds := []string{
		// Plain single-peer WireGuard.
		"[Interface]\nPrivateKey = aA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = bB=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		// AmneziaWG 2.0 with the full obfuscation param set.
		"[Interface]\nPrivateKey = k\nAddress = 10.13.13.2/32, fd00::2/64\nJc = 5\nJmin = 49\nJmax = 998\nS1 = 17\nS2 = 110\nS3 = 25\nS4 = 40\nH1 = 500000000-900000000\nH2 = 1000000000-1400000000\nH3 = 1500000000-1900000000\nH4 = 2000000000-2400000000\nI1 = 0xdeadbeef\nI2 = 0xcafebabe\n[Peer]\nPublicKey = p\nEndpoint = host.example:8443\nAllowedIPs = 0.0.0.0/0\nPresharedKey = psk\n",
		// WARP-style with Reserved bytes.
		"[Interface]\nPrivateKey = k\nAddress = 172.16.0.2/32\nMTU = 1280\nReserved = 1,2,3\n[Peer]\nPublicKey = p\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n",
		// Multi-peer mesh.
		"[Interface]\nPrivateKey = k\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = a\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = 15\n[Peer]\nPublicKey = b\nEndpoint = 2.2.2.2:51820\nAllowedIPs = 10.0.0.3/32\n",
		// Malformed / adversarial shapes.
		"[Interface]\n[Peer]\n",
		"[Interface]\nPrivateKey\nAddress=\n[Peer]\nEndpoint=:\n",
		"[Interface]\r\nPrivateKey = k\r\n[Peer]\r\nEndpoint = [::1]:51820\r\n",
		"[Interface]\nMTU = 999999999999999999999\nReserved = a,b,c,d,e\nJc = notanumber\n[Peer]\nEndpoint = host:notaport\n",
		"[Interface]\n   PrivateKey=k   \n\t[Peer]\tPublicKey=p\n",
		"[Peer]\nEndpoint = 1.2.3.4:51820\n", // no [Interface]
		"not a conf at all",
		"[Interface]\n" + "Address = " + "1.2.3.4/32,\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		// Contract: no panic / no hang on any input.
		e, err := parseConf(data)
		if err == nil && e != nil {
			_ = e.ID
			_ = e.Engine
			_ = e.Protocol
			_ = e.Params
		}
	})
}
