package importer

import "testing"

// FuzzParseClash hammers the hand-rolled Clash YAML reader with arbitrary input.
// ParseClash + looksLikeClash run on UNTRUSTED pasted configs and do a lot of
// string slicing (dash columns, splitTopLevel, indent stacks), so the contract
// under fuzz is simply: NEVER panic or hang, regardless of how malformed the
// input is. (Correctness of well-formed configs is covered by clash_test.go.)
func FuzzParseClash(f *testing.F) {
	seeds := []string{
		"proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: p}\n",
		"proxies:\n  - name: v\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: 11111111-1111-1111-1111-111111111111\n    network: ws\n    ws-opts:\n      path: /x\n      headers:\n        Host: a.com\n",
		"proxies:\n  - {name: t, type: tuic, server: 1.2.3.4, port: 8446, uuid: u, password: p, alpn: [h3, h2]}\n  - {name: w, type: wireguard, server: 1.2.3.4, port: 51820, private-key: K, public-key: P, ip: 10.0.0.2/32}\n",
		"proxies:\n  - name: r\n    type: vless\n    server: 1.2.3.4\n    port: 443\n    uuid: u\n    flow: xtls-rprx-vision\n    reality-opts:\n      public-key: pbk\n      short-id: 00\n",
		"proxies:\n  - {name: h, type: hysteria2, server: a, port: 443, password: p, ports: \"443-8443\", up: 50 Mbps}\n",
		"proxies: [{name: a, type: ss, server: x, port: 1, cipher: c, password: p}, {name: b, type: trojan, server: y, port: 2, password: q}]\n",
		"proxies: []\n",
		"proxies:\n  - garbage without colon\n",
		"proxies:\n  - {malformed flow\n",
		"proxies:\n  - name: x\n    type: ss\n    alpn:\n      - h3\n      - h2\n    port: 1\n",
		"port: 1\nproxies:\nnot-a-list\n",
		"not a clash config at all",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		// Contract: no panic / no hang on any input.
		_ = looksLikeClash(data)
		eps, errs := ParseClash(data)
		_ = errs
		for i := range eps {
			_ = eps[i].ID
			_ = eps[i].Engine
			_ = eps[i].Protocol
		}
		// The real entry point dispatches through here; it must also be panic-free.
		_, _ = ParseSubscription(data)
	})
}
