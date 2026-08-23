package netvpn

import (
	"strings"
	"testing"
)

// Synthetic dumps only (dummy keys, RFC5737 IPs, fake headers) — never real device data.

func TestParseWgDump_AmneziaWG(t *testing.T) {
	// AmneziaWG interface line carries extra obfuscation columns (Jc/Jmin/Jmax/S1/S2,
	// H-ranges, I-header hex, on/off) after the standard 5 — the parser must ignore them.
	dump := strings.Join([]string{
		"awg0\tPRIV0_secret\tPUB0\t54154\t5\t49\t998\t17\t110\t25\t40\t1-2\t3-4\t5-6\t7-8\t0xdeadbeef\t0xcafef00d\toff",
		"awg0\tPEERPUB0\tPSK0_secret\t192.0.2.10:8443\t10.0.0.0/24,0.0.0.0/0\t1700000000\t12345\t6789\t21",
	}, "\n")

	got := parseWgDump(dump, "amneziawg")
	if len(got) != 1 {
		t.Fatalf("want 1 interface, got %d", len(got))
	}
	d := got[0]
	if d.Iface != "awg0" || d.Type != "amneziawg" || d.PublicKey != "PUB0" || d.ListenPort != 54154 {
		t.Fatalf("interface fields wrong: %+v", d)
	}
	if len(d.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(d.Peers))
	}
	p := d.Peers[0]
	if p.PublicKey != "PEERPUB0" || p.Endpoint != "192.0.2.10:8443" {
		t.Fatalf("peer pubkey/endpoint wrong: %+v", p)
	}
	if len(p.AllowedIPs) != 2 || p.AllowedIPs[1] != "0.0.0.0/0" {
		t.Fatalf("allowed-ips wrong: %v", p.AllowedIPs)
	}
	if p.LastHandshake != 1700000000 || p.RxBytes != 12345 || p.TxBytes != 6789 {
		t.Fatalf("peer counters wrong: %+v", p)
	}
	if !d.FullTunnel() {
		t.Fatalf("expected FullTunnel (0.0.0.0/0 present)")
	}
	if !d.Active(1700000050) || d.Active(1700009999) {
		t.Fatalf("Active() window wrong")
	}
	// Secrets must never survive parsing: no private key, no PSK, no magic headers.
	for _, leak := range []string{"PRIV0_secret", "PSK0_secret", "0xdeadbeef", "0xcafef00d"} {
		if strings.Contains(d.PublicKey, leak) {
			t.Fatalf("leak in PublicKey: %s", leak)
		}
		for _, pr := range d.Peers {
			if strings.Contains(pr.PublicKey, leak) || strings.Contains(pr.Endpoint, leak) {
				t.Fatalf("leak in peer: %s", leak)
			}
		}
	}
}

func TestParseWgDump_SplitTunnelAndEdges(t *testing.T) {
	dump := strings.Join([]string{
		"wg0\tPRIV1\tPUB1\t51820\t0",
		"wg0\tPEERPUB1\t(none)\t198.51.100.5:51820\t10.1.0.0/16\t1700000100\t111\t222\t0",
		"wg0\tPEERPUB2\t(none)\t(none)\t10.2.0.0/16\t0\t0\t0\t0", // roaming peer, never handshook
	}, "\n")
	got := parseWgDump(dump, "wireguard")
	if len(got) != 1 || got[0].Type != "wireguard" || len(got[0].Peers) != 2 {
		t.Fatalf("split-tunnel parse wrong: %+v", got)
	}
	if got[0].FullTunnel() {
		t.Fatalf("split tunnel must not be FullTunnel")
	}
	if got[0].Peers[1].Endpoint != "" {
		t.Fatalf("roaming peer endpoint should be empty, got %q", got[0].Peers[1].Endpoint)
	}
	if got[0].Active(9999999999) {
		t.Fatalf("never-handshook peers must be inactive")
	}

	if r := parseWgDump("", "wireguard"); len(r) != 0 {
		t.Fatalf("empty dump must yield no results, got %d", len(r))
	}
	if r := parseWgDump("garbage\tline", "wireguard"); len(r) != 0 {
		t.Fatalf("too-short line must be skipped, got %d", len(r))
	}
}
