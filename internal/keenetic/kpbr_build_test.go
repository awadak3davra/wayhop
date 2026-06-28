package keenetic

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuildKernelPlan_FullArtifacts(t *testing.T) {
	fetch := func(url string) ([]string, error) {
		switch {
		case strings.Contains(url, "telegram"):
			return []string{"149.154.160.0/20"}, nil
		case strings.Contains(url, "discord_ips"):
			return []string{"162.159.0.0/16"}, nil
		case strings.Contains(url, "youtube"):
			return []string{"youtube.com", "*.youtu.be"}, nil
		}
		return nil, nil
	}
	in := KernelInputs{
		KeenPBRConfig:  []byte(kpFixture),
		LocalListFiles: map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx", "jac.red"}},
		RunningConfig:  rcFixture, // Wireguard0/1/2/5; no Wireguard3 (keentest dead → remapped)
		WanGateway:     "172.20.0.1",
		ExtraBypassIPs: []string{"195.58.46.23"}, // resolved Wireguard1 hostname
		Fetch:          fetch,
	}
	art, err := BuildKernelPlan(in)
	if err != nil {
		t.Fatal(err)
	}

	// ipset restore: inlined IP feed present; bypass has live peer IPs + the resolved hostname.
	has(t, "ipset", art.IpsetRestore, "149.154.160.0/20") // telegram feed
	has(t, "ipset", art.IpsetRestore, "create wr_bypass_4 hash:net")
	has(t, "ipset", art.IpsetRestore, "add wr_bypass_4 192.0.2.10/32")   // Wireguard0 peer
	has(t, "ipset", art.IpsetRestore, "add wr_bypass_4 195.58.46.23/32") // resolved Wireguard1
	// a domain zone's set is created (DNS-populated, timeout) and NOT pre-filled with domains.
	if !strings.Contains(art.IpsetRestore, "timeout 86400") {
		t.Errorf("expected a DNS-populated set with a timeout:\n%s", art.IpsetRestore)
	}

	// dnsmasq: domains from the youtube feed + the inline torrents/local lists.
	has(t, "dnsmasq", art.DnsmasqConfig, "youtube.com")
	has(t, "dnsmasq", art.DnsmasqConfig, "rutracker.org") // torrents (Manual domains)
	has(t, "dnsmasq", art.DnsmasqConfig, "lampa.mx")      // local.lst

	// iptables: MARK rules, bypass RETURN, S86 guard, CONNMARK, WAN-fallback MASQUERADE.
	has(t, "iptables", art.IptablesScript, "-m set --match-set wr_bypass_4 dst -j RETURN")
	has(t, "iptables", art.IptablesScript, "-m mark --mark 0x00000250/0xffffffff -j RETURN")
	has(t, "iptables", art.IptablesScript, "-j MARK --set-xmark")
	has(t, "iptables", art.IptablesScript, "-j CONNMARK --save-mark")
	has(t, "iptables", art.IptablesScript, "-t nat") // WAN-fallback MASQUERADE
	// tunnel NAT — the forwarded-traffic fix: MASQUERADE on the TUNNEL egress ifaces (not just WAN),
	// covering every failover-member iface so forwarded LAN flows don't black-hole on a re-election.
	has(t, "iptables", art.IptablesScript, "-A POSTROUTING -o nwg1 -j MASQUERADE")
	has(t, "iptables", art.IptablesScript, "-o nwg0 -j MASQUERADE")
	has(t, "teardown", art.Teardown, "-D POSTROUTING -o nwg1 -j MASQUERADE")

	// failover cron elects per-table egress; routes to the group's kernel member nwg1.
	has(t, "cron", art.FailoverCron, "set_table")
	has(t, "cron", art.FailoverCron, "nwg1")
	has(t, "cron", art.FailoverCron, "WAN")
	// load-independent liveness: the RX-counter delta is tried BEFORE ICMP (fixes the under-load
	// flapping that demoted Telegram); RX is sampled once per run; WG handshake is a middle layer.
	has(t, "cron", art.FailoverCron, "rx_advanced")
	// NAT persistence backstop: the cron re-asserts the tunnel MASQUERADE every run (idempotent),
	// so a missed netfilter.d hook event can't leave forwarded traffic black-holed for long.
	has(t, "cron", art.FailoverCron, `iptables -t nat -C POSTROUTING -o "$i" -j MASQUERADE`)
	has(t, "cron", art.FailoverCron, "/sys/class/net/$1/statistics/rx_bytes")
	has(t, "cron", art.FailoverCron, "for i in ") // up-front RX snapshot loop
	has(t, "cron", art.FailoverCron, "latest-handshakes")
	if strings.Index(art.FailoverCron, `rx_advanced "$1" && return 0`) > strings.Index(art.FailoverCron, "ping -c3") {
		t.Error("probe must try the cheap RX signal before falling to ICMP ping")
	}
	// L1 stickiness: the cron reads the installed default and KEEPS a still-healthy tunnel egress
	// instead of preemptively failing back (the zero-debounce up-switch that dropped live calls).
	has(t, "cron", art.FailoverCron, "ip route show default table")
	has(t, "cron", art.FailoverCron, `if probe "$cur"; then`)
	// The generated failover cron must be valid POSIX shell.
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(art.FailoverCron)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("sh -n rejected the failover cron:\n%v\n%s", e, out)
		}
	}

	// netfilter.d hook re-creates sets if gone + re-asserts iptables/ip.
	has(t, "hook", art.NetfilterHook, "ipset list -n")
	has(t, "hook", art.NetfilterHook, "--match-set")

	// cutover.sh: fastnat off, retire keen-pbr only, dnsmasq HUP, done marker.
	cut := EmitCutoverScript(art, CutoverPaths{})
	has(t, "cutover", cut, "nf_conntrack_fastnat")
	has(t, "cutover", cut, "S80keen-pbr stop")
	has(t, "cutover", cut, "S56dnsmasq restart") // ipset= directives need a restart, not HUP
	has(t, "cutover", cut, "WR_KPBR_CUTOVER_DONE")
	// fastnat must be disabled AFTER retiring keen-pbr (which re-enables it on stop).
	if strings.Index(cut, "nf_conntrack_fastnat") < strings.Index(cut, "S80keen-pbr stop") {
		t.Error("fastnat must be disabled AFTER keen-pbr stop, not before")
	}
	if strings.Contains(cut, "S86ru_routing") || strings.Contains(cut, "S89hy_failover") {
		t.Error("cutover must NOT touch S86 (RU-routing) or S89 (default failover)")
	}

	// rollback.sh: tear down WR plane + restore keen-pbr.
	rb := EmitRollbackScript(art, CutoverPaths{})
	has(t, "rollback", rb, "ipset destroy")
	has(t, "rollback", rb, "S80keen-pbr start")
	has(t, "rollback", rb, "WR_KPBR_ROLLBACK_DONE")
}

func has(t *testing.T, what, hay, needle string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("[%s] missing %q in:\n%s", what, needle, hay)
	}
}
