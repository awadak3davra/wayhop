package keenetic

import (
	"fmt"
	"strings"
)

// kpbr_cutover.go renders the device-applyable cutover.sh + rollback.sh from KernelArtifacts.
// The cutover retires keen-pbr ONLY (S86 RU-routing + S89 default failover stay), disables the
// HW-NAT fast-path (it bypasses the mangle marking PBR needs), loosens rp_filter (tunnel paths
// are asymmetric), installs the Velinx kernel plane + dnsmasq ipset config (dnsmasq restart —
// ipset= directives need a reload, not SIGHUP) and the failover cron + netfilter.d re-assert hook.
// No sing-box restart (transports unchanged).

// CutoverPaths are the on-device file locations (defaults match the live box).
type CutoverPaths struct {
	DnsmasqDir    string // default /opt/etc/dnsmasq.d
	DnsmasqFile   string // default 30-velinx.conf (within DnsmasqDir)
	FailoverCron  string // default /opt/etc/cron.1min/wr-failover
	NetfilterHook string // default /opt/etc/ndm/netfilter.d/40-velinx.sh
	KeenPBRInit   string // default /opt/etc/init.d/S80keen-pbr
	KeenPBRHook   string // default /opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh
	KeenPBRDnsSh  string // default /opt/usr/lib/keen-pbr/dnsmasq.sh
	DnsmasqInit   string // default /opt/etc/init.d/S56dnsmasq (restart, not SIGHUP, to load ipset=)
}

func (p *CutoverPaths) defaults() {
	if p.DnsmasqDir == "" {
		p.DnsmasqDir = "/opt/etc/dnsmasq.d"
	}
	if p.DnsmasqFile == "" {
		p.DnsmasqFile = "30-velinx.conf"
	}
	if p.FailoverCron == "" {
		p.FailoverCron = "/opt/etc/cron.1min/wr-failover"
	}
	if p.NetfilterHook == "" {
		p.NetfilterHook = "/opt/etc/ndm/netfilter.d/40-velinx.sh"
	}
	if p.KeenPBRInit == "" {
		p.KeenPBRInit = "/opt/etc/init.d/S80keen-pbr"
	}
	if p.KeenPBRHook == "" {
		p.KeenPBRHook = "/opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh"
	}
	if p.KeenPBRDnsSh == "" {
		p.KeenPBRDnsSh = "/opt/usr/lib/keen-pbr/dnsmasq.sh"
	}
	if p.DnsmasqInit == "" {
		p.DnsmasqInit = "/opt/etc/init.d/S56dnsmasq"
	}
}

// heredoc writes `cat > path <<'TAG' … TAG` with a single-quoted tag (no expansion). The tag is
// chosen to not appear in body (the bodies are shell/ipset/dnsmasq — never contain these tags).
func heredoc(b *strings.Builder, path, tag, body string) {
	fmt.Fprintf(b, "cat > %s <<'%s'\n", path, tag)
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "%s\n", tag)
}

// EmitCutoverScript renders the device cutover.sh. Applied to the live kernel without saving the
// NDM config (S86/S89 stay); S82velinx-pbr re-applies the plane at boot, so WR PERSISTS across
// reboots — the explicit revert is rollback.sh, NOT a reboot. While unverified the dead-man's-
// switch is the keen-pbr backstop (its /tmp deadline clears on reboot, so it also fires post-boot).
func EmitCutoverScript(art *KernelArtifacts, paths CutoverPaths) string {
	paths.defaults()
	dns := paths.DnsmasqDir + "/" + paths.DnsmasqFile
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# Velinx kernel-PBR cutover — replaces keen-pbr LIST routing; KEEPS S86+S89.\n")
	b.WriteString("# 1. retire keen-pbr ONLY (S86 + S89 untouched)\n")
	fmt.Fprintf(&b, "[ -x %s ] && %s deactivate 2>/dev/null\n", paths.KeenPBRDnsSh, paths.KeenPBRDnsSh)
	// Remove keen-pbr's generated dnsmasq ipset config explicitly — `deactivate` (above) may not
	// exist on this keen-pbr build, leaving the 1.4MB config loaded so dnsmasq redundantly tries
	// to populate now-destroyed kpbr* sets on every censored-domain resolve (wasted CPU/RAM).
	b.WriteString("rm -f /opt/etc/dnsmasq.d/keen-pbr.conf\n")
	fmt.Fprintf(&b, "%s stop 2>/dev/null\n", paths.KeenPBRInit)
	fmt.Fprintf(&b, "chmod -x %s\n", paths.KeenPBRInit)
	fmt.Fprintf(&b, "[ -f %s ] && chmod -x %s\n", paths.KeenPBRHook, paths.KeenPBRHook)
	b.WriteString("# 2. HW-NAT fastnat OFF (AFTER keen-pbr stop re-enables it; bypasses mangle marking)\n")
	b.WriteString("#    + rp_filter loose (tunnel reply paths are asymmetric)\n")
	b.WriteString("echo 0 > /proc/sys/net/netfilter/nf_conntrack_fastnat 2>/dev/null\n")
	b.WriteString("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > \"$f\" 2>/dev/null; done\n")
	b.WriteString("# 3. Velinx kernel plane: ipsets + mangle/nat MARK + ip rule/route\n")
	b.WriteString("ipset restore -! <<'WRIPSET'\n")
	b.WriteString(art.IpsetRestore)
	if !strings.HasSuffix(art.IpsetRestore, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("WRIPSET\n")
	b.WriteString(art.IptablesScript)
	b.WriteString(art.IPScript)
	b.WriteString("# 4. dnsmasq ipset domain config + RESTART (ipset= directives need a restart, not SIGHUP)\n")
	heredoc(&b, dns, "WRDNS", art.DnsmasqConfig)
	fmt.Fprintf(&b, "%s restart 2>/dev/null\n", paths.DnsmasqInit)
	b.WriteString("# 5. failover cron + netfilter.d re-assert hook\n")
	heredoc(&b, paths.FailoverCron, "WRCRON", art.FailoverCron)
	fmt.Fprintf(&b, "chmod +x %s\n", paths.FailoverCron)
	heredoc(&b, paths.NetfilterHook, "WRHOOK", art.NetfilterHook)
	fmt.Fprintf(&b, "chmod +x %s\n", paths.NetfilterHook)
	heredoc(&b, "/opt/etc/init.d/S82velinx-pbr", "WRBOOT", BootInitScript(paths))
	b.WriteString("chmod +x /opt/etc/init.d/S82velinx-pbr\n")
	b.WriteString("# 6. initial failover election (populate the table routes now)\n")
	fmt.Fprintf(&b, "sh %s\n", paths.FailoverCron)
	b.WriteString("echo WR_KPBR_CUTOVER_DONE\n")
	return b.String()
}

// BootInitScript renders the routing boot init (e.g. /opt/etc/init.d/S82velinx-pbr): at boot
// it re-creates the kernel plane via the netfilter hook (ipsets/iptables/ip-rules/fastnat) and
// runs the failover election so the routing tables point at a LIVE tunnel — NOT the hook's
// static hard-pin (which would blackhole a list if its primary tunnel is down at boot). The
// netfilter hook covers NDM rebuilds; the 1-min cron maintains; this covers cold boot.
func BootInitScript(paths CutoverPaths) string {
	paths.defaults()
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Velinx kernel-PBR boot apply. Auto-generated; ENABLED=yes → runs at boot.\n")
	b.WriteString("ENABLED=yes\n")
	b.WriteString("case \"$1\" in\n")
	fmt.Fprintf(&b, "  start|\"\") sh %s >/dev/null 2>&1; sh %s >/dev/null 2>&1 ;;\n", paths.NetfilterHook, paths.FailoverCron)
	b.WriteString("  stop) : ;;\n")
	b.WriteString("esac\nexit 0\n")
	return b.String()
}

// EmitRollbackScript renders the device rollback.sh: tear down the Velinx plane and restore
// keen-pbr (which re-creates its own ipsets/rules + re-disables fastnat on start).
func EmitRollbackScript(art *KernelArtifacts, paths CutoverPaths) string {
	paths.defaults()
	dns := paths.DnsmasqDir + "/" + paths.DnsmasqFile
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# Velinx kernel-PBR rollback — tear down WR plane, restore keen-pbr.\n")
	fmt.Fprintf(&b, "rm -f %s %s %s /opt/etc/init.d/S82velinx-pbr\n", paths.FailoverCron, paths.NetfilterHook, dns)
	b.WriteString(art.Teardown)
	b.WriteString("# restore keen-pbr (re-creates its ipsets/rules; re-disables fastnat on start)\n")
	fmt.Fprintf(&b, "[ -f %s ] && chmod +x %s\n", paths.KeenPBRHook, paths.KeenPBRHook)
	fmt.Fprintf(&b, "chmod +x %s\n", paths.KeenPBRInit)
	fmt.Fprintf(&b, "%s start 2>/dev/null\n", paths.KeenPBRInit)
	b.WriteString("kill -HUP $(pidof dnsmasq) 2>/dev/null\n")
	b.WriteString("rm -f /opt/wr-deadman\n")
	b.WriteString("echo WR_KPBR_ROLLBACK_DONE\n")
	return b.String()
}
