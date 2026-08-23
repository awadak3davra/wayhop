package keenetic

import (
	"fmt"
	"os"
	"strings"

	"wayhop/internal/atomicfile"
)

// netfilter.go installs WayHop's NDM netfilter.d re-apply hook. KeeneticOS NDM rebuilds
// netfilter periodically and on every config change, WIPING any iptables rules added from
// /opt (the red-team's "NDM rebuild silently kills LAN-through-TUN" hole — this is why the
// live S89/keen-pbr re-assert their rules from a netfilter.d hook + a 1-min cron). WayHop
// installs its own hook so the LAN-through-TUN forwarding survives every rebuild.

// NetfilterHookOptions configure the hook.
type NetfilterHookOptions struct {
	Path     string // default /opt/etc/ndm/netfilter.d/40-wayhop.sh
	TunIface string // the routing TUN device; default "wr-tun"
}

func (o *NetfilterHookOptions) defaults() {
	if o.Path == "" {
		o.Path = "/opt/etc/ndm/netfilter.d/40-wayhop.sh"
	}
	if o.TunIface == "" {
		o.TunIface = "wr-tun"
	}
}

// wrNetfilterHookScript renders the hook: idempotently (`-C || -I/-A`) re-assert LAN↔TUN
// FORWARD + TUN MASQUERADE, gated on the `$table` NDM passes in and on the TUN existing
// (mirrors S89's ensure_lan_fwd). Safe to run on every netfilter event.
func wrNetfilterHookScript(tun string) string {
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# WayHop — re-assert LAN-through-TUN forwarding after NDM netfilter rebuilds.\n")
	b.WriteString("# Auto-generated; do not edit. Removed on WayHop teardown.\n")
	fmt.Fprintf(&b, "IF=%s\n", tun)
	b.WriteString(`ip link show "$IF" >/dev/null 2>&1 || exit 0` + "\n")
	b.WriteString(`if [ "$table" = "filter" ]; then` + "\n")
	b.WriteString(`  iptables -C FORWARD -i br0 -o "$IF" -j ACCEPT 2>/dev/null || iptables -I FORWARD -i br0 -o "$IF" -j ACCEPT` + "\n")
	b.WriteString(`  iptables -C FORWARD -i "$IF" -o br0 -j ACCEPT 2>/dev/null || iptables -I FORWARD -i "$IF" -o br0 -j ACCEPT` + "\n")
	b.WriteString("fi\n")
	b.WriteString(`if [ "$table" = "nat" ]; then` + "\n")
	b.WriteString(`  iptables -t nat -C POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IF" -j MASQUERADE` + "\n")
	b.WriteString("fi\n")
	b.WriteString("exit 0\n")
	return b.String()
}

// InstallNetfilterHook writes the hook executable. ⚠️ DEVICE-WRITING (cutover only); runs on
// the device, so the file lands in NDM's netfilter.d. Idempotent (atomic overwrite).
func InstallNetfilterHook(opt NetfilterHookOptions) error {
	opt.defaults()
	if err := atomicfile.Write(opt.Path, []byte(wrNetfilterHookScript(opt.TunIface)), 0o755); err != nil {
		return fmt.Errorf("install netfilter hook %s: %w", opt.Path, err)
	}
	return nil
}

// RemoveNetfilterHook deletes the hook (WayHop teardown). A missing file is not an error.
func RemoveNetfilterHook(opt NetfilterHookOptions) error {
	opt.defaults()
	if err := os.Remove(opt.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove netfilter hook %s: %w", opt.Path, err)
	}
	return nil
}
