package keenetic

import (
	"fmt"
	"net/netip"
	"strings"
)

// kernel.go is WayHop's Keenetic KERNEL routing plane (raw `ip route`, run via the Runner),
// replacing S87example_default (endpoint bypasses + local-DNR-direct + mgmt-reverse) and S89's
// default tier. The default route points at wr-tun, so sing-box owns the Hy2/AWG/VLESS failover
// (its default_3tier group); the NDM-managed WAN default (metric 1000) is the kernel backstop
// if wr-tun dies (→ traffic falls to WAN, matching the user's all-VPN-down→WAN choice). RU-
// direct stays with the kept S86 (fwmark 0x250 → table 250), which is evaluated before this
// default. Specific routes here (bypass/local-DNR/mgmt-reverse) override the default→wr-tun.

// KernelPlaneOptions describe the kernel routing plane.
type KernelPlaneOptions struct {
	TunIface    string   // routing TUN, e.g. "wr-tun"
	WanIface    string   // WAN interface, e.g. "eth3"
	WanGateway  string   // discovered at runtime (IPv4 default via <gw> dev <wan>)
	WanGateway6 string   // discovered at runtime (IPv6 default via <gw6> dev <wan>); "" when no IPv6 WAN
	TunMetric   int      // default-route metric for the TUN (default 50; below the WAN backstop 1000)
	MgmtTun     string   // mgmt tunnel for reverse routes, e.g. "nwg2"
	BypassIPs   []string // /32 VPN server endpoints → WAN (anti-loop)
	LocalDirect []string // CIDRs forced WAN-direct (e.g. a local ISP's DNR range)
	MgmtReverse []string // subnets routed back via the mgmt tunnel (e.g. 10.0.0.0/24)
}

func (o *KernelPlaneOptions) defaults() {
	if o.TunIface == "" {
		o.TunIface = "wr-tun"
	}
	if o.WanIface == "" {
		o.WanIface = "eth3"
	}
	if o.TunMetric == 0 {
		o.TunMetric = 50
	}
	if o.MgmtTun == "" {
		o.MgmtTun = "nwg2"
	}
}

// addrIs6 reports whether dst (a bare IP or a CIDR prefix) is a genuine IPv6 address. A v4-mapped v6
// address (::ffff:a.b.c.d) counts as v4. Unparseable tokens default to v4 — preserving the legacy
// IPv4 command form for any non-IP string rather than silently dropping it.
func addrIs6(dst string) bool {
	dst = strings.TrimSpace(dst)
	if p, err := netip.ParsePrefix(dst); err == nil {
		return p.Addr().Is6() && !p.Addr().Is4In6()
	}
	if a, err := netip.ParseAddr(dst); err == nil {
		return a.Is6() && !a.Is4In6()
	}
	return false
}

// kernelPlaneHasV6 reports whether any bypass/local-direct target needs the IPv6 WAN gateway.
func kernelPlaneHasV6(o KernelPlaneOptions) bool {
	for _, ip := range o.BypassIPs {
		if addrIs6(ip) {
			return true
		}
	}
	for _, cidr := range o.LocalDirect {
		if addrIs6(cidr) {
			return true
		}
	}
	return false
}

// kernelPlaneAddCommands renders the idempotent `ip route replace` commands to bring the
// kernel plane up. WanGateway (IPv4) must be set (discover it first); WanGateway6 is needed only when
// a bypass/local-direct target is IPv6.
func kernelPlaneAddCommands(o KernelPlaneOptions) ([]string, error) {
	o.defaults()
	if o.WanGateway == "" {
		return nil, fmt.Errorf("kernel plane: WAN gateway not set")
	}
	var c []string
	// route emits a WAN-via route for dst in the correct address family. A v6 destination MUST use the
	// v6 gateway and the `ip -6` family: pairing a v6 dest with the IPv4 gateway makes iproute2 reject
	// the command and roll back the whole cutover. When the box has no IPv6 WAN (WanGateway6 unset) the
	// v6 target is SKIPPED rather than aborting — a v6 endpoint can't be bypassed without a v6 WAN.
	route := func(dst string, metric int) {
		if addrIs6(dst) {
			if o.WanGateway6 == "" {
				return
			}
			c = append(c, fmt.Sprintf("ip -6 route replace %s via %s dev %s metric %d", dst, o.WanGateway6, o.WanIface, metric))
			return
		}
		c = append(c, fmt.Sprintf("ip route replace %s via %s dev %s metric %d", dst, o.WanGateway, o.WanIface, metric))
	}
	for _, ip := range o.BypassIPs { // anti-loop: VPN servers reachable only via WAN
		route(ip, 50)
	}
	for _, cidr := range o.LocalDirect { // local ISP ranges never tunneled
		route(cidr, 100)
	}
	for _, cidr := range o.MgmtReverse { // admin-reply routing back via the mgmt tunnel (dev-only: iproute2 infers the family from the dest)
		c = append(c, fmt.Sprintf("ip route replace %s dev %s", cidr, o.MgmtTun))
	}
	// General default → wr-tun (sing-box). The NDM WAN default (metric 1000) backstops it.
	c = append(c, fmt.Sprintf("ip route replace default dev %s metric %d", o.TunIface, o.TunMetric))
	return c, nil
}

// kernelPlaneDelCommands renders the teardown (`ip route del`, best-effort, reverse order).
func kernelPlaneDelCommands(o KernelPlaneOptions) []string {
	o.defaults()
	c := []string{fmt.Sprintf("ip route del default dev %s metric %d", o.TunIface, o.TunMetric)}
	for _, cidr := range o.MgmtReverse {
		c = append(c, fmt.Sprintf("ip route del %s dev %s", cidr, o.MgmtTun))
	}
	del := func(dst string) {
		if addrIs6(dst) {
			c = append(c, fmt.Sprintf("ip -6 route del %s", dst))
			return
		}
		c = append(c, fmt.Sprintf("ip route del %s", dst))
	}
	for _, cidr := range o.LocalDirect {
		del(cidr)
	}
	for _, ip := range o.BypassIPs {
		del(ip)
	}
	return c
}

// discoverWanGateway reads the live WAN gateway from the routing table.
func discoverWanGateway(run Runner, wanIface string) (string, error) {
	out, err := run.Run("", "sh", "-c", "ip route show default | awk '/dev "+wanIface+"/{print $3; exit}'")
	if err != nil {
		return "", fmt.Errorf("discover WAN gateway: %w", err)
	}
	gw := strings.TrimSpace(out)
	if gw == "" {
		return "", fmt.Errorf("WAN gateway not found on %s", wanIface)
	}
	return gw, nil
}

// discoverWanGateway6 reads the live IPv6 WAN gateway from the routing table. Best-effort: a box with
// no IPv6 WAN returns an error and the caller then simply skips any v6 bypass/local-direct routes.
func discoverWanGateway6(run Runner, wanIface string) (string, error) {
	out, err := run.Run("", "sh", "-c", "ip -6 route show default | awk '/dev "+wanIface+"/{print $3; exit}'")
	if err != nil {
		return "", fmt.Errorf("discover IPv6 WAN gateway: %w", err)
	}
	gw := strings.TrimSpace(out)
	if gw == "" {
		return "", fmt.Errorf("IPv6 WAN gateway not found on %s", wanIface)
	}
	return gw, nil
}

// ApplyKernelPlane discovers the WAN gateway (if unset) and applies the kernel routes. ⚠️
// DEVICE-WRITING; cutover only. Wire into Cutover via ApplyKernel.
func ApplyKernelPlane(run Runner, o KernelPlaneOptions) error {
	o.defaults()
	if o.WanGateway == "" {
		gw, err := discoverWanGateway(run, o.WanIface)
		if err != nil {
			return err
		}
		o.WanGateway = gw
	}
	// Discover the IPv6 WAN gateway too when any bypass/local-direct target is IPv6, so those routes
	// get the correct `ip -6 ... via <v6-gw>` form. Best-effort: on a box with no IPv6 WAN this fails
	// and kernelPlaneAddCommands skips the v6 targets rather than aborting the cutover.
	if o.WanGateway6 == "" && kernelPlaneHasV6(o) {
		if gw6, err := discoverWanGateway6(run, o.WanIface); err == nil {
			o.WanGateway6 = gw6
		}
	}
	cmds, err := kernelPlaneAddCommands(o)
	if err != nil {
		return err
	}
	for _, cmd := range cmds {
		if _, err := run.Run("", "sh", "-c", cmd); err != nil {
			return fmt.Errorf("apply kernel route %q: %w", cmd, err)
		}
	}
	return nil
}

// TeardownKernelPlane removes the kernel routes (best-effort). ⚠️ DEVICE-WRITING.
func TeardownKernelPlane(run Runner, o KernelPlaneOptions) error {
	for _, cmd := range kernelPlaneDelCommands(o) {
		_, _ = run.Run("", "sh", "-c", cmd)
	}
	return nil
}
