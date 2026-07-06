package keenetic

import (
	"fmt"
	"strings"
)

// kernel.go is WayHop's Keenetic KERNEL routing plane (raw `ip route`, run via the Runner),
// replacing S87default_via_nl (endpoint bypasses + local-DNR-direct + mgmt-reverse) and S89's
// default tier. The default route points at wr-tun, so sing-box owns the Hy2/AWG/VLESS failover
// (its default_3tier group); the NDM-managed WAN default (metric 1000) is the kernel backstop
// if wr-tun dies (→ traffic falls to WAN, matching the user's all-VPN-down→WAN choice). RU-
// direct stays with the kept S86 (fwmark 0x250 → table 250), which is evaluated before this
// default. Specific routes here (bypass/local-DNR/mgmt-reverse) override the default→wr-tun.

// KernelPlaneOptions describe the kernel routing plane.
type KernelPlaneOptions struct {
	TunIface    string   // routing TUN, e.g. "wr-tun"
	WanIface    string   // WAN interface, e.g. "eth3"
	WanGateway  string   // discovered at runtime (default via <gw> dev <wan>)
	TunMetric   int      // default-route metric for the TUN (default 50; below the WAN backstop 1000)
	MgmtTun     string   // mgmt tunnel for reverse routes, e.g. "nwg2"
	BypassIPs   []string // /32 VPN server endpoints → WAN (anti-loop)
	LocalDirect []string // CIDRs forced WAN-direct (e.g. mom's local DNR 109.254.0.0/16)
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

// kernelPlaneAddCommands renders the idempotent `ip route replace` commands to bring the
// kernel plane up. WanGateway must be set (discover it first).
func kernelPlaneAddCommands(o KernelPlaneOptions) ([]string, error) {
	o.defaults()
	if o.WanGateway == "" {
		return nil, fmt.Errorf("kernel plane: WAN gateway not set")
	}
	var c []string
	for _, ip := range o.BypassIPs { // anti-loop: VPN servers reachable only via WAN
		c = append(c, fmt.Sprintf("ip route replace %s via %s dev %s metric 50", ip, o.WanGateway, o.WanIface))
	}
	for _, cidr := range o.LocalDirect { // mom's local ISP ranges never tunneled
		c = append(c, fmt.Sprintf("ip route replace %s via %s dev %s metric 100", cidr, o.WanGateway, o.WanIface))
	}
	for _, cidr := range o.MgmtReverse { // admin-reply routing back via the mgmt tunnel
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
	for _, cidr := range o.LocalDirect {
		c = append(c, fmt.Sprintf("ip route del %s", cidr))
	}
	for _, ip := range o.BypassIPs {
		c = append(c, fmt.Sprintf("ip route del %s", ip))
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
