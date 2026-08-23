package server

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
)

// The IPv6 leak row deliberately stops one question short. It answers "can v6 go AROUND the
// tunnels" and then says, in its own detail, that whether the tunnel actually carries v6 is a
// separate question. That question has a price, and it was measured rather than argued:
//
// on a router whose v6 default routes egress four tunnels, a plain HTTPS GET from the router itself
// picked the AAAA of its target and failed outright with "connect: network is unreachable", then
// succeeded on the next attempt over IPv4. Nothing on the panel accounted for it. The router's own
// fetches are the ones that pay: routing-list refreshes, the update check, an engine download. They
// resolve a name, get an AAAA, try a route that exists but carries nothing, and fail intermittently
// depending on which address the resolver hands back first.
//
// So this row answers exactly that and nothing more: v6 is routed somewhere, does anything come
// back?

// ipv6CarriedTarget is the probe destination: a well-known public resolver reachable over v6 when v6
// works at all. TCP rather than ICMP because TCP is what the router's own fetches use, and an ICMP
// answer would not prove a connection can be made.
const ipv6CarriedTarget = "[2606:4700:4700::1111]:443"

// ipv6CarriedVerdict is the pure decision. Applicable only where the leak row already established
// the shape: a global v6 address AND a default route into a tunnel. Anywhere else this row has
// nothing to say and must say so rather than inventing a pass.
func ipv6CarriedVerdict(hasGlobal, defaultsIntoTunnel, probed, reachable bool) (status, summary, fix string) {
	if !hasGlobal || !defaultsIntoTunnel {
		return "na", "no IPv6 is routed into a tunnel here, so there is nothing to carry", ""
	}
	if !probed {
		// The probe did not run. Saying "works" would be the reassuring guess this file has been
		// burned by before; saying "broken" would be the opposite guess. Neither is evidence.
		return "warn", "IPv6 is routed into a tunnel, but this check could not test whether it carries traffic", ""
	}
	if reachable {
		return "pass", "IPv6 routed into the tunnel reaches the internet", ""
	}
	return "warn",
		"IPv6 is routed into a tunnel that does not carry it",
		"The router's own outbound requests — routing-list refreshes, the update check, engine downloads — " +
			"resolve a name, pick its IPv6 address, and fail on this dead route before falling back. " +
			"Either give the tunnel working IPv6 or remove the IPv6 default route so nothing chooses it."
}

// ipv6CarriedProbe dials the target and reports whether the dial was even attempted. A dial that
// could not run (no v6 stack at all) is not evidence that v6 is broken.
func ipv6CarriedProbe(ctx context.Context) (probed, reachable bool) {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp6", ipv6CarriedTarget)
	if err == nil {
		_ = c.Close()
		return true, true
	}
	if ctx.Err() != nil {
		return false, false
	}
	// "network is unreachable" and a refusal are both real answers about this router's v6 path; a
	// timeout is too, on a route that exists.
	return true, false
}

// ipv6CarriedCheck is the battery row. Read-only.
func ipv6CarriedCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "ipv6-carried", Label: "IPv6 works where it is routed"}
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		row.Status, row.Summary = "na", "this host has no IPv6 state to read"
		return row
	}
	hasGlobal := ipv6HasGlobal(string(b))
	devs := ipv6DefaultRouteDevices()
	intoTunnel := false
	if hasGlobal && len(devs) > 0 {
		wan, _ := probeWANInterface()
		intoTunnel = true
		for _, d := range devs {
			if wan == "" || d == wan {
				intoTunnel = false // out the uplink, or we cannot tell — that is the leak row's business
			}
		}
	}
	var probed, reachable bool
	if hasGlobal && intoTunnel {
		probed, reachable = ipv6CarriedProbe(ctx)
	}
	row.Status, row.Summary, row.Fix = ipv6CarriedVerdict(hasGlobal, intoTunnel, probed, reachable)
	if intoTunnel && len(devs) > 0 {
		row.Detail = "IPv6 default route egresses " + strings.Join(devs, ", ")
	}
	return row
}
