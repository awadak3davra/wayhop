package server

import (
	"context"
	"fmt"
	"strings"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// The router-native half of the routing switch (routingswitch.go). Turning routing off removes what
// a native plan ROUTES with and keeps what it CONNECTS with: the tunnels stay up, unrouted, so
// turning routing back on is one commit away and nothing has to be re-created.
//
//   - OpenWrt: nothing to do here. Every UCI tunnel WayHop writes carries route_allowed_ips='0'
//     (netvpn/openwrt_write.go), so netifd installs no route for it; what steers traffic into it is
//     the kernel plane, which the switch removes on its own.
//   - KeeneticOS: the plan's `ip route` commands and the `ip global` ladder that hands the default
//     route to a tunnel. Its `interface WireguardN` blocks stay.

// routingOff removes a native target's routing and leaves its interfaces. changed reports whether
// anything on the router was edited, so an off state already in force is not saved again.
func (adapter *exactNativePlatformAdapter) routingOff(ctx context.Context, target nativeplan.Plan) (changed bool, err error) {
	if adapter == nil {
		return false, errExactNativePlatform
	}
	switch target.Platform {
	case platform.OpenWrt:
		return false, nil
	case platform.Keenetic:
		if adapter.keenetic == nil {
			return false, errExactNativePlatform
		}
		return adapter.keenetic.routingOff(ctx, target)
	default:
		return false, errExactNativePlatform
	}
}

// routingSave makes the router's current native state its startup configuration, after the switch
// changed it either way. Without it a Keenetic reboot would bring back from flash exactly the state
// the switch just left (routes and ladder after "off", none after "on").
func (adapter *exactNativePlatformAdapter) routingSave(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil {
		return errExactNativePlatform
	}
	switch target.Platform {
	case platform.OpenWrt:
		// UCI commits are already durable; the switch wrote nothing native there.
		return nil
	case platform.Keenetic:
		if adapter.keenetic == nil || adapter.keenetic.runner == nil {
			return errExactNativePlatform
		}
		if _, err := adapter.keenetic.runner.ParseBatch(ctx, []string{exactKeeneticSaveCommand}); err != nil {
			return fmt.Errorf("%w: the configuration could not be saved", errExactKeeneticApply)
		}
		return nil
	default:
		return errExactNativePlatform
	}
}

// routingOff lowers every interface the plan raised on the `ip global` ladder (keenetic.
// RoutingOffPriorities) and removes the plan's routes that are still in force, then reads the
// running config back: an accepted-but-ignored command must not be reported as routing removed.
// It is idempotent — a route already gone is not asked for again, which is what lets boot re-assert
// the off state on a router that already has it.
func (adapter *exactKeeneticNativeAdapter) routingOff(ctx context.Context, target nativeplan.Plan) (changed bool, err error) {
	if adapter == nil || adapter.runner == nil || adapter.readConfig == nil {
		return false, errExactKeeneticUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	if !validExactKeeneticTarget(target) {
		return false, errExactKeeneticPlan
	}
	plan := target.Keenetic
	if len(plan.Routes) == 0 && len(plan.GlobalPriority) == 0 {
		return false, nil
	}
	running, err := adapter.readConfig(ctx)
	if err != nil || strings.TrimSpace(running) == "" {
		return changed, fmt.Errorf("%w: the running configuration could not be read", errExactKeeneticApply)
	}
	observedBefore := keenetic.GlobalPriorities(running)
	lowered, err := keenetic.RoutingOffPriorities(plan, observedBefore)
	if err != nil {
		return changed, fmt.Errorf("%w: %v", errExactKeeneticPlan, err)
	}
	lines := normalizedNDMConfigLines(running)
	var removals []string
	for _, command := range keenetic.RouteTeardownCommands(plan) {
		if containsRetiredNDMIdentity(lines, normalizeNDMCommand(strings.TrimPrefix(command, "no "))) {
			removals = append(removals, command)
		}
	}
	if !validExactKeeneticTeardown(removals) {
		return false, errExactKeeneticPlan
	}
	// The ladder first, as cleanup does: while a raised tunnel stands it carries everything, and the
	// routes are the narrower decision underneath it.
	pending := map[string]int{}
	for iface, want := range lowered {
		if observedBefore[iface] != want {
			pending[iface] = want
		}
	}
	if len(pending) == 0 && len(removals) == 0 {
		return false, nil
	}
	changed = true
	for _, block := range keenetic.LadderBlocks(pending) {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), block...)); err != nil {
			return changed, fmt.Errorf("%w: lowering %s", errExactKeeneticApply, strings.TrimPrefix(block[0], "interface "))
		}
	}
	if len(removals) != 0 {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), removals...)); err != nil {
			return changed, fmt.Errorf("%w: removing the routes", errExactKeeneticApply)
		}
	}
	after, err := adapter.readConfig(ctx)
	if err != nil || strings.TrimSpace(after) == "" {
		return changed, fmt.Errorf("%w: the running configuration could not be read back", errExactKeeneticApply)
	}
	observed := keenetic.GlobalPriorities(after)
	for iface, want := range lowered {
		if observed[iface] != want {
			return changed, fmt.Errorf("%w: %s still reads ip global %d, not %d", errExactKeeneticApply, iface, observed[iface], want)
		}
	}
	afterLines := normalizedNDMConfigLines(after)
	for _, route := range plan.Routes {
		if key := normalizeNDMCommand(keenetic.RouteKey(route)); containsRetiredNDMIdentity(afterLines, key) {
			return changed, fmt.Errorf("%w: %q is still in force", errExactKeeneticApply, key)
		}
	}
	return true, nil
}
