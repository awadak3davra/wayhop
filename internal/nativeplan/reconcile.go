package nativeplan

import (
	"fmt"
	"sort"

	"wayhop/internal/keenetic"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

// Reconciliation is the exact native delta between the authenticated baseline and target plans.
// The target plans create/update desired resources; removals are derived only from previously
// WayHop-owned decisions. External/adopted interfaces never enter a teardown list.
type Reconciliation struct {
	Platform         platform.Platform
	Target           *Plan
	OpenWrtRemovals  []netvpn.RemovalPlan
	KeeneticTeardown []string
	// KeeneticPriorityRestore puts back the `ip global` values on interfaces the baseline raised and
	// the target no longer does. It is separate from KeeneticTeardown because it is not a removal:
	// these are `interface X` / `ip global N` blocks writing the router's own numbers back, and the
	// teardown list is validated as `no …` commands. Without it a successful apply could leave a
	// tunnel on top of the ladder holding a default route the profile no longer asks for.
	KeeneticPriorityRestore [][]string
}

func Reconcile(previous, target *Plan, capabilities platform.CapabilitySet, networkUCI, firewallUCI string) (*Reconciliation, error) {
	if target == nil || (target.Platform != platform.OpenWrt && target.Platform != platform.Keenetic) {
		return nil, fmt.Errorf("native reconcile: target platform is unavailable")
	}
	if previous != nil && previous.Platform != target.Platform {
		return nil, fmt.Errorf("native reconcile: baseline platform %q differs from target %q", previous.Platform, target.Platform)
	}
	if err := validateManagedTargetOwnership(previous, target); err != nil {
		return nil, err
	}
	result := &Reconciliation{Platform: target.Platform, Target: target}
	if previous == nil {
		return result, nil
	}
	switch target.Platform {
	case platform.OpenWrt:
		removals, err := reconcileOpenWrt(previous, target, capabilities, networkUCI, firewallUCI)
		if err != nil {
			return nil, err
		}
		result.OpenWrtRemovals = removals
	case platform.Keenetic:
		if previous.Keenetic == nil || target.Keenetic == nil {
			return nil, fmt.Errorf("native reconcile: Keenetic baseline or target plan is missing")
		}
		for _, decision := range previous.Decisions {
			if nativeManagedPath(decision.Path) {
				if err := requireCapability(capabilities, decision.RollbackCap, decision.EndpointID); err != nil {
					return nil, fmt.Errorf("native reconcile: Keenetic teardown authority: %w", err)
				}
			}
		}
		// Prepare applies the target additively before commit removes obsolete resources. Never
		// remove an interface/route whose identity is still present in the target: doing so after
		// prepare would tear down the just-updated connection.
		targetOwned := make(map[string]bool)
		for _, command := range keenetic.TeardownCommands(target.Keenetic) {
			targetOwned[command] = true
		}
		for _, command := range keenetic.TeardownCommands(previous.Keenetic) {
			if !targetOwned[command] {
				result.KeeneticTeardown = append(result.KeeneticTeardown, command)
			}
		}
		// The priority ladder reconciles the same way, but cannot ride the list above: it is an edit to
		// a setting the ROUTER owns, so there is no `no` command that undoes it.
		result.KeeneticPriorityRestore = keenetic.StaleGlobalPriorityBlocks(previous.Keenetic, target.Keenetic)
	}
	return result, nil
}

// validateManagedTargetOwnership prevents a live interface name from granting its own write
// authority. PathNativeManage means the compiler observed an existing router resource; it is safe
// only when the authenticated baseline says WayHop already owned the same endpoint/interface.
// A desired Owner value or a matching generated name is not ownership evidence.
func validateManagedTargetOwnership(previous, target *Plan) error {
	owned := make(map[string]string)
	if previous != nil {
		for _, decision := range previous.Decisions {
			if nativeManagedPath(decision.Path) && decision.EndpointID != "" && decision.Interface != "" {
				owned[decision.EndpointID] = decision.Interface
			}
		}
	}
	for _, decision := range target.Decisions {
		if decision.Path != PathNativeManage && decision.Path != PathNativeUpdate {
			continue
		}
		if decision.EndpointID == "" || decision.Interface == "" ||
			owned[decision.EndpointID] != decision.Interface {
			return fmt.Errorf("native reconcile: endpoint %q cannot manage interface %q without matching authenticated ownership",
				decision.EndpointID, decision.Interface)
		}
	}
	return nil
}

func reconcileOpenWrt(previous, target *Plan, capabilities platform.CapabilitySet, networkUCI, firewallUCI string) ([]netvpn.RemovalPlan, error) {
	if previous.Keenetic != nil || target.Keenetic != nil {
		return nil, fmt.Errorf("native reconcile: OpenWrt plan contains Keenetic artifacts")
	}
	targetInterfaces := make(map[string]bool)
	for _, decision := range target.Decisions {
		if nativeManagedPath(decision.Path) {
			targetInterfaces[decision.Interface] = true
		}
	}
	live := netvpn.ParseUCIShow(networkUCI)
	var removals []netvpn.RemovalPlan
	for _, decision := range previous.Decisions {
		if !nativeManagedPath(decision.Path) || targetInterfaces[decision.Interface] {
			continue
		}
		if decision.RollbackCap == "" {
			return nil, fmt.Errorf("native reconcile: baseline endpoint %q has no authenticated remove authority", decision.EndpointID)
		}
		if err := requireCapability(capabilities, decision.RollbackCap, decision.EndpointID); err != nil {
			return nil, fmt.Errorf("native reconcile: current remove authority: %w", err)
		}
		if _, exists := live[decision.Interface]; !exists {
			for _, zone := range netvpn.ParseFirewallZones(firewallUCI) {
				for _, member := range zone.Networks {
					if member == decision.Interface {
						return nil, fmt.Errorf("native reconcile: absent interface %q remains in firewall zone %q", decision.Interface, zone.Name)
					}
				}
			}
			continue
		}
		removal, err := netvpn.BuildRemovalPlan(decision.Interface, networkUCI, firewallUCI)
		if err != nil {
			return nil, fmt.Errorf("native reconcile: endpoint %q: %w", decision.EndpointID, err)
		}
		removals = append(removals, removal)
	}
	sort.Slice(removals, func(i, j int) bool { return removals[i].Iface < removals[j].Iface })
	return removals, nil
}

func nativeManagedPath(path Path) bool {
	return path == PathNativeCreate || path == PathNativeManage || path == PathNativeUpdate
}
