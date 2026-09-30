package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

var (
	errExactOpenWrtUnavailable = errors.New("exact OpenWrt native adapter is unavailable")
	errExactOpenWrtPlan        = errors.New("exact OpenWrt native plan is invalid")
	errExactOpenWrtOperation   = errors.New("exact OpenWrt native operation failed")
)

const (
	exactOpenWrtCommandTimeout = 15 * time.Second
	exactOpenWrtOutputLimit    = 1 << 20
	exactOpenWrtMaxCommand     = 64 << 10
	exactOpenWrtShellPath      = "/bin/sh"
)

type exactOpenWrtCommandRunner interface {
	Run(context.Context, string, string, ...string) (string, error)
}

type exactOpenWrtContextRunner struct{}

func (exactOpenWrtContextRunner) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	if ctx == nil || stdin != "" || name != "sh" || len(args) != 2 || args[0] != "-c" ||
		!validExactOpenWrtCommand(args[1]) {
		return "", errExactOpenWrtPlan
	}
	output, err := runHostCommandBounded(ctx, exactOpenWrtCommandTimeout, exactOpenWrtOutputLimit,
		applyHostCommandWaitDelay, exactOpenWrtShellPath, "-c", args[1])
	if err != nil {
		return "", errExactOpenWrtOperation
	}
	return output, nil
}

type exactOpenWrtPlanRunner struct {
	ctx    context.Context
	runner exactOpenWrtCommandRunner
}

func (runner exactOpenWrtPlanRunner) Run(stdin, name string, args ...string) (string, error) {
	return runner.runner.Run(runner.ctx, stdin, name, args...)
}

// exactOpenWrtNativeAdapter is deliberately plan-driven. It receives no Config, Profile, UCI
// builder, or capability detector, so it cannot reinterpret a reviewed transaction at execution
// time. netvpn.Plan.Apply performs a fresh UCI preflight, stages, reads back, verifies, then commits.
type exactOpenWrtNativeAdapter struct {
	runner exactOpenWrtCommandRunner
}

func newExactOpenWrtNativeAdapter(runner exactOpenWrtCommandRunner) (*exactOpenWrtNativeAdapter, error) {
	if runner == nil {
		return nil, errExactOpenWrtUnavailable
	}
	return &exactOpenWrtNativeAdapter{runner: runner}, nil
}

func (adapter *exactOpenWrtNativeAdapter) prepare(
	ctx context.Context,
	target nativeplan.Plan,
) error {
	if adapter == nil || adapter.runner == nil {
		return errExactOpenWrtUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := validateExactOpenWrtTarget(target); err != nil {
		return err
	}
	for _, plan := range target.OpenWrt {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		converged, err := adapter.targetConverged(ctx, plan)
		if err != nil {
			return err
		}
		if converged {
			continue
		}
		result, err := plan.Apply(exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner})
		if err != nil || !result.Applied {
			if err == nil {
				err = errExactOpenWrtPlan
			}
			return fmt.Errorf("%w: prepare interface %q: %v", errExactOpenWrtPlan, plan.Iface, err)
		}
	}
	// The engine-plugin devices join the reviewed zone before the plugins start, so the first packet
	// forwarded into a new TUN already has a policy.
	for _, binding := range target.OpenWrtBindings {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		result, err := binding.Apply(exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner})
		if err != nil || !result.Applied {
			if err == nil {
				err = errExactOpenWrtPlan
			}
			return fmt.Errorf("%w: bind device %q: %v", errExactOpenWrtPlan, binding.Device, err)
		}
	}
	return nil
}

func (adapter *exactOpenWrtNativeAdapter) commit(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil || adapter.runner == nil {
		return errExactOpenWrtUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if reconcile.Platform != platform.OpenWrt ||
		reconcile.Target == nil || reconcile.Target.Platform != platform.OpenWrt ||
		len(reconcile.KeeneticTeardown) != 0 {
		return errExactOpenWrtPlan
	}
	seen := make(map[string]bool, len(reconcile.OpenWrtRemovals))
	for _, removal := range reconcile.OpenWrtRemovals {
		if removal.Iface == "" || seen[removal.Iface] {
			return errExactOpenWrtPlan
		}
		seen[removal.Iface] = true
		if err := context.Cause(ctx); err != nil {
			return err
		}
		converged, err := adapter.removalConverged(ctx, removal)
		if err != nil {
			return err
		}
		if converged {
			continue
		}
		result, err := removal.Apply(exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner})
		if err != nil || !result.Applied {
			if err == nil {
				err = errExactOpenWrtPlan
			}
			return fmt.Errorf("%w: remove interface %q: %v", errExactOpenWrtPlan, removal.Iface, err)
		}
	}
	unbound := make(map[string]bool, len(reconcile.OpenWrtUnbindings))
	for _, unbinding := range reconcile.OpenWrtUnbindings {
		if !validExactOpenWrtUnbinding(unbinding) || unbound[unbinding.Device] {
			return errExactOpenWrtPlan
		}
		unbound[unbinding.Device] = true
		if err := context.Cause(ctx); err != nil {
			return err
		}
		result, err := unbinding.Apply(exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner})
		if err != nil || !result.Applied {
			if err == nil {
				err = errExactOpenWrtPlan
			}
			return fmt.Errorf("%w: unbind device %q: %v", errExactOpenWrtPlan, unbinding.Device, err)
		}
	}
	return nil
}

// targetConverged makes authenticated replay idempotent without rebuilding the plan from mutable
// desired state. It accepts only the exact intended interface plus its named firewall-zone binding;
// any partial or different state falls through to Plan.Apply, whose original preconditions then
// refuse rather than overwriting an operator edit.
func (adapter *exactOpenWrtNativeAdapter) targetConverged(
	ctx context.Context,
	plan netvpn.Plan,
) (bool, error) {
	if !validExactOpenWrtWritePlan(plan) {
		return false, errExactOpenWrtPlan
	}
	runner := exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner}
	changes, err := runner.Run("", "sh", "-c", "uci changes")
	if err != nil {
		return false, errExactOpenWrtOperation
	}
	if strings.TrimSpace(changes) != "" {
		return false, nil
	}
	network, err := runner.Run("", "sh", "-c", "uci show network")
	if err != nil {
		return false, errExactOpenWrtOperation
	}
	if len(plan.VerifyAgainst(network)) != 0 {
		return false, nil
	}
	if plan.Zone == "" {
		return true, nil
	}
	firewall, err := runner.Run("", "sh", "-c", "uci show firewall")
	if err != nil {
		return false, errExactOpenWrtOperation
	}
	zone, ok := netvpn.FindZone(netvpn.ParseFirewallZones(firewall), plan.Zone)
	if !ok {
		return false, nil
	}
	for _, iface := range zone.Networks {
		if iface == plan.Iface {
			return true, nil
		}
	}
	return false, nil
}

// removalConverged is the removal counterpart: an already-absent owned interface is success only
// when no firewall zone still names it. A half-removed target falls through and is refused by the
// exact removal preconditions instead of being reported as repaired.
func (adapter *exactOpenWrtNativeAdapter) removalConverged(
	ctx context.Context,
	plan netvpn.RemovalPlan,
) (bool, error) {
	if !validExactOpenWrtRemovalPlan(plan) {
		return false, errExactOpenWrtPlan
	}
	runner := exactOpenWrtPlanRunner{ctx: ctx, runner: adapter.runner}
	for _, config := range []string{"network", "firewall"} {
		changes, err := runner.Run("", "sh", "-c", "uci changes "+config)
		if err != nil {
			return false, errExactOpenWrtOperation
		}
		if strings.TrimSpace(changes) != "" {
			return false, nil
		}
	}
	network, err := runner.Run("", "sh", "-c", "uci show network")
	if err != nil {
		return false, errExactOpenWrtOperation
	}
	if _, present := netvpn.ParseUCIShow(network)[plan.Iface]; present {
		return false, nil
	}
	firewall, err := runner.Run("", "sh", "-c", "uci show firewall")
	if err != nil {
		return false, errExactOpenWrtOperation
	}
	return len(plan.VerifyRemoved(network, firewall)) == 0, nil
}

func validExactOpenWrtWritePlan(plan netvpn.Plan) bool {
	if netvpn.ValidInterfaceName(plan.Iface) != nil || plan.Intended.Name != plan.Iface ||
		(plan.Expected.Name != "" && plan.Expected.Name != plan.Iface) ||
		len(plan.Commands) == 0 || len(plan.Commit) == 0 ||
		(plan.Zone == "") != (plan.ZoneRef == "") {
		return false
	}
	for _, command := range append(append([]string(nil), plan.Commands...), plan.Commit...) {
		if !validExactOpenWrtCommand(command) {
			return false
		}
	}
	return true
}

// validExactOpenWrtBinding holds a device binding to the one shape it may have: a safe device name, a
// zone and its reference, firewall commands only, and the firewall commit.
func validExactOpenWrtBinding(binding netvpn.DeviceBinding) bool {
	if netvpn.ValidInterfaceName(binding.Device) != nil || binding.Zone == "" || binding.ZoneRef == "" ||
		len(binding.Commit) == 0 || len(binding.Commands) > 1 {
		return false
	}
	return validExactOpenWrtFirewallCommands(binding.Commands, binding.Commit)
}

func validExactOpenWrtUnbinding(unbinding netvpn.DeviceUnbinding) bool {
	if netvpn.ValidInterfaceName(unbinding.Device) != nil || len(unbinding.Commands) == 0 ||
		len(unbinding.Commands) != len(unbinding.Zones) || len(unbinding.Commit) == 0 {
		return false
	}
	return validExactOpenWrtFirewallCommands(unbinding.Commands, unbinding.Commit)
}

// validExactOpenWrtFirewallCommands admits only firewall staging commands and the firewall commit:
// a binding never touches /etc/config/network.
func validExactOpenWrtFirewallCommands(commands, commit []string) bool {
	for _, command := range commands {
		if !validExactOpenWrtCommand(command) ||
			!strings.HasPrefix(command, "uci add_list firewall.") && !strings.HasPrefix(command, "uci del_list firewall.") {
			return false
		}
	}
	for _, command := range commit {
		if command != "uci commit firewall" && command != "/etc/init.d/firewall reload" {
			return false
		}
	}
	return true
}

func validExactOpenWrtRemovalPlan(plan netvpn.RemovalPlan) bool {
	if netvpn.ValidInterfaceName(plan.Iface) != nil || plan.Expected.Name != plan.Iface ||
		len(plan.Commands) == 0 || len(plan.Commit) == 0 {
		return false
	}
	for _, command := range append(append([]string(nil), plan.Commands...), plan.Commit...) {
		if !validExactOpenWrtCommand(command) {
			return false
		}
	}
	return true
}

func validExactOpenWrtCommand(command string) bool {
	if command == "" || len(command) > exactOpenWrtMaxCommand ||
		strings.TrimSpace(command) != command || strings.ContainsAny(command, "\r\n\x00") ||
		unsafeOpenWrtShellSyntax(command) {
		return false
	}
	exact := []string{
		"uci changes", "uci show network", "uci show firewall",
		"uci revert network", "uci revert firewall",
		"uci commit network", "uci commit firewall",
		"/etc/init.d/network reload", "/etc/init.d/firewall reload",
	}
	for _, allowed := range exact {
		if command == allowed {
			return true
		}
	}
	if iface := strings.TrimPrefix(command, "ifdown "); iface != command &&
		iface != "" && !strings.ContainsRune(iface, ' ') && netvpn.ValidInterfaceName(iface) == nil {
		return true
	}
	prefixes := []string{
		"uci set network.", "uci set firewall.",
		"uci add_list network.", "uci add_list firewall.",
		"uci del_list network.", "uci del_list firewall.",
		"uci -q delete network.", "uci -q delete firewall.",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(command, prefix) && len(command) > len(prefix) {
			return true
		}
	}
	return false
}

func unsafeOpenWrtShellSyntax(command string) bool {
	var single, double, escaped bool
	for _, r := range command {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !single {
			escaped = true
			continue
		}
		if r == '\'' && !double {
			single = !single
			continue
		}
		if r == '"' && !single {
			double = !double
			continue
		}
		if !single && strings.ContainsRune("`$", r) {
			return true
		}
		if !single && !double && strings.ContainsRune(";&|<>()", r) {
			return true
		}
	}
	return single || double || escaped
}

func validateExactOpenWrtTarget(target nativeplan.Plan) error {
	if target.Platform != platform.OpenWrt || target.Keenetic != nil {
		return errExactOpenWrtPlan
	}
	plans := make(map[string]bool, len(target.OpenWrt))
	for _, plan := range target.OpenWrt {
		if plan.Iface == "" || plans[plan.Iface] {
			return errExactOpenWrtPlan
		}
		plans[plan.Iface] = true
	}
	bindings := make(map[string]bool, len(target.OpenWrtBindings))
	for _, binding := range target.OpenWrtBindings {
		if !validExactOpenWrtBinding(binding) || bindings[binding.Device] || plans[binding.Device] {
			return errExactOpenWrtPlan
		}
		bindings[binding.Device] = true
	}
	managed, plugins := 0, 0
	seenEndpoints := make(map[string]bool, len(target.Decisions))
	for _, decision := range target.Decisions {
		if decision.EndpointID == "" || seenEndpoints[decision.EndpointID] {
			return errExactOpenWrtPlan
		}
		seenEndpoints[decision.EndpointID] = true
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
			managed++
			if decision.Interface == "" || !plans[decision.Interface] {
				return errExactOpenWrtPlan
			}
		case nativeplan.PathNativeAdopt, nativeplan.PathExternal:
			if netvpn.ValidInterfaceName(decision.Interface) != nil || plans[decision.Interface] {
				return errExactOpenWrtPlan
			}
		case nativeplan.PathCompatibility:
			// The OpenWrt compatibility add-on is a core outbound, not a router interface. A
			// non-empty value here would be a forged binding from a different platform plan.
			if decision.Interface != "" {
				return errExactOpenWrtPlan
			}
		case nativeplan.PathEnginePlugin:
			// WayHop's engine runs it on its own device, which the plan binds to the reviewed zone and
			// never writes to /etc/config/network.
			plugins++
			if !bindings[decision.Interface] {
				return errExactOpenWrtPlan
			}
		default:
			return errExactOpenWrtPlan
		}
	}
	if managed != len(plans) || plugins != len(bindings) {
		return errExactOpenWrtPlan
	}
	return nil
}
