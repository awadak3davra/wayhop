package server

import (
	"context"
	"errors"

	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

var errExactNativePlatform = errors.New("exact native platform adapter is unavailable")

// exactNativePlatformAdapter is the sole platform selector for a native program. It never falls
// back across platforms and never invokes the compatibility core.
type exactNativePlatformAdapter struct {
	openwrt  *exactOpenWrtNativeAdapter
	keenetic *exactKeeneticNativeAdapter
}

func newExactNativePlatformAdapter(
	openwrt *exactOpenWrtNativeAdapter,
	keenetic *exactKeeneticNativeAdapter,
) (*exactNativePlatformAdapter, error) {
	if openwrt == nil && keenetic == nil {
		return nil, errExactNativePlatform
	}
	return &exactNativePlatformAdapter{openwrt: openwrt, keenetic: keenetic}, nil
}

func (adapter *exactNativePlatformAdapter) prepare(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil {
		return errExactNativePlatform
	}
	switch target.Platform {
	case platform.OpenWrt:
		if adapter.openwrt == nil {
			return errExactNativePlatform
		}
		return adapter.openwrt.prepare(ctx, target)
	case platform.Keenetic:
		if adapter.keenetic == nil {
			return errExactNativePlatform
		}
		return adapter.keenetic.prepare(ctx, target)
	default:
		return errExactNativePlatform
	}
}

func (adapter *exactNativePlatformAdapter) commit(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil {
		return errExactNativePlatform
	}
	if reconcile.Target == nil || reconcile.Platform != reconcile.Target.Platform {
		return errExactNativePlatform
	}
	switch reconcile.Platform {
	case platform.OpenWrt:
		if adapter.openwrt == nil {
			return errExactNativePlatform
		}
		return adapter.openwrt.commit(ctx, reconcile)
	case platform.Keenetic:
		if adapter.keenetic == nil {
			return errExactNativePlatform
		}
		return adapter.keenetic.commit(ctx, reconcile)
	default:
		return errExactNativePlatform
	}
}

func (adapter *exactNativePlatformAdapter) abort(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil {
		return errExactNativePlatform
	}
	switch target.Platform {
	case platform.Keenetic:
		if adapter.keenetic == nil {
			return errExactNativePlatform
		}
		return adapter.keenetic.abort(ctx, target)
	case platform.OpenWrt:
		// Each OpenWrt Plan.Apply rolls its own partially staged transaction back. Cross-plane
		// rollback remains owned by the durable recovery journal, never an inferred UCI delete.
		return nil
	default:
		return errExactNativePlatform
	}
}

// persist makes the live native state survive a reboot (Keenetic `system configuration save`).
// It runs only for a saving Apply or a Keep after every plane has been verified.
func (adapter *exactNativePlatformAdapter) persist(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil || reconcile.Target == nil || reconcile.Platform != reconcile.Target.Platform {
		return errExactNativePlatform
	}
	switch reconcile.Platform {
	case platform.Keenetic:
		if adapter.keenetic == nil {
			return errExactNativePlatform
		}
		return adapter.keenetic.persist(ctx, reconcile)
	case platform.OpenWrt:
		if adapter.openwrt == nil || len(reconcile.KeeneticTeardown) != 0 {
			return errExactNativePlatform
		}
		// UCI target/removal adapters already commit and read back atomically per exact plan.
		return nil
	default:
		return errExactNativePlatform
	}
}

func (adapter *exactNativePlatformAdapter) postcheck(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil || reconcile.Target == nil || reconcile.Platform != reconcile.Target.Platform {
		return errExactNativePlatform
	}
	switch reconcile.Platform {
	case platform.OpenWrt:
		// Every OpenWrt target/removal plan performs its own fresh read-back before returning. Do not
		// reinterpret it through a different backend here.
		if adapter.openwrt == nil || len(reconcile.KeeneticTeardown) != 0 {
			return errExactNativePlatform
		}
		return nil
	case platform.Keenetic:
		if adapter.keenetic == nil || len(reconcile.OpenWrtRemovals) != 0 {
			return errExactNativePlatform
		}
		return adapter.keenetic.postcheck(ctx, *reconcile.Target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore)
	default:
		return errExactNativePlatform
	}
}
