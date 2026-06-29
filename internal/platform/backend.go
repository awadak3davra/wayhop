package platform

import (
	"context"

	"velinx/internal/model"
)

// RoutingBackend applies a Velinx profile's routing to the host and removes it. There is
// one implementation per platform — OpenWrt (nft/fw4 PBR + sing-box) and Keenetic (native
// NDM interfaces/routes + a sing-box fallback for non-native protocols). cmd/velinx
// resolves the right one at runtime via Detect(). The seam is intentionally small: the
// daemon hands a profile to Apply and the backend owns ALL platform specifics (how routing
// is realized, which kernel/native facilities are used, how state is torn down).
//
// Implementations are stateful — they remember what they applied so a re-Apply is idempotent
// (it replaces the prior Velinx state) — and must be safe to call repeatedly.
type RoutingBackend interface {
	// Platform reports which platform this backend drives.
	Platform() Platform
	// Apply realizes the profile's routing, replacing any previously-applied Velinx
	// state. A production deployment should guard this with the failsafe rollback (a failed
	// apply must not leave the router unreachable).
	Apply(ctx context.Context, p *model.Profile) error
	// Teardown removes all Velinx-managed routing this backend applied.
	Teardown(ctx context.Context) error
}
