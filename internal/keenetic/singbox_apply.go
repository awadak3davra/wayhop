package keenetic

import (
	"encoding/json"
	"fmt"

	"wayhop/internal/atomicfile"
)

// Runner runs a shell command (injectable for tests). Same method shape as pbr.Runner so an
// ExecRunner satisfies both. The Keenetic sing-box (fallback) plane is managed Entware-side
// via an init.d service, NOT over RCI — hence a command runner rather than the RCIClient.
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}

// SingboxApplyOptions tune where the fallback sing-box config lives + how its service
// restarts. Defaults match the live Hopper SE (probed read-only): config dir
// /opt/etc/sing-box, service /opt/etc/init.d/S99sing-box (standard Entware rc.func script
// running `sing-box run -D /opt/var/lib/sing-box -C /opt/etc/sing-box`).
type SingboxApplyOptions struct {
	ConfigPath  string // default /opt/etc/sing-box/config.json
	ServiceInit string // default /opt/etc/init.d/S99sing-box
}

func (o *SingboxApplyOptions) defaults() {
	if o.ConfigPath == "" {
		o.ConfigPath = "/opt/etc/sing-box/config.json"
	}
	if o.ServiceInit == "" {
		o.ServiceInit = "/opt/etc/init.d/S99sing-box"
	}
}

// ApplySingbox writes the fallback sing-box config atomically, then restarts the Entware
// service so sing-box reloads it (bringing up the wrtunN TUN devices that NDM routes to).
// A nil/empty cfg is a no-op (no non-native endpoints → nothing to run).
//
// ⚠️ DEVICE-WRITING. The sing-box plane must be applied BEFORE the NDM `ip route … wrtunN`
// commands (the TUN devices have to exist before a route can target them). Runs ONLY on the
// device, ONLY on a user-OK'd deploy — the research loop never calls it.
func ApplySingbox(cfg map[string]any, opt SingboxApplyOptions, run Runner) error {
	if len(cfg) == 0 {
		return nil
	}
	opt.defaults()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sing-box config: %w", err)
	}
	// 0o600: this config carries endpoint credentials — keep it root-only (see StageSingboxConfig).
	if err := atomicfile.Write(opt.ConfigPath, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", opt.ConfigPath, err)
	}
	if _, err := run.Run("", opt.ServiceInit, "restart"); err != nil {
		return fmt.Errorf("restart sing-box: %w", err)
	}
	return nil
}
