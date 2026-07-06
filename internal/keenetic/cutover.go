package keenetic

import (
	"fmt"
	"strings"
)

// cutover.go is the device-mutating cutover from the keen-pbr + S89 stack to WayHop. It is
// BUILT but the research loop NEVER runs it — only a user-gated, failsafe-wrapped deploy does
// (see SafeApply). This file holds the reversible retire/restore of the old stack (the
// rollback foundation); pre-flight + profile assembly + kernel-plane apply come in later
// pieces.

// oldStackServices are the keen-pbr + failover init.d services WayHop replaces, in boot/
// dependency order. Disable = stop + `chmod -x` (rc.unslung boots only executable S* scripts:
// `find … -perm -u+x -name 'S*'`); restore = `chmod +x` + start. Validated read-only on the
// Hopper SE.
//
// NOT retired (kept, coexists): S86ru_routing — RU-direct via ipset ru_cidrs + fwmark 0x250 →
// table 250 → WAN (so RU banks see mom's local ISP IP). Its fwmark rule is checked BEFORE the
// main-table default, so it keeps working alongside WayHop's default→wr-tun; it is re-
// applied by 60-wgbot-policy.sh (which WayHop also keeps), NOT the keen-pbr netfilter hook.
// Replicating its 8589-CIDR ipset/table would be needless risk. Also kept: sockd, DNS chain,
// nfqws, cams_isolate. WayHop's kernel plane takes over S87's bypasses/mgmt-reverse/default.
var oldStackServices = []string{
	"S80keen-pbr",       // list policy routing (fwmark + ipset) → replaced by sing-box
	"S87default_via_nl", // default route + mgmt-reverse + endpoint bypasses → replaced by the kernel plane
	"S89hy_failover",    // 3-tier default failover (cron-driven) → replaced by default→wr-tun + sing-box
}

// oldStackCron is the per-minute driver that re-probes S89; disable it so the failover loop
// can't fight WayHop's routing.
const oldStackCron = "/opt/etc/cron.1min/hy-failover"

// oldStackNetfilterHooks re-apply keen-pbr's firewall on EVERY NDM netfilter rebuild
// (50-keen-pbr-routing.sh calls `S80keen-pbr reapply-firewall`). They MUST be cut too, or
// keen-pbr's rules resurrect after a rebuild even with the service stopped. (60-wgbot-policy
// and 100-nfqws are left alone — separate concerns.)
var oldStackNetfilterHooks = []string{
	"/opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh",
}

func initd(s string) string { return "/opt/etc/init.d/" + s }

// RetireOldStack stops the keen-pbr + failover stack and prevents boot / cron / netfilter
// re-activation — fully reversible by RestoreOldStack. The re-apply paths (netfilter hooks +
// cron) are cut FIRST so nothing resurrects the old rules while services are being stopped.
// ⚠️ DEVICE-WRITING; cutover only.
func RetireOldStack(run Runner) error {
	for _, h := range oldStackNetfilterHooks {
		if _, err := run.Run("", "chmod", "-x", h); err != nil {
			return fmt.Errorf("disable netfilter hook %s: %w", h, err)
		}
	}
	if _, err := run.Run("", "chmod", "-x", oldStackCron); err != nil {
		return fmt.Errorf("disable cron %s: %w", oldStackCron, err)
	}
	for _, s := range oldStackServices {
		_, _ = run.Run("", initd(s), "stop") // best-effort stop (a not-running service is fine)
		if _, err := run.Run("", "chmod", "-x", initd(s)); err != nil {
			return fmt.Errorf("disable %s: %w", s, err)
		}
	}
	return nil
}

// RestoreOldStack re-enables and restarts the keen-pbr + failover stack — the cutover
// rollback, the inverse of RetireOldStack: services back up (in original order) BEFORE the
// re-apply paths resume. ⚠️ DEVICE-WRITING.
func RestoreOldStack(run Runner) error {
	for _, s := range oldStackServices {
		if _, err := run.Run("", "chmod", "+x", initd(s)); err != nil {
			return fmt.Errorf("re-enable %s: %w", s, err)
		}
		if _, err := run.Run("", initd(s), "start"); err != nil {
			return fmt.Errorf("start %s: %w", s, err)
		}
	}
	if _, err := run.Run("", "chmod", "+x", oldStackCron); err != nil {
		return fmt.Errorf("re-enable cron %s: %w", oldStackCron, err)
	}
	for _, h := range oldStackNetfilterHooks {
		if _, err := run.Run("", "chmod", "+x", h); err != nil {
			return fmt.Errorf("re-enable netfilter hook %s: %w", h, err)
		}
	}
	return nil
}

// CutoverOptions bundle the inputs + knobs for the full cutover. SingboxConfig is the
// assembled routing config (LiveProfile + ImportKeenPBR + fakeipDNS + keeneticTUN, built by
// pre-flight/assembly); ApplyKernel/TeardownKernel apply/remove the kernel-pbr plane (default
// route + RU-direct + anti-loop) — injected so the orchestration stays decoupled from the
// pbr wiring.
type CutoverOptions struct {
	SingboxConfig  map[string]any
	Netfilter      NetfilterHookOptions
	Stage          SingboxStageOptions
	ServiceInit    string // S99 sing-box init script; default /opt/etc/init.d/S99sing-box
	SingboxBin     string // sing-box binary for the pre-restart config-check gate; default /opt/sbin/sing-box
	ApplyKernel    func() error
	TeardownKernel func() error
}

func (o *CutoverOptions) defaults() {
	if o.ServiceInit == "" {
		o.ServiceInit = "/opt/etc/init.d/S99sing-box"
	}
	if o.SingboxBin == "" {
		o.SingboxBin = "/opt/sbin/sing-box"
	}
}

// Cutover performs the device-mutating cutover from the keen-pbr + S89 stack to WayHop,
// in order: retire the old stack → install the netfilter re-apply hook → stage the new
// sing-box config → CHECK the staged config (`sing-box check`) → restart sing-box → apply the
// kernel-pbr plane. The check gate is critical: `S99sing-box restart` returns 0 even if sing-box
// dies on an invalid config, so without it a bad artifact would let the cutover proceed to move
// the kernel default onto wr-tun with sing-box down → LAN black-hole. It returns a `rollback`
// closure (the failsafe arms it) that reverses EVERY step — restore the original sing-box
// config + restart, remove the hook, tear down the kernel plane, restart the old stack — each
// inverse being idempotent / no-op-safe, so it's safe on any partial state. If ANY step
// fails, Cutover rolls back immediately and returns the error.
//
// ⚠️ DEVICE-WRITING. The research loop NEVER calls it; only a user-gated, failsafe-wrapped
// deploy (SafeApply) does. Applied UNSAVED so a reboot also reverts.
func Cutover(run Runner, o CutoverOptions) (rollback func() error, err error) {
	o.defaults()
	o.Stage.defaults() // resolve ConfigPath so the check gate can point at the staged file

	rollback = func() error {
		var errs []string
		if e := RestoreSingboxConfig(o.Stage); e != nil {
			errs = append(errs, "restore sing-box config: "+e.Error())
		}
		if _, e := run.Run("", o.ServiceInit, "restart"); e != nil {
			errs = append(errs, "restart sing-box: "+e.Error())
		}
		if e := RemoveNetfilterHook(o.Netfilter); e != nil {
			errs = append(errs, "remove netfilter hook: "+e.Error())
		}
		if o.TeardownKernel != nil {
			if e := o.TeardownKernel(); e != nil {
				errs = append(errs, "teardown kernel: "+e.Error())
			}
		}
		if e := RestoreOldStack(run); e != nil {
			errs = append(errs, "restore old stack: "+e.Error())
		}
		if len(errs) > 0 {
			return fmt.Errorf("rollback errors: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"retire old stack", func() error { return RetireOldStack(run) }},
		{"install netfilter hook", func() error { return InstallNetfilterHook(o.Netfilter) }},
		{"stage sing-box config", func() error { return StageSingboxConfig(o.SingboxConfig, o.Stage) }},
		// Gate the restart: validate the STAGED config first. A failed check trips the immediate
		// rollback (old config restored + sing-box restarted) instead of black-holing the LAN.
		{"check sing-box config", func() error {
			if _, e := run.Run("", o.SingboxBin, "check", "-c", o.Stage.ConfigPath); e != nil {
				return fmt.Errorf("staged sing-box config is invalid: %w", e)
			}
			return nil
		}},
		{"restart sing-box", func() error { _, e := run.Run("", o.ServiceInit, "restart"); return e }},
		{"apply kernel plane", func() error {
			if o.ApplyKernel != nil {
				return o.ApplyKernel()
			}
			return nil
		}},
	}
	for _, s := range steps {
		if e := s.fn(); e != nil {
			_ = rollback()
			return nil, fmt.Errorf("cutover failed at %q (rolled back): %w", s.name, e)
		}
	}
	return rollback, nil
}
