package keenetic

import "wayhop/internal/failsafe"

// CutoverCheck builds the failsafe connectivity check. It proves LAN-through-TUN forwarding by
// fetching the public exit IP and asserting it is NOT the raw WAN/ISP IP: a VPN exit means the
// TUN is forwarding LAN traffic; the raw WAN IP means traffic is leaking past the tunnel (a
// broken cutover that must NOT be committed). probeExitIP is injected — it must run a request
// the way a LAN client would (through the TUN), not router-origin. This is the red-team's fix
// for "check() can't tell router-has-WAN from LAN-through-TUN-is-dead".
func CutoverCheck(probeExitIP func() (string, error), rawWanIP string) func() bool {
	return func() bool {
		ip, err := probeExitIP()
		if err != nil || ip == "" {
			return false
		}
		return ip != rawWanIP
	}
}

// RunCutover is the user-gated, failsafe-wrapped cutover entry point. It prepares the cutover
// from the pre-flight reads, runs it (device-writing, applied UNSAVED so a reboot reverts),
// and arms the failsafe with Cutover's all-or-nothing rollback. The operator watches a client
// device and ConfirmSafe's (system configuration save) only once connectivity is verified; if
// the check fails, the failsafe rolls back to the keen-pbr + S89 stack (or, last resort,
// reboots to the saved good config).
//
// ⚠️ DEVICE-WRITING. The ONLY entry that performs the cutover. NEVER called by the research
// loop — only on an explicit user-gated deploy with a person watching.
func RunCutover(run Runner, in PrepareInputs, mgr *failsafe.Manager, check func() bool, reboot func(), allowReboot bool) ([]string, error) {
	cOpt, warns, err := PrepareCutover(run, in)
	if err != nil {
		return warns, err
	}
	rollback, err := Cutover(run, cOpt)
	if err != nil {
		return warns, err // Cutover already rolled back on failure
	}
	mgr.Arm(check, rollback, reboot, allowReboot)
	return warns, nil
}
