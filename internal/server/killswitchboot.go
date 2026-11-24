package server

import (
	"context"
	"log"
	"os"
	"strings"

	"wayhop/internal/pbr"
)

// killswitchboot.go says what the kill switch's boot hold did before the daemon was up:
// the hook's stamps in tmpfs tell a full fill, a partial one, and a broad hold the hook had to lift
// because nothing filled the table in time. Loud in the log and the webhook once at start, and a row
// in the Diagnostics battery for as long as the boot lasts.

// ksBootState is the boot hold's outcome since this boot.
type ksBootState struct {
	Lifted     bool   // the hook lifted the broad hold
	Partial    string // why the fill was incomplete ("" = it was not)
	Filled     bool   // the fill installed the static prefixes
	Ready      bool   // the table is filled (fill or daemon)
	OrphanHook bool   // a hook is installed and no applied state owns it
}

// ksBootStatus reads the stamps beside the ready stamp.
func (s *Server) ksBootStatus() ksBootState {
	r := s.ksb.readyPath()
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	st := ksBootState{Lifted: exists(r + pbr.StampLifted), Filled: exists(r + pbr.StampFilled), Ready: exists(r)}
	if b, err := os.ReadFile(r + pbr.StampPartial); err == nil {
		st.Partial = strings.TrimSpace(string(b))
		if st.Partial == "" {
			st.Partial = "unknown"
		}
	}
	hook := s.ksb.hookPath
	if hook == "" {
		hook = keeneticPBRHookPath
	}
	st.OrphanHook = s.kernelBaseline() == nil && !s.config().Demo && exists(hook)
	return st
}

// summary is one line for the log and the webhook; "" when there is nothing to say.
func (st ksBootState) summary() string {
	var parts []string
	if st.Lifted {
		parts = append(parts, "no full fill and no full daemon sync in time after boot: the broad hold was LIFTED by its time bound (kill-switched destinations known then stay held)")
	}
	if st.Partial != "" {
		parts = append(parts, "the boot fill was incomplete ("+st.Partial+"): addresses learned before the reboot may be missing from the hold")
	}
	if st.OrphanHook {
		parts = append(parts, "a kill switch hook is installed but no applied state owns it: the daemon cannot fill or release its hold; Apply again (the hook lifts the broad hold by itself after kill_switch_boot_hold_lift)")
	}
	return strings.Join(parts, "; ")
}

// reportKillSwitchBoot logs and alerts what the boot hold did, once at start.
func (s *Server) reportKillSwitchBoot() {
	if s.config().Demo {
		return
	}
	if msg := s.ksBootStatus().summary(); msg != "" {
		log.Printf("KILL SWITCH BOOT: %s", msg)
		s.alert("WayHop kill switch at boot: " + msg)
	}
}

// ksFillToolPresent reports whether the plane's fill tool exists (tests stand in via ksb.fillToolOK).
func (s *Server) ksFillToolPresent(p string) bool {
	if s.ksb.fillToolOK != nil {
		return s.ksb.fillToolOK(p)
	}
	return isExecutableFile(p)
}

// killSwitchBootCheck is the Diagnostics row.
func (s *Server) killSwitchBootCheck(context.Context) healthRow {
	row := healthRow{ID: "killswitch_boot", Label: "Kill switch after boot"}
	k := s.kernelBaseline()
	st := s.ksBootStatus()
	active := k != nil && k.Plan.KillSwitchBackstop(keeneticKillSwitchOptions(*k.Ipset)).Active()
	switch {
	case st.OrphanHook:
		row.Status, row.Summary = "fail", "a kill switch hook is installed that no applied state owns"
		row.Fix = "Apply again, or switch routing off to remove it."
	case k != nil && len(k.Plan.KillSwitchScopedZones()) > 0: // a plane applied before the refusal
		row.Status = "fail"
		row.Summary = "the applied plane has a kill switch for some devices only (" + strings.Join(k.Plan.KillSwitchScopedZones(), ", ") +
			"): those devices' traffic reaches the provider in every firewall rebuild and at boot"
		row.Fix = "Apply those lists or rules to all devices, or switch the kill switch off for their group, then apply again."
	case !active:
		row.Status, row.Summary = "na", "no kill-switched list covers the whole LAN"
	case st.Lifted:
		row.Status, row.Summary = "warn", "the broad boot hold was lifted by the router before the kill-switched destinations were all known"
		row.Detail = st.summary()
		row.Fix = "Check why WayHop did not start in time after the reboot (log). Kill-switched destinations known at boot stayed held."
	case st.Partial != "":
		row.Status, row.Summary = "warn", "the boot fill was incomplete: "+st.Partial
		row.Detail = "Addresses of kill-switched names learned before the reboot may have reached the provider until clients asked the resolver again."
	case !st.Ready:
		row.Status, row.Summary = "warn", "the backstop has not been filled since boot: unlisted forwarded traffic is held"
	default:
		row.Status, row.Summary = "pass", "kill-switched destinations held since boot"
	}
	// A fill tool that is gone (a test build run from tmpfs) never runs at the next boot;
	// the hold then waits for its lift.
	if k != nil && k.Ipset != nil && active && k.Ipset.FillTool != "" && !s.ksFillToolPresent(k.Ipset.FillTool) {
		if row.Status == "pass" {
			row.Status = "warn"
		}
		row.Detail = strings.TrimSpace(row.Detail + " The boot fill tool " + k.Ipset.FillTool + " is not on the router: after a reboot the " +
			"kill-switched destinations come back only from the router's own fallback when the broad hold is lifted. Apply again with the installed WayHop running.")
	}
	if k != nil && k.Ipset != nil && k.Ipset.BootHoldLift == 0 && active {
		row.Detail = strings.TrimSpace(row.Detail + " The broad boot hold has no time limit in this plane (strict, or applied before kill_switch_boot_hold_lift existed).")
	}
	return row
}
