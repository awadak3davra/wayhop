package server

import (
	"context"
	"log"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/localtz"
)

// Scheduled core restart (config.CoreRestart; competitor gap 12: Passwall2 restarts on a weekday or
// interval schedule, nikki on a cron expression). The watchdog restarts a core that crashes; this is
// for the one that keeps running and degrades, which is what people schedule restarts for. Opt-in:
// a restart drops every connection the core carries.

// coreRestartTick is how often the schedule is looked at; a daily time is matched to the minute.
const coreRestartTick = 30 * time.Second

// coreRestartDue reports whether a restart is due at now, read as wall time in loc for a daily time.
// A daily time fires in its minute and not again for that minute, however often the loop looks; an
// interval counts from the last restart, or from when the daemon started.
//
// now, last and started must keep their monotonic readings (plain time.Now()): an interval is
// measured on that clock, so a router without a real-time clock, which boots days behind and is then
// stepped by NTP, does not see six hours pass in one tick. Only the daily match reads the wall clock.
func coreRestartDue(spec string, now time.Time, loc *time.Location, last, started time.Time) bool {
	hour, minute, every, err := config.ParseCoreRestart(spec)
	if err != nil || (every == 0 && spec == "") {
		return false
	}
	if every > 0 {
		from := last
		if from.IsZero() {
			from = started
		}
		return now.Sub(from) >= every
	}
	local := now.In(loc)
	if local.Hour() != hour || local.Minute() != minute {
		return false
	}
	if last.IsZero() {
		return true
	}
	// The night a DST change repeats an hour shows the same minute twice, an hour apart: the date and
	// minute it last fired, not the time since, is what says it already ran.
	const stamp = "2006-01-02 15:04"
	return now.Sub(last) >= time.Hour && last.In(loc).Format(stamp) != local.Format(stamp)
}

// coreRestartLoop restarts the core when the schedule says so.
func (s *Server) coreRestartLoop(ctx context.Context) {
	t := time.NewTicker(coreRestartTick)
	defer t.Stop()
	var last time.Time
	started := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now() // not .In(loc): that drops the monotonic reading the interval is measured on
		if !coreRestartDue(s.config().CoreRestart, now, localtz.Location(), last, started) {
			continue
		}
		last = now // counted even when skipped below, so a busy minute does not retry all hour
		s.restartCoreOnSchedule()
	}
}

// restartCoreOnSchedule restarts the core WayHop runs, unless that would be wrong now: in the demo,
// with no core of its own running, with routing switched off, or while an Apply holds the plane.
func (s *Server) restartCoreOnSchedule() {
	if s.config().Demo || s.singbox == nil || !s.singbox.Running() || s.routingIsOff() {
		return
	}
	if !s.applyMu.TryLock() {
		log.Printf("core: scheduled restart skipped - an Apply is in progress")
		return
	}
	defer s.applyMu.Unlock()
	if err := s.singbox.Reload(); err != nil {
		log.Printf("core: scheduled restart failed: %v (the watchdog keeps trying to bring it up)", err)
		s.alert("⚠️ WayHop: the scheduled restart of the proxy core failed: " + outputTail(err.Error(), 300))
		return
	}
	log.Printf("core: restarted on schedule (%s)", s.config().CoreRestart)
}
