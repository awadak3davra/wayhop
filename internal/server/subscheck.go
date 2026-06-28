package server

import (
	"context"
	"fmt"
	"time"
)

// subscriptionVerdict maps a configured auto-refreshing subscription's last-run state to a battery
// status. Pure for unit-testing. A failed last fetch warns; a refresh that hasn't happened in well
// over its interval warns (it may be silently failing or the timer wasn't re-armed); otherwise pass.
func subscriptionVerdict(refreshHours int, last time.Time, errStr string, now time.Time) (status, summary, fix string) {
	if errStr != "" {
		return "warn", "last subscription refresh failed: " + errStr,
			"WakeRoute couldn't re-fetch your subscription, so it may be missing servers your provider rotated in. Check the subscription URL is reachable from the router (the DNS/reachability diagnostics help) or re-import it."
	}
	if last.IsZero() {
		return "pass", "auto-refresh enabled; not run yet", ""
	}
	age := now.Sub(last)
	// Stale = older than two intervals plus a 1h grace (one missed tick is fine).
	if age > time.Duration(refreshHours)*2*time.Hour+time.Hour {
		return "warn", fmt.Sprintf("last refresh %s ago (every %dh)", age.Round(time.Hour), refreshHours),
			"The subscription hasn't refreshed on schedule — the daemon may have restarted, or the fetch is silently failing. Check the subscription URL's reachability; a Save re-arms the refresh timer."
	}
	return "pass", fmt.Sprintf("last refresh %s ago", age.Round(time.Hour)), ""
}

// subscriptionCheck is a Diagnostics-battery probe for an auto-refreshing subscription: it flags a
// failing or stalled refresh, which silently leaves your endpoint list outdated (the provider rotated
// servers but WakeRoute never re-fetched) — a confusing "my servers stopped working" failure.
// Read-only; pass/skip when no auto-refreshing subscription is configured.
func (s *Server) subscriptionCheck(_ context.Context) healthRow {
	row := healthRow{ID: "subscription", Label: "Subscription auto-refresh is healthy"}
	c := s.config()
	if c.Subscription.URL == "" || c.Subscription.RefreshHours <= 0 {
		row.Status, row.Summary = "pass", "no auto-refreshing subscription configured"
		return row
	}
	last, _, errStr := s.subStatus.snapshot()
	row.Status, row.Summary, row.Fix = subscriptionVerdict(c.Subscription.RefreshHours, last, errStr, time.Now())
	return row
}
