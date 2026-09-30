package tgbot

import (
	"context"
	"errors"
	"time"

	"wayhop/internal/config"
)

// Backend is everything the bot needs from the daemon. The server package implements it over its
// own internals; tests implement it with a fake. Every method must be safe for concurrent use and
// must return promptly: the caller's context carries the deadline.
type Backend interface {
	// Status is the Dashboard in one value. It never fails as a whole: a part that could not be read
	// is marked unknown inside it.
	Status(ctx context.Context) Status
	// TestExit probes one exit now (the panel's "Test now") and returns its refreshed view.
	TestExit(ctx context.Context, id string) (Exit, error)
	// Events returns the newest failover-log entries, newest first.
	Events(limit int) EventLog
	// Pulse is the cheap part of the state, read every few seconds by the alert watcher.
	Pulse(ctx context.Context) Pulse
	// Boot describes this daemon start, for the "back online" alert.
	Boot() BootInfo
	// ConfirmApply keeps the configuration under test (the panel's Keep).
	ConfirmApply(ctx context.Context) error
	// RollbackApply restores the committed configuration (the panel's Roll back).
	RollbackApply(ctx context.Context) error
	// Trace explains where traffic to a domain or IP goes: what it resolves to, the live connections
	// and the exits they took, and the configured rules and lists that reference it.
	Trace(ctx context.Context, target string) (Trace, error)
	// Devices lists the LAN clients the router knows (DHCP leases and ARP), with what each moves
	// right now where the router can measure it. It samples for a moment, so it is not instant.
	Devices(ctx context.Context) DeviceList
	// Diagnose runs the Diagnostics page's server-side checks.
	Diagnose(ctx context.Context) []Check
	// Ping and Lookup are the Diagnostics page's ping and DNS tools. Both refuse a target that is not
	// a hostname or an address with ErrBadTarget.
	Ping(ctx context.Context, host string) (PingResult, error)
	Lookup(ctx context.Context, host string) (LookupResult, error)
	// SpeedTest measures throughput the way the Diagnostics page's speed test does, twice: the
	// provider's line (straight out, past the routing core), then either the route traffic with no
	// rule of its own takes through WayHop (exit "") or one exit's own tunnel, bound to its kernel
	// interface so nobody's traffic moves onto it (ErrUnavailable for an exit that is not a kernel
	// tunnel). Each leg moves about 15 MB. One test runs at a time on the router, the panel's
	// included: ErrBusy while another is running. step is told as each leg starts.
	SpeedTest(ctx context.Context, exit string, step func(leg string)) (SpeedReport, error)

	// Maintenance: the panel's own operations, for owners.

	// RestartDaemon restarts the whole WayHop service through the init system. The bot's own
	// process goes with it; the answer has to be sent before this is called.
	RestartDaemon(ctx context.Context) error
	// RefreshLists re-downloads every routing list that has a source into its cache. Nothing is
	// activated: the refreshed lists take effect on the next Apply.
	RefreshLists(ctx context.Context) (ListsRefresh, error)
	// RefreshSubscription re-fetches the imported subscription and adds new connections.
	RefreshSubscription(ctx context.Context) (added int, err error)
	// ApplyPreview reviews the saved changes the way Review & Apply does.
	ApplyPreview(ctx context.Context) (ApplyPreview, error)
	// ApplyTest applies the reviewed revision as a test (the fail-safe window, not saved),
	// acknowledging the findings the review listed as needing it.
	ApplyTest(ctx context.Context, rev string) error
	// Backup is the panel's full backup: every connection, group, list and saved server. It holds
	// every secret.
	Backup(ctx context.Context) (name string, data []byte, err error)
	// UpdateCheck asks whether a newer WayHop exists (the Components page's self row). It may reach
	// GitHub, so the bot calls it on a button and once a day, never per status.
	UpdateCheck(ctx context.Context) UpdateInfo
	// UpdateInstall downloads, verifies and swaps in WayHop version, then restarts the service.
	UpdateInstall(ctx context.Context, version string) (UpdateResult, error)

	// ClaimDigest records that the daily summary for day ("2006-01-02", the router's date) is going
	// out and reports whether it had not been already. The record outlives the process, so a daemon
	// restarted in the digest's half hour does not send it twice.
	ClaimDigest(day string) bool
}

// UpdateInfo is the answer to "is there a newer WayHop?".
type UpdateInfo struct {
	Current   string
	Latest    string
	Available bool   // a newer release exists and this build can install it
	Decided   bool   // the versions could be compared at all
	Managed   string // the package manager that owns the binary ("apk", "opkg"); "" = self-managed
	NoChannel bool   // the release list is not published: this build does not self-update
	Auto      bool   // auto-update is on
	Err       string // the check failed, in a sentence
}

// UpdateResult is what an install did.
type UpdateResult struct {
	Installed  string
	Restarting bool
	Note       string
}

// ErrUnavailable is an operation this daemon cannot do here (the demo has no init system).
var ErrUnavailable = errors.New("not available on this router")

// ListsRefresh is the outcome of a routing-list refresh.
type ListsRefresh struct {
	Lists   int         // lists with a source
	Changed int         // lists whose content changed
	Failed  []FeedIssue // lists whose feed failed; each keeps what it had, if anything
	// Unreached lists were not asked: the refresh ran out of time first.
	Unreached int
}

// ApplyPreview is what an Apply would do now.
type ApplyPreview struct {
	Pending      bool
	Rev          string   // the revision the review describes; ApplyTest applies exactly that
	Count        int      // number of changes, 0 when not counted
	MayInterrupt bool     // connections may drop briefly
	Blockers     []string // titles of findings that block an Apply; the panel is where they are fixed
	Confirms     []string // titles of findings an Apply acknowledges
}

// ErrBadTarget is the refusal of a target that is not a hostname or an IP address.
var ErrBadTarget = errors.New("not a domain name or an IP address")

// ErrBusy refuses what the router runs one at a time while another run is under way.
var ErrBusy = errors.New("already running")

// The legs of a speed test.
const (
	LegLine  = "line"  // the provider's line, past the routing core
	LegRoute = "route" // the default route through WayHop, or one exit's tunnel
)

// SpeedReport is one speed test.
type SpeedReport struct {
	Line  SpeedLeg
	Route SpeedLeg
	// Exit names the exit measured on its own; "" when Route is the default route through WayHop.
	Exit string
	// Via names the default route by the configured rules ("Auto (fastest) → nl-main") when Route
	// measured it.
	Via string
	// Direct: by the configured rules the test's site goes straight out, so the route through WayHop
	// is the line itself; Blocked: a rule blocks it. Either way Route is Skipped.
	Direct, Blocked bool
	// ByRule: a rule or list names the test's site, so Direct or Blocked is that rule's doing, not
	// the default route's.
	ByRule bool
	// Native: the router routes natively, without sing-box, so there is no default route through
	// the core to measure and Route is Skipped.
	Native bool
}

// SpeedLeg is one measured path.
type SpeedLeg struct {
	Skipped bool   // not measured (see SpeedReport for why)
	Err     string // the measurement failed
	// NoAnswer: it failed because the path took the requests and answered none in time, as a dead
	// tunnel does. Err still holds the details.
	NoAnswer bool
	// Through, on the line leg: the tunnel the router's own traffic left by, which makes the leg
	// that tunnel's speed and not the provider's line.
	Through  string
	DownMbps float64
	UpMbps   float64 // 0 when the upload did not complete
	// UpMissed: the upload was tried and not measured; the view says so instead of leaving it out.
	UpMissed  bool
	LatencyMs int // negative when the latency probe did not complete
}

// Trace is where traffic to one destination goes.
type Trace struct {
	Target       string
	IPs          []string
	ResolveError string
	// Live counts the live connections to the target by the exit they took (an outbound tag). This
	// is the ground truth; the configured matches below say what could route it.
	Live       map[string]int
	Configured []TraceMatch
	Maybe      []TraceMatch // geo and remote sets that may also match; they cannot be checked here
	Note       string
}

// TraceMatch is a rule, list or kernel zone that references the target.
type TraceMatch struct {
	Kind string // rule | list | kernel-zone
	ID   string
	Name string // the list's or rule's display name, ID when it has none
	Why  string
	Via  string // outbound tag
}

// Device is one LAN client.
type Device struct {
	Name  string // hostname, "" when unknown
	IP    string
	MAC   string
	Group string // the device group it belongs to, "" for none
	// Down and Up are bytes per second over a short sample, when DeviceList.Measured, over its IPv4
	// address and the IPv6 ones the neighbour table ties to its MAC.
	Down, Up int64
	// FastPath: some of its connections run on a flowtable fast path that does not count them, so
	// what it moves there is unknown rather than nothing.
	FastPath bool
}

// DeviceList is the LAN and, where the router keeps per-connection byte counts, who is using it.
type DeviceList struct {
	Devices []Device
	// Measured: Down and Up were sampled. False where there is no connection table or it counts no
	// bytes: a list of idle devices would then be a false answer, so none is given.
	Measured bool
}

// Check is one row of the Diagnostics battery.
type Check struct {
	ID      string
	Label   string
	Status  string // pass | warn | fail | na
	Summary string
	Fix     string
}

// PingResult is one ping from the router.
type PingResult struct {
	Target  string
	Ran     bool // a measurement was taken at all
	OK      bool
	LossPct int     // -1 unknown
	AvgMs   float64 // -1 unknown
}

// LookupResult is one DNS lookup through the router's resolver.
type LookupResult struct {
	Target string
	IPs    []string
	CNAME  string
	Err    string
}

// Pulse is what the alert watcher compares from one tick to the next.
type Pulse struct {
	LocalFault bool
	Core       CorePulse
	FailSafe   FailSafePulse
	Mem        MemPulse
}

// CorePulse is the crash-restart supervisor's view of sing-box.
type CorePulse struct {
	Supervised bool // WayHop wants it running
	Alive      bool
	Restarts   int // crash-restart attempts since the daemon started
	Failed     int // attempts whose start failed
	LastError  string
}

// FailSafePulse is the test-Apply window.
type FailSafePulse struct {
	Pending     bool   // the window is running
	Live        bool   // a tested configuration runs unsaved
	Phase       string // the fail-safe phase: armed, degraded, committed, rolled_back, ...
	SecondsLeft int
	LastError   string
	// Checked and CheckOK are the last connectivity check: an automatic rollback follows a failed
	// one, a rollback somebody pressed does not.
	Checked bool
	CheckOK bool
}

// MemPulse is RAM use.
type MemPulse struct {
	Known   bool
	UsedPct float64
}

// BootInfo describes the daemon start.
type BootInfo struct {
	DaemonStart time.Time
	RouterUp    time.Duration // the router's uptime when the daemon started; 0 = unknown
	LastSeen    time.Time     // the last heartbeat before this start; zero = none recorded
	Version     string
}

// Store persists the bot's settings. Update runs fn on a copy and saves the result atomically.
type Store interface {
	Telegram() config.Telegram
	UpdateTelegram(fn func(*config.Telegram) error) error
}

// Status is a point-in-time picture of the router.
type Status struct {
	At      time.Time
	Version string
	Demo    bool

	Core       Core
	ExitIP     ExitIP
	Exits      []Exit
	Groups     []Group
	LocalFault bool // every exit failed at once: the uplink, not the tunnels
	System     System
	Traffic    Rates
	Changes    Changes
	FailSafe   FailSafe
	Update     SelfUpdate
	// Feeds are the routing lists whose feed refreshes are failing (see FailingFeeds).
	Feeds []FeedIssue
}

// Core is the routing core's state.
type Core struct {
	Available  bool // sing-box is installed
	Running    bool
	NativeOnly bool // the live profile needs no sing-box: an absent core is by design
	Restarts   int  // crash-restarts since the daemon started
}

// ExitIP is the public address traffic leaves from, as the exit-IP lookup saw it.
type ExitIP struct {
	Known   bool
	IP      string
	Country string // "Netherlands"
	Code    string // ISO 3166-1 alpha-2, "NL"
	City    string
	Org     string
}

// Exit is one endpoint as the health monitor sees it.
type Exit struct {
	ID          string
	Name        string
	Kind        string // protocol, e.g. "wireguard", "vless"
	State       string // alive | down | unknown
	LatencyMs   int
	AvgLatency  int
	SuccessRate int // percent
	UptimeS     int64
	RateUp      int64 // bytes per second
	RateDown    int64
	// BytesUp and BytesDown are the running totals the monitor attributes to the exit, which the
	// daily digest turns into a day's traffic by difference. 0 = not measured.
	BytesUp   int64
	BytesDown int64
	Cause     string // why it is down, from the knowledge base
	Fix       string
	// CauseID names the cause: the two the monitor words itself ("no-response", "engine-missing")
	// are translated; a knowledge-base entry keeps its own words.
	CauseID string
	// Group marks the health of a failover group, which the monitor probes like an exit. It is
	// shown on the group's line and left out of the exit list and counts.
	Group bool
	// Tunnel: a kernel tunnel (WireGuard, AmneziaWG), whose speed can be measured on its own by
	// binding to its interface, moving nobody's traffic.
	Tunnel bool
}

// Exit states, as the health monitor reports them.
const (
	StateAlive   = "alive"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// Group is a failover/selector group and the member the core elected.
type Group struct {
	ID      string
	Name    string
	Members []string // exit ids
	Elected string   // the member exit's id, "" when unknown (never an interface name)
}

// System is the router's resources.
type System struct {
	Known      bool
	MemUsedPct float64
	Load1      float64
	UptimeS    int64
	TempC      float64 // 0 = unavailable
}

// Rates is the current throughput.
type Rates struct {
	Known bool
	Up    int64 // bytes per second
	Down  int64
}

// Changes is the saved-but-not-applied state.
type Changes struct {
	Known   bool // false: could not be read (the configuration was being written)
	Pending bool
	Count   int // number of changes when the review could count them, 0 = not counted
}

// FeedIssue is a routing list whose feed failed its last refresh. The list keeps the content it last
// got, so the sites it held still route; the ones added upstream since do not.
type FeedIssue struct {
	List  string    // the list's name
	Fails int       // refreshes in a row that failed
	Since time.Time // the first of them
	Err   string    // why the last one failed, credentials removed
	// Empty: the list has nothing from its feeds, so it routes nothing of theirs: it never loaded,
	// or it was given new feeds that have not loaded yet.
	Empty bool
}

// feedFailing is how many refreshes in a row must fail before a list is named: one failure is often
// a blip of the feed's host, two at least an hour apart are not (the server counts no closer).
const feedFailing = 2

// FailingFeeds is the lists worth naming: those whose feed failed feedFailing refreshes in a row.
func (s Status) FailingFeeds() []FeedIssue {
	var out []FeedIssue
	for _, f := range s.Feeds {
		if f.Fails >= feedFailing {
			out = append(out, f)
		}
	}
	return out
}

// FailSafe is the test-Apply window.
type FailSafe struct {
	Armed     bool
	Remaining time.Duration
	Health    string // up | down | unknown: the last connectivity check
}

// SelfUpdate is the self-updater's view.
type SelfUpdate struct {
	Available bool
	Latest    string
}

// Event is one failover-log entry.
type Event struct {
	At        time.Time
	Kind      string // down | up | switch
	ID        string
	Name      string
	From, To  string
	LatencyMs int
}

// EventLog is a page of the failover log.
type EventLog struct {
	Known  bool // false: the log could not be read at all (no monitor)
	Events []Event
	Since  time.Time // the log covers nothing before this (it is RAM-only)
	Total  int
}

// Health is the headline verdict of a Status.
type Health int

// Headline verdicts, from best to worst.
const (
	HealthGood Health = iota
	HealthTesting
	HealthDegraded
	HealthLocalFault
	HealthDown
)

// Verdict reduces a Status to its headline.
func (s Status) Verdict() Health {
	up, down := s.ExitCounts()
	coreDown := s.Core.Available && !s.Core.Running && !s.Core.NativeOnly
	switch {
	case coreDown:
		return HealthDown
	case s.LocalFault:
		return HealthLocalFault
	case down > 0 && up == 0:
		return HealthDown
	case s.FailSafe.Armed:
		return HealthTesting
	case down > 0:
		return HealthDegraded
	}
	return HealthGood
}

// ExitCounts is how many exits are up and down; unknown ones count as neither.
func (s Status) ExitCounts() (up, down int) {
	for _, e := range s.Exits {
		if e.Group {
			continue
		}
		switch e.State {
		case StateAlive:
			up++
		case StateDown:
			down++
		}
	}
	return up, down
}

// ExitByID finds an exit in the status.
func (s Status) ExitByID(id string) (Exit, bool) {
	for _, e := range s.Exits {
		if e.ID == id {
			return e, true
		}
	}
	return Exit{}, false
}
