package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"wayhop/internal/platform"
)

// The strict host snapshot must not inherit the old, unbounded exec/read helpers. These limits are
// deliberately small enough for a router control-plane request while leaving ample room for nft and
// ip output. A caller deadline may make the command bound shorter, never longer.
const (
	applyHostCommandTimeout     = 3 * time.Second
	applyHostCommandOutputLimit = 64 << 10
	applyHostCommandWaitDelay   = 250 * time.Millisecond
	applyHostTextLimit          = 256 << 10
	applyHostSysctlLimit        = 4 << 10
	applyHostConntrackLines     = 400
	applyHostConntrackBytes     = 1 << 20
	applyHostConntrackLineBytes = 128 << 10
)

// Command errors are fixed sentinels. In particular, neither stderr nor an executable path can
// reach the API-facing host snapshot through Error().
var (
	errApplyHostCommandCanceled = errors.New("host command canceled")
	errApplyHostCommandTimeout  = errors.New("host command timed out")
	errApplyHostCommandOutput   = errors.New("host command output exceeded the safety limit")
	errApplyHostCommandPipes    = errors.New("host command pipes did not close")
	errApplyHostCommandFailed   = errors.New("host command failed")
	errApplyHostReadLimit       = errors.New("host input exceeded the safety limit")
)

// API-safe observation errors. Keep these constant: probe failures are persisted and hashed into a
// HostRev, so host paths, command output, and changing OS error text must not leak or churn the rev.
const (
	applyHostProbeCanceledError   = "host observation canceled"
	applyHostDefaultRouteError    = "default-route device observation unavailable"
	applyHostDefaultRouteAbsent   = "default-route device is absent"
	applyHostBridgeDevicesError   = "bridge device observation unavailable"
	applyHostFirewallOffloadError = "firewall offload observation unavailable"
	applyHostFlowtableError       = "flowtable observation unavailable"
	applyHostPPEError             = "hardware offload knob observation unavailable"
	applyHostFastNATError         = "fast-path knob observation unavailable"
	applyHostConntrackError       = "conntrack offload observation unavailable"
	applyHostMarkedPlaneError     = "policy-routing plane observation unavailable"
)

// runHostCommandBounded runs one argv-only command with independently bounded time, retained output,
// and pipe-drain time. WaitDelay is essential here: a successful command may spawn a descendant that
// inherits stdout/stderr, otherwise Cmd.Wait can remain stuck after the direct child has exited.
func runHostCommandBounded(
	ctx context.Context,
	timeout time.Duration,
	outputLimit int,
	waitDelay time.Duration,
	name string,
	args ...string,
) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = applyHostCommandTimeout
	}
	if outputLimit <= 0 {
		outputLimit = applyHostCommandOutputLimit
	}
	if waitDelay <= 0 {
		waitDelay = applyHostCommandWaitDelay
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := newApplyHostCommandOutput(outputLimit, cancel)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Stdout = applyHostCommandWriter{output: output, retain: true}
	cmd.Stderr = applyHostCommandWriter{output: output}
	cmd.WaitDelay = waitDelay
	err := cmd.Run()

	// Classify from facts, never from err.Error(). Output overflow wins over the cancellation it
	// deliberately triggered, and ErrWaitDelay is kept distinct from ordinary non-zero exit.
	if output.exceededLimit() {
		return "", errApplyHostCommandOutput
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "", errApplyHostCommandPipes
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "", errApplyHostCommandCanceled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return "", errApplyHostCommandTimeout
	}
	if err != nil {
		return "", errApplyHostCommandFailed
	}
	return output.stdoutString(), nil
}

// applyHostCommandOutput is a shared stdout+stderr budget. Write reports all bytes consumed so the
// child does not receive a misleading short write, but the first overflow cancels it immediately.
// Only stdout is retained; stderr is intentionally never exposed.
type applyHostCommandOutput struct {
	mu        sync.Mutex
	remaining int
	stdout    []byte
	exceeded  bool
	cancel    context.CancelFunc
}

func newApplyHostCommandOutput(limit int, cancel context.CancelFunc) *applyHostCommandOutput {
	return &applyHostCommandOutput{remaining: limit, cancel: cancel}
}

type applyHostCommandWriter struct {
	output *applyHostCommandOutput
	retain bool
}

func (w applyHostCommandWriter) Write(p []byte) (int, error) {
	if w.output == nil {
		return len(p), nil
	}
	w.output.consume(p, w.retain)
	return len(p), nil
}

func (o *applyHostCommandOutput) consume(p []byte, retain bool) {
	o.mu.Lock()
	take := len(p)
	if take > o.remaining {
		take = o.remaining
	}
	if retain && take > 0 {
		o.stdout = append(o.stdout, p[:take]...)
	}
	o.remaining -= take
	cancel := len(p) > take && !o.exceeded
	if len(p) > take {
		o.exceeded = true
	}
	o.mu.Unlock()
	if cancel && o.cancel != nil {
		o.cancel()
	}
}

func (o *applyHostCommandOutput) exceededLimit() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.exceeded
}

func (o *applyHostCommandOutput) stdoutString() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.stdout)
}

type applyHostCommandFunc func(context.Context, string, ...string) (string, error)

// applyHostIO is injectable so barrier tests can prove that one observation never silently falls
// back to an unbounded package helper or the real test host.
type applyHostIO struct {
	runCommand applyHostCommandFunc
	openFile   func(string) (io.ReadCloser, error)
	readDir    func(string) ([]os.DirEntry, error)
	stat       func(string) (os.FileInfo, error)

	sysClassNetPath string
	firewallPath    string
	ppePath         string
	fastNATPath     string
	conntrackPath   string
}

func productionApplyHostIO() applyHostIO {
	return applyHostIO{
		runCommand: func(ctx context.Context, name string, args ...string) (string, error) {
			return runHostCommandBounded(
				ctx,
				applyHostCommandTimeout,
				applyHostCommandOutputLimit,
				applyHostCommandWaitDelay,
				name,
				args...,
			)
		},
		openFile: func(path string) (io.ReadCloser, error) { return os.Open(path) },
		readDir:  os.ReadDir,
		stat:     os.Stat,

		sysClassNetPath: "/sys/class/net",
		firewallPath:    "/etc/config/firewall",
		ppePath:         "/proc/sys/net/hwnat/ppe_enabled",
		fastNATPath:     "/proc/sys/net/netfilter/nf_conntrack_fastnat",
		conntrackPath:   "/proc/net/nf_conntrack",
	}
}

// probeAutoOffloadDevicesContext is the production entry point for strict host capture. It observes
// the default-route device plus real bridge devices and never calls the legacy unbounded probe.
func probeAutoOffloadDevicesContext(ctx context.Context) ([]string, []string) {
	return probeAutoOffloadDevicesWithIO(ctx, productionApplyHostIO())
}

func probeAutoOffloadDevicesWithIO(ctx context.Context, host applyHostIO) ([]string, []string) {
	if err := contextError(ctx); err != "" {
		return nil, []string{err}
	}
	var devices, probeErrors []string
	route, err := host.runCommand(ctx, "ip", "-o", "route", "show", "default")
	if err != nil {
		probeErrors = append(probeErrors, applyHostDefaultRouteError)
	} else if device := parseDefaultRouteDev(route); device != "" {
		devices = appendUniqueStr(devices, device)
	} else {
		probeErrors = append(probeErrors, applyHostDefaultRouteAbsent)
	}
	if err := contextError(ctx); err != "" {
		return nil, []string{err}
	}

	bridgeText, bridgeCommandErr := host.runCommand(ctx, "ip", "-o", "link", "show", "type", "bridge")
	bridges := parseBridgeLinks(bridgeText)
	if len(bridges) == 0 {
		var fallbackOK bool
		bridges, fallbackOK = probeBridgeDevicesFromSysfs(ctx, host)
		// A successful empty `ip` result is authoritative. If `ip` failed, sysfs must have been
		// readable for the fallback to count as a complete observation.
		if bridgeCommandErr != nil && !fallbackOK {
			probeErrors = append(probeErrors, applyHostBridgeDevicesError)
		}
	}
	if err := contextError(ctx); err != "" {
		return nil, []string{err}
	}
	for _, bridge := range bridges {
		devices = appendUniqueStr(devices, bridge)
	}
	return devices, probeErrors
}

func probeBridgeDevicesFromSysfs(ctx context.Context, host applyHostIO) ([]string, bool) {
	entries, err := host.readDir(host.sysClassNetPath)
	if err != nil {
		return nil, false
	}
	var bridges []string
	for _, entry := range entries {
		if contextError(ctx) != "" {
			return nil, false
		}
		_, err := host.stat(filepath.Join(host.sysClassNetPath, entry.Name(), "bridge"))
		switch {
		case err == nil:
			bridges = appendUniqueStr(bridges, entry.Name())
		case errors.Is(err, fs.ErrNotExist):
			// A normal non-bridge interface has no bridge subdirectory.
		default:
			return nil, false
		}
	}
	sort.Strings(bridges)
	return bridges, true
}

// observeEffectiveOffloadContext is the production entry point for strict host capture. Each signal
// is read fresh, conntrack is streamed rather than loaded wholesale, and the verdict remains the
// platform package's single pure DetectOffload implementation.
func observeEffectiveOffloadContext(
	ctx context.Context,
	requested string,
	pbrTable string,
) (platform.OffloadState, []string) {
	return observeEffectiveOffloadWithIO(ctx, requested, pbrTable, productionApplyHostIO())
}

func observeEffectiveOffloadWithIO(
	ctx context.Context,
	requested string,
	pbrTable string,
	host applyHostIO,
) (platform.OffloadState, []string) {
	input := platform.OffloadInputs{Requested: requested}
	if err := contextError(ctx); err != "" {
		return platform.DetectOffload(input), []string{err}
	}

	var probeErrors []string
	flowtables, err := host.runCommand(ctx, "nft", "list", "flowtables")
	if err == nil {
		input.Flowtables = flowtables
		input.FlowtablesKnown = true
	} else {
		probeErrors = append(probeErrors, applyHostFlowtableError)
	}

	if text, err := readApplyHostText(ctx, host, host.firewallPath, applyHostTextLimit); err == nil {
		input.FirewallUCI = text
	} else if !errors.Is(err, fs.ErrNotExist) {
		probeErrors = append(probeErrors, applyHostFirewallOffloadError)
	}
	if text, err := readApplyHostText(ctx, host, host.ppePath, applyHostSysctlLimit); err == nil {
		input.PPEEnabled = text
	} else if !errors.Is(err, fs.ErrNotExist) {
		probeErrors = append(probeErrors, applyHostPPEError)
	}
	if text, err := readApplyHostText(ctx, host, host.fastNATPath, applyHostSysctlLimit); err == nil {
		input.FastNAT = text
	} else if !errors.Is(err, fs.ErrNotExist) {
		probeErrors = append(probeErrors, applyHostFastNATError)
	}
	if sample, err := readApplyHostConntrack(ctx, host, host.conntrackPath); err == nil {
		input.Conntrack = sample
		input.ConntrackKnown = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		probeErrors = append(probeErrors, applyHostConntrackError)
	}

	if strings.TrimSpace(pbrTable) != "" {
		markedPlane, err := host.runCommand(ctx, "nft", "list", "table", "inet", pbrTable)
		if err == nil {
			input.MarkedPlane = strings.TrimSpace(markedPlane) != ""
		} else if isApplyHostSafetyError(err) {
			// A normal non-zero exit means the table is absent. Safety-bound failures are different:
			// timeout/cancellation/output truncation did not establish absence.
			probeErrors = append(probeErrors, applyHostMarkedPlaneError)
		}
	}
	if err := contextError(ctx); err != "" {
		return platform.DetectOffload(platform.OffloadInputs{Requested: requested}), []string{err}
	}
	return platform.DetectOffload(input), uniqueApplyHostErrors(probeErrors)
}

func readApplyHostText(ctx context.Context, host applyHostIO, path string, limit int) (string, error) {
	reader, err := host.openFile(path)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	return readApplyHostTextReader(ctx, reader, limit)
}

func readApplyHostTextReader(ctx context.Context, reader io.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", errApplyHostReadLimit
	}
	var out strings.Builder
	buf := make([]byte, 8<<10)
	for {
		if contextError(ctx) != "" {
			return "", errApplyHostCommandCanceled
		}
		n, err := reader.Read(buf)
		if n > 0 {
			if out.Len()+n > limit {
				return "", errApplyHostReadLimit
			}
			_, _ = out.Write(buf[:n])
		}
		switch {
		case errors.Is(err, io.EOF):
			return out.String(), nil
		case err != nil:
			return "", err
		case n == 0:
			return "", io.ErrNoProgress
		}
	}
}

func readApplyHostConntrack(ctx context.Context, host applyHostIO, path string) (string, error) {
	reader, err := host.openFile(path)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	return readApplyHostConntrackReader(ctx, reader, applyHostConntrackLines, applyHostConntrackBytes)
}

// readApplyHostConntrackReader stops immediately after maxLines. Scanner may hold a small read-ahead
// buffer, but it can never consume the remainder of a large conntrack table as the old readFile did.
func readApplyHostConntrackReader(
	ctx context.Context,
	reader io.Reader,
	maxLines int,
	maxBytes int,
) (string, error) {
	if maxLines <= 0 || maxBytes <= 0 {
		return "", errApplyHostReadLimit
	}
	scanner := bufio.NewScanner(&applyHostContextReader{ctx: ctx, reader: reader})
	scanner.Buffer(make([]byte, 4<<10), applyHostConntrackLineBytes)
	var out strings.Builder
	for line := 0; line < maxLines && scanner.Scan(); line++ {
		text := scanner.Text()
		if out.Len()+len(text)+1 > maxBytes {
			return "", errApplyHostReadLimit
		}
		_, _ = out.WriteString(text)
		_ = out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if err := contextError(ctx); err != "" {
		return "", errApplyHostCommandCanceled
	}
	return out.String(), nil
}

type applyHostContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *applyHostContextReader) Read(p []byte) (int, error) {
	if r.ctx != nil {
		select {
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		default:
		}
	}
	return r.reader.Read(p)
}

func contextError(ctx context.Context) string {
	if ctx == nil || ctx.Err() == nil {
		return ""
	}
	return applyHostProbeCanceledError
}

func isApplyHostSafetyError(err error) bool {
	return errors.Is(err, errApplyHostCommandCanceled) ||
		errors.Is(err, errApplyHostCommandTimeout) ||
		errors.Is(err, errApplyHostCommandOutput) ||
		errors.Is(err, errApplyHostCommandPipes)
}

func uniqueApplyHostErrors(in []string) []string {
	var out []string
	for _, value := range in {
		if value != "" {
			out = appendUniqueStr(out, value)
		}
	}
	return out
}
