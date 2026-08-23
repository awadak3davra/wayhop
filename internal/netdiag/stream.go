package netdiag

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
)

// streamCmd runs name+args and calls emit once per output line as the process
// produces it (merged stdout+stderr, line-buffered), so a slow tool like
// traceroute surfaces each hop live instead of dumping everything on completion.
// It returns when the process exits or ctx is cancelled. emit must be safe to
// call from this goroutine only (it is called serially).
func streamCmd(ctx context.Context, emit func(string), name string, args ...string) {
	cmd := exec.CommandContext(ctx, name, args...)
	pr, pw := io.Pipe()
	// Same writer for both streams: os/exec serializes the writes, so hop/reply
	// lines never interleave mid-line.
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		emit(name + " unavailable: " + err.Error())
		_ = pw.Close()
		return
	}
	go func() { _ = cmd.Wait(); _ = pw.Close() }()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		emit(sc.Text())
	}
	if err := sc.Err(); err != nil {
		emit(name + ": output read error: " + err.Error())
	}
	// Close the read end so that if we stopped early (e.g. a >64 KiB line → ErrTooLong) the
	// cmd's now-unread pipe writes unblock and the process is reaped immediately, rather than
	// the Wait goroutine leaking until ctx is cancelled.
	_ = pr.Close()
}

// validIfaceRe guards the interface name passed to `ping -I` / `traceroute -i`
// (same argument-injection concern as ValidTarget). Real iface names (awg0, eth0,
// br-lan, tun-keen) fit; max 15 chars (IFNAMSIZ-1).
var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

// ValidIface reports whether s is a safe interface name to bind a probe to.
func ValidIface(s string) bool { return s != "" && validIfaceRe.MatchString(s) }

// StreamPing emits each ping reply line as it arrives (count echo requests). When
// iface is a valid interface name, the probe is bound to it (`ping -I <iface>`),
// so ICMP can be sent through a specific tunnel/link instead of only the WAN.
func StreamPing(ctx context.Context, emit func(string), host, iface string, count int) {
	if !ValidTarget(host) {
		emit("invalid target")
		return
	}
	if count < 1 || count > 20 {
		count = 5
	}
	if runtime.GOOS == "windows" {
		streamCmd(ctx, emit, "ping", "-n", strconv.Itoa(count), "-w", "1500", host)
		return
	}
	args := []string{"-c", strconv.Itoa(count), "-W", "2"}
	if ValidIface(iface) {
		args = append(args, "-I", iface)
	}
	streamCmd(ctx, emit, "ping", append(args, host)...)
}

var pingMsRe = regexp.MustCompile(`time[=<]([0-9.]+)`)

// parsePingMs extracts the round-trip latency (ms) from ping output, PREFERRING the summary
// average (min/avg/max — over all echoes) and falling back to the first per-packet time=
// (some busybox builds print no summary). Returns 0 when no latency is parseable (caller
// treats the endpoint as alive-but-latency-unknown). Rounds rather than truncates.
func parsePingMs(out string) int {
	if m := reAvgUnix.FindStringSubmatch(out); len(m) == 2 {
		if f, e := strconv.ParseFloat(m[1], 64); e == nil {
			return int(f + 0.5)
		}
	}
	if m := pingMsRe.FindStringSubmatch(out); len(m) == 2 {
		if f, e := strconv.ParseFloat(m[1], 64); e == nil {
			return int(f + 0.5)
		}
	}
	return 0
}

// ReachableViaIface sends ONE ICMP echo to host bound to a kernel interface
// (`ping -I <iface>`) and reports whether a reply came back + the round-trip ms.
// This is how the health monitor probes native interface-backed endpoints
// (AmneziaWG/WireGuard nwgN) that are NOT sing-box outbounds, so the Clash delay
// test cannot see them. Returns (false,0) on a bad iface/target or no reply.
func ReachableViaIface(ctx context.Context, iface, host string, timeoutS int) (bool, int) {
	if !ValidIface(iface) || !ValidTarget(host) {
		return false, 0
	}
	if timeoutS < 1 || timeoutS > 10 {
		timeoutS = 3
	}
	// 3 echoes, alive if ANY replies — tolerant of single-packet loss (a 1-packet probe flaps).
	out, err := exec.CommandContext(ctx, "ping", "-c", "3", "-W", strconv.Itoa(timeoutS), "-I", iface, host).CombinedOutput()
	if err != nil {
		return false, 0
	}
	return true, parsePingMs(string(out))
}

// ReachableViaIfaceProbe is ReachableViaIface plus the question it could not previously answer:
// did the probe RUN.
//
// The bool form returns false for a missing ping binary, an interface the kernel does not have, and
// a genuine 100%-loss reply — and the health monitor mapped every false to Down. Every native
// tunnel (AmneziaWG/WireGuard, which are the endpoints probed this way) would therefore be marked
// dead on a router without ping on the service PATH, and failover reads those states to decide
// where traffic goes. "Nothing answered" and "nothing was asked" have to be different answers.
//
// ran is false only when the probe never produced a reply/loss verdict: a start failure, a rejected
// interface or target, or a cancelled context. A non-zero exit from ping itself IS a measurement —
// that is how ping reports loss.
func ReachableViaIfaceProbe(ctx context.Context, iface, host string, timeoutS int) (alive bool, ms int, ran bool) {
	if !ValidIface(iface) || !ValidTarget(host) {
		return false, 0, false
	}
	if timeoutS < 1 || timeoutS > 10 {
		timeoutS = 3
	}
	out, err := exec.CommandContext(ctx, "ping", "-c", "3", "-W", strconv.Itoa(timeoutS), "-I", iface, host).CombinedOutput()
	if ctx.Err() != nil {
		return false, 0, false
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return false, 0, false // ping could not be executed — nothing was measured
	}
	if err != nil {
		return false, 0, true // ping ran and reported failure: a real measurement of "unreachable"
	}
	return true, parsePingMs(string(out)), true
}

// StreamTraceroute emits each hop line as it completes (up to maxHops). When iface
// is valid the trace is bound to it (`traceroute -i <iface>`).
func StreamTraceroute(ctx context.Context, emit func(string), host, iface string, maxHops int) {
	if !ValidTarget(host) {
		emit("invalid target")
		return
	}
	if maxHops < 1 || maxHops > 30 {
		maxHops = 20
	}
	if runtime.GOOS == "windows" {
		streamCmd(ctx, emit, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "1000", host)
		return
	}
	args := []string{"-n", "-m", strconv.Itoa(maxHops), "-w", "2"}
	if ValidIface(iface) {
		args = append(args, "-i", iface)
	}
	streamCmd(ctx, emit, "traceroute", append(args, host)...)
}
