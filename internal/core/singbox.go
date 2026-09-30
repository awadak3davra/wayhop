// Package core supervises the sing-box process: locate, check, start, stop, reload.
package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wayhop/internal/atomicfile"
)

// SingBox manages a sing-box process driven by a generated config file.
type SingBox struct {
	bin    string
	config string

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{} // closed when the supervised process exits
	desired   bool          // Start was called and Stop was not (watchdog intent)
	closed    bool          // Shutdown was called — the supervisor is done for this process's lifetime; no new spawn
	startedAt time.Time
	exitErr   error
	log       *ringLog
}

// New returns a supervisor for the given binary and config path.
func New(bin, config string) *SingBox {
	return &SingBox{bin: bin, config: config, log: newRingLog(500)}
}

// LogLines returns the captured sing-box output (oldest first).
func (s *SingBox) LogLines() []string { return s.log.Lines() }

// isStraySingbox reports whether a /proc cmdline (NUL-separated argv) is a sing-box running
// our config — the stray-reap match. Pure, so it is unit-tested without spawning processes.
func isStraySingbox(cmdline []byte, binBase, config string) bool {
	if len(cmdline) == 0 || config == "" {
		return false
	}
	argv0 := cmdline
	if i := bytes.IndexByte(cmdline, 0); i >= 0 {
		argv0 = cmdline[:i]
	}
	return filepath.Base(string(argv0)) == binBase && bytes.Contains(cmdline, []byte(config))
}

// ReapStrays SIGKILLs any sing-box left over from a PREVIOUS daemon instance — one orphaned
// when the old daemon was OOM-killed, crashed, or self-updated/restarted. Such an orphan keeps
// the cache.db flock (and the clash/TUN bindings), so when this daemon starts its own core
// sing-box loops on "initialize cache-file: timeout" until the orphan happens to die. Run ONCE
// at startup, BEFORE the daemon starts its own core — nothing it manages is up yet, so any
// sing-box running THIS config is necessarily a stray. Best-effort + Linux-only (scans /proc);
// a no-op where /proc is absent (dev host / demo) or the config path is unset.
func (s *SingBox) ReapStrays() {
	if s.config == "" {
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return // no procfs — not a Linux router; nothing to reap
	}
	base := filepath.Base(s.bin)
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !isStraySingbox(data, base, s.config) {
			continue
		}
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(syscall.SIGKILL)
			log.Printf("core: reaped orphaned sing-box (pid %d) holding the cache-file lock", pid)
		}
	}
}

// ringLog keeps the last N lines written to it (sing-box stdout+stderr).
type ringLog struct {
	mu    sync.Mutex
	lines []string
	size  int
	buf   []byte
}

func newRingLog(size int) *ringLog { return &ringLog{size: size} }

func (r *ringLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(r.buf[:i]), "\r")
		r.buf = r.buf[i+1:]
		if line == "" {
			continue
		}
		// Append, and only compact to the most-recent `size` lines once we've grown
		// to 2×size — amortized O(1) per line instead of shifting the whole slice
		// on every line (matters on a chatty log + a slow router CPU).
		r.lines = append(r.lines, line)
		if len(r.lines) > 2*r.size {
			r.lines = append(r.lines[:0], r.lines[len(r.lines)-r.size:]...)
		}
	}
	return len(p), nil
}

// ansiStripWriter removes ANSI escape sequences on their way to w.
//
// sing-box colours its level tag and its per-connection id unconditionally: it
// does not probe for a terminal, and its log block has no colour switch at all
// (verified against 1.12.17, which accepts only disabled/level/output/timestamp
// and rejects `disable_color` as an unknown field). Here that stdout is a pipe
// that ends up in logd on OpenWrt and in the ring buffer the Diagnostics page
// renders, so `logread` and the panel were showing literal ESC[31m...ESC[0m.
// Stripping on the way through fixes both, and keeps holding for a
// user-replaced engine binary that colours on its own terms.
//
// The parser covers the 7-bit ECMA-48 forms a logger can emit, not just the SGR
// colours sing-box uses today: CSI (ESC [ ... final byte), the string forms
// OSC/DCS/SOS/PM/APC (ESC ] ... BEL or ST), nF sequences such as a charset
// designation (ESC ( B), and the two-byte escapes (ESC c, ESC 7). A control byte
// such as a newline ends whatever sequence is in progress and passes through, so
// a sequence the engine never finished — killed mid-write, or a logger bug — can
// lose at most the rest of its own line, never the lines after it. This is a
// log: the ring buffer splits on newlines and the classifier reads whole lines.
//
// The parser state survives across calls, so a sequence split over two writes
// is still removed. Write always reports the caller's full length: the dropped
// bytes were consumed, not short-written.
type ansiStripWriter struct {
	mu    sync.Mutex
	w     io.Writer
	state ansiState
	out   []byte
}

type ansiState uint8

const (
	ansiText      ansiState = iota // plain bytes pass through
	ansiEsc                        // just after ESC: the next byte names the form
	ansiCSI                        // inside ESC [ ... : parameters and intermediates until a final byte
	ansiString                     // inside OSC/DCS/SOS/PM/APC: until BEL or ST (ESC \)
	ansiStringEsc                  // ESC seen inside a string form: a backslash completes ST
	ansiNF                         // inside ESC <intermediate> ... : until a final byte
)

const (
	asciiBEL = 0x07
	asciiESC = 0x1b
)

func (a *ansiStripWriter) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.out = a.out[:0]
	for _, b := range p {
		a.feed(b)
	}
	if len(a.out) > 0 {
		if _, err := a.w.Write(a.out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// feed advances the parser by one byte, appending to a.out whatever is text.
func (a *ansiStripWriter) feed(b byte) {
	switch a.state {
	case ansiText:
		if b == asciiESC {
			a.state = ansiEsc
			return
		}
		a.out = append(a.out, b)
	case ansiEsc:
		switch {
		case b == '[':
			a.state = ansiCSI
		case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
			a.state = ansiString
		case b >= 0x20 && b <= 0x2f:
			a.state = ansiNF
		case b >= 0x30 && b <= 0x7e:
			a.state = ansiText // a two-byte escape (ESC c, ESC 7, ESC =): consumed whole
		default:
			a.abort(b) // a control or non-ASCII byte: this was not an escape sequence
		}
	case ansiCSI:
		switch {
		case b >= 0x40 && b <= 0x7e:
			a.state = ansiText // the final byte
		case b >= 0x20 && b <= 0x3f:
			// parameter (0x30-0x3F) and intermediate (0x20-0x2F) bytes continue the sequence
		default:
			a.abort(b)
		}
	case ansiNF:
		switch {
		case b >= 0x30 && b <= 0x7e:
			a.state = ansiText // the final byte
		case b >= 0x20 && b <= 0x2f:
			// further intermediate bytes
		default:
			a.abort(b)
		}
	case ansiString:
		switch {
		case b == asciiBEL:
			a.state = ansiText
		case b == asciiESC:
			a.state = ansiStringEsc
		case b < 0x20:
			a.abort(b) // a newline inside an unterminated string form: one line lost, not the log
		}
	case ansiStringEsc:
		if b == '\\' {
			a.state = ansiText // ST
			return
		}
		// Not ST: the string form ended without its terminator, and a new escape begins here.
		a.state = ansiEsc
		a.feed(b)
	}
}

// abort ends a sequence that cannot continue with b — a control byte such as a newline, a
// non-ASCII byte, or a fresh ESC — and lets b take its normal path as text.
func (a *ansiStripWriter) abort(b byte) {
	a.state = ansiText
	a.feed(b)
}

func (r *ringLog) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

// Available reports whether the sing-box binary exists and looks runnable.
func (s *SingBox) Available() bool {
	if s.bin == "" {
		return false
	}
	if _, err := exec.LookPath(s.bin); err == nil {
		return true
	}
	info, err := os.Stat(s.bin)
	return err == nil && !info.IsDir()
}

// Check validates the active config with `sing-box check`.
func (s *SingBox) Check(ctx context.Context) error {
	return s.CheckConfig(ctx, s.config)
}

// CheckConfig validates an arbitrary config file with `sing-box check`. Used by
// apply to verify a freshly generated config before swapping it in.
func (s *SingBox) CheckConfig(ctx context.Context, path string) error {
	if !s.Available() {
		return fmt.Errorf("sing-box binary not found at %q", s.bin)
	}
	out, err := exec.CommandContext(ctx, s.bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check failed: %v: %s", err, out)
	}
	return nil
}

// Version returns the raw `sing-box version` output (version line + the "Tags:" build-feature
// line). Used to detect which protocols the deployed build supports (e.g. with_quic for
// hysteria2/tuic). Read-only.
func (s *SingBox) Version(ctx context.Context) (string, error) {
	if !s.Available() {
		return "", fmt.Errorf("sing-box binary not found at %q", s.bin)
	}
	out, err := exec.CommandContext(ctx, s.bin, "version").CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sing-box version failed: %w", err)
	}
	return string(out), nil
}

// Start launches sing-box if it is not already running. It marks the process as
// "desired" (the watchdog restarts it if it later crashes) and tracks its exit
// via a goroutine so Alive() stays accurate without a separate Wait() caller.
func (s *SingBox) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.aliveLocked() {
		s.desired = true
		return nil
	}
	return s.startLocked()
}

// StartIfDesiredDead (re)starts the core only when it is still DESIRED but not
// alive, entirely under mu — so a concurrent Stop() (which clears desired and
// kills the process) can't be overtaken by a stale Alive() read in the watchdog.
// This closes the TOCTOU where the watchdog read Desired()=true before an
// intentional native-only Stop() and Alive()=false after it, then resurrected a
// redundant sing-box TUN core over the kernel-PBR datapath.
//
// It NEVER promotes desired from false→true: it only acts when the core is
// ALREADY desired. Setting desired=true is reserved for the explicit user/boot
// Start(). Returns whether it actually (re)started the process.
func (s *SingBox) StartIfDesiredDead() (started bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.desired || s.aliveLocked() {
		// Either deliberately Stopped (desired=false) or already up — not a crash
		// the watchdog should act on.
		return false, nil
	}
	if err := s.startLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// startLocked spawns sing-box and installs the exit-tracking goroutine. The
// caller MUST hold s.mu. It is the shared spawn path for Start() and
// StartIfDesiredDead(); it sets desired=true ONLY on a successful spawn (so a
// missing/failed binary never leaves the watchdog looping — same contract as the
// original Start()).
func (s *SingBox) startLocked() error {
	if s.closed {
		// The daemon is shutting down. Refuse to spawn so an in-flight HTTP apply
		// handler (or any other late Start caller) can't resurrect the core after
		// teardown and orphan a process holding the listen ports + cache.db flock.
		// This is the shared spawn path for Start() and StartIfDesiredDead(), so the
		// single gate covers every spawn atomically under s.mu.
		return fmt.Errorf("sing-box supervisor is shutting down")
	}
	if !s.Available() {
		// Nothing to supervise (e.g. demo with no binary) — don't mark desired,
		// or the watchdog would loop on a process it can never start.
		return fmt.Errorf("sing-box binary not found at %q", s.bin)
	}
	cmd := exec.Command(s.bin, "run", "-c", s.config)
	// One writer value for both streams: os/exec then shares a single pipe and a
	// single copier goroutine for stdout and stderr, so the strip state stays linear.
	mw := &ansiStripWriter{w: io.MultiWriter(os.Stdout, s.log)}
	cmd.Stdout = mw
	cmd.Stderr = mw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	done := make(chan struct{})
	s.cmd = cmd
	s.done = done
	s.desired = true
	s.startedAt = time.Now()
	s.exitErr = nil
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.exitErr = err
		s.mu.Unlock()
		close(done)
	}()
	return nil
}

// Stop terminates sing-box if it is running and clears the "desired" intent so
// the watchdog won't restart it.
func (s *SingBox) Stop() error {
	s.mu.Lock()
	s.desired = false
	cmd, done := s.cmd, s.done
	s.cmd, s.done = nil, nil
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// If the process already exited on its own (a crash), the exit goroutine has
	// closed done. Killing an already-reaped process returns a spurious error
	// (os.ErrProcessDone on Unix, EINVAL on Windows) — that is NOT a Stop failure,
	// and returning it would make Reload() abort instead of relaunching the core.
	if done != nil {
		select {
		case <-done:
			return nil
		default:
		}
	}
	// Graceful first: SIGTERM lets sing-box tear down its TUN before we force-kill
	// it. In TUN-gateway mode sing-box installs kernel routing state (auto_route ip
	// rules + a route table, the auto_redirect nft table); SIGKILL bypasses its
	// signal handler so that state is left stranded on a now-dead tun0 (a transient
	// routing blackhole on every reload/restart) until a fresh start re-establishes
	// it. SIGTERM removes it cleanly (traffic falls back to the WAN default instead).
	// Wait briefly for a clean exit, then force-kill. On Windows (demo) Signal is
	// unsupported and returns an error, so we fall straight through to Kill.
	if err := cmd.Process.Signal(syscall.SIGTERM); err == nil && done != nil {
		grace := time.NewTimer(stopGrace)
		select {
		case <-done:
			grace.Stop()
			return nil
		case <-grace.C:
		}
	}
	err := cmd.Process.Kill()
	if done != nil {
		// Bound the final wait: cmd.Wait() (which `done` tracks) also blocks on the stdout/stderr
		// copier goroutines, and those feed a non-*os.File MultiWriter — a wedged writer could keep
		// Wait() from ever returning. The process is dead after Kill, so don't hang Stop() (and every
		// caller holding applyMu) on a stuck copier.
		select {
		case <-done:
		case <-time.After(killGrace):
		}
	}
	if errors.Is(err, os.ErrProcessDone) {
		return nil // lost the race: process died between the select and Kill
	}
	return err
}

// Shutdown permanently quiesces the supervisor: it marks the core "closed" so no
// later Start()/StartIfDesiredDead() can spawn a fresh process, then stops the
// running core. Call it ONCE from the daemon's shutdown path, AFTER the watchdog has
// stopped. Unlike Stop() (used for normal mode switches, which leaves the supervisor
// reusable), the closed flag is never cleared — this closes the race where an
// in-flight HTTP apply handler that outlives httpSrv.Shutdown's deadline calls
// Start() just after Stop() and orphans a new sing-box holding the listen ports and
// the cache.db flock. Setting closed first, then Stop, means either the apply's
// spawn is refused (closed already set) or its just-spawned process is killed by the
// subsequent Stop — never a survivor.
func (s *SingBox) Shutdown() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.Stop()
}

// stopGrace is how long Stop() waits for a clean SIGTERM exit before SIGKILL. A
// var (not const) so tests can shrink it.
var stopGrace = 3 * time.Second

// killGrace bounds the post-SIGKILL wait for cmd.Wait() to return: a wedged stdout/stderr copier
// (non-*os.File MultiWriter) must not hang Stop() forever after the process is already dead.
var killGrace = 3 * time.Second

// Reload re-applies the config by restarting sing-box. sing-box also supports
// SIGHUP on Unix, but a restart is portable and good enough for M1.
func (s *SingBox) Reload() error {
	if err := s.Stop(); err != nil {
		// Stop() already cleared "desired" and niled cmd/done, so returning here would leave the core
		// DOWN and un-supervised — the watchdog never retries. Re-assert the intent (symmetric with
		// the Start-failure path below) so it keeps trying to bring the core back up.
		s.mu.Lock()
		s.desired = true
		s.mu.Unlock()
		return err
	}
	err := s.Start()
	if err != nil {
		// Stop() cleared the "desired" intent and Start() only sets it on success,
		// so a failed reload would leave the core both DOWN and un-supervised — the
		// watchdog would never retry. Re-assert the intent so it keeps trying to
		// bring the core back up.
		s.mu.Lock()
		s.desired = true
		s.mu.Unlock()
	}
	return err
}

// Running reports whether sing-box is currently up (alive). Note: after a crash
// this is false even though Start was called — see Desired() for intent.
func (s *SingBox) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aliveLocked()
}

// Alive reports whether the supervised process is currently running.
func (s *SingBox) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aliveLocked()
}

func (s *SingBox) aliveLocked() bool {
	if s.cmd == nil || s.done == nil {
		return false
	}
	select {
	case <-s.done: // exited
		return false
	default:
		return true
	}
}

// Desired reports whether sing-box is supposed to be running (Start called,
// Stop not). The watchdog uses this to decide whether a crash warrants a restart.
func (s *SingBox) Desired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desired
}

// StartedAt is when the current process was launched (zero if never started).
func (s *SingBox) StartedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startedAt
}

// Backup copies the active config to <config>.bak (no-op if it doesn't exist yet).
func (s *SingBox) Backup() error {
	if _, err := os.Stat(s.config); err != nil {
		return backupStatVerdict(err)
	}
	bak := s.config + ".bak"
	if err := copyFile(s.config, bak); err != nil {
		return err
	}
	// Confirm the snapshot actually landed. copyFile is atomic, but a full filesystem can fail the
	// rename in ways worth catching here rather than at rollback time, when it is too late to tell
	// the user anything useful.
	st, err := os.Stat(bak)
	if err != nil {
		return fmt.Errorf("rollback snapshot is missing right after writing it: %w", err)
	}
	if st.Size() == 0 {
		return fmt.Errorf("rollback snapshot is empty — it would not restore anything")
	}
	return nil
}

// Restore restores the config from <config>.bak (used by fail-safe rollback).
func (s *SingBox) Restore() error {
	bak := s.config + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return fmt.Errorf("no backup config to restore")
	}
	return copyFile(bak, s.config)
}

// Commit marks the active config as the known-good baseline (<config>.good).
func (s *SingBox) Commit() error {
	if _, err := os.Stat(s.config); err != nil {
		return nil
	}
	return copyFile(s.config, s.config+".good")
}

// backupStatVerdict decides what a failed stat of the live config means.
//
// "The file is not there" and "I could not find out" are different answers, and returning nil for
// both is what made this worth fixing: nil means "snapshot taken". handleApply reacts carefully to
// a Backup error — it records it, logs that the fail-safe may be unable to restore, and surfaces it
// — and none of that could ever fire, because every stat failure reported success. The rollback
// target is the fail-safe's only way back from a bad config.
//
// Split out as a pure function so the distinction is testable on any platform: the non-ENOENT stat
// failures that motivate it (EACCES, EIO, a read-only overlay) cannot be produced through the
// filesystem on the Windows dev box, and a test that skips is a test that proves nothing.
func backupStatVerdict(err error) error {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil // no live config yet (first apply) — there is genuinely nothing to snapshot
	}
	return fmt.Errorf("cannot read the live config to snapshot it: %w", err)
}

// copyFile copies src to dst with a durable, atomic write (temp + fsync +
// rename). These dst paths are the config snapshots the fail-safe relies on —
// .bak (rollback target), .good (baseline), and the live config itself on
// Restore — so a power loss mid-write must not leave a torn/zero-length config
// that won't start. That is exactly what atomicfile guards against on a router.
//
// CALLER INVARIANT: Backup/Restore/Commit must be called under the SAME lock that
// serializes config writes (the server's applyMu — held by handleApply, the fail-safe
// rollback, RollbackNow, and handleApplyConfirm). atomicfile.Write is itself torn-write-safe
// (it stages to a UNIQUE temp then atomically renames, so concurrent writers can never leave a
// half-written file), but the invariant still matters for LOGICAL serialization: run lock-free, a
// Commit could snapshot a config mid-swap (a half-applied .good baseline) and a Restore could race
// an in-flight apply's write so last-writer-wins the WRONG config. Every caller holds applyMu; keep it that way.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicfile.Write(dst, data, 0o600)
}
