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
	if !s.Available() {
		// Nothing to supervise (e.g. demo with no binary) — don't mark desired,
		// or the watchdog would loop on a process it can never start.
		return fmt.Errorf("sing-box binary not found at %q", s.bin)
	}
	cmd := exec.Command(s.bin, "run", "-c", s.config)
	mw := io.MultiWriter(os.Stdout, s.log)
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
		<-done // let the exit-tracking goroutine finish Wait()
	}
	if errors.Is(err, os.ErrProcessDone) {
		return nil // lost the race: process died between the select and Kill
	}
	return err
}

// stopGrace is how long Stop() waits for a clean SIGTERM exit before SIGKILL. A
// var (not const) so tests can shrink it.
var stopGrace = 3 * time.Second

// Reload re-applies the config by restarting sing-box. sing-box also supports
// SIGHUP on Unix, but a restart is portable and good enough for M1.
func (s *SingBox) Reload() error {
	if err := s.Stop(); err != nil {
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
		return nil
	}
	return copyFile(s.config, s.config+".bak")
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
