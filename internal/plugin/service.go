package plugin

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/binstore"
)

// ServiceSpec is a long-running process the daemon runs for itself rather than for a connection: the
// Telegram bridge (tgbridge). It is kept apart from the connection plugins on purpose. Sync reconciles
// the plugins to the set an Apply carries and stops everything else, so a service among them would
// be stopped by every Apply; here Sync never sees it, while Supervise restarts it with the same
// backoff and StopByBin and StopAll stop it like any plugin.
type ServiceSpec struct {
	Bin  string   // engine binary, resolved like a plugin's (binDir, a binary kept compressed, then PATH)
	Args []string // argv after the binary
	Env  []string // added over the daemon's environment: where a secret goes, out of the argv
	UID  int      // run as this uid/gid when the daemon is root; 0 = as the daemon
	// Scrub are values masked in the output the API shows, should the process ever print them.
	Scrub []string
}

func (s ServiceSpec) equal(o ServiceSpec) bool {
	return s.Bin == o.Bin && s.UID == o.UID && slices.Equal(s.Args, o.Args) &&
		slices.Equal(s.Env, o.Env) && slices.Equal(s.Scrub, o.Scrub)
}

// ServiceStatus is what the daemon knows about a service.
type ServiceStatus struct {
	Running     bool
	NeedsBinary bool
	Reason      string // why it is not running, or that it is backing off after crashes
	// Exits counts the times it ended on its own since this spec was started, LastExit the last of
	// them, and LastOutput the last line it wrote before that exit, with Scrub masked: for a process
	// that refuses to start ("Address in use") that line is the whole diagnosis.
	Exits      int
	LastExit   time.Time
	LastOutput string
	StartedAt  time.Time
}

// RunService makes the named service run spec, or stops and forgets it for nil. The same spec is a
// no-op while the process runs or Supervise is restarting it, so the owner may call this on a timer
// without defeating the crash backoff; a service that never started (binary missing, exec refused)
// is tried again. A different spec stops the old process and starts the new one.
//
// After StopAll it does nothing. The daemon's shutdown calls StopAll last, but an HTTP handler can
// outlive the 5 s httpSrv.Shutdown (a Components install, which then syncs the Telegram bridge) and
// call this afterwards; the process it started would be tracked by nobody, survive the daemon, keep
// its port so the next daemon's bridge exits with "Address in use", and keep serving the secret it
// was started with, where turning the bridge off or regenerating the secret cannot reach it.
func (m *Manager) RunService(name string, spec *ServiceSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	old := m.services[name]
	if spec == nil {
		if old != nil {
			m.stop(name, old)
			delete(m.services, name)
		}
		return
	}
	if old != nil && old.svc != nil && old.svc.equal(*spec) && (old.running || old.managed) {
		return
	}
	if old != nil {
		m.stop(name, old)
		delete(m.services, name)
	}
	m.services[name] = m.startService(*spec)
}

// strayWait bounds how long ReapStrays waits for a killed leftover to exit and let go of its port,
// as awgStaleWait does for an orphaned amneziawg-go's socket.
const strayWait = 2 * time.Second

// ReapStrays SIGKILLs every process running binary bin as uid that this manager did not start, then
// waits (at most strayWait) for them to exit. It returns how many it signalled.
//
// Such a process is a service an earlier daemon left behind when it ended without StopAll: a SIGKILL
// (the init script's kill, install.sh's kill -9, the OOM killer), a panic, or log.Fatalf when the
// panel's port is taken. The leftover keeps its port, so the new daemon's own process exits at every
// start with "Address in use", and it keeps serving with the settings it was started with: turning
// the service off or regenerating its secret never reaches it, so a leaked link stays good. The
// daemon calls this once at start, before its first RunService for bin, whether the service is
// enabled or not - a disabled one is exactly the case where nothing else would ever end it.
//
// The uid is what marks the process as WayHop's: a service runs as a uid of its own that nothing
// else on the router uses, so a binary of the same name run as root or as another user (upstream's
// own tg-ws-proxy-rs service, say) is left alone. uid <= 0 marks nothing and is a no-op, as is a
// host without /proc (only a root daemon runs a service as its uid, so only there is there anything
// to find).
func (m *Manager) ReapStrays(bin string, uid int) int {
	if uid <= 0 || bin == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	root, kill := m.procRoot, m.killPID
	if root == "" {
		root = "/proc"
	}
	if kill == nil {
		kill = killPID
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	ours := map[int]bool{os.Getpid(): true}
	for _, set := range []map[string]*proc{m.procs, m.services} {
		for _, p := range set {
			if p.cmd != nil && p.cmd.Process != nil {
				ours[p.cmd.Process.Pid] = true
			}
		}
	}
	var killed []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || ours[pid] || !isStray(root, pid, bin, uid) {
			continue
		}
		if err := kill(pid); err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.Printf("wayhop: %s (pid %d) was left running by an earlier daemon and could not be ended: %v", bin, pid, err)
			continue
		}
		log.Printf("wayhop: ended %s (pid %d, uid %d) left running by an earlier daemon", bin, pid, uid)
		killed = append(killed, pid)
	}
	n := len(killed)
	deadline := time.Now().Add(strayWait)
	for len(killed) > 0 && time.Now().Before(deadline) {
		killed = slices.DeleteFunc(killed, func(pid int) bool { return !isStray(root, pid, bin, uid) })
		if len(killed) > 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(killed) > 0 {
		log.Printf("wayhop: %s %v did not exit within %s; starting anyway", bin, killed, strayWait)
	}
	return n
}

// isStray reports whether /proc/<pid> under root is a live process running bin as uid. The name is
// the kernel's comm (the executable's base name cut to 15 bytes) or, should the process have renamed
// its main thread, argv[0]'s base name; the uid is the real one. A zombie is not one: it has already
// let go of its port, and init reaps it.
func isStray(root string, pid int, bin string, uid int) bool {
	dir := filepath.Join(root, strconv.Itoa(pid))
	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return false
	}
	uidOK := false
	for _, ln := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		switch {
		case k == "State" && len(f) > 0 && (f[0] == "Z" || f[0] == "X"):
			return false
		case k == "Uid" && len(f) > 0:
			uidOK = f[0] == strconv.Itoa(uid)
		}
	}
	if !uidOK {
		return false
	}
	base := filepath.Base(bin)
	comm := base
	if len(comm) > 15 {
		comm = comm[:15]
	}
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil && strings.TrimRight(string(b), "\n") == comm {
		return true
	}
	argv, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return false
	}
	argv0, _, _ := bytes.Cut(argv, []byte{0})
	return len(argv0) > 0 && path.Base(string(argv0)) == base
}

// killPID SIGKILLs a process (os.Process.Kill is SIGKILL on Unix).
func killPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer func() { _ = p.Release() }()
	return p.Kill()
}

func (m *Manager) startService(spec ServiceSpec) *proc {
	sp := spec
	sp.Args = slices.Clone(spec.Args)
	sp.Env = slices.Clone(spec.Env)
	sp.Scrub = slices.Clone(spec.Scrub)
	p := &proc{svc: &sp, binName: sp.Bin, runArgs: sp.Args, runEnv: sp.Env, runUID: sp.UID,
		output: newTailWriter(serviceTail), startedAt: time.Now()}
	bin, ok := m.resolve(sp.Bin)
	if !ok {
		p.needsBin = true
		return p
	}
	if err := launchProc(p, bin); err != nil {
		p.reason = "start " + sp.Bin + ": " + err.Error()
	}
	return p
}

// ServiceStatus reports the named service; ok is false when it is not running nor was asked to.
func (m *Manager) ServiceStatus(name string) (ServiceStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.services[name]
	if p == nil {
		return ServiceStatus{}, false
	}
	st := ServiceStatus{Running: p.running, NeedsBinary: p.needsBin, Reason: p.reason,
		Exits: p.exits, LastExit: p.lastExit, LastOutput: p.lastOut, StartedAt: p.startedAt}
	// Between ticks a process that has just exited still reads as running; say what it is.
	if p.running && procDied(p) {
		st.Running = false
	}
	if p.svc != nil {
		st.Reason = scrub(st.Reason, p.svc.Scrub)
	}
	return st, true
}

// BinaryPresent reports whether an engine binary is where resolve would find it, without unpacking a
// compressed one: for a status page, which must not write to tmpfs to answer a question.
func (m *Manager) BinaryPresent(name string) bool {
	m.mu.Lock()
	binDir := m.binDir
	m.mu.Unlock()
	return binaryPresent(binDir, name)
}

func binaryPresent(binDir, name string) bool {
	if binDir != "" {
		for _, p := range []string{filepath.Join(binDir, name), binstore.Stored(binDir, name, true)} {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return true
			}
		}
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// noteExit records an incarnation that ended on its own, for ServiceStatus.
func noteExit(p *proc) {
	p.exits++
	p.lastExit = time.Now()
	if p.output == nil {
		return
	}
	line := p.output.lastLine()
	if p.waitErr != nil {
		line = strings.TrimSpace(line + " (" + p.waitErr.Error() + ")")
	}
	var masks []string
	if p.svc != nil {
		masks = p.svc.Scrub
	}
	p.lastOut = scrub(line, masks)
	p.output.reset()
}

// scrub masks every non-empty value of masks in s.
func scrub(s string, masks []string) string {
	for _, v := range masks {
		if v != "" {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

// serviceTail is how much of a service's output is kept: enough for the last few lines of an
// error, never a growing log on a router with a few MB of RAM to spare.
const serviceTail = 4 << 10

// tailWriter keeps the last n bytes written to it. It is the process's stdout and stderr, so it is
// written from exec's copying goroutine while Supervise reads it.
type tailWriter struct {
	mu  sync.Mutex
	n   int
	buf []byte
}

func newTailWriter(n int) *tailWriter { return &tailWriter{n: n} }

func (t *tailWriter) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, b...)
	if over := len(t.buf) - t.n; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(b), nil
}

// lastLine is the last non-empty line written.
func (t *tailWriter) lastLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := bytes.Split(bytes.TrimRight(t.buf, "\r\n\t "), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(string(lines[i])); l != "" {
			return l
		}
	}
	return ""
}

func (t *tailWriter) reset() {
	t.mu.Lock()
	t.buf = t.buf[:0]
	t.mu.Unlock()
}
