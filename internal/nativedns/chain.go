package nativedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/atomicfile"
)

// chain.go sets the upstream chain of the Entware dnsmasq that answers a Keenetic's clients.
//
// The write-back plan only ever rendered 00-upstream.conf into the conf-dir. dnsmasq reads the main
// config first, and on Entware that is where the upstreams live, so a chain written beside them lands
// BEHIND them: measured on a live Keenetic, server=1.1.1.1 and server=8.8.8.8 in /opt/etc/dnsmasq.conf
// answered every lookup in plaintext over the provider, whatever the conf-dir said. So this path owns
// the whole chain: it writes 00-upstream.conf and moves the upstream directives of the main config
// aside, as comments that say so, which also makes the move reversible by reading the file.
//
// Everything else in both files is left alone, and the writer runs outside Apply: there is no profile
// state to reconcile (the files are the state, read back on every page load) and a restart of dnsmasq
// is all it takes. What Apply gives a kernel write, this path has to give itself, which is what the
// trial, the syntax test, the verification and the rollback below are.

const (
	// MainConfMovedPrefix marks a line this path moved aside in the main config.
	MainConfMovedPrefix = "# wayhop-moved: "
	// mainConfAddedNote precedes the conf-dir line this path added to a main config that had none.
	mainConfAddedNote = "# wayhop-added: the upstream chain lives in this directory"
	// MaxChainRows bounds a chain after groups expand. dnsmasq asks strictly in order and waits for a
	// client's retry between rows, so a longer chain only means more waiting.
	MaxChainRows = 16
	// chainOrigMain and chainOrigUpstream hold the files as they were before the first write, outside
	// the conf-dir so dnsmasq cannot read them as configuration.
	chainOrigMain     = "dnsmasq.conf.orig"
	chainOrigUpstream = "00-upstream.conf.orig"
)

// reIfaceName is what a kernel interface name can be: IFNAMSIZ-1 characters that need no quoting.
// Anything else would be an injection into dnsmasq's configuration, not an interface.
var reIfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// ValidIfaceName reports whether name can be written after `@` in a server= line.
func ValidIfaceName(name string) bool { return reIfaceName.MatchString(name) }

// ChainRow is one upstream in the order dnsmasq asks them. Iface binds the query to a kernel
// interface; empty means the router's ordinary path.
type ChainRow struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
	Iface   string `json:"iface,omitempty"`
}

// Line is the row as dnsmasq reads it.
func (r ChainRow) Line() string {
	return "server=" + serverRef(NativeResolver{Address: r.Address, Port: r.Port, Iface: r.Iface})
}

// ValidateChain refuses a chain dnsmasq could not run, or that would forward into itself.
func ValidateChain(rows []ChainRow) error {
	if len(rows) == 0 {
		return errors.New("the chain needs at least one upstream")
	}
	if len(rows) > MaxChainRows {
		return fmt.Errorf("%d upstreams after groups expand, the limit is %d", len(rows), MaxChainRows)
	}
	for i, r := range rows {
		ip := net.ParseIP(r.Address)
		switch {
		case ip == nil:
			return fmt.Errorf("upstream %d: %q is not an IP address, and dnsmasq takes nothing else here", i+1, r.Address)
		case ip.IsUnspecified() || ip.IsMulticast():
			return fmt.Errorf("upstream %d: %s cannot answer lookups", i+1, r.Address)
		case r.Port < 0 || r.Port > 65535:
			return fmt.Errorf("upstream %d: port %d is out of range", i+1, r.Port)
		case r.Iface != "" && !ValidIfaceName(r.Iface):
			return fmt.Errorf("upstream %d: %q is not an interface name", i+1, r.Iface)
		case ip.IsLoopback() && r.Iface != "":
			return fmt.Errorf("upstream %d: %s is this router, so it cannot be reached through %s", i+1, r.Address, r.Iface)
		case ip.IsLoopback() && (r.Port == 0 || r.Port == 53):
			return fmt.Errorf("upstream %d: %s on port 53 is dnsmasq itself, which would ask itself forever", i+1, r.Address)
		}
	}
	return nil
}

// RenderChain is the 00-upstream.conf content for a chain: strict-order, because without it dnsmasq
// asks every row at once (measured on 2.90: the last-resort row gets every first query) and no-resolv,
// because resolv.conf would add the router's own plaintext servers to the chain.
func RenderChain(rows []ChainRow) string {
	nd := NativeDNS{Platform: "keenetic", StrictOrder: true, NoResolv: true}
	for _, r := range rows {
		nd.Resolvers = append(nd.Resolvers, NativeResolver{Kind: KindPlain, Address: r.Address, Port: r.Port, Iface: r.Iface})
	}
	return "# Set on WayHop's DNS page. Lines marked `wayhop-moved` in the main config were the upstreams before it.\n" +
		RenderDnsmasqD(nd)
}

// movedAside reports a main-config directive that belongs to the chain. Split-DNS (server=/domain/...)
// is routing for one name and stays; all-servers is the opposite of strict-order and goes.
func movedAside(line string) bool {
	switch line {
	case "no-resolv", "strict-order", "all-servers":
		return true
	}
	if strings.HasPrefix(line, "resolv-file=") {
		return true
	}
	for _, key := range []string{"server=", "local="} {
		if v, ok := strings.CutPrefix(line, key); ok {
			return !strings.HasPrefix(strings.TrimSpace(v), "/")
		}
	}
	return false
}

// RewriteMainConf moves the chain's directives out of the main config. moved lists them as written. It
// also makes sure the conf-dir is read at all: a main config with no conf-dir gets one, or the chain
// would never be seen and dnsmasq would come up with no upstream.
func RewriteMainConf(main, confDir string) (out string, moved []string, addedConfDir bool) {
	var lines []string
	hasConfDir := false
	for _, ln := range strings.Split(main, "\n") {
		trimmed := strings.TrimSpace(ln)
		if movedAside(trimmed) {
			moved = append(moved, trimmed)
			lines = append(lines, MainConfMovedPrefix+trimmed)
			continue
		}
		if v, ok := strings.CutPrefix(trimmed, "conf-dir="); ok {
			dir, _, _ := strings.Cut(v, ",")
			hasConfDir = hasConfDir || strings.TrimRight(strings.TrimSpace(dir), "/") == strings.TrimRight(confDir, "/")
		}
		lines = append(lines, ln)
	}
	out = strings.Join(lines, "\n")
	if !hasConfDir {
		addedConfDir = true
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += mainConfAddedNote + "\nconf-dir=" + confDir + ",*.conf\n"
	}
	return out, moved, addedConfDir
}

// RestoreMainConf is the inverse of RewriteMainConf, applied to the file as it is now rather than to a
// copy from before the first write: anything edited in the main config since then survives.
func RestoreMainConf(main string) string {
	var lines []string
	skipNext := false
	for _, ln := range strings.Split(main, "\n") {
		if skipNext {
			skipNext = false
			continue
		}
		if ln == mainConfAddedNote {
			skipNext = true
			continue
		}
		if v, ok := strings.CutPrefix(ln, MainConfMovedPrefix); ok {
			ln = v
		}
		lines = append(lines, ln)
	}
	return strings.Join(lines, "\n")
}

// ChainHost is everything the write touches, so the sequence can be asserted without a router.
type ChainHost struct {
	MainConf     string // /opt/etc/dnsmasq.conf
	UpstreamConf string // /opt/etc/dnsmasq.d/00-upstream.conf
	ConfDir      string // /opt/etc/dnsmasq.d
	StateDir     string // where the files as they were before the first write are kept
	// Usable says why this router cannot take a chain (no Entware dnsmasq, say); nil means it can.
	Usable func() error
	// Test runs dnsmasq's own syntax check over the files as written.
	Test func(ctx context.Context) (string, error)
	// Restart restarts the service that answers clients.
	Restart func(ctx context.Context) error
	// Trial asks a throwaway dnsmasq, with this row as its only upstream, for an answer.
	Trial func(ctx context.Context, row ChainRow) error
	// Verify asks the restarted service for an answer through the whole chain.
	Verify func(ctx context.Context) error
	// Probe asks a resolver directly for an answer; nil uses ProbeResolver.
	Probe func(ctx context.Context, addr string) error
}

// ChainStep is one line of what the write did.
type ChainStep struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// ChainReport is the outcome: on failure Error says why and RolledBack whether files had changed and
// were put back. A refusal before the first write has RolledBack false and leaves the router untouched.
type ChainReport struct {
	OK         bool        `json:"ok"`
	RolledBack bool        `json:"rolled_back,omitempty"`
	Error      string      `json:"error,omitempty"`
	Steps      []ChainStep `json:"steps"`
}

func (rep *ChainReport) step(name string, err error, detail string) {
	st := ChainStep{Step: name, OK: err == nil, Detail: detail}
	if err != nil && detail == "" {
		st.Detail = err.Error()
	}
	rep.Steps = append(rep.Steps, st)
}

// Managed reports that this path has written the chain and Restore has something to undo.
func (h ChainHost) Managed() bool {
	_, err := os.Stat(filepath.Join(h.StateDir, chainOrigMain))
	return err == nil
}

// Rev identifies the two files the chain owns, so a write based on an older read is refused rather than
// discarding what somebody changed on the router in between.
func (h ChainHost) Rev() string {
	main, _ := os.ReadFile(h.MainConf)
	up, _ := os.ReadFile(h.UpstreamConf)
	return fileRev(main, up)
}

// ChainPlan is what a write would do, read from the router but changing nothing.
type ChainPlan struct {
	Lines []string `json:"lines"` // the server= lines, in the order dnsmasq asks them
	// Content is 00-upstream.conf as it would be written.
	Content string `json:"content"`
	// Moved are the main-config directives this write moves aside.
	Moved []string `json:"moved,omitempty"`
	// AddedConfDir says the main config had no conf-dir and gains one.
	AddedConfDir bool `json:"added_conf_dir,omitempty"`
	// Foreign are upstreams in other conf-dir files, which this path does not own and dnsmasq also asks.
	Foreign []string `json:"foreign,omitempty"`
}

// Plan renders the write for review.
func (h ChainHost) Plan(rows []ChainRow) (ChainPlan, error) {
	if err := ValidateChain(rows); err != nil {
		return ChainPlan{}, err
	}
	main, err := os.ReadFile(h.MainConf)
	if err != nil {
		return ChainPlan{}, fmt.Errorf("read the main dnsmasq config: %w", err)
	}
	_, moved, added := RewriteMainConf(string(main), h.ConfDir)
	plan := ChainPlan{Content: RenderChain(rows), Moved: moved, AddedConfDir: added, Foreign: h.foreignUpstreams()}
	for _, r := range rows {
		plan.Lines = append(plan.Lines, r.Line())
	}
	return plan, nil
}

// foreignUpstreams lists the plain upstreams other conf-dir files hold. The glob is the one the main
// config reads them by.
func (h ChainHost) foreignUpstreams() []string {
	files, _ := filepath.Glob(filepath.Join(h.ConfDir, "*.conf"))
	sort.Strings(files)
	var out []string
	for _, f := range files {
		if filepath.Clean(f) == filepath.Clean(h.UpstreamConf) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "server="); ok && !strings.HasPrefix(v, "/") {
				out = append(out, filepath.Base(f)+": "+strings.TrimSpace(v))
			}
		}
	}
	return out
}

// fileState is a file's bytes, or its absence, so it can be put back exactly.
type fileState struct {
	path string
	data []byte
	had  bool
	perm os.FileMode
}

func readFileState(path string) (fileState, error) {
	st := fileState{path: path, perm: 0o644}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		st.data, st.had = data, true
		if info, statErr := os.Stat(path); statErr == nil {
			st.perm = info.Mode().Perm()
		}
	case !os.IsNotExist(err):
		return st, err
	}
	return st, nil
}

func (st fileState) restore() error {
	if !st.had {
		if err := os.Remove(st.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return atomicfile.WriteOutsideDir(st.path, st.data, st.perm)
}

// Apply writes a chain. In order, and stopping at the first thing that fails:
//
//  1. Trial. Each row bound to an interface is asked through a throwaway dnsmasq under its normal user,
//     because the panel's root cannot prove what dnsmasq running as nobody can bind. No row answering
//     stops here with the router untouched; a row that does not answer is reported but does not stop a
//     chain whose other rows work, since its tunnel can come back and dnsmasq will use it.
//  2. Write both files, keeping the first-ever versions in StateDir.
//  3. dnsmasq's syntax check. A failure restores the files with nothing restarted.
//  4. Restart, then ask the running service for an answer. A failure restores the files and restarts
//     again: a house with no DNS is worse than a house with the DNS it had.
func (h ChainHost) Apply(ctx context.Context, rows []ChainRow) ChainReport {
	rep := ChainReport{Steps: []ChainStep{}}
	refuse := func(err error) ChainReport {
		rep.Error = err.Error()
		return rep
	}
	if h.Usable != nil {
		if err := h.Usable(); err != nil {
			return refuse(err)
		}
	}
	if err := ValidateChain(rows); err != nil {
		return refuse(err)
	}
	mainBefore, err := readFileState(h.MainConf)
	if err != nil || !mainBefore.had {
		return refuse(fmt.Errorf("read the main dnsmasq config: %v", orMissing(err)))
	}
	upBefore, err := readFileState(h.UpstreamConf)
	if err != nil {
		return refuse(fmt.Errorf("read the upstream file: %w", err))
	}

	bound, answered := 0, 0
	probe := h.Probe
	if probe == nil {
		probe = ProbeResolver
	}
	for _, r := range rows {
		ip := net.ParseIP(r.Address)
		if ip != nil && ip.IsLoopback() && r.Port > 0 {
			bound++
			addr := net.JoinHostPort(r.Address, strconv.Itoa(r.Port))
			trialErr := probe(ctx, addr)
			if trialErr == nil {
				answered++
			}
			rep.step("trial "+r.Line(), trialErr, "")
			continue
		}
		if r.Iface == "" {
			continue
		}
		bound++
		trialErr := h.Trial(ctx, r)
		if trialErr == nil {
			answered++
		}
		rep.step("trial "+r.Line(), trialErr, "")
	}
	if bound > 0 && answered == 0 {
		return refuse(errors.New("no upstream bound to a tunnel answered through dnsmasq, so nothing was changed: " +
			"the tunnels may be down, or this dnsmasq cannot bind to them"))
	}

	createdState := false
	if !h.Managed() {
		if err := h.saveOriginals(mainBefore, upBefore); err != nil {
			return refuse(fmt.Errorf("keep the current files: %w", err))
		}
		createdState = true
	}
	undo := func(cause error) ChainReport {
		rep.Error = cause.Error()
		if restoreErr := errors.Join(mainBefore.restore(), upBefore.restore()); restoreErr != nil {
			rep.Error += "; putting the files back also failed: " + restoreErr.Error()
		}
		rep.RolledBack = true
		if createdState {
			h.forgetOriginals()
		}
		return rep
	}

	newMain, _, _ := RewriteMainConf(string(mainBefore.data), h.ConfDir)
	// The chain first: at no moment may the main config have given up its upstreams with none to replace them.
	if err := atomicfile.WriteOutsideDir(h.UpstreamConf, []byte(RenderChain(rows)), 0o644); err != nil {
		rep.step("write the chain", err, "")
		return undo(fmt.Errorf("write %s: %w", h.UpstreamConf, err))
	}
	if err := atomicfile.WriteOutsideDir(h.MainConf, []byte(newMain), mainBefore.perm); err != nil {
		rep.step("write the main config", err, "")
		return undo(fmt.Errorf("write %s: %w", h.MainConf, err))
	}
	rep.step("write the chain and move the old upstreams aside", nil, "")

	if out, err := h.Test(ctx); err != nil {
		rep.step("dnsmasq syntax check", err, strings.TrimSpace(out))
		return undo(fmt.Errorf("dnsmasq refused the new configuration: %s", strings.TrimSpace(out+" "+err.Error())))
	}
	rep.step("dnsmasq syntax check", nil, "")

	verifyErr := h.restartAndVerify(ctx, &rep)
	if verifyErr != nil {
		out := undo(verifyErr)
		// The running dnsmasq is on the bad chain until it is restarted on the files just put back.
		if err := h.Restart(ctx); err != nil {
			out.Error += "; restarting dnsmasq on the old files also failed: " + err.Error()
		}
		return out
	}
	rep.OK = true
	return rep
}

func (h ChainHost) restartAndVerify(ctx context.Context, rep *ChainReport) error {
	if err := h.Restart(ctx); err != nil {
		rep.step("restart dnsmasq", err, "")
		return fmt.Errorf("restart dnsmasq: %w", err)
	}
	rep.step("restart dnsmasq", nil, "")
	if err := h.Verify(ctx); err != nil {
		rep.step("ask dnsmasq for an answer", err, "")
		return fmt.Errorf("dnsmasq did not answer after the restart: %w", err)
	}
	rep.step("ask dnsmasq for an answer", nil, "")
	return nil
}

// Restore puts back what the first write replaced: the moved lines return to the main config as it is
// now, and 00-upstream.conf returns to what it held, or goes if there was none.
func (h ChainHost) Restore(ctx context.Context) ChainReport {
	rep := ChainReport{Steps: []ChainStep{}}
	if !h.Managed() {
		rep.Error = "WayHop has not written this router's upstream chain, so there is nothing to restore"
		return rep
	}
	mainNow, err := readFileState(h.MainConf)
	if err != nil || !mainNow.had {
		rep.Error = fmt.Sprintf("read the main dnsmasq config: %v", orMissing(err))
		return rep
	}
	upNow, err := readFileState(h.UpstreamConf)
	if err != nil {
		rep.Error = fmt.Sprintf("read the upstream file: %v", err)
		return rep
	}
	undo := func(cause error) ChainReport {
		rep.Error = cause.Error()
		rep.RolledBack = true
		if restoreErr := errors.Join(mainNow.restore(), upNow.restore()); restoreErr != nil {
			rep.Error += "; putting the files back also failed: " + restoreErr.Error()
		}
		return rep
	}
	origUp, err := readFileState(filepath.Join(h.StateDir, chainOrigUpstream))
	if err != nil {
		rep.Error = fmt.Sprintf("read the kept upstream file: %v", err)
		return rep
	}
	if origUp.had {
		err = atomicfile.WriteOutsideDir(h.UpstreamConf, origUp.data, 0o644)
	} else if err = os.Remove(h.UpstreamConf); os.IsNotExist(err) {
		err = nil
	}
	if err == nil {
		err = atomicfile.WriteOutsideDir(h.MainConf, []byte(RestoreMainConf(string(mainNow.data))), mainNow.perm)
	}
	if err != nil {
		rep.step("put the files back", err, "")
		return undo(fmt.Errorf("put the files back: %w", err))
	}
	rep.step("put the files back", nil, "")
	if out, err := h.Test(ctx); err != nil {
		rep.step("dnsmasq syntax check", err, strings.TrimSpace(out))
		return undo(fmt.Errorf("dnsmasq refused the restored configuration: %s", strings.TrimSpace(out+" "+err.Error())))
	}
	rep.step("dnsmasq syntax check", nil, "")
	if verifyErr := h.restartAndVerify(ctx, &rep); verifyErr != nil {
		out := undo(verifyErr)
		if err := h.Restart(ctx); err != nil {
			out.Error += "; restarting dnsmasq on the chain also failed: " + err.Error()
		}
		return out
	}
	h.forgetOriginals()
	rep.OK = true
	return rep
}

func (h ChainHost) saveOriginals(main, up fileState) error {
	if err := os.MkdirAll(h.StateDir, 0o700); err != nil {
		return err
	}
	if up.had {
		if err := atomicfile.Write(filepath.Join(h.StateDir, chainOrigUpstream), up.data, 0o600); err != nil {
			return err
		}
	}
	// Last, because its presence is what Managed reads.
	return atomicfile.Write(filepath.Join(h.StateDir, chainOrigMain), main.data, 0o600)
}

func (h ChainHost) forgetOriginals() {
	os.Remove(filepath.Join(h.StateDir, chainOrigMain))
	os.Remove(filepath.Join(h.StateDir, chainOrigUpstream))
}

func orMissing(err error) error {
	if err != nil {
		return err
	}
	return os.ErrNotExist
}

// BoundIfaces lists the interfaces a rendered chain binds to, each once.
func BoundIfaces(upstreamConf string) []string {
	nd := ReadDnsmasqD(upstreamConf, "")
	seen := map[string]bool{}
	var out []string
	for _, r := range nd.Resolvers {
		if r.Iface != "" && !seen[r.Iface] {
			seen[r.Iface] = true
			out = append(out, r.Iface)
		}
	}
	return out
}

// VerifyTimeout bounds how long a restarted dnsmasq has to answer through its chain. A first row whose
// tunnel is up but silent takes a retransmit to fall through, which ProbeResolver sends.
const VerifyTimeout = 15 * time.Second
