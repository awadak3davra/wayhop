package server

// fastdns.go is the daemon's side of the fast DNS plane (routing mode "fast" on OpenWrt;
// pbr/fastdns.go has the kernel side): which devices are on the LAN, the remote rule-sets the
// kernel needs as text, the dnsmasq snippet that fills the dlist sets, the carry-over of those sets
// across an Apply, and what Review and Diagnostics say about it all.
//
// Flash: nothing here is written outside /tmp. The decompiled rule-sets, the snippet (dnsmasq's
// conf-dir on OpenWrt is /tmp/dnsmasq.<instance>.d) and the copy of the sets kept over a daemon
// restart all live in RAM and are gone after a reboot.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/cidrfeed"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// Paths and commands, variables so tests can point them elsewhere.
var (
	// fastDNSRunDir holds the decompiled rule-sets and the carry-over copy of the dlist sets.
	fastDNSRunDir = "/tmp/wayhop"
	// fastDNSConfGlob finds the running dnsmasq configurations (one per instance).
	fastDNSConfGlob = "/var/etc/dnsmasq.conf.*"
	// fastDNSDefaultConfDir is dnsmasq's conf-dir of the first instance when none is stated.
	fastDNSDefaultConfDir = "/tmp/dnsmasq.d"
	// fastDNSRAMDir holds the snippet when dnsmasq's conf-dir is on flash: dnsmasq's run dir.
	fastDNSRAMDir = "/var/run/dnsmasq"
	// fastRemoteAutoFetch lets a compile that finds a remote list's content missing start its fetch;
	// the package's tests turn it off (no network from a unit test).
	fastRemoteAutoFetch = true
	// fastDNSRestart restarts dnsmasq: SIGHUP does not reload nftset= lines.
	fastDNSRestart = func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "/etc/init.d/dnsmasq", "restart").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// fastDNSVersion runs `dnsmasq --version`.
	fastDNSVersion = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "dnsmasq", "--version").CombinedOutput()
		return string(out), err
	}
	// fastDNSDecompile turns a binary rule-set into its JSON source with the installed core.
	fastDNSDecompile = func(ctx context.Context, bin, in, out string) error {
		res, err := exec.CommandContext(ctx, bin, "rule-set", "decompile", in, "-o", out).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res)))
		}
		return nil
	}
)

const (
	// fastDNSSnippetName is the file WayHop owns in each dnsmasq conf-dir.
	fastDNSSnippetName = "wayhop-fastpath.conf"
	// fastDNSRAMFile is the snippet's name in fastDNSRAMDir when the conf-dir is on flash; only files
	// with fastDNSRAMExt are read from that dir (dnsmasq keeps its pid file there too).
	fastDNSRAMFile = "nftset" + fastDNSRAMExt
	fastDNSRAMExt  = ".wayhop-fastpath"
	// fastDNSCarryFile keeps the dlist elements over a daemon restart (RAM).
	fastDNSCarryFile = "dlist-cache.nft"
	// fastRemoteMaxBytes bounds one downloaded rule-set.
	fastRemoteMaxBytes = 16 << 20
	// fastRemoteMaxJSON bounds the decompiled source of one rule-set.
	fastRemoteMaxJSON = 8 << 20
	// fastRemoteMaxCIDRs bounds the prefixes of one remote list.
	fastRemoteMaxCIDRs = 100000
	// fastNamesMax bounds the names the snippet carries across every list (Review refuses beyond).
	fastNamesMax = 50000
	// fastListMaxBytes bounds one read of the dlist sets.
	fastListMaxBytes = 16 << 20
	// fastRemoteRetry is the shortest gap between two attempts at a list whose content is missing.
	fastRemoteRetry = time.Minute
)

// fastDNSRuntime is the plane's state in the daemon.
type fastDNSRuntime struct {
	mu sync.Mutex
	// remote is each remote list's decompiled content, by list id.
	remote map[string]fastRemoteEntry
	// inflight is the lists being fetched now.
	inflight map[string]bool
	// nftset caches the dnsmasq probe: 0 unknown, 1 has nftset, -1 lacks it.
	nftset   int
	nftsetAt time.Time
	// snippet is what was last written, dirs where, err the last failure, restarted when.
	snippet   string
	dirs      []string
	err       string
	restarted time.Time
	// overfull is the names the last snippet left out because their lists do not fit one dnsmasq line
	// (polish 1a: Review refuses them, a remote list refreshed at run time can still bring one).
	overfull []string
	// remoteGen counts loads of remote content that changed the RAM copy. loadedKey is the content
	// (planRemote) the snippet was filled from, elemKey the content the rlist sets were filled from:
	// the loop reloads them live when the content moves.
	remoteGen          int
	loadedKey, elemKey string
	// live is the remote content the installed plane uses, by list id; rejected says why a refreshed
	// copy was not taken live.
	live     map[string]pbr.RemoteSet
	rejected map[string]string
	// pinReady says whether the core pin's devices were set (every remote list loaded). retryAt and
	// backoff pace a failed live reload.
	pinReady bool
	// backedOut says the post-install watch took the snippet out because the LAN's DNS failed; the
	// next install clears it. dnsFails counts the loop's consecutive failed checks of dnsmasq.
	backedOut bool
	watchGen  int
	// backouts counts back-outs with no clean watch between; gaveUp ends the retries until the next
	// install.
	backouts int
	gaveUp   bool
	// restartOwed says the back-out's restart left dnsmasq not answering.
	restartOwed bool
	// restartTries counts the owed restarts since dnsmasq last answered; past fastDNSMaxOwedRestarts
	// they stop and Diagnostics fails.
	restartTries int
	dnsFails     int
	dnsErr       string
	retryAt      time.Time
	backoff      time.Duration
	// seed is the addresses carried into the table at the last install (the fresh-address baseline
	// for FastDNSLoop), seedKey the sets they were carried into.
	seed    map[netip.Addr]bool
	seedKey string
	// keenetic is the KeeneticOS fast plane's share of this state (keeneticfast.go); the fields above
	// that are not nft-specific (the watch, back-out and retry bookkeeping) serve it too.
	keenetic keeneticFastState
}

// fastRemoteEntry is one remote list's content.
type fastRemoteEntry struct {
	set     pbr.RemoteSet
	fetched time.Time // zero: never loaded
	tried   time.Time
	err     string
}

// fastDNSOn reports whether the fast DNS plane applies: routing mode "fast" on OpenWrt, the only
// platform where its snippet, its Review and its loop run. KeeneticOS keeps its own resolver plane
// (ipset); any other host keeps the kernel plane without it.
func (s *Server) fastDNSOn(c config.Config) bool {
	return s.routingMode(c) == "fast" && s.detectedPlatform() == platform.OpenWrt
}

// fastDNSCompileOptions adds the fast DNS plane to a compile's options.
func (s *Server) fastDNSCompileOptions(c config.Config, opts *pbr.Options) {
	if !s.fastDNSOn(c) {
		return
	}
	opts.FastDNS = true
	opts.DNSEnforce = c.FastDNSEnforceOn()
	opts.LANIfaces = s.fastLANIfaces(c)
	opts.RemoteSets = s.fastRemoteSets(c)
}

// fastLANIfaces is the LAN devices as the kill-switch guard's reading has them: devices a LAN
// firewall zone holds that carry a route. Nothing in the demo or off OpenWrt.
func (s *Server) fastLANIfaces(c config.Config) []string {
	if c.Demo || s.detectedPlatform() != platform.OpenWrt {
		return nil
	}
	s.ksLocal.mu.Lock()
	read := s.ksLocal.read
	s.ksLocal.mu.Unlock()
	if !read {
		s.refreshGuardLocal(false)
	}
	local, _, _ := s.guardLocalState()
	var out []string
	for _, l := range local {
		if l.House {
			out = append(out, l.Dev)
		}
	}
	return sortedUniqueStrings(out)
}

// fastRemoteSets is the loaded content of the profile's remote lists for a compile. A list without
// content is left out (Compile then warns about it, and Review refuses the Apply), and a fetch is
// started for it. A direct list keeps what it can express: what it cannot falls to the main table,
// which is where a direct list sends it anyway.
func (s *Server) fastRemoteSets(c config.Config) map[string]pbr.RemoteSet {
	if s.store == nil {
		return nil
	}
	p := s.store.Profile()
	var missing bool
	out := map[string]pbr.RemoteSet{}
	s.fastDNS.mu.Lock()
	for _, rl := range p.RoutingLists {
		if !rl.Enabled || rl.Source == "" {
			continue
		}
		e, ok := s.fastDNS.remote[rl.ID]
		if !ok || e.fetched.IsZero() || e.set.Source != rl.Source {
			missing = true
			continue
		}
		set := e.set
		if rl.Outbound == model.OutboundDirect {
			set.Unrepresentable = nil
		}
		out[rl.ID] = set
	}
	s.fastDNS.mu.Unlock()
	if missing && !c.Demo && fastRemoteAutoFetch {
		wctx, now := s.bgContext(), time.Now()
		s.goBackground(func() { s.fastRemoteRefresh(wctx, now) })
	}
	return out
}

// fastRemoteRefresh loads the remote lists whose content is missing, of another source, or older than
// the list's refresh interval. Each list is fetched by one caller at a time; a missing one is tried at
// most once a minute. Content that changed is logged: it reaches the kernel at the next Apply.
func (s *Server) fastRemoteRefresh(ctx context.Context, now time.Time) {
	if s.store == nil || !s.fastDNSOn(s.config()) || s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return
	}
	p := s.store.Profile()
	for _, rl := range p.RoutingLists {
		if !rl.Enabled || rl.Source == "" {
			continue
		}
		interval := time.Duration(cidrIntervalHours(rl)) * time.Hour
		s.fastDNS.mu.Lock()
		if s.fastDNS.remote == nil {
			s.fastDNS.remote = map[string]fastRemoteEntry{}
			s.fastDNS.inflight = map[string]bool{}
		}
		e := s.fastDNS.remote[rl.ID]
		fresh := !e.fetched.IsZero() && e.set.Source == rl.Source && now.Sub(e.fetched) < interval
		soon := now.Sub(e.tried) < fastRemoteRetry
		busy := s.fastDNS.inflight[rl.ID]
		if fresh || soon || busy {
			s.fastDNS.mu.Unlock()
			continue
		}
		s.fastDNS.inflight[rl.ID] = true
		s.fastDNS.mu.Unlock()

		fctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		set, err := s.fetchRemoteSet(fctx, rl)
		cancel()

		s.fastDNS.mu.Lock()
		delete(s.fastDNS.inflight, rl.ID)
		e = s.fastDNS.remote[rl.ID]
		e.tried = now
		if err != nil {
			e.err = err.Error()
			log.Printf("fast path: remote list %q: %v (the last good content stays)", rl.ID, err)
		} else {
			changed := e.fetched.IsZero() || !sameRemoteSet(e.set, set)
			e.set, e.fetched, e.err = set, now, ""
			if changed {
				// FastDNSLoop reloads the installed sets and snippet from the new copy.
				s.fastDNS.remoteGen++
				log.Printf("fast path: remote list %q loaded (%d names, %d prefixes)", rl.ID, len(set.Domains), len(set.CIDRs))
				saveRemoteCopy(rl.ID, set)
			}
		}
		s.fastDNS.remote[rl.ID] = e
		s.fastDNS.mu.Unlock()
	}
}

func sameRemoteSet(a, b pbr.RemoteSet) bool {
	return a.Source == b.Source && strings.Join(a.Domains, "\n") == strings.Join(b.Domains, "\n") &&
		strings.Join(a.CIDRs, "\n") == strings.Join(b.CIDRs, "\n") && strings.Join(a.Unrepresentable, ",") == strings.Join(b.Unrepresentable, ",")
}

// fetchRemoteSet downloads a list's rule-set by the list's own download path (the same client the
// CIDR and domain feeds use: a socket bound to the tunnel the list names, because the router's own
// direct HTTPS may not get through), decompiles a binary one with the installed core, and reads the
// result. Both files are in /tmp and removed afterwards.
func (s *Server) fetchRemoteSet(ctx context.Context, rl model.RoutingList) (pbr.RemoteSet, error) {
	via := s.feedVia(rl)
	iface, err := s.feedIface(via)
	if err != nil {
		return pbr.RemoteSet{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rl.Source, nil)
	if err != nil {
		return pbr.RemoteSet{}, err
	}
	resp, err := s.listFetchClient(via).Do(req)
	if err != nil {
		return pbr.RemoteSet{}, feedFetchError(iface, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pbr.RemoteSet{}, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, fastRemoteMaxBytes+1))
	if err != nil {
		return pbr.RemoteSet{}, fmt.Errorf("download: %w", err)
	}
	if len(body) > fastRemoteMaxBytes {
		return pbr.RemoteSet{}, fmt.Errorf("download: larger than %d MiB", fastRemoteMaxBytes>>20)
	}
	src := body
	if fastRemoteFormat(rl) == "binary" {
		dir := filepath.Join(fastDNSRunDir, "fastpath")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return pbr.RemoteSet{}, err
		}
		in := filepath.Join(dir, safeFileName(rl.ID)+".srs")
		out := filepath.Join(dir, safeFileName(rl.ID)+".json")
		defer os.Remove(in)
		defer os.Remove(out)
		if err := os.WriteFile(in, body, 0o600); err != nil {
			return pbr.RemoteSet{}, err
		}
		bin := strings.TrimSpace(s.config().SingBox.Bin)
		if bin == "" {
			bin = "sing-box"
		}
		if err := fastDNSDecompile(ctx, bin, in, out); err != nil {
			return pbr.RemoteSet{}, fmt.Errorf("decompile: %w", err)
		}
		if st, err := os.Stat(out); err == nil && st.Size() > fastRemoteMaxJSON {
			return pbr.RemoteSet{}, fmt.Errorf("decompile: the rule-set's source is larger than %d MiB", fastRemoteMaxJSON>>20)
		}
		if src, err = os.ReadFile(out); err != nil {
			return pbr.RemoteSet{}, fmt.Errorf("decompile: %w", err)
		}
	}
	set, err := parseRuleSetSource(src)
	if err != nil {
		return pbr.RemoteSet{}, err
	}
	set.Source = rl.Source
	return set, nil
}

// saveRemoteCopy keeps a list's decompiled content in RAM-backed /tmp, so a daemon restart (procd
// respawn, an upgrade) has it before the boot converge reinstalls the plane.
// A reboot clears it: the plane then holds the core pin until the lists are fetched again.
func saveRemoteCopy(id string, set pbr.RemoteSet) {
	dir := filepath.Join(fastDNSRunDir, "fastpath")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	b, err := json.Marshal(set)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	_ = os.WriteFile(filepath.Join(dir, safeFileName(id)+".remote.json.gz"), buf.Bytes(), 0o600)
}

// LoadFastDNSRemoteCache reads the copies saveRemoteCopy left in /tmp for the profile's remote lists
// (same source only), as loaded at the file's time. Called at daemon start, before the boot converge.
func (s *Server) LoadFastDNSRemoteCache() {
	if s == nil || s.store == nil {
		return
	}
	p := s.store.Profile()
	dir := filepath.Join(fastDNSRunDir, "fastpath")
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	for _, rl := range p.RoutingLists {
		if !rl.Enabled || rl.Source == "" {
			continue
		}
		file := filepath.Join(dir, safeFileName(rl.ID)+".remote.json.gz")
		st, err := os.Stat(file)
		if err != nil || st.Size() > fastRemoteMaxJSON {
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		var set pbr.RemoteSet
		zr, err := gzip.NewReader(f)
		if err == nil {
			err = json.NewDecoder(io.LimitReader(zr, fastRemoteMaxJSON)).Decode(&set)
		}
		f.Close()
		if err != nil || set.Source != rl.Source {
			continue
		}
		if s.fastDNS.remote == nil {
			s.fastDNS.remote = map[string]fastRemoteEntry{}
			s.fastDNS.inflight = map[string]bool{}
		}
		s.fastDNS.remote[rl.ID] = fastRemoteEntry{set: set, fetched: st.ModTime()}
		s.fastDNS.remoteGen++
	}
}

// fastRemoteFormat mirrors the generator's ruleSetFormat: explicit Format, else .json is source.
func fastRemoteFormat(rl model.RoutingList) string {
	if rl.Format == "binary" || rl.Format == "source" {
		return rl.Format
	}
	u := rl.Source
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if strings.HasSuffix(strings.ToLower(u), ".json") {
		return "source"
	}
	return "binary"
}

func safeFileName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// parseRuleSetSource reads a sing-box rule-set source (`{"version": N, "rules": [...]}`): the domain,
// domain_suffix and ip_cidr of its default rules. Every other matcher (domain_keyword, domain_regex,
// a port, a process, a logical or inverted rule) is named in Unrepresentable.
func parseRuleSetSource(src []byte) (pbr.RemoteSet, error) {
	var doc struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(src, &doc); err != nil {
		return pbr.RemoteSet{}, fmt.Errorf("rule-set source: %w", err)
	}
	var set pbr.RemoteSet
	bad := map[string]bool{}
	for _, r := range doc.Rules {
		if t := jsonString(r["type"]); t != "" && t != "default" {
			bad[t+" rule"] = true
			continue
		}
		if inv := strings.TrimSpace(string(r["invert"])); inv == "true" {
			bad["invert"] = true
			continue
		}
		ok := true
		for k := range r {
			switch k {
			case "type", "invert", "domain", "domain_suffix", "ip_cidr":
			default:
				bad[k] = true
				ok = false
			}
		}
		if !ok {
			continue
		}
		for _, d := range append(jsonStrings(r["domain"]), jsonStrings(r["domain_suffix"])...) {
			if d = strings.TrimPrefix(strings.TrimSpace(d), "."); d != "" {
				set.Domains = append(set.Domains, d)
			}
		}
		set.CIDRs = append(set.CIDRs, jsonStrings(r["ip_cidr"])...)
	}
	if len(set.CIDRs) > fastRemoteMaxCIDRs {
		bad[fmt.Sprintf("more than %d prefixes", fastRemoteMaxCIDRs)] = true
	}
	if len(set.Domains) > cidrfeed.MaxDomains {
		bad[fmt.Sprintf("more than %d names", cidrfeed.MaxDomains)] = true
	}
	for k := range bad {
		set.Unrepresentable = append(set.Unrepresentable, k)
	}
	sort.Strings(set.Unrepresentable)
	sort.Strings(set.Domains)
	sort.Strings(set.CIDRs)
	return set, nil
}

func jsonString(raw json.RawMessage) string {
	var s string
	if len(raw) > 0 && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// jsonStrings reads a rule field that is a string or a list of strings.
func jsonStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	if s := jsonString(raw); s != "" {
		return []string{s}
	}
	return nil
}

// --- dnsmasq ---------------------------------------------------------------------------------

// fastDNSConfDirs finds dnsmasq's conf-dirs from its running configurations, or the first instance's
// default when none states one and it exists.
func fastDNSConfDirs() []string {
	files := map[string]string{}
	paths, _ := filepath.Glob(fastDNSConfGlob)
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			files[p] = string(b)
		}
	}
	if dirs := pbr.DnsmasqConfDirs(files); len(dirs) > 0 {
		return dirs
	}
	if st, err := os.Stat(fastDNSDefaultConfDir); err == nil && st.IsDir() {
		return []string{fastDNSDefaultConfDir}
	}
	return nil
}

// planRemote is the remote lists' content a plan's zones are filled from: per
// list, the RAM copy when it is of the source the plan was reviewed with and still expressible
// (no matcher nothing can express at a list that is not direct; together, Review's name checks);
// otherwise the content the installed plane already uses (live), so an unapplied source edit or a
// refresh Review would have refused never reaches the kernel or dnsmasq. Why a copy was passed over
// is kept for Diagnostics. key identifies the chosen content (what was loaded is compared with it).
func (s *Server) planRemote(plan *pbr.Plan) (names map[string][]string, sets map[string]pbr.RemoteSet, key string) {
	names, sets = map[string][]string{}, map[string]pbr.RemoteSet{}
	if plan == nil {
		return names, sets, ""
	}
	srcs, direct, routedRemote := plan.RemoteSources(), plan.RemoteDirect(), plan.RemoteRoutedLists()
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	if s.fastDNS.rejected == nil {
		s.fastDNS.rejected = map[string]string{}
	}
	ids := plan.RemoteLists()
	live := map[string]pbr.RemoteSet{}  // the content in force, of the reviewed source
	fresh := map[string]pbr.RemoteSet{} // the RAM copy, where it is of the reviewed source and differs
	for _, id := range ids {
		src := srcs[id]
		of := func(set pbr.RemoteSet) bool { return src == "" || set.Source == src }
		if l, ok := s.fastDNS.live[id]; ok && of(l) {
			live[id] = l
		}
		e, ok := s.fastDNS.remote[id]
		if !ok || e.fetched.IsZero() || !of(e.set) {
			continue
		}
		if len(e.set.Unrepresentable) > 0 && !direct[id] {
			s.fastDNS.rejected[id] = "its refreshed content holds " + strings.Join(e.set.Unrepresentable, ", ") + ", which fast mode cannot express"
			continue
		}
		// A list routed by a table was routed so because it held no private space (pbr routeLarge);
		// a refresh that brings some would be sent main by the private excludes.
		if routedRemote[id] && pbr.TouchesPrivate(e.set.CIDRs) {
			s.fastDNS.rejected[id] = "its refreshed content names private networks, which a list routed by a table cannot carry; Apply to move it back into nft"
			continue
		}
		delete(s.fastDNS.rejected, id)
		fresh[id] = e.set
	}
	choose := func(useFresh bool) {
		for _, id := range ids {
			if set, ok := fresh[id]; ok && (useFresh || !hasLive(live, id)) {
				sets[id] = set
			} else if set, ok := live[id]; ok {
				sets[id] = set
			} else {
				delete(sets, id)
			}
		}
		for id := range names {
			delete(names, id)
		}
		for id, set := range sets {
			names[id] = set.Domains
		}
	}
	// The refreshed copies are judged together, by Review's own checks over the installed plan:
	// the snippet's whole name count, and no name in more zones than one dnsmasq line can name
	// (a dropped core-list name would be pinned past the core). Refused, the content in force stays.
	choose(true)
	why := ""
	switch {
	case plan.FastNameCount(names) > fastNamesMax:
		why = fmt.Sprintf("its refreshed content takes the names in fast mode past %d", fastNamesMax)
	case len(plan.OverfullFastNames(names)) > 0:
		why = "its refreshed content puts names into more lists than one dnsmasq line can name"
	}
	if why != "" {
		for id := range fresh {
			if hasLive(live, id) && !sameRemoteSet(fresh[id], live[id]) {
				s.fastDNS.rejected[id] = why
			}
		}
		choose(false)
	}
	h := sha256.New()
	for _, id := range ids {
		if set, ok := sets[id]; ok {
			fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x01", id, set.Source, remoteNamesKey(set), strings.Join(set.CIDRs, ","))
		}
	}
	return names, sets, fmt.Sprintf("%x", h.Sum(nil))
}

// hasLive reports content in force for list id.
func hasLive(live map[string]pbr.RemoteSet, id string) bool {
	_, ok := live[id]
	return ok
}

// remoteNamesKey identifies a remote list's names.
func remoteNamesKey(set pbr.RemoteSet) string {
	sum := sha256.Sum256([]byte(strings.Join(set.Domains, "\n")))
	return fmt.Sprintf("%x", sum[:8])
}

// markRemoteLive records the content the installed plane was filled from.
func (s *Server) markRemoteLive(sets map[string]pbr.RemoteSet) {
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	if s.fastDNS.live == nil {
		s.fastDNS.live = map[string]pbr.RemoteSet{}
	}
	for id, set := range sets {
		s.fastDNS.live[id] = set
	}
}

// remoteNames is the RAM copy's names by list id, and the generation they are of.
func (s *Server) remoteNames() (names map[string][]string, sets map[string]pbr.RemoteSet, gen int) {
	names, sets = map[string][]string{}, map[string]pbr.RemoteSet{}
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	for id, e := range s.fastDNS.remote {
		if e.fetched.IsZero() {
			continue
		}
		names[id] = e.set.Domains
		sets[id] = e.set
	}
	return names, sets, s.fastDNS.remoteGen
}

// syncFastDNS makes dnsmasq's snippet the one plan needs (nil or a plan without names: none), and
// restarts dnsmasq only when a file changed. Called after the kernel plane is installed (its sets
// must exist before dnsmasq adds to them), after it is torn down or retired, and when the remote
// lists' RAM copy changed; a rollback reinstalls the baseline's plane and so its snippet.
//
// Every way the names would silently not fill the sets fails the step: a
// dnsmasq without nftset, no conf-dir found, a snippet that could not be written, and a resolver on
// 127.0.0.1:53 that does not answer the snippet's canary after the restart (another resolver in
// front, or a dnsmasq that refused the snippet: keen-pbr #142). In the last case the snippet is taken
// out and dnsmasq restarted again first, so the LAN keeps its DNS.
func (s *Server) syncFastDNS(ctx context.Context, plan *pbr.Plan) error {
	return s.syncFastDNSMode(ctx, plan, false)
}

// syncFastDNSMode is syncFastDNS; keep is the live reload's mode: a snippet that
// fails is replaced by the last one that worked rather than by none, and the content generation is not
// marked loaded, so the loop tries again with backoff.
func (s *Server) syncFastDNSMode(ctx context.Context, plan *pbr.Plan, keep bool) error {
	if s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return nil
	}
	names, _, key := s.planRemote(plan)
	content := plan.RenderFastDnsmasq(names)
	overfull := plan.OverfullFastNames(names)
	s.fastDNS.mu.Lock()
	s.fastDNS.overfull = overfull
	s.fastDNS.mu.Unlock()
	if len(overfull) > 0 {
		log.Printf("fast path: %d name(s) left out of the dnsmasq snippet, in more lists than one line can name: %s",
			len(overfull), strings.Join(shortList(overfull, 5), ", "))
	}
	dirs := fastDNSConfDirs()
	s.fastDNS.mu.Lock()
	prevDirs, prevContent := s.fastDNS.dirs, s.fastDNS.snippet
	s.fastDNS.mu.Unlock()
	advance := true
	record := func(content string, errs []string, restarted time.Time) {
		s.fastDNS.mu.Lock()
		s.fastDNS.snippet, s.fastDNS.dirs, s.fastDNS.err = content, dirs, strings.Join(errs, "; ")
		if !restarted.IsZero() {
			s.fastDNS.restarted = restarted
		}
		if advance {
			s.fastDNS.loadedKey = key
		}
		s.fastDNS.mu.Unlock()
		if len(errs) > 0 {
			log.Printf("fast path: dnsmasq snippet: %s", strings.Join(errs, "; "))
		}
	}
	if content != "" {
		var why string
		switch {
		case s.dnsmasqNftset(ctx) < 0:
			why = "the router's dnsmasq is built without nftset (install dnsmasq-full)"
		case len(dirs) == 0:
			why = "dnsmasq's conf-dir was not found (no conf-dir= in " + fastDNSConfGlob + " and no " + fastDNSDefaultConfDir + ")"
		}
		if why != "" {
			// Ours goes from wherever it was: it fills nothing here.
			writeFastSnippet("", nil, prevDirs)
			record("", []string{why}, time.Time{})
			return fmt.Errorf("fast path: the lists' names cannot reach the kernel: %s", why)
		}
	}
	// fallback is what goes back when the new snippet fails: the last working one in keep mode, none
	// otherwise (an Apply then fails and rolls back to its baseline, which writes its own).
	fallback := ""
	if keep {
		fallback = prevContent
		advance = false
	}
	// The LAN's DNS as it is now: if it resolves a real name before, it has to after the restart too
	// (live 22.11: the canary answered from dnsmasq itself while forwarding had died).
	upBefore := content != "" && content != prevContent && fastDNSUpstream(ctx) == nil
	changed, errs := writeFastSnippet(content, dirs, prevDirs)
	if content != "" && len(errs) > 0 {
		writeFastSnippet(fallback, dirs, prevDirs)
		_ = fastDNSRestartVerified(ctx, fallback != "", false)
		record(fallback, errs, time.Time{})
		return fmt.Errorf("fast path: the dnsmasq snippet could not be written: %s", strings.Join(errs, "; "))
	}
	if keep {
		advance = true // set back below on a failure
	}
	if !changed {
		record(content, errs, time.Time{})
		return nil
	}
	lines := strings.Count(content, "\n")
	if lines > 0 {
		lines-- // the header
	}
	if err := fastDNSRestartVerified(ctx, content != "", upBefore); err != nil {
		if content == "" {
			record(content, append(errs, "dnsmasq restart: "+err.Error()), time.Time{})
			return nil
		}
		// Take ours out (or put the last working one back) and bring dnsmasq back with it.
		writeFastSnippet(fallback, dirs, prevDirs)
		what := "the snippet was removed"
		if fallback != "" {
			what = "the previous snippet was put back"
		}
		failed := fmt.Errorf("dnsmasq did not answer as itself with the fast path snippet (%d lines): %v; %s", lines, err, what)
		if back := fastDNSRestartVerified(ctx, fallback != "", false); back != nil {
			failed = fmt.Errorf("%v, and dnsmasq still does not answer with it: %v", failed, back)
		}
		if keep {
			advance = false
		}
		record(fallback, append(errs, failed.Error()), time.Time{})
		return failed
	}
	log.Printf("fast path: dnsmasq restarted: its nftset snippet changed (%d lines in %s)", lines, strings.Join(dirs, ", "))
	record(content, errs, time.Now())
	if content != "" && !keep {
		// A live reload runs it itself, after any flush of the sets.
		wctx := s.bgContext()
		s.goBackground(func() { s.fastDNSWarmUp(wctx, plan) })
	}
	return nil
}

// writeFastSnippet writes content into each of dirs (removing it where content is empty) and removes
// it from a directory written before that is no longer read. changed says a file moved.
func writeFastSnippet(content string, dirs, prevDirs []string) (changed bool, errs []string) {
	all := sortedUniqueStrings(append(append([]string(nil), dirs...), prevDirs...))
	put := func(file, want string) {
		old, readErr := os.ReadFile(file)
		switch {
		case want == "" && readErr == nil:
			if err := os.Remove(file); err != nil {
				errs = append(errs, err.Error())
				return
			}
			changed = true
		case want != "" && string(old) != want:
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				errs = append(errs, err.Error())
				return
			}
			if err := os.WriteFile(file, []byte(want), 0o644); err != nil {
				errs = append(errs, err.Error())
				return
			}
			changed = true
		}
	}
	ramWanted := ""
	for _, dir := range all {
		want := content
		if !containsString(dirs, dir) {
			want = ""
		}
		if fastDNSIsRAM(dir) {
			put(filepath.Join(dir, fastDNSSnippetName), want)
			continue
		}
		// A conf-dir on flash (OpenWrt 25.12 with confdir '/etc/dnsmasq.d'): the
		// snippet changes with every list, so it goes to RAM, and the flash dir gets a pointer to it
		// that never changes: written once, removed when the plane goes. The RAM dir is dnsmasq's own
		// run dir, which its init creates before every start and mounts into its ujail read-write, so
		// the pointer never names a missing directory and the jail sees the file (verified by the
		// canary after the restart: a jail that does not see it fails the step).
		pointer := ""
		if want != "" {
			pointer = "# WayHop fast path: the snippet lives in RAM (generated; removed with the plane)\nconf-dir=" +
				fastDNSRAMDir + ",*" + fastDNSRAMExt + "\n"
			ramWanted = want
		}
		put(filepath.Join(dir, fastDNSSnippetName), pointer)
	}
	if ramWanted != "" || content == "" {
		put(filepath.Join(fastDNSRAMDir, fastDNSRAMFile), ramWanted)
	}
	return changed, errs
}

// fastDNSIsRAM reports a conf-dir on tmpfs (/tmp, /var, which OpenWrt links to /tmp).
var fastDNSIsRAM = func(dir string) bool {
	return strings.HasPrefix(dir, "/tmp/") || strings.HasPrefix(dir, "/var/") || dir == "/tmp"
}

// fastDNSRestartVerified restarts dnsmasq and waits up to ten seconds for it to run and answer;
// canary asks that the answer is the snippet's own (the resolver on :53 is this dnsmasq with it), and
// upstream that it also resolves a real external name through its upstreams.
func fastDNSRestartVerified(ctx context.Context, canary, upstream bool) error {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := fastDNSRestart(rctx); err != nil {
		return err
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = fastDNSAlive(rctx, canary); err == nil && upstream {
			err = fastDNSUpstream(rctx)
		}
		if err == nil {
			return nil
		}
		select {
		case <-rctx.Done():
			return err
		case <-time.After(time.Second):
		}
	}
	return err
}

// dnsmasqNftset reports whether dnsmasq can fill nft sets (dnsmasq-full), cached for ten minutes:
// 1 yes, -1 no, 0 not known (the probe failed to run).
func (s *Server) dnsmasqNftset(ctx context.Context) int {
	s.fastDNS.mu.Lock()
	if s.fastDNS.nftset != 0 && time.Since(s.fastDNS.nftsetAt) < 10*time.Minute {
		v := s.fastDNS.nftset
		s.fastDNS.mu.Unlock()
		return v
	}
	s.fastDNS.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	out, err := fastDNSVersion(pctx)
	cancel()
	v := -1
	switch {
	case pbr.DnsmasqHasNftset(out):
		v = 1
	case err != nil && !strings.Contains(out, "Compile time options"):
		v = 0
	}
	s.fastDNS.mu.Lock()
	s.fastDNS.nftset, s.fastDNS.nftsetAt = v, time.Now()
	s.fastDNS.mu.Unlock()
	return v
}

// --- the dynamic sets across an Apply and a restart ------------------------------------------

// listDlistSets reads the named sets of table in one `nft -f -` run (one process, not one per
// set, and a bound of its own rather than the exact runner's 1 MiB). An error
// when any set is missing (nft refuses the whole run): the caller then knows the table is not whole.
// carryCandidates are the sets of the new plan worth reading from the live table: the ones the
// installed plan has too (a set the live table lacks fails the whole `nft -f` listing, and every
// other set's addresses would be lost with it). No installed plan known: all of them.
func carryCandidates(names []string, prev *pbr.Plan) []string {
	if prev == nil {
		return names
	}
	had := map[string]bool{}
	for _, n := range prev.DlistSets() {
		had[n] = true
	}
	var out []string
	for _, n := range names {
		if had[n] {
			out = append(out, n)
		}
	}
	return out
}

// listDlistSetsTolerant reads the sets in one run, and when that run fails (one of them is missing),
// each set on its own, keeping what could be read. The error is returned only when nothing was.
func listDlistSetsTolerant(ctx context.Context, nftPath, table string, names []string) (map[string][]pbr.DlistElement, error) {
	all, err := listDlistSets(ctx, nftPath, table, names)
	if err == nil || len(names) < 2 {
		return all, err
	}
	out := map[string][]pbr.DlistElement{}
	for _, n := range names {
		one, oneErr := listDlistSets(ctx, nftPath, table, []string{n})
		if oneErr != nil {
			continue
		}
		for k, v := range one {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, err
	}
	return out, nil
}

var listDlistSets = func(ctx context.Context, nftPath, table string, names []string) (map[string][]pbr.DlistElement, error) {
	if len(names) == 0 {
		return map[string][]pbr.DlistElement{}, nil
	}
	if nftPath == "" {
		nftPath = "nft"
	}
	var prog strings.Builder
	for _, n := range names {
		fmt.Fprintf(&prog, "list set inet %s %s\n", table, n)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(prog.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, fastListMaxBytes+1))
	waitErr := cmd.Wait()
	switch {
	case readErr != nil:
		return nil, readErr
	case len(out) > fastListMaxBytes:
		return nil, fmt.Errorf("the sets' listing is larger than %d MiB", fastListMaxBytes>>20)
	case waitErr != nil:
		return nil, waitErr
	}
	return pbr.ParseNftSetListings(string(out)), nil
}

// fastInstallProgram is what the kernel adapter loads in the same transaction as the plan's table:
// the resolver-fed addresses carried from the live sets (only into zones whose names did not change
// since prev; from the copy saved at the last stop where the live table is gone), and the remote
// lists' prefixes from the RAM copy. It records the carried addresses as the fresh-address baseline.
func (s *Server) fastInstallProgram(ctx context.Context, nftPath string, plan *pbr.Plan, prev *pbr.Plan) string {
	if plan == nil {
		return ""
	}
	sets := map[string][]pbr.DlistElement{}
	if names := plan.DlistSets(); len(names) > 0 {
		allowed := plan.CarrySets(prev)
		live, err := listDlistSetsTolerant(ctx, nftPath, plan.DNSTable(), carryCandidates(names, prev))
		if err != nil {
			live = readDlistCache(time.Now())
		}
		seed := map[netip.Addr]bool{}
		for name, elems := range live {
			if !allowed[name] {
				continue
			}
			sets[name] = elems
			for _, e := range elems {
				if a, err := netip.ParseAddr(e.Addr); err == nil {
					seed[a] = true
				}
			}
		}
		s.fastDNS.mu.Lock()
		s.fastDNS.seed, s.fastDNS.seedKey = seed, strings.Join(names, ",")
		s.fastDNS.mu.Unlock()
	}
	return plan.RenderDlistCarry(sets)
}

// fastMustLoad is the program the kernel adapter loads after the table and must succeed: the
// remote lists' prefixes from the RAM copy, and the core pin's devices, set only
// when every remote list the plan carries is loaded (until then nothing is pinned and the core carries
// the lists by name). It records what it loaded for FastDNSLoop.
func (s *Server) fastMustLoad(_ context.Context, plan *pbr.Plan) string {
	if plan == nil {
		return ""
	}
	_, remote, key := s.planRemote(plan)
	ready := remoteReady(plan, remote)
	s.fastDNS.mu.Lock()
	s.fastDNS.elemKey, s.fastDNS.pinReady = key, ready
	s.fastDNS.mu.Unlock()
	s.markRemoteLive(remote)
	return plan.RenderRemoteElements(remote) + plan.RenderPinElements(ready)
}

// missingRemote names the plan's remote lists without content, each with its last fetch error.
func missingRemote(plan *pbr.Plan, s *Server) []string {
	var out []string
	_, sets, _ := s.planRemote(plan)
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	for _, id := range plan.RemoteLists() {
		if _, ok := sets[id]; ok {
			continue
		}
		e := s.fastDNS.remote[id]
		if e.err != "" {
			out = append(out, id+" ("+e.err+")")
		} else {
			out = append(out, id)
		}
	}
	return out
}

// remoteReady reports whether every remote list the plan carries has content in the RAM copy.
func remoteReady(plan *pbr.Plan, remote map[string]pbr.RemoteSet) bool {
	for _, id := range plan.RemoteLists() {
		if _, ok := remote[id]; !ok {
			return false
		}
	}
	return true
}

// readDlistCache reads the copy written at the last daemon stop, each timeout less the time since.
func readDlistCache(now time.Time) map[string][]pbr.DlistElement {
	b, err := os.ReadFile(filepath.Join(fastDNSRunDir, fastDNSCarryFile))
	if err != nil {
		return map[string][]pbr.DlistElement{}
	}
	text := string(b)
	elapsed := 0
	if first, _, ok := strings.Cut(text, "\n"); ok {
		if v, ok := strings.CutPrefix(first, "# written "); ok {
			if at, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && now.Unix() > at {
				elapsed = int(now.Unix() - at)
			}
		}
	}
	out := map[string][]pbr.DlistElement{}
	for set, elems := range pbr.ParseDlistCarry(text) {
		for _, e := range elems {
			if e.Left > 0 {
				if e.Left -= elapsed; e.Left <= 0 {
					continue
				}
			}
			out[set] = append(out[set], e)
		}
	}
	return out
}

// SaveFastDNSCache keeps the installed plan's dlist elements in RAM over a daemon restart: the next
// Apply puts them back if the table is gone by then. Called on daemon stop.
func (s *Server) SaveFastDNSCache(ctx context.Context) {
	if s == nil || s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return
	}
	plan := s.installedKernelPlan()
	if plan == nil || len(plan.DlistSets()) == 0 {
		return
	}
	sets, err := listDlistSets(ctx, "", plan.DNSTable(), plan.DlistSets())
	if err != nil {
		return
	}
	program := plan.RenderDlistCarry(sets)
	if program == "" {
		return
	}
	if err := os.MkdirAll(fastDNSRunDir, 0o700); err != nil {
		return
	}
	text := "# written " + strconv.FormatInt(time.Now().Unix(), 10) + "\n" + program
	if err := os.WriteFile(filepath.Join(fastDNSRunDir, fastDNSCarryFile), []byte(text), 0o600); err != nil {
		log.Printf("fast path: the dlist sets were not saved for the restart: %v", err)
	}
}

// --- Review ----------------------------------------------------------------------------------

// fastReviewFacts is what the fast DNS review reads besides the plan and the profile.
type fastReviewFacts struct {
	// nftset: 1 dnsmasq has nftset, -1 it does not, 0 not known.
	nftset int
	// remoteErr is the last fetch error of each remote list whose content is missing.
	remoteErr map[string]string
	// remoteNames is the RAM copy's names by list id (the name cap counts them).
	remoteNames map[string][]string
	// remoteCIDRs is how many prefixes each remote list holds (the large-list notes).
	remoteCIDRs map[string]int
	// resolver is why the router's dnsmasq cannot be the LAN resolver the snippet needs ("" = it can):
	// no conf-dir, not running, or moved off port 53.
	resolver string
}

const fastDNSHybridRemedy = "Switch routing mode to hybrid, where the core matches it, or remove "

// fastDNSFindings is the fast DNS plane's review: what refuses the Apply (a list the plane cannot
// express, content not loaded, a kill switch, a resolver that cannot fill the sets, unknown LAN
// devices beside a core pin, too many names) and what Review should say about it (a widened name,
// DNS enforcement off, the caveats).
func fastDNSFindings(cfg config.Config, prof *model.Profile, plan *pbr.Plan, facts fastReviewFacts) []PlanFinding {
	if prof == nil || plan == nil || !plan.FastDNS {
		return nil
	}
	var out []PlanFinding
	block := func(id, item, detail, remedy string, reason platform.ReasonCode) {
		out = append(out, PlanFinding{ID: id, Setting: "routing mode fast", Item: item,
			Requested: "matched in fast mode", Effective: "cannot be matched without the core's TUN",
			Severity: platform.SeverityBlocked, Reason: reason, Blocks: platform.BlocksApply, Detail: detail, Remedy: remedy})
	}
	note := func(id, item, detail, remedy string) {
		out = append(out, PlanFinding{ID: id, Setting: "routing mode fast", Item: item,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
			Detail: detail, Remedy: remedy})
	}
	// Unknown LAN devices beside core-only lists: nothing is pinned past the TUN, and nothing says
	// which sources the pin may skip. Refused rather than run as hybrid with a
	// promise of fast mode.
	if plan.CorePin && len(plan.LANIfaces) == 0 {
		block("fast_path.lan_unknown", "core pin",
			"Lists sent to a proxy keep the core's TUN in fast mode, and only the LAN's devices are pinned past it. The LAN's "+
				"devices are not known (the firewall's zones could not be read), so every LAN flow would go through the core.",
			"Check that `uci show firewall` works on the router and names the LAN zone, or switch routing mode to hybrid.",
			platform.ReasonInterfaceMissing)
	}
	names := len(plan.DlistSets()) > 0
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled || rl.Source == "" || rl.Outbound == model.OutboundDirect {
			continue
		}
		names = true
		label := listName(&rl)
		if why, ok := facts.remoteErr[rl.ID]; ok {
			detail := fmt.Sprintf("The list %q is a remote rule-set. In fast mode the kernel needs its names and prefixes as text, "+
				"which the daemon fetches and decompiles; it has not loaded them yet", label)
			if why != "" {
				detail += ": " + why
			}
			block("fast_path.remote_not_loaded."+rl.ID, label, detail+".",
				"Wait for the download (Review again in a minute), check the list's download path, or "+strings.ToLower(fastDNSHybridRemedy[:1])+fastDNSHybridRemedy[1:]+"the list.",
				platform.ReasonFeatureWouldBeDropped)
		}
	}
	for _, w := range planUnrepresentable(prof, plan) {
		block("fast_path.unrepresentable."+w.Scope, w.Scope, w.Msg, fastDNSHybridRemedy+"the "+w.what+".", platform.ReasonModeConflict)
	}
	for _, r := range prof.Rules {
		if !r.Disabled && !r.Default && len(r.GeoSite) == 0 && len(r.Domain)+len(r.DomainSuffix) > 0 {
			names = true
			if len(r.Domain) > 0 {
				note("fast_path.domain_widened."+r.ID, r.ID,
					fmt.Sprintf("The rule %q matches exact names (%s). dnsmasq matches a name and every name under it, so in fast mode "+
						"the rule also takes their subdomains.", r.ID, strings.Join(r.Domain, ", ")),
					"Nothing to do if the subdomains may go the same way; otherwise use hybrid mode for this rule.")
			}
		}
	}
	if !names {
		return out
	}
	if n := plan.FastNameCount(facts.remoteNames); n > fastNamesMax {
		block("fast_path.names_cap", "names in fast mode",
			fmt.Sprintf("The lists carry %d names in fast mode; at most %d fit dnsmasq's configuration and the router's memory.", n, fastNamesMax),
			"Use smaller lists, or switch routing mode to hybrid.", platform.ReasonFeatureWouldBeDropped)
	}
	if over := plan.OverfullFastNames(facts.remoteNames); len(over) > 0 {
		shown := shortList(over, 5)
		block("fast_path.names_overfull", "names in fast mode",
			fmt.Sprintf("%d name(s) belong to more lists and rules than one dnsmasq line can name (%s). dnsmasq fills the sets of "+
				"one line per name, so some of those lists would never get the name's addresses.", len(over), strings.Join(shown, ", ")),
			"Keep each name in fewer lists (merge device-scoped copies of a list), or switch routing mode to hybrid.",
			platform.ReasonFeatureWouldBeDropped)
	}
	for zone, bad := range plan.InvalidFastNames(facts.remoteNames) {
		shown := bad
		if len(shown) > 5 {
			shown = append(append([]string(nil), shown[:5]...), fmt.Sprintf("and %d more", len(bad)-5))
		}
		note("fast_path.invalid_names."+zone, zone,
			fmt.Sprintf("%d name(s) of %s are not names dnsmasq can take (longer than 253 characters, a label over 63, "+
				"or characters a host name cannot have) and are left out of its snippet: %s.", len(bad), zone, strings.Join(shown, ", ")),
			"Correct or remove those entries.")
	}
	// Names without a dot are not in the resolver's sets; say so rather than drop them.
	var single []string
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled {
			continue
		}
		raw := append(append([]string(nil), rl.Manual...), rl.DomainCache...)
		raw = append(raw, facts.remoteNames[rl.ID]...)
		for _, d := range pbr.SingleLabelNames(raw) {
			if net.ParseIP(d) == nil {
				single = append(single, listName(&rl)+": "+d)
			}
		}
	}
	for _, r := range prof.Rules {
		if r.Disabled || r.Default {
			continue
		}
		for _, d := range pbr.SingleLabelNames(append(append([]string(nil), r.Domain...), r.DomainSuffix...)) {
			single = append(single, r.ID+": "+d)
		}
	}
	if len(single) > 0 {
		note("fast_path.single_label", "names in fast mode",
			fmt.Sprintf("%d name(s) have no dot (%s). The router's resolver does not send such names upstream, so in fast mode "+
				"they fill no set and are not routed by these lists.", len(single), strings.Join(shortList(single, 5), ", ")),
			"Write the full name (host.example.lan), or use hybrid mode where the core matches it.")
	}
	var refused, scopedV4 []string
	for _, z := range plan.Zones {
		switch {
		case z.V6Refused():
			refused = append(refused, z.Name)
		case z.DNSNoV6 && len(plan.FastNames(facts.remoteNames)[z.Name]) > 0:
			scopedV4 = append(scopedV4, z.Name)
		}
	}
	if len(refused) > 0 || len(scopedV4) > 0 {
		detail := "Lists sent to a tunnel that carries only IPv4 (" + strings.Join(append(append([]string(nil), refused...), scopedV4...), ", ") +
			") cannot take the IPv6 addresses of their names."
		if len(refused) > 0 {
			detail += " IPv6 to those addresses is refused (a TCP reset, or ICMPv6 administratively prohibited) unless another " +
				"list routes it, so a device falls back to the IPv4 address, which the tunnel carries."
		}
		if len(scopedV4) > 0 {
			detail += " Lists scoped to devices (" + strings.Join(scopedV4, ", ") + ") cannot be told apart for IPv6, so their " +
				"names' IPv6 addresses leave by the provider, as in hybrid mode."
		}
		note("fast_path.v4only_names", "names in fast mode", detail,
			"Give the tunnel an IPv6 address if it can carry IPv6, or turn IPv6 off for the devices that must use it.")
	}
	// Large lists (pbr routed.go, live 22.11): routed by tables of their own, or kept in nft with what
	// that costs the resolver.
	if len(plan.DlistSets()) > 0 {
		var routed []string
		for _, r := range plan.RoutedZones(pbr.Options{}) {
			routed = append(routed, r.Zone.Name)
		}
		if len(routed) > 0 {
			n := 0
			for _, r := range plan.RoutedZones(pbr.Options{}) {
				n += len(r.Zone.RouteV4) + len(r.Zone.RouteV6) + facts.remoteCIDRs[r.Zone.RemoteList]
			}
			note("fast_path.routed", "large lists",
				fmt.Sprintf("%d large list(s) (%s, %d prefixes) are routed by kernel routing tables instead of nft sets, so the "+
					"resolver's set updates stay cheap. They rank below every other list (a smaller list, a name list or a direct "+
					"list holding the same address wins), and take about %d KB of kernel memory (about 120 bytes per route).",
					len(routed), strings.Join(routed, ", "), n, n*120/1024), "")
		}
		var kept []string
		for _, z := range append(append([]pbr.Zone(nil), plan.Zones...), plan.CoreZones...) {
			if !z.Routed && len(z.V4)+len(z.V6)+facts.remoteCIDRs[z.RemoteList] > pbr.RoutedPrefixMin {
				kept = append(kept, z.Name)
			}
		}
		if len(kept) > 0 {
			note("fast_path.large_nft", "large lists",
				fmt.Sprintf("Large list(s) %s stay in nft sets (block lists, lists naming private networks, device-scoped, at a group or fastest list, "+
					"sent to a proxy, static lists beside the core's TUN, or "+
					"the LAN's devices are not known). dnsmasq rebuilds its view of the whole ruleset for every address it "+
					"adds, so each listed name's first answer can take a second or more on this router (measured: 0.27 s per "+
					"add with one 10 000-prefix set, twice that with two).", strings.Join(kept, ", ")),
				"Send the list to a single tunnel without a device scope, make it smaller, or use hybrid mode.")
		}
	}
	if plan.CorePin && !plan.GuardNames && len(plan.CoreZones) > 0 {
		note("fast_path.core_v6", "names in fast mode",
			"The core's TUN carries no IPv6 here, so IPv6 to the lists sent to a proxy is refused (a TCP reset, or ICMPv6 "+
				"administratively prohibited) and a device falls back to their IPv4 addresses, which the core carries. In hybrid "+
				"mode that IPv6 leaves by the provider.", "")
	}
	if killSwitchAny(prof) {
		block("fast_path.kill_switch", "kill switch",
			"A kill switch is on, and this configuration has lists or rules that match names. In fast mode the names are "+
				"carried by the resolver's sets, which the kill switch guard does not hold.",
			"Kill switch with domain lists needs routing mode hybrid: switch to hybrid, or turn the kill switch off.",
			platform.ReasonModeConflict)
	}
	if facts.nftset < 0 {
		block("fast_path.dnsmasq_nftset", "dnsmasq",
			"The router's dnsmasq is built without nftset, so it cannot put the lists' names into the kernel's sets.",
			"Install dnsmasq-full in place of dnsmasq: on OpenWrt 25.12 `apk del dnsmasq && apk add dnsmasq-full`, on 24.10 "+
				"`opkg remove dnsmasq && opkg install dnsmasq-full`. Or switch routing mode to hybrid.",
			platform.ReasonBinaryLacksFeature)
	}
	if facts.resolver != "" {
		block("fast_path.resolver", "dnsmasq",
			"In fast mode the router's dnsmasq has to be the resolver the LAN asks on port 53, with its conf-dir, for the "+
				"lists' names to fill the kernel's sets: "+facts.resolver+".",
			"Run dnsmasq as the LAN resolver on port 53 (another resolver can forward to it), or switch routing mode to hybrid.",
			platform.ReasonMissingService)
	}
	if !cfg.FastDNSEnforceOn() {
		note("fast_path.dns_enforce_off", "fast_dns_enforce",
			"DNS enforcement is off: a device that resolves through another server (its own DNS, DNS over TLS) never fills the "+
				"lists' sets, and its traffic to the listed names goes the default way.",
			"Set fast_dns_enforce back to true (the default), unless every device uses the router's DNS.")
	} else if len(plan.LANIfaces) == 0 {
		note("fast_path.dns_enforce_unknown_lan", "DNS enforcement", "The LAN's devices are not known (the firewall's zones could not be read), so "+
			"the DNS redirect is not installed.", "Check that `uci show firewall` works on the router.")
	}
	note("fast_path.caveats", "names in fast mode",
		"Names are routed by the addresses dnsmasq answers with. Every other site on a listed name's address (a shared CDN) "+
			"goes the same way; after a router reboot a device with a cached answer reaches a listed site directly until it "+
			"asks again; names an app resolves over DNS over HTTPS are not seen (the resolver's use-application-dns.net and "+
			"iCloud Private Relay blocks are the answer to that).", "")
	return out
}

// shortList is the first n of list, with "and K more" when it is longer.
func shortList(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string(nil), list[:n]...), fmt.Sprintf("and %d more", len(list)-n))
}

// fastUnrep is one list or rule the fast DNS plane cannot express.
type fastUnrep struct {
	Scope, Msg, what string
}

// planUnrepresentable lists the rules the fast DNS plane cannot express (spec: "not representable"):
// geosite at an outbound that is not direct, and a destination port at a tunnel or block outbound
// (the kernel cannot match ports, and a pinned flow never reaches the core that
// could). A rule at a core-only outbound is the core's and keeps its port.
func planUnrepresentable(prof *model.Profile, plan *pbr.Plan) []fastUnrep {
	core := map[string]bool{}
	if plan != nil {
		for _, z := range plan.CoreZones {
			core[z.EgressTag] = true
		}
	}
	var out []fastUnrep
	for _, r := range prof.Rules {
		if r.Disabled || r.Default || r.Outbound == model.OutboundDirect {
			continue
		}
		switch {
		case len(r.GeoSite) > 0:
			out = append(out, fastUnrep{Scope: r.ID, what: "geosite matcher",
				Msg: fmt.Sprintf("The rule %q matches geosite %s, which neither the kernel nor the resolver can express.", r.ID, strings.Join(r.GeoSite, ", "))})
		case len(r.Port) > 0 && !core[r.Outbound]:
			out = append(out, fastUnrep{Scope: r.ID, what: "port matcher",
				Msg: fmt.Sprintf("The rule %q matches destination ports, which the kernel plane cannot express; in fast mode its "+
					"traffic never reaches the core that could.", r.ID)})
		}
	}
	return out
}

// planUnrepresentableRemote names the remote lists whose loaded content has matchers nothing can
// express (direct lists aside: what they cannot match goes direct anyway).
func (s *Server) planUnrepresentableRemote(prof *model.Profile) []fastUnrep {
	var out []fastUnrep
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled || rl.Source == "" || rl.Outbound == model.OutboundDirect {
			continue
		}
		e, ok := s.fastDNS.remote[rl.ID]
		if !ok || e.fetched.IsZero() || e.set.Source != rl.Source || len(e.set.Unrepresentable) == 0 {
			continue
		}
		label := listName(&rl)
		out = append(out, fastUnrep{Scope: rl.ID, what: "list " + label,
			Msg: fmt.Sprintf("The list %q holds %s, which neither the kernel nor the resolver can express.", label, strings.Join(e.set.Unrepresentable, ", "))})
	}
	return out
}

// killSwitchAny reports an enabled kill switch: a group's, or a list's "block when every tunnel is down".
func killSwitchAny(prof *model.Profile) bool {
	for _, g := range prof.Groups {
		if g.KillSwitch {
			return true
		}
	}
	for _, rl := range prof.RoutingLists {
		if rl.Enabled && (model.ListKillSwitch(prof, rl) || model.EffectiveAllDown(prof, rl) == model.OnAllDownBlock) {
			return true
		}
	}
	return false
}

// fastDNSResolverProblem says why the router's dnsmasq cannot serve the snippet ("" = it can): no
// conf-dir, not running, or a port other than 53 in its uci section. Read at Review.
var fastDNSResolverProblem = func(ctx context.Context) string {
	if len(fastDNSConfDirs()) == 0 {
		return "dnsmasq's conf-dir was not found (no conf-dir= in " + fastDNSConfGlob + " and no " + fastDNSDefaultConfDir + ")"
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, "pidof", "dnsmasq").Output(); err != nil || strings.TrimSpace(string(out)) == "" {
		return "dnsmasq is not running"
	}
	out, err := exec.CommandContext(cctx, "uci", "-q", "show", "dhcp").Output()
	if err != nil {
		return ""
	}
	for _, sec := range uciSections("dhcp", string(out)) {
		if sec.typ != "dnsmasq" {
			continue
		}
		if port := sec.first("port"); port != "" && port != "53" {
			return "dnsmasq is set to port " + port + ", so another resolver answers the LAN on port 53"
		}
	}
	return ""
}

// fastDNSReview is the live wrapper of fastDNSFindings.
func (s *Server) fastDNSReview(ctx context.Context, cfg config.Config, prof *model.Profile, plan *pbr.Plan) []PlanFinding {
	if plan == nil || !plan.FastDNS {
		return nil
	}
	facts := fastReviewFacts{remoteErr: map[string]string{}}
	var sets map[string]pbr.RemoteSet
	facts.remoteNames, sets, _ = s.remoteNames()
	facts.remoteCIDRs = map[string]int{}
	for id, set := range sets {
		facts.remoteCIDRs[id] = len(set.CIDRs)
	}
	s.fastDNS.mu.Lock()
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled || rl.Source == "" {
			continue
		}
		e, ok := s.fastDNS.remote[rl.ID]
		if !ok || e.fetched.IsZero() || e.set.Source != rl.Source {
			facts.remoteErr[rl.ID] = e.err
		}
	}
	s.fastDNS.mu.Unlock()
	if len(plan.DlistSets()) > 0 || len(facts.remoteErr) > 0 {
		facts.nftset = s.dnsmasqNftset(ctx)
		facts.resolver = fastDNSResolverProblem(ctx)
	}
	out := fastDNSFindings(cfg, prof, plan, facts)
	if base := s.supervisedBaseline(); base != nil && staleFastPlan(base.Materialization.Kernel) {
		out = append(out, PlanFinding{ID: "fast_path.earlier_build", Setting: "routing mode fast", Item: "routing plane",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
			Detail: "The routing plane on the router was planned by an earlier build of WayHop and is not re-rendered after the " +
				"upgrade. This Apply plans it again.", Remedy: "Apply."})
	}
	for _, w := range s.planUnrepresentableRemote(prof) {
		out = append(out, PlanFinding{ID: "fast_path.unrepresentable." + w.Scope, Setting: "routing mode fast", Item: w.Scope,
			Requested: "matched in fast mode", Effective: "cannot be matched without the core's TUN",
			Severity: platform.SeverityBlocked, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksApply,
			Detail: w.Msg, Remedy: fastDNSHybridRemedy + "the " + w.what + "."})
	}
	return out
}

// --- Diagnostics -------------------------------------------------------------------------------

// fastDNSCheck is the Diagnostics row of the fast DNS plane: its sets and how many addresses dnsmasq
// has put in them, the snippet, and whether the core pin and the DNS enforcement are installed.
func (s *Server) fastDNSCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "fast_dns", Label: "Fast mode: names through the resolver"}
	cfg := s.config()
	if !cfg.Demo && s.keeneticFastOn(cfg) {
		return s.keeneticFastCheck(ctx, row)
	}
	plan := s.installedKernelPlan()
	if cfg.Demo || !s.fastDNSOn(cfg) || plan == nil || !plan.HasFastDNS() {
		row.Status, row.Summary = "na", "no list or rule matches names in fast mode"
		return row
	}
	if base := s.supervisedBaseline(); base != nil && staleFastPlan(base.Materialization.Kernel) {
		// Hunt4 #1: not re-rendered; whatever the router still runs is the earlier build's.
		row.Status = "fail"
		row.Summary = "the routing plane was planned by an earlier build of WayHop"
		row.Detail = "After an upgrade a fast-mode plane is planned again rather than re-rendered, so the router keeps what " +
			"the earlier build installed until the next Apply (after a reboot, nothing)."
		row.Fix = "Review and Apply once."
		return row
	}
	elements := 0
	sets, readErr := listDlistSets(ctx, "", plan.DNSTable(), plan.DlistSets())
	for _, elems := range sets {
		elements += len(elems)
	}
	s.fastDNS.mu.Lock()
	snippet, dirs, ferr, restarted := s.fastDNS.snippet, s.fastDNS.dirs, s.fastDNS.err, s.fastDNS.restarted
	dnsFails, dnsErr, backedOut := s.fastDNS.dnsFails, s.fastDNS.dnsErr, s.fastDNS.backedOut
	restartGaveUp := s.fastDNS.restartOwed && s.fastDNS.restartTries >= fastDNSMaxOwedRestarts
	overfull := append([]string(nil), s.fastDNS.overfull...)
	var rejected []string
	for id, why := range s.fastDNS.rejected {
		rejected = append(rejected, id+": "+why)
	}
	s.fastDNS.mu.Unlock()
	sort.Strings(rejected)
	lines := 0
	if snippet != "" {
		lines = strings.Count(snippet, "\n") - 1
	}
	pin := "off"
	if plan.CorePinActive() {
		pin = "on"
	}
	enforce := "off"
	if plan.DNSEnforceActive() {
		enforce = "on"
	}
	row.Summary = fmt.Sprintf("%d sets, %d addresses resolved · dnsmasq snippet %d lines · core pin %s · DNS enforcement %s",
		len(plan.DlistSets()), elements, lines, pin, enforce)
	detail := []string{}
	if len(dirs) > 0 {
		detail = append(detail, "snippet in "+strings.Join(dirs, ", "))
	}
	if !restarted.IsZero() {
		detail = append(detail, "dnsmasq last restarted for it "+restarted.Format(time.RFC3339))
	}
	row.Detail = strings.Join(detail, "; ")
	switch {
	case restartGaveUp:
		row.Status = "fail"
		row.Detail = fmt.Sprintf("dnsmasq did not answer after %d restarts following a back-out; WayHop stopped restarting it", fastDNSMaxOwedRestarts)
		row.Fix = "Restart dnsmasq by hand (/etc/init.d/dnsmasq restart) or reboot the router, and check its log."
	case backedOut:
		row.Status = "fail"
		row.Detail = ferr
		row.Fix = "Switch routing mode to hybrid, or Apply again once the resolver is healthy."
	case ferr != "":
		row.Status = "warn"
		row.Detail = ferr
		row.Fix = "Check that dnsmasq-full is installed and running; Apply again to rewrite the snippet."
	case readErr != nil && len(plan.DlistSets()) > 0:
		row.Status = "warn"
		row.Detail = "the sets could not be read: " + readErr.Error()
		row.Fix = "Apply again: the kernel plane reinstalls its table."
	case plan.CorePin && !plan.CorePinActive():
		row.Status = "warn"
		row.Detail = "the LAN's devices are not known, so no flow is pinned past the core"
	case dnsFails > 0:
		row.Status = "warn"
		row.Detail = fmt.Sprintf("the router's resolver missed the last %d check(s) through its upstreams: %s", dnsFails, dnsErr)
		row.Fix = "Check dnsmasq's CPU (top) and its upstreams; switch routing mode to hybrid if it does not recover."
	case len(missingRemote(plan, s)) > 0:
		// Until a remote list is loaded the core carries everything unpinned.
		row.Status = "warn"
		row.Detail = "remote lists not loaded yet, so the core carries all LAN traffic (nothing pinned): " + strings.Join(missingRemote(plan, s), "; ")
		row.Fix = "Check the lists' download path; the daemon retries every minute."
	case len(rejected) > 0:
		// A refresh Review would have refused is not taken live; the last good content stays.
		row.Status = "warn"
		row.Detail = "a remote list was refreshed to content fast mode cannot use, so the content applied before stays in force: " + strings.Join(rejected, "; ")
		row.Fix = "Review the list (its source changed what it holds), or switch routing mode to hybrid, then Apply."
	case len(overfull) > 0:
		// Polish 1a: a remote list refreshed at run time put a name into more lists than one dnsmasq
		// line can name; it is left out rather than routed by only some of its lists.
		row.Status = "warn"
		row.Detail = fmt.Sprintf("%d name(s) are in more lists than one dnsmasq line can name and are left out of the resolver's sets "+
			"(they go the way their addresses' static entries say): %s", len(overfull), strings.Join(shortList(overfull, 5), ", "))
		row.Fix = "Keep each name in fewer lists (merge device-scoped copies of a list), or switch routing mode to hybrid."
	default:
		row.Status = "pass"
	}
	return row
}
