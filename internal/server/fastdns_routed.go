package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// The large lists' routing tables (pbr routed.go): their prefixes are routes, loaded here because a
// table of ten thousand routes cannot go through the kernel adapter's one-command-per-line runner.
// The rules that look the tables up are part of the plane's artifact (RenderIP / RenderTeardown), so
// the postcheck, the reconcile loop and the teardown own them as every other rule.

// routedIP runs the router's ip with args and stdin. A variable so tests answer for it.
var routedIP = func(ctx context.Context, stdin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ip", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedWriter{w: &out, n: 16 << 20}, &limitedWriter{w: &errb, n: 64 << 10}
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// limitedWriter keeps at most n bytes.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// syncRoutedTables makes each large list's table hold exactly its prefixes: what is missing or points
// elsewhere is replaced, what is no longer listed is deleted, nothing is flushed first, so the table
// never stands empty under live flows. Remote prefixes are the content in force (planRemote). A plan
// without large lists does nothing.
func (s *Server) syncRoutedTables(ctx context.Context, plan *pbr.Plan) error {
	zones := plan.RoutedZones(pbr.Options{})
	if len(zones) == 0 || s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return nil
	}
	// The content in force, never a refreshed copy the reload has not yet taken.
	return s.syncRoutedTablesWith(ctx, zones, s.liveRemote(plan))
}

// preloadRoutedTables fills, before an install, the tables of plan that the installed plane (prev)
// does not use, with the content the install will take. Their rules come with the install, so until
// then the routes are inert; a failed preload only logs (the install's own sync decides).
func (s *Server) preloadRoutedTables(ctx context.Context, plan, prev *pbr.Plan) {
	if s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return
	}
	used := map[int]bool{}
	for _, r := range prev.RoutedZones(pbr.Options{}) {
		used[r.Table] = true
	}
	var fresh []pbr.RoutedZone
	for _, r := range plan.RoutedZones(pbr.Options{}) {
		if !used[r.Table] {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		return
	}
	_, remote, _ := s.planRemote(plan)
	if err := s.syncRoutedTablesWith(ctx, fresh, remote); err != nil {
		log.Printf("fast path: preloading the large lists' tables: %v", err)
	}
}

// syncRoutedTablesWith is syncRoutedTables for zones with the given remote content.
func (s *Server) syncRoutedTablesWith(ctx context.Context, zones []pbr.RoutedZone, remote map[string]pbr.RemoteSet) error {
	var failures []string
	for _, r := range zones {
		v4, v6 := r.RoutedPrefixes(remote)
		if r.Dev != "" && !routedDevUp(r.Dev) {
			// Not there yet (boot, a tunnel being brought up), or down: its routes cannot be added,
			// and the lookup falls through to main as the egress table's does. What the table still
			// holds goes, so no route through another (an earlier Apply's) device stays;
			// FastDNSLoop fills it once the device is up.
			v4, v6 = nil, nil
		}
		for _, fam := range []struct {
			flag   string
			wanted []string
		}{{"-4", v4}, {"-6", v6}} {
			if fam.flag == "-6" && len(fam.wanted) == 0 && len(r.Zone.RouteV6) == 0 && (!r.Zone.RemoteRouted || r.Zone.DNSNoV6) {
				continue // a list without IPv6
			}
			if err := s.syncRoutedTable(ctx, r, fam.flag, fam.wanted); err != nil {
				failures = append(failures, err.Error())
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("the large lists' routes: %s", strings.Join(failures, "; "))
	}
	return nil
}

// routedDevUp reports a device that exists and is up. A variable for tests.
var routedDevUp = func(dev string) bool {
	ifc, err := net.InterfaceByName(dev)
	return err == nil && ifc.Flags&net.FlagUp != 0
}

// liveRemote is the remote content the installed plane uses (markRemoteLive), of each list's reviewed
// source.
func (s *Server) liveRemote(plan *pbr.Plan) map[string]pbr.RemoteSet {
	srcs := plan.RemoteSources()
	out := map[string]pbr.RemoteSet{}
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	for id, src := range srcs {
		if set, ok := s.fastDNS.live[id]; ok && (src == "" || set.Source == src) {
			out[id] = set
		}
	}
	return out
}

// repairRoutedTables is the loop's pass over the large lists' tables: under applyMu, so it never
// writes an older plan's routes over an Apply in progress, with the plan read again
// under the lock; skipped while an Apply holds it.
func (s *Server) repairRoutedTables(ctx context.Context) {
	if !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	plan := s.installedKernelPlan()
	if plan == nil || !plan.FastDNS {
		return
	}
	if err := s.syncRoutedTables(ctx, plan); err != nil {
		log.Printf("fast path: %v; tried again next tick", err)
	}
}

// syncRoutedTable brings one family of one table to wanted.
func (s *Server) syncRoutedTable(ctx context.Context, r pbr.RoutedZone, flag string, wanted []string) error {
	out, err := routedIP(ctx, "", flag, "route", "show", "table", fmt.Sprint(r.Table))
	if err != nil {
		// A table nothing was ever put in does not exist yet: iproute2 6.18 (ip-tiny on OpenWrt
		// 25.12) says "FIB table does not exist" and exits 2 (live 22.11). That is an empty table.
		if !routedTableMissing(err) {
			return err
		}
		out = ""
	}
	have := parseRoutedTable(out, flag == "-6")
	want := map[string]bool{}
	var batch strings.Builder
	for _, p := range wanted {
		want[p] = true
		if have[p] == routedKind(r) {
			continue
		}
		fmt.Fprintf(&batch, "route replace %s table %d\n", r.RouteSpec(p), r.Table)
	}
	for p, kind := range have {
		if !want[p] {
			if kind == "blackhole" {
				fmt.Fprintf(&batch, "route del blackhole %s table %d\n", p, r.Table)
			} else {
				fmt.Fprintf(&batch, "route del %s table %d\n", p, r.Table)
			}
		}
	}
	if batch.Len() == 0 {
		return nil
	}
	if _, err := routedIP(ctx, batch.String(), flag, "-force", "-batch", "-"); err != nil {
		return err
	}
	log.Printf("fast path: large list %s: table %d (%s) holds %d prefixes", r.Zone.Name, r.Table, flag, len(wanted))
	return nil
}

// routedTableMissing reports ip's answer for a routing table that does not exist yet.
func routedTableMissing(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "table does not exist") || strings.Contains(msg, "no such file or directory")
}

// routedKind is how a table's route for r reads back: the device, or "blackhole".
func routedKind(r pbr.RoutedZone) string {
	if r.Dev == "" {
		return "blackhole"
	}
	return "dev " + r.Dev
}

// parseRoutedTable reads `ip route show table N`: per canonical prefix, "blackhole" or "dev <dev>".
// ip prints 0.0.0.0/0 and ::/0 as "default".
func parseRoutedTable(out string, v6 bool) map[string]string {
	have := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		kind := ""
		if f[0] == "blackhole" || f[0] == "unreachable" || f[0] == "prohibit" {
			kind, f = f[0], f[1:]
			if len(f) == 0 {
				continue
			}
		}
		if f[0] == "default" {
			if v6 {
				f[0] = "::/0"
			} else {
				f[0] = "0.0.0.0/0"
			}
		}
		p, err := netip.ParsePrefix(f[0])
		if err != nil {
			a, aerr := netip.ParseAddr(f[0])
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if kind == "" {
			for i := 1; i+1 < len(f); i++ {
				if f[i] == "dev" {
					kind = "dev " + f[i+1]
					break
				}
			}
		}
		have[p.Masked().String()] = kind
	}
	return have
}

// routedIndex answers which large list's table routes an address (longest prefix wins, as the table
// does; between tables, the first in rule order). The trace and the Dashboard read it for a flow with
// no plan mark: such a flow to a large list's address left by that list's egress, not "direct".
type routedIndex struct {
	mask   uint32
	tables []routedTableIndex
}

type routedTableIndex struct {
	tag  string
	bits map[int]map[netip.Addr]bool // prefix length -> masked prefix addresses
	lens []int                       // lengths present, longest first
}

// newRoutedIndex indexes plan's large lists with the remote content in force. nil without any.
func newRoutedIndex(plan *pbr.Plan, remote map[string]pbr.RemoteSet) *routedIndex {
	zones := plan.RoutedZones(pbr.Options{})
	if len(zones) == 0 {
		return nil
	}
	idx := &routedIndex{mask: plan.Mask}
	for _, r := range zones {
		t := routedTableIndex{tag: r.Zone.EgressTag, bits: map[int]map[netip.Addr]bool{}}
		v4, v6 := r.RoutedPrefixes(remote)
		for _, s := range append(v4, v6...) {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			if t.bits[p.Bits()] == nil {
				t.bits[p.Bits()] = map[netip.Addr]bool{}
				t.lens = append(t.lens, p.Bits())
			}
			t.bits[p.Bits()][p.Addr()] = true
		}
		sort.Sort(sort.Reverse(sort.IntSlice(t.lens)))
		idx.tables = append(idx.tables, t)
	}
	return idx
}

// lookup is the egress tag of the table that routes dst for an unmarked flow ("" none).
func (x *routedIndex) lookup(dst string, mark uint32) string {
	if x == nil || mark&x.mask != 0 {
		return ""
	}
	a, err := netip.ParseAddr(dst)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	for _, t := range x.tables {
		for _, bits := range t.lens {
			if bits > a.BitLen() {
				continue
			}
			p, err := a.Prefix(bits)
			if err == nil && t.bits[bits][p.Addr()] {
				return t.tag
			}
		}
	}
	return ""
}
