package nativedns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The file the audit measured: the two upstreams and both directives sit in the main config.
const mainConfFixture = "no-resolv\nstrict-order\nserver=1.1.1.1\nserver=8.8.8.8\nconf-dir=/opt/etc/dnsmasq.d,*.conf\n"

var tunnelChain = []ChainRow{
	{Address: "1.1.1.1", Iface: "nwg1"},
	{Address: "8.8.8.8", Iface: "nwg0"},
	{Address: "1.1.1.1"},
}

// fakeHost is a ChainHost over a temp dir, counting what it was asked to run.
type fakeHost struct {
	ChainHost
	restarts, tests, verifies int
	trials                    []ChainRow
}

func newFakeHost(t *testing.T, main string, upstream *string) *fakeHost {
	t.Helper()
	root := t.TempDir()
	confDir := filepath.Join(root, "etc", "dnsmasq.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeHost{}
	f.ChainHost = ChainHost{
		MainConf:     filepath.Join(root, "etc", "dnsmasq.conf"),
		UpstreamConf: filepath.Join(confDir, "00-upstream.conf"),
		ConfDir:      confDir,
		StateDir:     filepath.Join(root, "var", "native-dns"),
		Test:         func(context.Context) (string, error) { f.tests++; return "syntax check OK", nil },
		Restart:      func(context.Context) error { f.restarts++; return nil },
		Trial:        func(_ context.Context, r ChainRow) error { f.trials = append(f.trials, r); return nil },
		Verify:       func(context.Context) error { f.verifies++; return nil },
	}
	writeTestFile(t, f.MainConf, main)
	if upstream != nil {
		writeTestFile(t, f.UpstreamConf, *upstream)
	}
	return f
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// adopted is what the page reads back: the two files as dnsmasq reads them, main config first.
func (f *fakeHost) adopted(t *testing.T) NativeDNS {
	t.Helper()
	up, err := os.ReadFile(f.UpstreamConf)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return ReadDnsmasqD(readTestFile(t, f.MainConf)+"\n"+DnsmasqDirSentinel+"\n"+string(up), "")
}

func refs(nd NativeDNS) []string {
	var out []string
	for _, r := range nd.Resolvers {
		out = append(out, serverRef(r))
	}
	return out
}

// The defect: a chain written beside the main config's upstreams landed behind them, so the plaintext
// servers kept answering. After a write, what dnsmasq reads must be the chain and nothing else.
func TestApplyReplacesTheMainConfigsUpstreams(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	rep := f.Apply(context.Background(), tunnelChain)
	if !rep.OK {
		t.Fatalf("apply failed: %+v", rep)
	}
	nd := f.adopted(t)
	want := []string{"1.1.1.1@nwg1", "8.8.8.8@nwg0", "1.1.1.1"}
	if got := refs(nd); !reflect.DeepEqual(got, want) {
		t.Fatalf("dnsmasq would ask %v, want %v", got, want)
	}
	if !nd.StrictOrder || !nd.NoResolv {
		t.Errorf("the chain needs strict-order and no-resolv: %+v", nd)
	}
	main := readTestFile(t, f.MainConf)
	if !strings.Contains(main, "conf-dir=/opt/etc/dnsmasq.d,*.conf") {
		t.Errorf("the conf-dir line must stay: %q", main)
	}
	if !strings.Contains(main, MainConfMovedPrefix+"server=1.1.1.1") {
		t.Errorf("the old upstream should still be readable in the file: %q", main)
	}
	if f.restarts != 1 || f.verifies != 1 || f.tests != 1 {
		t.Errorf("restart/verify/test = %d/%d/%d, want one each", f.restarts, f.verifies, f.tests)
	}
	if !f.Managed() {
		t.Error("a written chain must be restorable")
	}
}

// Only rows bound to an interface are tried: a plain row needs no proof of binding, and trying it
// would send a query in plaintext just to find out it can.
func TestApplyTriesOnlyTheBoundRows(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	f.Apply(context.Background(), tunnelChain)
	if len(f.trials) != 2 || f.trials[0].Iface != "nwg1" || f.trials[1].Iface != "nwg0" {
		t.Fatalf("tried %+v", f.trials)
	}
}

// No tunnel row answering stops the write with the router exactly as it was: restarting dnsmasq into a
// chain that cannot answer would cost the house its DNS to learn what the trial already said.
func TestApplyRefusesWhenNoBoundRowAnswers(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	f.Trial = func(context.Context, ChainRow) error { return errors.New("no answer") }
	rep := f.Apply(context.Background(), tunnelChain)
	if rep.OK || rep.RolledBack || rep.Error == "" {
		t.Fatalf("want a refusal, got %+v", rep)
	}
	if got := readTestFile(t, f.MainConf); got != mainConfFixture {
		t.Errorf("main config changed: %q", got)
	}
	if _, err := os.Stat(f.UpstreamConf); !os.IsNotExist(err) {
		t.Error("a refused write left a chain file")
	}
	if f.restarts != 0 || f.Managed() {
		t.Errorf("restarts=%d managed=%v after a refusal", f.restarts, f.Managed())
	}
}

func TestApplyProbesLocalLoopbackRow(t *testing.T) {
	localChain := []ChainRow{{Address: "127.0.0.1", Port: 5353}}

	t.Run("refused when local loopback does not answer", func(t *testing.T) {
		f := newFakeHost(t, mainConfFixture, nil)
		f.Probe = func(context.Context, string) error { return errors.New("connection refused") }
		rep := f.Apply(context.Background(), localChain)
		if rep.OK || rep.RolledBack || rep.Error == "" {
			t.Fatalf("want refusal, got %+v", rep)
		}
		if f.restarts != 0 {
			t.Errorf("restarts = %d, want 0", f.restarts)
		}
	})

	t.Run("succeeds when local loopback answers", func(t *testing.T) {
		f := newFakeHost(t, mainConfFixture, nil)
		f.Probe = func(context.Context, string) error { return nil }
		rep := f.Apply(context.Background(), localChain)
		if !rep.OK {
			t.Fatalf("apply failed: %+v", rep)
		}
		if f.restarts != 1 {
			t.Errorf("restarts = %d, want 1", f.restarts)
		}
	})
}

// A tunnel down right now is no reason to refuse a chain whose other rows work: it can come back, and
// dnsmasq will use it when it does. The report says so.
func TestApplyGoesOnWhenSomeBoundRowsAnswer(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	f.Trial = func(_ context.Context, r ChainRow) error {
		if r.Iface == "nwg1" {
			return errors.New("no answer")
		}
		return nil
	}
	rep := f.Apply(context.Background(), tunnelChain)
	if !rep.OK {
		t.Fatalf("apply failed: %+v", rep)
	}
	if rep.Steps[0].OK || !strings.Contains(rep.Steps[0].Step, "nwg1") {
		t.Errorf("the silent row must be reported: %+v", rep.Steps[0])
	}
}

// dnsmasq refusing the syntax puts both files back without touching the running service.
func TestApplyRollsBackOnSyntaxFailure(t *testing.T) {
	old := "server=9.9.9.9\n"
	f := newFakeHost(t, mainConfFixture, &old)
	f.Test = func(context.Context) (string, error) { return "bad option", errors.New("exit 1") }
	rep := f.Apply(context.Background(), tunnelChain)
	if rep.OK || !rep.RolledBack || !strings.Contains(rep.Error, "bad option") {
		t.Fatalf("got %+v", rep)
	}
	if got := readTestFile(t, f.MainConf); got != mainConfFixture {
		t.Errorf("main config not restored: %q", got)
	}
	if got := readTestFile(t, f.UpstreamConf); got != old {
		t.Errorf("upstream file not restored: %q", got)
	}
	if f.restarts != 0 {
		t.Errorf("restarted %d times for a config that never ran", f.restarts)
	}
	if f.Managed() {
		t.Error("a rolled-back first write leaves nothing to restore")
	}
}

// A restarted dnsmasq that does not answer goes back on the old files AND is restarted again: until
// then it is still running the chain that failed.
func TestApplyRollsBackWhenDnsmasqStopsAnswering(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	f.Verify = func(context.Context) error { f.verifies++; return errors.New("no answer") }
	rep := f.Apply(context.Background(), tunnelChain)
	if rep.OK || !rep.RolledBack {
		t.Fatalf("got %+v", rep)
	}
	if got := readTestFile(t, f.MainConf); got != mainConfFixture {
		t.Errorf("main config not restored: %q", got)
	}
	if _, err := os.Stat(f.UpstreamConf); !os.IsNotExist(err) {
		t.Error("the file that did not exist before must go")
	}
	if f.restarts != 2 {
		t.Errorf("restarts = %d, want the chain and then the way back", f.restarts)
	}
}

func TestRestorePutsBackWhatTheFirstWriteReplaced(t *testing.T) {
	old := "# my own\nserver=9.9.9.9\n"
	f := newFakeHost(t, mainConfFixture, &old)
	if rep := f.Apply(context.Background(), tunnelChain); !rep.OK {
		t.Fatalf("apply: %+v", rep)
	}
	// A second write must not overwrite what the first one kept.
	if rep := f.Apply(context.Background(), tunnelChain[:1]); !rep.OK {
		t.Fatalf("second apply: %+v", rep)
	}
	// Something edited on the router since then survives the restore.
	writeTestFile(t, f.MainConf, readTestFile(t, f.MainConf)+"addn-hosts=/opt/etc/hosts.extra\n")

	rep := f.Restore(context.Background())
	if !rep.OK {
		t.Fatalf("restore: %+v", rep)
	}
	main := readTestFile(t, f.MainConf)
	for _, want := range []string{"\nserver=1.1.1.1\n", "\nserver=8.8.8.8\n", "no-resolv\n", "addn-hosts=/opt/etc/hosts.extra"} {
		if !strings.Contains(main, want) {
			t.Errorf("restored main config lacks %q: %q", want, main)
		}
	}
	if strings.Contains(main, "wayhop-moved") {
		t.Errorf("markers left behind: %q", main)
	}
	if got := readTestFile(t, f.UpstreamConf); got != old {
		t.Errorf("upstream file = %q, want what it held", got)
	}
	if f.Managed() {
		t.Error("nothing is left to restore")
	}
}

func TestRestoreRemovesAChainFileThatWasNotThereBefore(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	if rep := f.Apply(context.Background(), tunnelChain); !rep.OK {
		t.Fatalf("apply: %+v", rep)
	}
	if rep := f.Restore(context.Background()); !rep.OK {
		t.Fatalf("restore: %+v", rep)
	}
	if _, err := os.Stat(f.UpstreamConf); !os.IsNotExist(err) {
		t.Error("the chain file should be gone")
	}
	if got := readTestFile(t, f.MainConf); got != mainConfFixture {
		t.Errorf("main config = %q, want it byte for byte", got)
	}
}

func TestRestoreRollsBackWhenTheOldUpstreamsDoNotAnswer(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	if rep := f.Apply(context.Background(), tunnelChain); !rep.OK {
		t.Fatalf("apply: %+v", rep)
	}
	chain := readTestFile(t, f.UpstreamConf)
	f.Verify = func(context.Context) error { return errors.New("no answer") }
	rep := f.Restore(context.Background())
	if rep.OK || !rep.RolledBack {
		t.Fatalf("got %+v", rep)
	}
	if got := readTestFile(t, f.UpstreamConf); got != chain {
		t.Errorf("the chain should be back: %q", got)
	}
	if !f.Managed() {
		t.Error("the chain is still WayHop's, so it can still be restored")
	}
}

func TestRestoreRefusesWithNothingToRestore(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	rep := f.Restore(context.Background())
	if rep.OK || rep.Error == "" || f.restarts != 0 {
		t.Fatalf("got %+v, restarts %d", rep, f.restarts)
	}
}

func TestRewriteMainConf(t *testing.T) {
	main := "port=53\nserver=1.1.1.1\nserver=/corp.example/10.0.0.1\nlocal=/lan/\nlocal=9.9.9.9\nall-servers\nresolv-file=/tmp/r\n" +
		"# server=8.8.8.8\nconf-dir=/opt/etc/dnsmasq.d/,*.conf\n"
	out, moved, added := RewriteMainConf(main, "/opt/etc/dnsmasq.d")
	if added {
		t.Error("the conf-dir is read already, trailing slash or not")
	}
	want := []string{"server=1.1.1.1", "local=9.9.9.9", "all-servers", "resolv-file=/tmp/r"}
	if !reflect.DeepEqual(moved, want) {
		t.Errorf("moved %v, want %v", moved, want)
	}
	for _, keep := range []string{"\nserver=/corp.example/10.0.0.1\n", "\nlocal=/lan/\n", "port=53\n", "# server=8.8.8.8\n"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q must stay: %q", keep, out)
		}
	}
	if got := ReadDnsmasqD(out, ""); len(got.Resolvers) != 0 {
		t.Errorf("upstreams left active: %+v", got.Resolvers)
	}
	if got := RestoreMainConf(out); got != main {
		t.Errorf("restore = %q, want %q", got, main)
	}
}

// With no conf-dir the chain would never be read and dnsmasq would start with no upstream at all.
func TestRewriteMainConfAddsAMissingConfDir(t *testing.T) {
	main := "server=1.1.1.1\n"
	out, _, added := RewriteMainConf(main, "/opt/etc/dnsmasq.d")
	if !added || !strings.Contains(out, "\nconf-dir=/opt/etc/dnsmasq.d,*.conf\n") {
		t.Fatalf("added=%v out=%q", added, out)
	}
	if got := RestoreMainConf(out); got != main {
		t.Errorf("restore = %q, want %q", got, main)
	}
}

func TestValidateChain(t *testing.T) {
	ok := [][]ChainRow{
		tunnelChain,
		{{Address: "127.0.0.1", Port: 5053}},
		{{Address: "127.0.0.1", Port: 5353}},
		{{Address: "2606:4700:4700::1111", Iface: "nwg1"}},
	}
	for _, rows := range ok {
		if err := ValidateChain(rows); err != nil {
			t.Errorf("%+v: %v", rows, err)
		}
	}
	bad := map[string][]ChainRow{
		"empty":        {},
		"hostname":     {{Address: "dns.example.com"}},
		"unspecified":  {{Address: "0.0.0.0"}},
		"loop":         {{Address: "127.0.0.1"}},
		"loop 53":      {{Address: "127.0.0.1", Port: 53}},
		"bound local":  {{Address: "127.0.0.1", Port: 5053, Iface: "nwg1"}},
		"port":         {{Address: "1.1.1.1", Port: 70000}},
		"injection":    {{Address: "1.1.1.1", Iface: "nwg1\nserver=6.6.6.6"}},
		"bind in addr": {{Address: "1.1.1.1@eth3"}},
		"too long":     make([]ChainRow, MaxChainRows+1),
	}
	for name, rows := range bad {
		if err := ValidateChain(rows); err == nil {
			t.Errorf("%s: accepted %+v", name, rows)
		}
	}
}

// The reader has to give back what the writer wrote, or the page would lose a binding on the next edit
// and show a tunnel row as the plaintext fallback.
func TestChainRoundTripsThroughTheReader(t *testing.T) {
	rows := []ChainRow{
		{Address: "1.1.1.1", Iface: "nwg1"},
		{Address: "9.9.9.9", Port: 5353, Iface: "nwg0"},
		{Address: "127.0.0.1", Port: 5053},
		{Address: "8.8.8.8"},
	}
	nd := ReadDnsmasqD(RenderChain(rows), "")
	if !nd.StrictOrder || !nd.NoResolv || len(nd.Resolvers) != len(rows) {
		t.Fatalf("read back %+v", nd)
	}
	for i, r := range nd.Resolvers {
		if r.Address != rows[i].Address || r.Port != rows[i].Port || r.Iface != rows[i].Iface {
			t.Errorf("row %d: %+v, want %+v", i, r, rows[i])
		}
	}
	if got := BoundIfaces(RenderChain(rows)); !reflect.DeepEqual(got, []string{"nwg1", "nwg0"}) {
		t.Errorf("bound ifaces %v", got)
	}
}

// A chain written by hand in the main config, as it was on a live Keenetic while the panel could not
// write one. The reader used to keep "@nwg1" in the address and call that row the plaintext fallback.
// It has to read as tunnels, survive a write from the page, and come back exactly on a restore.
func TestHandWrittenBoundChainInTheMainConfig(t *testing.T) {
	main := "no-resolv\nstrict-order\nserver=1.1.1.1@nwg1\nserver=8.8.8.8@nwg0\nserver=1.0.0.1\nconf-dir=/opt/etc/dnsmasq.d,*.conf\n"
	f := newFakeHost(t, main, nil)
	nd := f.adopted(t).MarkTunnels(func(iface string) bool { return strings.HasPrefix(iface, "nwg") })
	if got, want := refs(nd), []string{"1.1.1.1@nwg1", "8.8.8.8@nwg0", "1.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("read %v, want %v", got, want)
	}
	if r := nd.Resolvers[0]; r.Address != "1.1.1.1" || r.Iface != "nwg1" || !r.ViaTunnel || r.Tier != TierHidden || r.Source != "dnsmasq.conf server" {
		t.Errorf("tunnel row read as %+v", r)
	}
	if r := nd.Resolvers[2]; r.ViaTunnel || r.Tier != TierFallback {
		t.Errorf("last resort read as %+v", r)
	}

	if rep := f.Apply(context.Background(), []ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}, {Address: "1.0.0.1"}}); !rep.OK {
		t.Fatalf("apply: %+v", rep)
	}
	if got, want := refs(f.adopted(t)), []string{"1.1.1.1@nwg1", "1.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after a write dnsmasq would ask %v, want %v", got, want)
	}
	if rep := f.Restore(context.Background()); !rep.OK {
		t.Fatalf("restore: %+v", rep)
	}
	if got := readTestFile(t, f.MainConf); got != main {
		t.Errorf("restored main config = %q, want it byte for byte", got)
	}
}

// `@` also takes a source address and a source port in dnsmasq's syntax. Those are not interfaces.
func TestReaderKeepsOtherFormsOfBinding(t *testing.T) {
	nd := ReadDnsmasqD("server=1.1.1.1@192.0.2.1\nserver=8.8.8.8@nwg1#5000\n", "")
	if len(nd.Resolvers) != 2 {
		t.Fatalf("%+v", nd.Resolvers)
	}
	for i, want := range []string{"1.1.1.1@192.0.2.1", "8.8.8.8@nwg1#5000"} {
		if r := nd.Resolvers[i]; r.Iface != "" || r.Address != want {
			t.Errorf("row %d: %+v", i, r)
		}
		if got := serverRef(nd.Resolvers[i]); got != want {
			t.Errorf("row %d went back out as %q", i, got)
		}
	}
}

func TestMarkTunnelsPromotesOnlyTunnels(t *testing.T) {
	nd := ReadDnsmasqD(RenderChain(tunnelChain), "")
	nd.Resolvers = append(nd.Resolvers, NativeResolver{Kind: KindPlain, Address: "9.9.9.9", Iface: "eth3", Tier: TierFallback})
	got := nd.MarkTunnels(func(iface string) bool { return strings.HasPrefix(iface, "nwg") })
	if !got.Resolvers[0].ViaTunnel || got.Resolvers[0].Tier != TierHidden {
		t.Errorf("tunnel row: %+v", got.Resolvers[0])
	}
	if got.Resolvers[2].ViaTunnel || got.Resolvers[2].Tier != TierFallback {
		t.Errorf("unbound row: %+v", got.Resolvers[2])
	}
	if got.Resolvers[3].ViaTunnel {
		t.Errorf("the WAN is not a tunnel: %+v", got.Resolvers[3])
	}
	if nd.Resolvers[0].ViaTunnel {
		t.Error("the original was modified")
	}
}

func TestPlanReportsWhatWouldChangeWithoutChangingIt(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	writeTestFile(t, filepath.Join(f.ConfDir, "10-other.conf"), "server=4.4.4.4\nserver=/x.example/10.0.0.1\n")
	writeTestFile(t, filepath.Join(f.ConfDir, "wayhop-policy.conf"), "ipset=/a.example/s_4\n")
	plan, err := f.Plan(tunnelChain)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Lines, []string{"server=1.1.1.1@nwg1", "server=8.8.8.8@nwg0", "server=1.1.1.1"}) {
		t.Errorf("lines %v", plan.Lines)
	}
	if !reflect.DeepEqual(plan.Moved, []string{"no-resolv", "strict-order", "server=1.1.1.1", "server=8.8.8.8"}) {
		t.Errorf("moved %v", plan.Moved)
	}
	if !reflect.DeepEqual(plan.Foreign, []string{"10-other.conf: 4.4.4.4"}) {
		t.Errorf("foreign %v", plan.Foreign)
	}
	if got := readTestFile(t, f.MainConf); got != mainConfFixture {
		t.Errorf("a plan changed the main config: %q", got)
	}
}

func TestRevChangesWithEitherFile(t *testing.T) {
	f := newFakeHost(t, mainConfFixture, nil)
	a := f.Rev()
	writeTestFile(t, f.UpstreamConf, "server=9.9.9.9\n")
	b := f.Rev()
	writeTestFile(t, f.MainConf, mainConfFixture+"#\n")
	if c := f.Rev(); a == b || b == c {
		t.Errorf("revs %s %s %s", a, b, c)
	}
}

func TestRenderTrialConfCarriesTheServicesUser(t *testing.T) {
	got := renderTrialConf(ChainRow{Address: "1.1.1.1", Iface: "nwg1"}, 15353, "/x/trial.pid", "user=dnsuser\nserver=8.8.8.8\n")
	for _, want := range []string{"server=1.1.1.1@nwg1\n", "port=15353\n", "user=dnsuser\n", "no-resolv\n", "listen-address=127.0.0.1\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("trial conf lacks %q: %q", want, got)
		}
	}
	if strings.Contains(got, "8.8.8.8") {
		t.Errorf("only the row under trial may be an upstream: %q", got)
	}
}

// fakeResolver answers each query with the given rcode.
func fakeResolver(t *testing.T, rcode byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			out := append([]byte(nil), buf[:n]...)
			out[2], out[3] = 0x81, 0x80|rcode
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestProbeResolver(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode byte
		ok    bool
	}{{"an answer", 0, true}, {"no such name is a working path", 3, true}, {"SERVFAIL is no upstream", 2, false}, {"REFUSED", 5, false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			if err := ProbeResolver(ctx, fakeResolver(t, tc.rcode)); (err == nil) != tc.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestProbeResolverGivesUpOnSilence(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := ProbeResolver(ctx, pc.LocalAddr().String()); err == nil {
		t.Fatal("silence read as an answer")
	}
}

func TestAnswering(t *testing.T) {
	for _, tc := range []struct {
		name      string
		listeners []DNSListener
		want      Answering
	}{
		{"dnsmasq", []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53", Process: "dnsmasq"}}, Answering{PlaneNative, "dnsmasq"}},
		{"sing-box", []DNSListener{{Proto: "udp", Addr: "127.0.0.1:53", Process: "dnsmasq"}, {Proto: "udp", Addr: "0.0.0.0:53", Process: "sing-box"}}, Answering{PlaneCore, "sing-box"}},
		{"netstat could not say", []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53"}}, Answering{Plane: PlaneUnknown}},
		{"nothing", nil, Answering{Plane: PlaneUnknown}},
	} {
		if got := (EffectivePath{Listeners: tc.listeners}).Answering(); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestListenerProbeAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []DNSListener
		want string
	}{
		{"wildcard", []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53"}}, "127.0.0.1:53"},
		{"lan and loopback", []DNSListener{{Proto: "udp", Addr: "10.20.30.1:53"}, {Proto: "udp", Addr: "127.0.0.1:53"}}, "127.0.0.1:53"},
		{"lan only", []DNSListener{{Proto: "udp", Addr: "10.20.30.1:53"}}, "10.20.30.1:53"},
		{"v6 wildcard", []DNSListener{{Proto: "udp", Addr: ":::53"}}, "[::1]:53"},
		{"tcp only", []DNSListener{{Proto: "tcp", Addr: "0.0.0.0:53"}}, ""},
		{"nothing", nil, ""},
	} {
		if got := ListenerProbeAddr(tc.in); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A bound upstream must not read as a loop: only its address and port say where it goes.
func TestForwarderLoopsReadThroughABinding(t *testing.T) {
	listeners := []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53", Process: "dnsmasq"}}
	got := detectLoops(listeners, []string{"1.1.1.1@nwg1", "127.0.0.1#5053"}, nil, "53")
	if len(got) != 0 {
		t.Fatalf("false loop: %+v", got)
	}
}
