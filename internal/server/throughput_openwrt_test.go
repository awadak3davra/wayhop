package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/failover"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/speedtest"
)

// OpenWrt stage 3: the throughput feature on the nft plane. The download bound to a kernel link is
// the one KeeneticOS runs (ifaceDial: the device and the core's bypass mark, both required); what is
// OpenWrt's own is the elector's units electing by it, and a connection inside the proxy core being
// measured through the core's probe inbound.

// seedThroughput gives tunnels a fresh generic sample. The elector is created first: creating it
// restores the journal, which replaces whatever samples the server holds.
func seedThroughput(s *Server, mbps map[string]float64) {
	s.kernelElector()
	now := s.throughputNow().UnixMilli()
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	if s.throughput.tunnels == nil {
		s.throughput.tunnels = map[string]throughputTunnelState{}
	}
	for id, v := range mbps {
		st := s.throughput.tunnels[id]
		st.Success = speedtest.DownloadResult{Source: "ovh", Bytes: 10_000_000, TotalBytes: 10_000_000, SteadyMbps: v}
		st.SuccessAt, st.At = now, now
		s.throughput.tunnels[id] = st
	}
}

// A urltest group on the nft plane elects by its election mode. The table sits on a link whose
// handshake fails; by delay the next would be awg2 (38 ms), by throughput it is awg1 (80 Mbit/s
// against 40). The exit inside the core has the best figure of all and no link: it is never a
// candidate for the table.
func TestOpenWrtGroupElectsByThroughput(t *testing.T) {
	for _, tc := range []struct {
		mode  model.ElectionMode
		awg1  int // awg1's handshake, ms
		want  string
		wantP failover.Policy
	}{
		{model.ElectionLatency, 95, "awg2", failover.PolicyLatency},
		{model.ElectionThroughput, 95, "awg1", failover.PolicyThroughput},
		{model.ElectionMixed, 95, "awg1", failover.PolicyMixed},  // 95 ms against 38: not an outlier
		{model.ElectionMixed, 600, "awg2", failover.PolicyMixed}, // an outlier is out of the choice
	} {
		profile := refrouterProfile()
		profile.Groups[0].ElectionMode = tc.mode
		tables := &fakeTables{}
		s, plan := openwrtServer(t, profile, tables)
		table := egressTable(t, plan, "grp-auto")
		solo := egressTable(t, plan, "ru")
		tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg0", solo: "awg1"})}
		tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg0": -1, "awg1": tc.awg1, "awg2": 38})
		s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
		seedThroughput(s, map[string]float64{"nl": 20, "ru": 80, "fi": 40, "gw": 500})

		units := kernelUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()))
		if len(units) != 1 || units[0].Policy != tc.wantP || units[0].Iface["gw"] != "" {
			t.Fatalf("%s: units %+v", tc.mode, units)
		}
		s.attachThroughput(units)
		if tc.wantP != failover.PolicyLatency && units[0].Throughput["ru"].ThroughputKbps != 80_000 {
			t.Fatalf("%s: samples %+v", tc.mode, units[0].Throughput)
		}
		s.listFailoverTick(context.Background())
		if want := []string{"v4 " + tc.want + " " + itoa(table)}; !reflect.DeepEqual(tables.writes, want) {
			t.Errorf("%s (awg1 %d ms): writes %v, want %v", tc.mode, tc.awg1, tables.writes, want)
		}
	}
}

// A fastest list on the nft plane elects by throughput into its own table.
func TestOpenWrtFastestListElectsByThroughput(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru", "fi", "gw"}
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Mode: model.ElectionThroughput, Targets: []string{"149.154.167.51:443"}}
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("tg-calls"))
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: "awg0", egressTable(t, plan, "ru"): "awg1"})}
	tables.probes = handshakes("149.154.167.51:443", map[string]int{"awg0": -1, "awg1": 95, "awg2": 38})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	seedThroughput(s, map[string]float64{"nl": 20, "ru": 80, "fi": 40, "gw": 500})
	s.listFailoverTick(context.Background())
	if want := []string{"v4 awg1 " + itoa(list)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want %v", tables.writes, want)
	}
	if st := s.fastestStates()["tg-calls"]; st.Current != "ru" {
		t.Fatalf("state %+v", st)
	}
}

// coreProbeConfig writes a core config with the probe inbound for tags at the server's config path.
func coreProbeConfig(t *testing.T, s *Server, port int, tags ...string) {
	t.Helper()
	users := []map[string]any{}
	for _, tag := range tags {
		users = append(users, map[string]any{"username": generator.ProbeUser(tag), "password": "pw"})
	}
	raw, err := json.Marshal(map[string]any{"inbounds": []map[string]any{
		{"type": "mixed", "tag": generator.ProbeInboundTag, "listen": "127.0.0.1", "listen_port": port, "users": users}}})
	if err != nil {
		t.Fatal(err)
	}
	path := s.config().SingBox.Config
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A connection that exists only inside the proxy core is measured through the core's own outbound
// on OpenWrt, with the same bounds and the same budget as a bound download; where that cannot be
// done the reason is told, and no group, list or schedule spends the budget on it.
func TestOpenWrtCoreOnlyConnectionIsMeasuredThroughTheCore(t *testing.T) {
	s, seen := throughputServer(t, nil)
	s.cfg.Throughput.MaxBytes = 10_000_000
	ctx := context.Background()
	var exits []coreExit
	var coreOpts []speedtest.DownloadOptions
	s.throughputCoreRunOf = func(_ context.Context, exit coreExit, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
		exits, coreOpts = append(exits, exit), append(coreOpts, opts)
		return speedtest.DownloadResult{Source: "ovh", Bytes: 10_000_000, TotalBytes: 10_000_000, SteadyMbps: 55,
			Attempts: []speedtest.SourceAttempt{{Source: "ovh", Status: 200, Bytes: 10_000_000}}}, nil
	}
	running := true
	s.throughputCoreRunningOf = func() bool { return running }
	path := func(id string) (string, string) {
		p := s.store.Profile()
		native, known := s.currentNativeInterfaceBindings()
		return s.throughputPathOf(*p.EndpointByID(id), native, known)
	}

	// Not OpenWrt: as before.
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	coreProbeConfig(t, s, 17890, "core")
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if st := s.throughput.tunnels["core"]; len(exits) != 0 || st.Reason != reasonNoInterface {
		t.Fatalf("KeeneticOS: measured through the core (%v) or reason %q", exits, st.Reason)
	}
	if via, why := path("core"); via != "" || why != reasonNoInterface {
		t.Fatalf("KeeneticOS path: %q %q", via, why)
	}

	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	// The core is down.
	running = false
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if st := s.throughput.tunnels["core"]; len(exits) != 0 || st.Reason != reasonCoreDown {
		t.Fatalf("core down: %v, reason %q", exits, st.Reason)
	}
	// The running config has no probe user for it (applied before the connection existed).
	running = true
	coreProbeConfig(t, s, 17890, "other")
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if st := s.throughput.tunnels["core"]; len(exits) != 0 || st.Reason != reasonNeedApply {
		t.Fatalf("no probe user: %v, reason %q", exits, st.Reason)
	}
	if via, why := path("core"); via != "" || why != reasonNeedApply {
		t.Fatalf("path without a probe user: %q %q", via, why)
	}

	// Measurable.
	coreProbeConfig(t, s, 17890, "core", "nl")
	if via, why := path("core"); via != throughputViaCore || why != "" {
		t.Fatalf("path: %q %q", via, why)
	}
	if via, _ := path("nl"); via != throughputViaInterface {
		t.Fatalf("a tunnel with a link goes by %q", via)
	}
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if len(exits) != 1 || exits[0] != (coreExit{port: 17890, user: "x-core", password: "pw"}) || len(seen.ids) != 0 {
		t.Fatalf("exits %+v, bound runs %v", exits, seen.ids)
	}
	budget := throughputBudgetBytes(throughputSettings(s.config()))
	if o := coreOpts[0]; o.MaxBytes != 10_000_000 || o.MaxTotalBytes != budget || o.Network != "tcp4" || o.MaxDuration != 20*time.Second {
		t.Fatalf("the core run's bounds differ from a bound run's: %+v", o)
	}
	st := s.throughput.tunnels["core"]
	if st.Reason != "" || st.Success.SteadyMbps != 55 || st.SuccessAt == 0 {
		t.Fatalf("state %+v", st)
	}
	if _, used, _ := s.throughputUsage(s.throughputNow(), throughputSettings(s.config())); used != 10_000_000 {
		t.Fatalf("the month was charged %d bytes", used)
	}

	// A group's run does not spend on a member that is no candidate of the election.
	p := s.store.Profile()
	p.Groups[0].Members = []string{"nl", "core"}
	if err := s.store.Replace(p); err != nil {
		t.Fatal(err)
	}
	s.runThroughputScope(ctx, throughputRequest{Scope: "group", ID: "g"})
	if len(exits) != 1 || !reflect.DeepEqual(seen.ids, []string{"nl"}) {
		t.Fatalf("group run: core runs %d, bound runs %v", len(exits), seen.ids)
	}

	// The API says which way each connection is measured, and why one cannot be.
	var body struct {
		Measurable   []string          `json:"measurable"`
		Via          map[string]string `json:"via"`
		Unmeasurable map[string]string `json:"unmeasurable"`
	}
	get := func() {
		rec := httptest.NewRecorder()
		s.handleThroughput(rec, httptest.NewRequest(http.MethodGet, "/api/throughput", nil))
		body.Measurable, body.Via, body.Unmeasurable = nil, nil, nil
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
	}
	get()
	if body.Via["core"] != "core" || body.Via["nl"] != "interface" || len(body.Unmeasurable) != 0 || len(body.Measurable) != 4 {
		t.Fatalf("API: %+v", body)
	}
	running = false
	get()
	if body.Unmeasurable["core"] != reasonCoreDown || body.Via["core"] != "" || len(body.Measurable) != 3 {
		t.Fatalf("API with the core down: %+v", body)
	}
}

// fakeCoreProxy is the core's probe inbound as the download meets it: an HTTP proxy on loopback that
// accepts CONNECT from one user and relays the tunnel. preface, when set, is sent with the answer.
func fakeCoreProxy(t *testing.T, user, password string, preface []byte) (port int, connects *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	connects = &atomic.Int64{}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if req.Header.Get("Proxy-Authorization") != want {
					_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					return
				}
				up, err := net.Dial("tcp4", req.Host)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				connects.Add(1)
				_, _ = c.Write(append([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), preface...))
				var wg sync.WaitGroup
				wg.Add(1)
				go func() { defer wg.Done(); _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
				_ = c.(*net.TCPConn).CloseWrite()
				wg.Wait()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, connects
}

// The dial through the core: one CONNECT as the exit's user, the tunnel handed over whole (bytes
// that arrive with the answer too), a refusal and an answer that never ends reported as errors.
func TestCoreProxyDial(t *testing.T) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	port, connects := fakeCoreProxy(t, "x-gw", "pw", []byte("early"))
	ctx := context.Background()
	conn, err := coreProxyDial(coreExit{port: port, user: "x-gw", password: "pw"})(ctx, "tcp4", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 10)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "earlyhello" {
		t.Fatalf("through the tunnel: %q, %v", got, err)
	}
	if connects.Load() != 1 {
		t.Fatalf("%d tunnels opened", connects.Load())
	}
	// Another exit's user is refused by the core, and the download does not start.
	if _, err := coreProxyDial(coreExit{port: port, user: "x-other", password: "pw"})(ctx, "tcp4", echo.Addr().String()); err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("a refused CONNECT: %v", err)
	}
	// Nothing listens: an error, not a direct connection.
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := coreProxyDial(coreExit{port: 1, user: "x-gw", password: "pw"})(short, "tcp4", echo.Addr().String()); err == nil {
		t.Fatal("no probe port and no error")
	}
	// An answer that does not end is cut at its bound.
	flood, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer flood.Close()
	go func() {
		c, err := flood.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n"))
		junk := []byte("X-Fill: " + strings.Repeat("a", 500) + "\r\n")
		for i := 0; i < 64; i++ {
			if _, err := c.Write(junk); err != nil {
				return
			}
		}
	}()
	if _, err := coreProxyDial(coreExit{port: flood.Addr().(*net.TCPAddr).Port, user: "x-gw", password: "pw"})(ctx, "tcp4", echo.Addr().String()); err == nil {
		t.Fatal("an endless answer to CONNECT was accepted")
	}
}

// The reference router has 239 MB of RAM and about 68 MB free. A 100 MB download through the core's probe
// inbound keeps the one fixed 64 KB buffer: the heap does not follow the body, in use or in total.
func TestCoreThroughputOf100MBKeepsAFixedBuffer(t *testing.T) {
	if speedtest.DownloadBufferSize != 64<<10 {
		t.Fatalf("the download buffer is %d bytes, not 64 KB", speedtest.DownloadBufferSize)
	}
	const size = speedtest.DefaultDownloadBytes // 100 MB
	chunk := make([]byte, 64<<10)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for left := int64(2 * size); left > 0; left -= int64(len(chunk)) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer source.Close()
	port, connects := fakeCoreProxy(t, "x-gw", "pw", nil)
	prev := throughputResolve
	throughputResolve = func(_ context.Context, addr string) (string, error) { return addr, nil }
	t.Cleanup(func() { throughputResolve = prev })
	s := &Server{}
	opts := speedtest.DownloadOptions{MaxBytes: 256 << 10, MaxDuration: time.Minute, Warmup: 10 * time.Millisecond, MinObjectBytes: 1,
		Sources: []speedtest.DownloadSource{{ID: "test", URL: source.URL}}}
	exit := coreExit{port: port, user: "x-gw", password: "pw"}
	if _, err := s.runCoreThroughput(context.Background(), exit, opts); err != nil {
		t.Fatalf("warm-up run: %v", err)
	}

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	opts.MaxBytes = size
	res, err := s.runCoreThroughput(context.Background(), exit, opts)
	close(stop)
	<-done
	if err != nil || res.Bytes != size {
		t.Fatalf("100 MB through the core: %d bytes, %v", res.Bytes, err)
	}
	if connects.Load() < 2 {
		t.Fatalf("the download did not go through the proxy: %d tunnels", connects.Load())
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// The proxy and the source of this test live in the same process and are counted too.
	if grew := int64(peak.Load()) - int64(before.HeapAlloc); grew > 16<<20 {
		t.Errorf("the heap peaked %d bytes above its start during a %d-byte download", grew, size)
	}
	if total := after.TotalAlloc - before.TotalAlloc; total > uint64(size)/2 {
		t.Errorf("%d bytes were allocated for a %d-byte download: the body is being copied into new memory", total, size)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if kept := int64(after.HeapAlloc) - int64(before.HeapAlloc); kept > 1<<20 {
		t.Errorf("%d bytes stay allocated after the download", kept)
	}
}

// The reasons of the core path are classified for the panel.
func TestThroughputReasonOfTheCorePath(t *testing.T) {
	for err, want := range map[error]string{errThroughputCoreDown: reasonCoreDown, errThroughputNeedApply: reasonNeedApply, errThroughputNoInterface: reasonNoInterface} {
		if got := throughputReason(speedtest.DownloadResult{}, err, true); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	if !errors.Is(errThroughputCoreDown, errThroughputCoreDown) {
		t.Fatal("unreachable")
	}
}

// A measurement through the core is capped at its own, lower volume and does not start while the
// router is short of memory; it says why. A bound download keeps the configured volume.
func TestOpenWrtCoreMeasurementHasAMemoryGate(t *testing.T) {
	s, seen := throughputServer(t, nil)
	s.cfg.Throughput.MaxBytes = 100_000_000
	ctx := context.Background()
	var coreOpts []speedtest.DownloadOptions
	s.throughputCoreRunOf = func(_ context.Context, _ coreExit, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
		coreOpts = append(coreOpts, opts)
		return speedtest.DownloadResult{Source: "ovh", Bytes: 1_000_000, TotalBytes: 1_000_000, SteadyMbps: 20,
			Attempts: []speedtest.SourceAttempt{{Source: "ovh", Status: 200, Bytes: 1_000_000}}}, nil
	}
	s.throughputCoreRunningOf = func() bool { return true }
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	coreProbeConfig(t, s, 17890, "core", "nl")
	avail, readable := int64(40<<20), true
	s.throughputMemAvailableOf = func() (int64, bool) { return avail, readable }

	// Under the default floor of 48 MB: refused before any byte, with a reason of its own.
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	st := s.throughput.tunnels["core"]
	if len(coreOpts) != 0 || st.Reason != reasonLowMemory || !strings.Contains(st.Error, "40 MB available, 48 MB needed") {
		t.Fatalf("low memory: ran %d, state %+v", len(coreOpts), st)
	}
	if got := throughputReason(speedtest.DownloadResult{}, fmt.Errorf("x: %w", errThroughputLowMemory), true); got != reasonLowMemory {
		t.Fatalf("reason %q", got)
	}

	// Enough memory: runs, capped at the core's default 25 MB rather than the configured 100 MB.
	avail = 200 << 20
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if len(coreOpts) != 1 || coreOpts[0].MaxBytes != 25_000_000 {
		t.Fatalf("core run opts %+v", coreOpts)
	}
	// The cap and the floor are tunable.
	s.cfg.Throughput.CoreMaxBytes, s.cfg.Throughput.CoreMinFreeMB = 5_000_000, 300
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if st := s.throughput.tunnels["core"]; len(coreOpts) != 1 || st.Reason != reasonLowMemory {
		t.Fatalf("raised floor: ran %d, reason %q", len(coreOpts), st.Reason)
	}
	s.cfg.Throughput.CoreMinFreeMB = 0
	readable = false // meminfo unreadable: only the cap applies
	avail = 0
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "core"})
	if len(coreOpts) != 2 || coreOpts[1].MaxBytes != 5_000_000 {
		t.Fatalf("tuned cap: %+v", coreOpts)
	}

	// An interface-bound download is untouched by both, even with no memory to spare.
	readable, avail = true, 1<<20
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	if len(seen.opts) != 1 || seen.opts[0].MaxBytes != 100_000_000 {
		t.Fatalf("bound run %+v", seen.opts)
	}
}
