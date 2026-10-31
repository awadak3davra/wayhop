package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/model"
)

func TestCoreMinor(t *testing.T) {
	for _, tc := range []struct {
		in     string
		minor  int
		modern bool
	}{
		{"", -1, false},
		{"garbage", -1, false},
		{"1.12.17", 12, false},
		{"v1.13.21", 13, false},
		{"1.14.0", 14, true},
		{"1.14.3", 14, true},
		{"1.15.0-alpha.12", 15, true},
		{"sing-box version 1.14.3\n\nEnvironment: go1.25.1 linux/amd64\nTags: with_quic", 14, true},
		{"sing-box version 1.12.17\n\nEnvironment: go1.24.9 linux/arm64", 12, false},
		{"2.0.0", -1, false}, // a future major is not assumed to keep the 1.x schema
	} {
		if got := coreMinor(tc.in); got != tc.minor {
			t.Errorf("coreMinor(%q) = %d, want %d", tc.in, got, tc.minor)
		}
		if got := modernCore(tc.in); got != tc.modern {
			t.Errorf("modernCore(%q) = %v, want %v", tc.in, got, tc.modern)
		}
	}
}

// modernCoreProfile carries every construct the 1.14+ schema rewrites: a FakeIP DNS plane (which
// forces independent_cache), remote rule-sets fetched direct, through a tunnel, and through the
// profile-wide default, and a geosite rule (whose remote set is fetched direct).
func modernCoreProfile() *model.Profile {
	p := allProtocolProfile()
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "rd", Name: "Direct", Source: "https://example.com/direct.srs", Outbound: "p-vless", Enabled: true},
		model.RoutingList{ID: "rt", Name: "Tunnel", Source: "https://example.com/tunnel.json", DownloadVia: "p-trojan", Outbound: "g", Enabled: true},
	)
	p.Rules = append([]model.Rule{{ID: "geo", GeoSite: []string{"category-ads-all"}, Outbound: model.OutboundBlock}}, p.Rules...)
	dns := secureDNS()
	dns.FakeIP = true
	dns.IndependentCache = true
	dns.Servers[0].Detour, dns.Servers[1].Detour = "g", "g"
	dns.Servers = append(dns.Servers, model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	dns.Rules = []model.DNSRule{{ID: "fx", RuleSets: []string{"rt"}, Server: "fake"}, {ID: "lc", RuleSets: []string{"rd"}, Server: "local"}}
	p.DNS = dns
	return p
}

func TestModernCoreSchema(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache.db")
	opts := func(v string) Options {
		return Options{MixedPort: 7890, TunEnabled: true, CoreVersion: v, CacheFile: cache}
	}
	legacy, err := Generate(modernCoreProfile(), opts(""))
	if err != nil {
		t.Fatalf("generate (unknown core): %v", err)
	}
	pinned, err := Generate(modernCoreProfile(), opts("1.12.17"))
	if err != nil {
		t.Fatalf("generate (1.12.17): %v", err)
	}
	// Unknown and 1.12.x must render the very same bytes: the gate is a no-op until a caller opts in.
	lb, _ := json.Marshal(legacy.Config)
	pb, _ := json.Marshal(pinned.Config)
	if string(lb) != string(pb) {
		t.Fatalf("CoreVersion 1.12.17 changed the output; it must equal the unknown-core output")
	}
	if legacy.Config["dns"].(map[string]any)["independent_cache"] != true {
		t.Fatalf("1.12 form lost independent_cache (FakeIP pairs it there)")
	}
	if _, ok := legacy.Config["http_clients"]; ok {
		t.Fatalf("1.12 form must not carry http_clients (an unknown field before 1.14)")
	}

	modern, err := Generate(modernCoreProfile(), opts("1.14.3"))
	if err != nil {
		t.Fatalf("generate (1.14.3): %v", err)
	}
	if _, ok := modern.Config["dns"].(map[string]any)["independent_cache"]; ok {
		t.Errorf("1.14+ form still emits independent_cache (fatal on 1.15)")
	}
	route := modern.Config["route"].(map[string]any)
	want := map[string]string{ // rule-set tag -> http client it must download through
		"rs-rd":                    "rs-dl-direct",
		"rs-rt":                    "rs-dl-p-trojan",
		"geosite-category-ads-all": "rs-dl-direct",
	}
	remote := 0
	for _, s := range route["rule_set"].([]map[string]any) {
		if s["type"] != "remote" {
			continue
		}
		remote++
		if _, ok := s["download_detour"]; ok {
			t.Errorf("rule-set %v still carries download_detour (fatal on 1.15 at fetch time)", s["tag"])
		}
		tag, _ := s["tag"].(string)
		if w, ok := want[tag]; ok && s["http_client"] != w {
			t.Errorf("rule-set %s: http_client = %v, want %s", tag, s["http_client"], w)
		}
		if s["http_client"] == nil {
			t.Errorf("remote rule-set %s has no http_client", tag)
		}
	}
	if remote < 3 {
		t.Fatalf("profile should yield at least 3 remote rule-sets, got %d", remote)
	}
	gotClients := modern.Config["http_clients"].([]map[string]any)
	wantClients := []map[string]any{
		{"tag": "rs-dl-direct"}, // no detour: an http client may not detour to the empty direct outbound
		{"tag": "rs-dl-p-trojan", "detour": "p-trojan"},
	}
	if !reflect.DeepEqual(gotClients, wantClients) {
		t.Errorf("http_clients = %v, want %v", gotClients, wantClients)
	}
	// RuleSetDetour (the profile-wide default) flows through the same rewrite.
	viaDefault, err := Generate(modernCoreProfile(), Options{MixedPort: 7890, CoreVersion: "1.15.0-alpha.12", RuleSetDetour: "sel"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range viaDefault.Config["http_clients"].([]map[string]any) {
		if c["tag"] == "rs-dl-sel" && c["detour"] == "sel" {
			found = true
		}
	}
	if !found {
		t.Errorf("RuleSetDetour=sel did not become an http client: %v", viaDefault.Config["http_clients"])
	}
}

// singboxVersionOf asks the binary for its version, so a gated test can render the schema that
// binary wants. Fails the test when the binary does not answer like sing-box.
func singboxVersionOf(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "sing-box version ") {
		t.Fatalf("%s version: %v\n%s", bin, err, out)
	}
	return string(out)
}

// TestCoreVersionSingBoxCheck renders the full profile (every protocol, FakeIP DNS, remote rule-sets
// over direct and over a tunnel) for the version WR_SINGBOX reports, and runs the real check on it.
// On 1.12/1.13 that is the legacy form; on 1.14+ (incl. a 1.15 pre-release, which refuses the legacy
// independent_cache) it is the rewritten one. A deprecation warning from the binary fails the test
// too: a warning today is the startup FATAL of the next minor.
func TestCoreVersionSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	res, err := Generate(modernCoreProfile(), Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "core-version.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the config rendered for %q: %v\n%s", strings.SplitN(ver, "\n", 2)[0], err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field in the config rendered for its own version:\n%s", out)
	}
}

// TestCoreVersionRuleSetFetch RUNS the core (`check` never downloads a rule-set, and the 1.15
// download_detour refusal only fires on the first fetch) on a config with two remote rule-sets: one
// fetched direct, one fetched through a SOCKS endpoint that points back at the core's own mixed
// inbound, i.e. through a detour. Both must reach a local HTTP server before the core settles. The
// config is rendered for the version WR_SINGBOX reports, so 1.12/1.13 prove download_detour and 1.14+
// prove the http_clients rewrite. No TUN, no network beyond loopback.
func TestCoreVersionRuleSetFetch(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary to run the core")
	}
	ver := singboxVersionOf(t, bin)
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":1,"rules":[{"domain_suffix":["example.com"]}]}`))
	}))
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	// The detour: a SOCKS5 server in this process. (Not the core's own mixed inbound — sing-box
	// fetches rule-sets before it starts its inbounds.) It counts the connections it relays, which
	// proves the second set really travelled through the detour.
	socks, relayed := startTestSOCKS5(t)

	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "loop", Name: "loop", Engine: model.EngineSingBox, Protocol: model.ProtoSOCKS,
			Server: "127.0.0.1", Port: socks, Enabled: true, Params: map[string]any{}}},
		RoutingLists: []model.RoutingList{
			{ID: "d", Name: "D", Source: srv.URL + "/direct.json", Outbound: "loop", Enabled: true},
			{ID: "t", Name: "T", Source: srv.URL + "/tunnel.json", DownloadVia: "loop", Outbound: "loop", Enabled: true},
		},
		Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
	}
	dir := t.TempDir()
	res, err := Generate(p, Options{MixedPort: mixed, CoreVersion: ver, CacheFile: filepath.Join(dir, "cache.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	res.Config["log"] = map[string]any{"level": "info"}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(dir, "run.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "run", "-c", f)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	fetched := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return hits["/direct.json"] > 0 && hits["/tunnel.json"] > 0
	}
	deadline := time.Now().Add(20 * time.Second)
	for !fetched() && time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("sing-box exited before fetching both rule-sets (%v):\n%s", err, out.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
	// Give a fetch that FATALs after the request (a refused deprecated field) time to surface.
	select {
	case err := <-exited:
		t.Fatalf("sing-box exited after fetching (%v):\n%s", err, out.String())
	case <-time.After(1500 * time.Millisecond):
	}
	_ = cmd.Process.Kill()
	<-exited
	if !fetched() {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("rule-sets not fetched within 20s (hits %v):\n%s", hits, out.String())
	}
	if relayed() == 0 {
		t.Fatalf("the detoured rule-set did not go through the SOCKS detour:\n%s", out.String())
	}
	if s := out.String(); strings.Contains(s, "FATAL") || strings.Contains(s, "deprecated") {
		t.Fatalf("sing-box reported a fatal or deprecated field while fetching:\n%s", s)
	}
}

// startTestSOCKS5 serves a minimal no-auth SOCKS5 CONNECT relay on loopback for the test's lifetime
// and returns its port plus a counter of relayed connections.
func startTestSOCKS5(t *testing.T) (int, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	n := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				buf := make([]byte, 262)
				// greeting: VER NMETHODS METHODS...
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
					return
				}
				if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				// request: VER CMD RSV ATYP ADDR PORT
				if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					if _, err := io.ReadFull(c, buf[:4]); err != nil {
						return
					}
					host = net.IP(buf[:4]).String()
				case 3:
					if _, err := io.ReadFull(c, buf[:1]); err != nil {
						return
					}
					l := int(buf[0])
					if _, err := io.ReadFull(c, buf[:l]); err != nil {
						return
					}
					host = string(buf[:l])
				case 4:
					if _, err := io.ReadFull(c, buf[:16]); err != nil {
						return
					}
					host = net.IP(buf[:16]).String()
				default:
					return
				}
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				mu.Lock()
				n++
				mu.Unlock()
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// The TUN `stack` option: 1.15 deprecates it (removal 1.17), so 1.16 refuses to start with it. It is
// kept, with the measured stack, on every core that accepts it, and dropped only from 1.16.
func TestFitTUNToCore(t *testing.T) {
	stackOf := func(v string) (any, bool) {
		t.Helper()
		res, err := Generate(modernCoreProfile(), Options{MixedPort: 7890, TunEnabled: true, CoreVersion: v})
		if err != nil {
			t.Fatalf("generate (%q): %v", v, err)
		}
		for _, in := range res.Config["inbounds"].([]map[string]any) {
			if in["type"] == "tun" {
				st, ok := in["stack"]
				return st, ok
			}
		}
		t.Fatalf("generate (%q): no TUN inbound", v)
		return nil, false
	}
	for _, v := range []string{"", "1.12.17", "1.13.21", "1.14.4", "1.15.0-alpha.13"} {
		if st, ok := stackOf(v); !ok || st != "system" {
			t.Errorf("core %q: stack = %v (present %v), want the measured system stack kept", v, st, ok)
		}
	}
	if st, ok := stackOf("1.16.0"); ok {
		t.Errorf("core 1.16.0: stack = %v, want it dropped (the core refuses it)", st)
	}
	// A config decoded from JSON (the KeeneticOS fallback core is carried encoded) is fitted the same.
	decoded := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "stack": "gvisor"}, map[string]any{"type": "mixed"}}}
	FitTUNToCore(decoded, "1.16.1")
	if _, ok := decoded["inbounds"].([]any)[0].(map[string]any)["stack"]; ok {
		t.Error("decoded TUN inbound kept its stack on 1.16")
	}
}
