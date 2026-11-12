package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/nativedns"
)

const chainMainFixture = "no-resolv\nstrict-order\nserver=1.1.1.1\nserver=8.8.8.8\nconf-dir=/opt/etc/dnsmasq.d,*.conf\n"

// chainServer is a Server whose dnsmasq lives in a temp dir, with netstat saying it holds :53.
func chainServer(t *testing.T) (*Server, *nativedns.ChainHost, *int) {
	t.Helper()
	s := bindTestServer(t, feedProfile(), "")
	root := t.TempDir()
	confDir := filepath.Join(root, "dnsmasq.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	host := &nativedns.ChainHost{
		MainConf:     filepath.Join(root, "dnsmasq.conf"),
		UpstreamConf: filepath.Join(confDir, "00-upstream.conf"),
		ConfDir:      confDir,
		StateDir:     filepath.Join(root, "state"),
		Test:         func(context.Context) (string, error) { return "", nil },
		Restart:      func(context.Context) error { restarts++; return nil },
		Trial:        func(context.Context, nativedns.ChainRow) error { return nil },
		Verify:       func(context.Context) error { return nil },
	}
	if err := os.WriteFile(host.MainConf, []byte(chainMainFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	s.chainHostOf = func() nativedns.ChainHost { return *host }
	s.dnsPlatformOf = func() string { return "keenetic" }
	s.ifindexOf = func(string) int { return 7 }
	s.dnsRunnerOf = func(name string, args ...string) (string, error) {
		joined := name + " " + strings.Join(args, " ")
		switch {
		case name == "netstat":
			return "udp 0 0 0.0.0.0:53 0.0.0.0:* 951/dnsmasq\n", nil
		case strings.Contains(joined, "dnsmasq.conf"):
			main, _ := os.ReadFile(host.MainConf)
			up, _ := os.ReadFile(host.UpstreamConf)
			return string(main) + "\n" + nativedns.DnsmasqDirSentinel + "\n" + string(up), nil
		}
		return "", nil
	}
	return s, host, &restarts
}

func postJSON(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data)))
	return w
}

// What a row becomes: an endpoint its link, a group its members in order, a group's direct a row bound
// to nothing. The interface is never taken from the operator for a named outbound.
func TestExpandChainRows(t *testing.T) {
	p := feedProfile()
	for _, tc := range []struct {
		name string
		in   []chainRowReq
		want []nativedns.ChainRow
	}{
		{"plain", []chainRowReq{{Address: "1.1.1.1"}, {Address: "8.8.8.8", Via: "direct"}},
			[]nativedns.ChainRow{{Address: "1.1.1.1"}, {Address: "8.8.8.8"}}},
		{"endpoint", []chainRowReq{{Address: "1.1.1.1", Via: "fin"}}, []nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}}},
		{"group", []chainRowReq{{Address: "1.1.1.1", Via: "main"}},
			[]nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}, {Address: "1.1.1.1", Iface: "nwg0"}}},
		{"group ending in direct", []chainRowReq{{Address: "1.1.1.1", Via: "main-wan"}},
			[]nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}, {Address: "1.1.1.1"}}},
		{"local with a port", []chainRowReq{{Address: "127.0.0.1", Port: 5053}}, []nativedns.ChainRow{{Address: "127.0.0.1", Port: 5053}}},
		{"a binding the profile does not know stays", []chainRowReq{{Address: "1.1.1.1", Iface: "tun7"}}, []nativedns.ChainRow{{Address: "1.1.1.1", Iface: "tun7"}}},
		{"the same line twice is one line", []chainRowReq{{Address: "1.1.1.1", Via: "fin"}, {Address: "1.1.1.1", Via: "main"}},
			[]nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}, {Address: "1.1.1.1", Iface: "nwg0"}}},
	} {
		got, err := expandChainRows(&p, tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
	for name, in := range map[string]chainRowReq{
		"proxy":        {Address: "1.1.1.1", Via: "vless-de"},
		"proxies":      {Address: "1.1.1.1", Via: "proxies"},
		"switched off": {Address: "1.1.1.1", Via: "off"},
		"gone":         {Address: "1.1.1.1", Via: "gone"},
	} {
		if got, err := expandChainRows(&p, []chainRowReq{in}); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
}

func TestChainWarnings(t *testing.T) {
	dnsmasq := nativedns.Answering{Plane: nativedns.PlaneNative, Process: "dnsmasq"}
	bound := nativedns.ChainRow{Address: "1.1.1.1", Iface: "nwg1"}
	plain := nativedns.ChainRow{Address: "8.8.8.8"}
	for _, tc := range []struct {
		name string
		rows []nativedns.ChainRow
		plan nativedns.ChainPlan
		ans  nativedns.Answering
		want string
	}{
		{"plaintext first", []nativedns.ChainRow{plain, bound}, nativedns.ChainPlan{}, dnsmasq, "over your provider in plaintext"},
		{"plaintext last resort", []nativedns.ChainRow{bound, plain}, nativedns.ChainPlan{}, dnsmasq, "fall to 8.8.8.8"},
		{"no last resort", []nativedns.ChainRow{bound}, nativedns.ChainPlan{}, dnsmasq, "resolves nothing"},
		{"the retry a silent tunnel costs", []nativedns.ChainRow{bound}, nativedns.ChainPlan{}, dnsmasq, "client retry"},
		{"another program on :53", []nativedns.ChainRow{bound}, nativedns.ChainPlan{}, nativedns.Answering{Plane: nativedns.PlaneCore, Process: "sing-box"}, "will not reach clients"},
		{"unknown", []nativedns.ChainRow{bound}, nativedns.ChainPlan{}, nativedns.Answering{Plane: nativedns.PlaneUnknown}, "unconfirmed"},
		{"foreign files", []nativedns.ChainRow{bound}, nativedns.ChainPlan{Foreign: []string{"10-x.conf: 4.4.4.4"}}, dnsmasq, "10-x.conf"},
		{"WayHop resolver without a fallback", []nativedns.ChainRow{{Address: "127.0.0.1", Port: 5353}}, nativedns.ChainPlan{}, dnsmasq, "household has no DNS"},
	} {
		got := strings.Join(chainWarnings(tc.rows, tc.plan, tc.ans, 5353), " | ")
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q lacks %q", tc.name, got, tc.want)
		}
	}
	withFallback := strings.Join(chainWarnings([]nativedns.ChainRow{{Address: "127.0.0.1", Port: 5353}, plain}, nativedns.ChainPlan{}, dnsmasq, 5353), " | ")
	if strings.Contains(withFallback, "household has no DNS") {
		t.Errorf("a fallback behind the encrypted row still warned: %q", withFallback)
	}
	customPort := strings.Join(chainWarnings([]nativedns.ChainRow{{Address: "127.0.0.1", Port: 6053}}, nativedns.ChainPlan{}, dnsmasq, 6053), " | ")
	if !strings.Contains(customPort, "household has no DNS") {
		t.Errorf("a custom DNS port did not get the no-fallback warning: %q", customPort)
	}
}

// The page's whole picture: who answers, what the rows are bound to, and what can be chosen.
func TestGetDNSNativeNamesThePlaneAndTheChain(t *testing.T) {
	s, host, _ := chainServer(t)
	if err := os.WriteFile(host.UpstreamConf, []byte("server=9.9.9.9@nwg1\nserver=4.4.4.4@tun7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host.MainConf, []byte("conf-dir=/opt/etc/dnsmasq.d,*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.ifindexOf = func(name string) int {
		if name == "tun7" {
			return 0
		}
		return 7
	}
	w := httptest.NewRecorder()
	s.handleGetDNSNative(w, httptest.NewRequest(http.MethodGet, "/api/dns/native", nil))
	var resp struct {
		Answering nativedns.Answering `json:"answering"`
		Native    nativedns.NativeDNS `json:"native"`
		Chain     struct {
			Editable bool           `json:"editable"`
			Rev      string         `json:"rev"`
			Rows     []chainRowView `json:"rows"`
			Vias     []chainVia     `json:"vias"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if resp.Answering.Plane != nativedns.PlaneNative || resp.Answering.Process != "dnsmasq" {
		t.Errorf("answering %+v", resp.Answering)
	}
	if !resp.Chain.Editable || resp.Chain.Rev == "" {
		t.Errorf("chain %+v", resp.Chain)
	}
	if len(resp.Chain.Rows) != 2 || resp.Chain.Rows[0].Via != "fin" || resp.Chain.Rows[1].Via != "" || resp.Chain.Rows[1].Iface != "tun7" {
		t.Fatalf("rows %+v", resp.Chain.Rows)
	}
	if resp.Chain.Rows[0].LinkAbsent || !resp.Chain.Rows[1].LinkAbsent {
		t.Errorf("link state: %+v", resp.Chain.Rows)
	}
	// A row bound to a known tunnel reads as hidden, not as the plaintext fallback its kind suggests.
	if !resp.Native.Resolvers[0].ViaTunnel || resp.Native.Resolvers[1].ViaTunnel {
		t.Errorf("via_tunnel: %+v", resp.Native.Resolvers)
	}
	ids := map[string]bool{}
	for _, v := range resp.Chain.Vias {
		ids[v.ID] = true
	}
	if !ids["fin"] || !ids["main"] || !ids["main-wan"] {
		t.Errorf("vias %+v", resp.Chain.Vias)
	}
	// dnsmasq cannot bind to what sing-box carries, so it is not offered.
	if ids["vless-de"] || ids["proxies"] || ids["off"] {
		t.Errorf("offered something that cannot be bound: %+v", resp.Chain.Vias)
	}
}

// The same chain written by hand in the main config offers the connections it is bound to, so editing
// one row on the page cannot lose the others' tunnels.
func TestChainViewReadsAHandWrittenChainInTheMainConfig(t *testing.T) {
	s, host, _ := chainServer(t)
	main := "no-resolv\nstrict-order\nserver=1.1.1.1@nwg1\nserver=8.8.8.8@nwg0\nserver=1.0.0.1\nconf-dir=/opt/etc/dnsmasq.d,*.conf\n"
	if err := os.WriteFile(host.MainConf, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleGetDNSNative(w, httptest.NewRequest(http.MethodGet, "/api/dns/native", nil))
	var resp struct {
		Native nativedns.NativeDNS `json:"native"`
		Chain  struct {
			Rows []chainRowView `json:"rows"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	want := []chainRowView{{Address: "1.1.1.1", Via: "fin", Iface: "nwg1"}, {Address: "8.8.8.8", Via: "cyp", Iface: "nwg0"}, {Address: "1.0.0.1"}}
	if !reflect.DeepEqual(resp.Chain.Rows, want) {
		t.Fatalf("rows %+v, want %+v", resp.Chain.Rows, want)
	}
	// What the page's verdict is read from: a tunnel first, not "plaintext, your provider can read it".
	if !resp.Native.Resolvers[0].ViaTunnel || resp.Native.Resolvers[2].ViaTunnel {
		t.Errorf("resolvers %+v", resp.Native.Resolvers)
	}
}

// A router that cannot take a chain says why rather than offering it.
func TestChainViewSaysWhyItCannotEdit(t *testing.T) {
	s, host, _ := chainServer(t)
	host.Usable = func() error { return os.ErrNotExist }
	p := s.store.Profile()
	view := s.chainViewOf(nativedns.NativeDNS{}, &p)
	if view["editable"] != false || view["reason"] == nil {
		t.Fatalf("view %+v", view)
	}
}

func TestDNSChainPlanChangesNothing(t *testing.T) {
	s, host, restarts := chainServer(t)
	w := postJSON(t, s.handleDNSChainPlan, map[string]any{"rows": []chainRowReq{{Address: "1.1.1.1", Via: "main-wan"}}})
	if w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	var resp struct {
		Plan     nativedns.ChainPlan `json:"plan"`
		Warnings []string            `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Plan.Lines, []string{"server=1.1.1.1@nwg1", "server=1.1.1.1"}) {
		t.Errorf("lines %v", resp.Plan.Lines)
	}
	if len(resp.Plan.Moved) != 4 || len(resp.Warnings) == 0 {
		t.Errorf("plan %+v warnings %v", resp.Plan, resp.Warnings)
	}
	if got, _ := os.ReadFile(host.MainConf); string(got) != chainMainFixture || *restarts != 0 {
		t.Errorf("a plan touched the router: %q, restarts %d", got, *restarts)
	}
}

func TestDNSChainSetWritesAndRestores(t *testing.T) {
	s, host, restarts := chainServer(t)
	rows := []chainRowReq{{Address: "1.1.1.1", Via: "fin"}, {Address: "8.8.8.8", Via: "cyp"}, {Address: "1.1.1.1"}}

	w := postJSON(t, s.handleDNSChainSet, map[string]any{"rows": rows, "rev": host.Rev()})
	var rep nativedns.ChainReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || !rep.OK {
		t.Fatalf("%d %s (%v)", w.Code, w.Body, err)
	}
	up, _ := os.ReadFile(host.UpstreamConf)
	for _, want := range []string{"server=1.1.1.1@nwg1\n", "server=8.8.8.8@nwg0\n", "server=1.1.1.1\n", "strict-order\n", "no-resolv\n"} {
		if !strings.Contains(string(up), want) {
			t.Errorf("chain lacks %q: %s", want, up)
		}
	}
	if *restarts != 1 || !host.Managed() {
		t.Errorf("restarts %d managed %v", *restarts, host.Managed())
	}

	w = postJSON(t, s.handleDNSChainRestore, map[string]any{"rev": host.Rev()})
	rep = nativedns.ChainReport{}
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || !rep.OK {
		t.Fatalf("%d %s (%v)", w.Code, w.Body, err)
	}
	if got, _ := os.ReadFile(host.MainConf); string(got) != chainMainFixture {
		t.Errorf("main config %q", got)
	}
	if host.Managed() {
		t.Error("still managed after a restore")
	}
}

// A write based on what the router held before something else changed it is refused. dnsmasq.conf has no
// other guardian: an edit made over SSH would otherwise vanish under a page opened earlier.
func TestDNSChainSetRefusesAStaleRead(t *testing.T) {
	s, host, restarts := chainServer(t)
	rows := []chainRowReq{{Address: "1.1.1.1", Via: "fin"}}
	for _, rev := range []string{"", "not-the-rev"} {
		w := postJSON(t, s.handleDNSChainSet, map[string]any{"rows": rows, "rev": rev})
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "STALE_CONFIG") {
			t.Errorf("rev %q: %d %s", rev, w.Code, w.Body)
		}
	}
	if got, _ := os.ReadFile(host.MainConf); string(got) != chainMainFixture || *restarts != 0 {
		t.Errorf("refused write touched the router: %q, %d", got, *restarts)
	}
}

// Apply writes the same conf-dir and restarts the same service, so the two take turns.
func TestDNSChainSetWaitsForApply(t *testing.T) {
	s, host, _ := chainServer(t)
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	w := postJSON(t, s.handleDNSChainSet, map[string]any{"rows": []chainRowReq{{Address: "1.1.1.1"}}, "rev": host.Rev()})
	if w.Code != http.StatusConflict {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestDNSChainHandlersRefuseOtherPlatforms(t *testing.T) {
	s, host, _ := chainServer(t)
	s.dnsPlatformOf = func() string { return "openwrt" }
	body := map[string]any{"rows": []chainRowReq{{Address: "1.1.1.1"}}, "rev": host.Rev()}
	for name, h := range map[string]http.HandlerFunc{"plan": s.handleDNSChainPlan, "set": s.handleDNSChainSet, "restore": s.handleDNSChainRestore} {
		if w := postJSON(t, h, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestDNSChainSetRefusesWhatCannotBeBound(t *testing.T) {
	s, host, restarts := chainServer(t)
	w := postJSON(t, s.handleDNSChainSet, map[string]any{"rows": []chainRowReq{{Address: "1.1.1.1", Via: "vless-de"}}, "rev": host.Rev()})
	if w.Code != http.StatusBadRequest || *restarts != 0 {
		t.Fatalf("%d %s, restarts %d", w.Code, w.Body, *restarts)
	}
}

// The guard's trigger, as measured on dnsmasq 2.90: a new index on a name it was bound to. A first
// sighting, an interface that appeared, and one that only went away need no restart.
func TestChainGuardRestartsOnlyWhenATunnelWasRecreated(t *testing.T) {
	s, host, restarts := chainServer(t)
	if rep := host.Apply(context.Background(), []nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}, {Address: "1.1.1.1"}}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	*restarts = 0
	index := 0
	s.ifindexOf = func(string) int { return index }
	seen := map[string]int{}
	tick := func(i int) {
		index = i
		s.chainGuardTick(context.Background(), seen)
	}

	tick(0) // absent at the first look: dnsmasq binds it when it appears
	tick(5) // it appeared
	tick(5) // nothing happened
	if *restarts != 0 {
		t.Fatalf("restarted %d times with nothing recreated", *restarts)
	}
	tick(0) // deleted
	if *restarts != 0 {
		t.Fatal("restarting over a missing interface achieves nothing")
	}
	tick(9) // back, as a new interface
	if *restarts != 1 {
		t.Fatalf("restarts = %d, want one for the new interface", *restarts)
	}
	tick(9)
	if *restarts != 1 {
		t.Fatalf("restarts = %d, once is enough", *restarts)
	}
	tick(12) // recreated while still present between ticks
	if *restarts != 2 {
		t.Fatalf("restarts = %d", *restarts)
	}
}

// Apply holds the lock: the restart waits for the next tick, and is not forgotten.
func TestChainGuardRetriesAfterApply(t *testing.T) {
	s, host, restarts := chainServer(t)
	if rep := host.Apply(context.Background(), []nativedns.ChainRow{{Address: "1.1.1.1", Iface: "nwg1"}}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	*restarts = 0
	index := 5
	s.ifindexOf = func(string) int { return index }
	seen := map[string]int{}
	s.chainGuardTick(context.Background(), seen)
	index = 9
	s.applyMu.Lock()
	s.chainGuardTick(context.Background(), seen)
	s.applyMu.Unlock()
	if *restarts != 0 {
		t.Fatal("restarted during Apply")
	}
	s.chainGuardTick(context.Background(), seen)
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
}

func TestChainGuardIgnoresAChainItDidNotWrite(t *testing.T) {
	s, host, restarts := chainServer(t)
	if err := os.WriteFile(host.UpstreamConf, []byte("server=1.1.1.1@nwg1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	index := 5
	s.ifindexOf = func(string) int { return index }
	seen := map[string]int{}
	s.chainGuardTick(context.Background(), seen)
	index = 9
	s.chainGuardTick(context.Background(), seen)
	if *restarts != 0 {
		t.Fatalf("restarts = %d", *restarts)
	}
}
