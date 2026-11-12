package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wayhop/internal/config"
)

func TestGeneratorOptionBuildersCarryDNSPort(t *testing.T) {
	desired := DesiredSnapshot{Config: *config.Default()}
	desired.Config.RoutingMode = "mixed"
	opts, err := executionGeneratorOptions(desired, nil)
	if err != nil || opts.DNSPort != desired.Config.Ports.DNS {
		t.Errorf("executionGeneratorOptions DNSPort = %d, err %v", opts.DNSPort, err)
	}
	if got := executionKeeneticCompatibilityOptions(desired).DNSPort; got != desired.Config.Ports.DNS {
		t.Errorf("executionKeeneticCompatibilityOptions DNSPort = %d", got)
	}
	s := bindTestServer(t, feedProfile(), "")
	if got, _ := s.genOptionsWithPlan(nil, s.config()); got.DNSPort != s.config().Ports.DNS {
		t.Errorf("genOptionsWithPlan DNSPort = %d, want %d", got.DNSPort, s.config().Ports.DNS)
	}
}

func TestServeClientsFact(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	s.dnsRunnerOf = func(string, ...string) (string, error) { return "", nil }
	probeCalls := 0
	probe := func(context.Context, string) error { probeCalls++; return nil }
	fact := s.serveClientsFact(context.Background(), probe)
	if fact.Configured || fact.Listening || fact.Port != 5353 || probeCalls != 0 {
		t.Fatalf("not configured: %+v, probes %d", fact, probeCalls)
	}

	prof := s.store.Profile()
	dns := secureDNSTemplate(&prof)
	dns.ServeClients = true
	if err := s.store.SetDNS(dns); err != nil {
		t.Fatal(err)
	}
	var addr string
	var remaining time.Duration
	fact = s.serveClientsFact(context.Background(), func(ctx context.Context, got string) error {
		addr = got
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("probe has no deadline")
		} else {
			remaining = time.Until(deadline)
		}
		return nil
	})
	if !fact.Configured || !fact.Listening || fact.Port != 5353 {
		t.Fatalf("configured and listening: %+v", fact)
	}
	if addr != "127.0.0.1:5353" {
		t.Errorf("probe address = %q", addr)
	}
	if remaining <= 0 || remaining > 1500*time.Millisecond {
		t.Errorf("probe timeout = %v, want at most 1.5s", remaining)
	}
	fact = s.serveClientsFact(context.Background(), func(context.Context, string) error { return errors.New("not listening") })
	if !fact.Configured || fact.Listening {
		t.Fatalf("configured and not listening: %+v", fact)
	}

	s.cfg.Demo = true
	fact = s.serveClientsFact(context.Background(), func(context.Context, string) error {
		t.Fatal("demo probed a resolver")
		return nil
	})
	if !fact.Configured || !fact.Listening || fact.Port != 5353 {
		t.Fatalf("demo answer: %+v", fact)
	}
}

func TestGetDNSNativeDemoServeClients(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	prof := s.store.Profile()
	dns := secureDNSTemplate(&prof)
	dns.ServeClients = true
	if err := s.store.SetDNS(dns); err != nil {
		t.Fatal(err)
	}
	s.cfg.Demo = true
	s.dnsPlatformOf = func() string { return "" }
	w := httptest.NewRecorder()
	s.handleGetDNSNative(w, httptest.NewRequest(http.MethodGet, "/api/dns/native", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	var resp struct {
		Available    bool               `json:"available"`
		ServeClients serveClientsStatus `json:"serve_clients"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Available || !resp.ServeClients.Configured || !resp.ServeClients.Listening || resp.ServeClients.Port != 5353 {
		t.Fatalf("demo response: %+v", resp)
	}
}

func TestServeClientsFact_HeldBy(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	prof := s.store.Profile()
	dns := secureDNSTemplate(&prof)
	dns.ServeClients = true
	if err := s.store.SetDNS(dns); err != nil {
		t.Fatal(err)
	}

	// When another process holds the UDP port, listening must be false and held_by must be set.
	s.dnsRunnerOf = func(name string, args ...string) (string, error) {
		if name == "netstat" {
			return "udp 0 0 0.0.0.0:5353 0.0.0.0:* 1234/dnsmasq\n", nil
		}
		return "", nil
	}
	fact := s.serveClientsFact(context.Background(), func(context.Context, string) error {
		t.Fatal("probe should not be called when another process holds the port")
		return nil
	})
	if !fact.Configured {
		t.Error("want Configured=true")
	}
	if fact.Listening {
		t.Error("want Listening=false when held by dnsmasq")
	}
	if fact.HeldBy != "dnsmasq" {
		t.Errorf("HeldBy = %q, want dnsmasq", fact.HeldBy)
	}

	// When sing-box holds the port it is listening, even when its resolver cannot answer this moment.
	s.dnsRunnerOf = func(name string, args ...string) (string, error) {
		if name == "netstat" {
			return "udp 0 0 0.0.0.0:5353 0.0.0.0:* 5678/sing-box\n", nil
		}
		return "", nil
	}
	fact = s.serveClientsFact(context.Background(), func(context.Context, string) error {
		return errors.New("no upstream answered")
	})
	if !fact.Listening || fact.HeldBy != "" {
		t.Errorf("want Listening=true, HeldBy='', got %+v", fact)
	}

	// When netstat fails, fall back to probe alone.
	s.dnsRunnerOf = func(name string, args ...string) (string, error) {
		return "", errors.New("netstat not found")
	}
	probed := false
	fact = s.serveClientsFact(context.Background(), func(context.Context, string) error {
		probed = true
		return nil
	})
	if !probed || !fact.Listening {
		t.Errorf("probe should run on netstat failure, got probed=%v listening=%v", probed, fact.Listening)
	}
}
