package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func reach_hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TestEndpointReachCheck covers the diagnostic: a live server is reachable, a closed port
// is reported unreachable (warn), and an empty profile passes.
func TestEndpointReachCheck(t *testing.T) {
	// Reachable: a live httptest listener.
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ts.Close()
	upHost, upPort := reach_hostPort(t, ts.URL)

	// Unreachable: open then immediately close a listener so its loopback port is free →
	// a dial gets refused fast (no 4s timeout).
	ts2 := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	downHost, downPort := reach_hostPort(t, ts2.URL)
	ts2.Close()

	s := applyhealth_server(t)
	up := applyhealth_endpoint("up", "Reachable")
	up.Server, up.Port = upHost, upPort
	down := applyhealth_endpoint("down", "DeadServer")
	down.Server, down.Port = downHost, downPort
	for _, e := range []model.Endpoint{up, down} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatalf("UpsertEndpoint %s: %v", e.ID, err)
		}
	}
	// This test is about the DIAL path, which is production behaviour: the demo opens no sockets, and
	// applyhealth_server sets Demo only to keep the daemon inert. Saying so here keeps the two meanings
	// of that flag from quietly cancelling the subject of the test.
	s.cfg.Demo = false
	row := s.endpointReachCheck(context.Background())
	if row.Status != "warn" {
		t.Fatalf("status=%s want warn (one server unreachable): %+v", row.Status, row)
	}
	if !strings.Contains(row.Detail, "DeadServer") {
		t.Errorf("detail %q should name the unreachable endpoint", row.Detail)
	}

	// All reachable → pass.
	s2 := applyhealth_server(t)
	s2.cfg.Demo = false // same reason: the subject here is the dial, which only production performs
	if err := s2.store.UpsertEndpoint(up); err != nil {
		t.Fatal(err)
	}
	if r := s2.endpointReachCheck(context.Background()); r.Status != "pass" {
		t.Errorf("all-reachable status=%s want pass: %+v", r.Status, r)
	}

	// No endpoints → "na", not "pass". Nothing was dialled, so there is nothing to call reachable,
	// and a green row here is a router reporting that it verified something it never looked at.
	s3 := applyhealth_server(t)
	if r := s3.endpointReachCheck(context.Background()); r.Status != "na" {
		t.Errorf("no-endpoints status=%s want na: %+v", r.Status, r)
	}
}
