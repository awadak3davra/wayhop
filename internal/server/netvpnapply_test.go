package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

func emptyRouterUCI() (string, string, error) {
	return "network.lan=interface\n",
		"firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n", nil
}

func nativeRouteTestServer(t *testing.T) (*Server, *int) {
	t.Helper()
	cfg := config.Default()
	cfg.Demo = false
	reads := 0
	return &Server{
		cfg:   cfg,
		store: storeWithAWG(t),
		uciReader: func() (string, string, error) {
			reads++
			return "network.lan=interface\n",
				"firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n", nil
		},
		platformOf: func() platform.Platform { return platform.OpenWrt },
		netifdProtosOf: func() netvpn.RouterProtos {
			return netvpn.RouterProtos{"amneziawg": true}
		},
	}, &reads
}

func assertNativeMutationHasNoBypassRoute(t *testing.T, s *Server, reads *int, path string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = "localhost"
	authenticatedTestHandler(t, s).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST %s status %d, want no standalone mutation route (404): %s", path, rec.Code, rec.Body.String())
	}
	if *reads != 0 {
		t.Fatalf("POST %s read UCI %d time(s) before refusing", path, *reads)
	}
}

func TestNetvpnMutationHasNoRouteAroundStrictReviewedApply(t *testing.T) {
	for _, path := range []string{
		"/api/netvpn/apply?endpoint=ep-awg-1&zone=vpn",
		"/api/netvpn/remove?iface=wr_test",
		"/api/pbr/apply",
		"/api/pbr/teardown",
	} {
		t.Run(path, func(t *testing.T) {
			s, reads := nativeRouteTestServer(t)
			assertNativeMutationHasNoBypassRoute(t, s, reads, path)
		})
	}
}

func TestNetvpnPlanRouteRemainsReadOnlyAndAvailable(t *testing.T) {
	s, reads := nativeRouteTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/netvpn/plan?endpoint=ep-awg-1&zone=vpn", nil)
	req.Host = "localhost"
	authenticatedTestHandler(t, s).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET plan status %d: %s", rec.Code, rec.Body.String())
	}
	if *reads == 0 {
		t.Fatal("GET plan did not inspect the router before producing a preview")
	}
	var got struct {
		Hash     string   `json:"plan_hash"`
		Commands []string `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Hash == "" || len(got.Commands) == 0 {
		t.Fatalf("read-only preview omitted its exact plan: %+v", got)
	}
}

// The hash still defines the exact preview artifact that the strict transaction will embed. It
// must cover commit behavior as well as staged commands even though direct execution is dark.
func TestPlanHash_CoversTheCommitTailToo(t *testing.T) {
	base := netvpn.Plan{
		Iface:    derivedTestIface(),
		Commands: []string{"uci set network." + derivedTestIface() + "=interface"},
		Commit:   []string{"uci commit network", "/etc/init.d/network reload"},
	}
	other := base
	other.Commit = []string{"uci commit network"}
	if planHash(base) == planHash(other) {
		t.Error("two plans with different commit tails hash the same")
	}

	zoned := base
	zoned.Zone = "vpn"
	if planHash(base) == planHash(zoned) {
		t.Error("the firewall zone is not part of the pinned plan")
	}

	same := netvpn.Plan{
		Iface:    derivedTestIface(),
		Commands: []string{"uci set network." + derivedTestIface() + "=interface"},
		Commit:   []string{"uci commit network", "/etc/init.d/network reload"},
	}
	if planHash(base) != planHash(same) {
		t.Error("the same plan hashed differently twice")
	}
}
