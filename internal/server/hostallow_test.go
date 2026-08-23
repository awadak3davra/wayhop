package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// withLocalAddrs replaces the interface snapshot for one test. A real machine's addresses differ per
// host, so asserting against them would make every case below environment-dependent.
func withLocalAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	prev := localAddrs
	set := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		set[a] = struct{}{}
	}
	localAddrs = func() map[string]struct{} { return set }
	t.Cleanup(func() { localAddrs = prev })
}

func guard(t *testing.T, configured []string, anyHost bool) http.Handler {
	t.Helper()
	d := newHostDecider(func() []string { return configured }, func() bool { return anyHost })
	return hostAllowGuard(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func req(h http.Handler, method, host, origin string) int {
	r := httptest.NewRequest(method, "http://"+host+"/api/health", nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// TestHostAllowGuard_DefaultIsClosed is the regression for WH-SEC-002: the panel is unauthenticated
// and binds every interface, so an empty allowed_hosts must still refuse a Host this router does not
// answer to. It previously served ANY Host, which left DNS rebinding wide open.
func TestHostAllowGuard_DefaultIsClosed(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1", "198.51.100.7", "2001:db8::1")
	h := guard(t, nil, false)

	allow := []struct{ name, method, host string }{
		{"interface IP", "GET", "192.0.2.1"},
		{"interface IP with port", "GET", "192.0.2.1:8088"},
		{"second interface IP", "POST", "198.51.100.7:8088"},
		{"loopback v4", "GET", "127.0.0.1:8088"},
		{"loopback v6", "GET", "[::1]:8088"},
		{"localhost", "GET", "localhost:8088"},
		{"IPv6 literal in brackets", "GET", "[2001:db8::1]:8088"},
		{"IPv6 literal bare", "GET", "2001:db8::1"},
		{"case-insensitive IPv6", "GET", "[2001:DB8::1]:8088"},
	}
	for _, c := range allow {
		if got := req(h, c.method, c.host, ""); got != http.StatusOK {
			t.Errorf("%s: Host %q must be served by default, got %d", c.name, c.host, got)
		}
	}

	deny := []struct{ name, method, host string }{
		{"attacker GET", "GET", "attacker.example"},
		{"attacker POST", "POST", "attacker.example"},
		{"attacker with port", "GET", "attacker.example:8088"},
		{"attacker trailing dot", "GET", "attacker.example."},
		{"unrelated IP", "GET", "203.0.113.9:8088"},
		{"unrelated IPv6", "GET", "[2001:db8:dead::1]:8088"},
		{"empty host", "GET", ""},
	}
	for _, c := range deny {
		if got := req(h, c.method, c.host, ""); got != http.StatusForbidden {
			t.Errorf("%s: Host %q must be refused, got %d", c.name, c.host, got)
		}
	}
}

// TestHostAllowGuard_RebindDefeatsSameOrigin is the attack itself: after a rebind the attacker's
// page and the panel share an origin, so Origin==Host and the CSRF guard is satisfied. Only the Host
// guard stops it — which is why it wraps the same-origin guard rather than sitting beside it.
func TestHostAllowGuard_RebindDefeatsSameOrigin(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	d := newHostDecider(func() []string { return nil }, func() bool { return false })
	chain := hostAllowGuard(d, sameOriginGuard(inner))

	// Same-origin guard alone is satisfied: Origin equals Host.
	if got := req(chain, "POST", "attacker.example", "http://attacker.example"); got != http.StatusForbidden {
		t.Fatalf("rebind (Origin==Host==attacker) must be refused by the Host guard, got %d", got)
	}
	// And a GET, which carries no CSRF protection at all, is refused for the same reason.
	if got := req(chain, "GET", "attacker.example", "http://attacker.example"); got != http.StatusForbidden {
		t.Fatalf("rebind GET must be refused, got %d", got)
	}
	// A legitimate cross-origin POST is still the same-origin guard's job.
	if got := req(chain, "POST", "192.0.2.1:8088", "http://evil.example"); got != http.StatusForbidden {
		t.Fatalf("cross-origin POST must still be refused, got %d", got)
	}
	if got := req(chain, "POST", "192.0.2.1:8088", "http://192.0.2.1:8088"); got != http.StatusOK {
		t.Fatalf("same-origin POST to a local address must be served, got %d", got)
	}
}

// TestHostAllowGuard_ConfiguredIsAdditive proves an operator entry adds a name without removing the
// router's own addresses. That is what makes a wrong entry recoverable: the LAN IP keeps answering,
// so the list can be corrected from the live UI instead of over SSH.
func TestHostAllowGuard_ConfiguredIsAdditive(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1")
	h := guard(t, []string{"wayhop.example", "Router.LAN"}, false)

	for _, host := range []string{"wayhop.example", "wayhop.example:8088", "WAYHOP.EXAMPLE", "router.lan", "router.lan.", "192.0.2.1:8088", "127.0.0.1"} {
		if got := req(h, "GET", host, ""); got != http.StatusOK {
			t.Errorf("Host %q must be served, got %d", host, got)
		}
	}
	if got := req(h, "GET", "attacker.example", ""); got != http.StatusForbidden {
		t.Errorf("an unlisted, non-local Host must still be refused, got %d", got)
	}
}

// TestHostAllowGuard_NoLockout: a list naming only names this router does not have must not make the
// panel unreachable, or fixing it would need SSH.
func TestHostAllowGuard_NoLockout(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1")
	h := guard(t, []string{"typo.example"}, false)
	if got := req(h, "GET", "192.0.2.1:8088", ""); got != http.StatusOK {
		t.Fatalf("a self-excluding allow-list must still leave the LAN address reachable, got %d", got)
	}
}

// TestHostAllowGuard_HotReload: the decision reads the accessors per request, so a saved list and a
// cleared compatibility flag both take effect without a restart.
func TestHostAllowGuard_HotReload(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1")
	var configured []string
	var anyHost bool
	d := newHostDecider(func() []string { return configured }, func() bool { return anyHost })
	h := hostAllowGuard(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	if got := req(h, "GET", "wayhop.example", ""); got != http.StatusForbidden {
		t.Fatalf("unlisted name must start refused, got %d", got)
	}
	configured = []string{"wayhop.example"}
	if got := req(h, "GET", "wayhop.example", ""); got != http.StatusOK {
		t.Fatalf("adding the name must apply on the next request, got %d", got)
	}
	configured = nil
	if got := req(h, "GET", "wayhop.example", ""); got != http.StatusForbidden {
		t.Fatalf("removing the name must apply on the next request, got %d", got)
	}
}

// TestHostAllowGuard_CompatibilityFlag: the escape hatch works and is not the default. It exists for
// a deployment the allow-list cannot express; the test pins that it must be asked for explicitly.
func TestHostAllowGuard_CompatibilityFlag(t *testing.T) {
	withLocalAddrs(t, "192.0.2.1")
	if got := req(guard(t, nil, false), "GET", "attacker.example", ""); got != http.StatusForbidden {
		t.Fatalf("default must refuse; got %d", got)
	}
	if got := req(guard(t, nil, true), "GET", "attacker.example", ""); got != http.StatusOK {
		t.Fatalf("allow_any_host must serve any Host once set; got %d", got)
	}
}

// TestHostAllowGuard_NeverResolves is the rule that separates a fix from the bug: a name is allowed
// because this router carries it, never because it resolves to a local address. Accepting the latter
// would be the rebinding attack rewritten as policy.
func TestHostAllowGuard_NeverResolves(t *testing.T) {
	withLocalAddrs(t, "127.0.0.1", "192.0.2.1")
	h := guard(t, nil, false)
	// "localtest.me" and friends resolve to 127.0.0.1 in the real world. The guard must not care.
	for _, host := range []string{"localtest.me", "127.0.0.1.nip.io", "rebind.example"} {
		if got := req(h, "GET", host, ""); got != http.StatusForbidden {
			t.Errorf("Host %q must be refused: it is a NAME, and resolving it is the attack, got %d", host, got)
		}
	}
}

// TestHostAllowGuard_NewAddressIsPickedUp: an address that appears after boot (DHCP lease, a tunnel
// coming up) must be served without waiting out a cache, or the panel would 403 on its own new IP.
func TestHostAllowGuard_NewAddressIsPickedUp(t *testing.T) {
	prev := localAddrs
	t.Cleanup(func() { localAddrs = prev })
	current := map[string]struct{}{"192.0.2.1": {}}
	localAddrs = func() map[string]struct{} { return current }

	// The refresh-on-miss is rate-limited in production so an unknown Host cannot force an interface
	// enumeration per request; the test shortens that interval rather than sleeping through it.
	prevInt := localAddrMissRefresh
	localAddrMissRefresh = 0
	t.Cleanup(func() { localAddrMissRefresh = prevInt })

	h := guard(t, nil, false)
	if got := req(h, "GET", "198.51.100.7:8088", ""); got != http.StatusForbidden {
		t.Fatalf("address not yet present must be refused, got %d", got)
	}
	current = map[string]struct{}{"192.0.2.1": {}, "198.51.100.7": {}}
	if got := req(h, "GET", "198.51.100.7:8088", ""); got != http.StatusOK {
		t.Fatalf("a newly assigned address must be served on the next request, got %d", got)
	}
}
