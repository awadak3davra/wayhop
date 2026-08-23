package main

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/platform"
)

// TestListenOrDefault: an empty listen must fall back to the documented default bind, never stay
// empty — an empty Addr makes net/http bind the unauthenticated panel on 0.0.0.0:80.
func TestListenOrDefault(t *testing.T) {
	if got := listenOrDefault(""); got != config.Default().Listen {
		t.Errorf("empty listen = %q, want the default %q (must not stay empty -> :80)", got, config.Default().Listen)
	}
	for _, l := range []string{":8088", "127.0.0.1:8088", "192.168.50.1:9000"} {
		if got := listenOrDefault(l); got != l {
			t.Errorf("listenOrDefault(%q) = %q, want unchanged", l, got)
		}
	}
}

func TestRouterConfigPathAllowedPinsOneLedgerDomainPerRouter(t *testing.T) {
	for name, test := range map[string]struct {
		platform platform.Platform
		path     string
		want     bool
	}{
		"openwrt canonical":  {platform.OpenWrt, "/etc/wayhop/config.json", true},
		"openwrt alternate":  {platform.OpenWrt, "/tmp/other/config.json", false},
		"keenetic canonical": {platform.Keenetic, "/opt/etc/wayhop/custom.json", true},
		"keenetic alternate": {platform.Keenetic, "/opt/etc/other/config.json", false},
		"development host":   {platform.Unknown, "/tmp/wayhop/config.json", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := routerConfigPathAllowed(test.platform, test.path); got != test.want {
				t.Fatalf("allowed=%v want=%v", got, test.want)
			}
		})
	}
}

// TestRouterConfigDirMatchesThePredicate (L5): the refusal must name a directory the predicate would
// actually accept.
//
// The refusal used to state only the rejected path — measured while bringing a test binary up on the
// operator's OpenWrt box: `openwrt routers require the installation config directory; refusing an
// independent apply-state record at "/tmp/wh-test"`. Correct, and it left the required directory to
// be found by reading the source. It now names that directory, which is worth exactly as much as the
// two agreeing: a message pointing at a path the predicate rejects is worse than no path at all.
func TestRouterConfigDirMatchesThePredicate(t *testing.T) {
	// The expected paths are LITERALS here, not derived. routerConfigPathAllowed now asks
	// routerConfigDir, so "the message names a directory the predicate accepts" became tautological:
	// a mutation renaming the constant to /etc/wayhop-old kept both sides agreeing and passed, while
	// the daemon would have started refusing the real installation directory. A test that derives the
	// answer from the code under test cannot notice the code changing its mind.
	want := map[platform.Platform]string{
		platform.OpenWrt:  "/etc/wayhop",
		platform.Keenetic: "/opt/etc/wayhop",
	}
	for _, p := range []platform.Platform{platform.OpenWrt, platform.Keenetic} {
		dir := routerConfigDir(p)
		if dir != want[p] {
			t.Errorf("%s installs into %q, got %q", p, want[p], dir)
		}
		if dir == "" {
			t.Errorf("%s pins an installation directory, so the refusal must be able to name it", p)
			continue
		}
		if !routerConfigPathAllowed(p, dir+"/config.json") {
			t.Errorf("%s: the refusal names %q, which the predicate then rejects", p, dir)
		}
		// And the pairing must not be vacuous: some other directory has to be refused, or a predicate
		// that accepted everything would satisfy the check above.
		if routerConfigPathAllowed(p, "/tmp/wh-test/config.json") {
			t.Errorf("%s: an independent config directory must still be refused", p)
		}
	}
	// A platform with no fixed installation directory names none and accepts anything — that is what
	// keeps development hosts and the demo usable.
	if dir := routerConfigDir(platform.Platform("linux")); dir != "" {
		t.Errorf("a platform with no installation directory must name none, got %q", dir)
	}
	if !routerConfigPathAllowed(platform.Platform("linux"), "/tmp/anywhere/config.json") {
		t.Error("and must accept any path")
	}
}
